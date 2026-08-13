#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace noleax::agent {

// Bounded multi-producer/single-consumer ring queue.
//
// Slot sequence encoding (H4): slot i stores its logical Vyukov-style sequence number
// MINUS i, so an all-zero slot array is exactly the "every slot free at lap 0" state.
// That makes the queue usable straight out of fresh zero pages: neither construction nor
// reset_quiescent() ever writes the whole slot array, so a multi-GiB ring living in a
// dedicated anonymous mapping commits pages only when a producer first publishes into
// them (a producer's sequence READ of a never-touched slot faults in the shared zero
// page, which costs no memory; only the publishing write allocates a real page).
//
// Concurrency argument for the lazy initialization:
//   - Producers claim positions strictly in enqueue_ CAS order, so the first writer of
//     slot i in any lap is always the producer that claimed that position; consumers
//     only read a slot's value after an acquire load observes the published sequence
//     (release/acquire pairing, unchanged from the original algorithm).
//   - reset_quiescent() requires the caller to have stopped every producer and consumer
//     (unchanged contract). By then every lap-0 claim has max-updated
//     touched_watermark_ (sequenced before the claiming try_emplace returns, hence
//     happens-before the reset through the caller's external synchronization), so
//     re-zeroing exactly [0, touched_watermark_) restores the all-zero invariant for
//     every slot that was ever written; slots past the watermark still hold their
//     construction-time zero pages. Slots claimed at lap >= 1 imply all lap-0 positions
//     were claimed, which already pinned the watermark at the capacity.
//   - The distance arithmetic is unchanged: stored'(i, pos) = stored(i, pos) - i keeps
//     distance = stored' - (pos - i) == stored - pos, including the wrap test that
//     detects a full ring.
template <typename T>
class BoundedMpscQueue final {
  static_assert(std::is_trivially_copyable_v<T>);
  static_assert(std::is_nothrow_default_constructible_v<T>);
  static_assert(std::is_nothrow_copy_assignable_v<T>);
  static_assert(std::is_trivially_destructible_v<T>);
  static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

 public:
  // Reclaims externally provided slot storage; receives the base pointer and the byte
  // size (capacity * slot_size()).
  using StorageDeleter = void (*)(void* slots, std::size_t bytes) noexcept;

  // Heap-backed storage: eagerly value-initialized (every page committed up front).
  explicit BoundedMpscQueue(std::size_t capacity)
      : capacity_{validate_capacity(capacity)},
        mask_{capacity_ - 1U},
        slots_{new Slot[static_cast<std::size_t>(capacity_)]()},
        storage_deleter_{&delete_heap_slots} {}

  // Takes ownership of an externally allocated slot array of `capacity` slots. The
  // storage must read as all zeros (a fresh anonymous mapping qualifies) and stays
  // owned until `deleter(base, bytes)` runs in the destructor.
  BoundedMpscQueue(std::size_t capacity, void* slots, StorageDeleter deleter)
      : capacity_{validate_capacity(capacity)},
        mask_{capacity_ - 1U},
        slots_{static_cast<Slot*>(slots)},
        storage_deleter_{deleter} {
    if (slots == nullptr || deleter == nullptr) {
      throw std::invalid_argument{
          "MPSC queue external slot storage requires storage and a deleter"};
    }
  }

  ~BoundedMpscQueue() {
    storage_deleter_(slots_, static_cast<std::size_t>(capacity_) * sizeof(Slot));
  }

  BoundedMpscQueue(const BoundedMpscQueue&) = delete;
  BoundedMpscQueue& operator=(const BoundedMpscQueue&) = delete;
  BoundedMpscQueue(BoundedMpscQueue&&) = delete;
  BoundedMpscQueue& operator=(BoundedMpscQueue&&) = delete;

  // Footprint of one ring slot (sequence word + event); the slot array is
  // capacity() * slot_size() bytes.
  [[nodiscard]] static constexpr std::size_t slot_size() noexcept { return sizeof(Slot); }

  template <typename Producer>
    requires std::is_nothrow_invocable_v<Producer&, T&, std::uint64_t>
  [[nodiscard]] bool try_emplace(Producer&& producer) noexcept {
    std::uint64_t position = enqueue_.value.load(std::memory_order_relaxed);
    Slot* slot = nullptr;
    std::size_t slot_index = 0U;

    for (;;) {
      if (position == std::numeric_limits<std::uint64_t>::max()) {
        note_drop();
        return false;
      }

      slot_index = static_cast<std::size_t>(position & mask_);
      slot = &slots_[slot_index];
      const std::uint64_t sequence = slot->sequence.load(std::memory_order_acquire);
      const std::uint64_t distance = sequence - (position - slot_index);
      if (distance == 0U) {
        if (enqueue_.value.compare_exchange_weak(position, position + 1U, std::memory_order_relaxed,
                                                 std::memory_order_relaxed)) {
          break;
        }
      } else if (distance > std::numeric_limits<std::uint64_t>::max() / 2U) {
        note_drop();
        return false;
      } else {
        position = enqueue_.value.load(std::memory_order_relaxed);
      }
    }

    // A lap-0 claim first-touches the slot: pin the reset watermark before publishing so
    // a later quiescent reset re-zeroes every slot that was ever written.
    if (position < capacity_) {
      note_touched(position + 1U);
    }
    std::forward<Producer>(producer)(slot->value, position + 1U);
    slot->sequence.store(position + 1U - slot_index, std::memory_order_release);
    return true;
  }

  [[nodiscard]] bool try_push(const T& value) noexcept {
    return try_emplace([&value](T& destination, std::uint64_t) noexcept { destination = value; });
  }

  [[nodiscard]] bool try_pop(T& value) noexcept {
    const std::uint64_t position = dequeue_.value.load(std::memory_order_relaxed);
    if (position == std::numeric_limits<std::uint64_t>::max()) {
      return false;
    }
    const std::size_t slot_index = static_cast<std::size_t>(position & mask_);
    Slot& slot = slots_[slot_index];
    if (slot.sequence.load(std::memory_order_acquire) != position + 1U - slot_index) {
      return false;
    }

    note_occupancy_high_water(position);
    value = slot.value;
    slot.sequence.store(position + capacity_ - slot_index, std::memory_order_release);
    dequeue_.value.store(position + 1U, std::memory_order_relaxed);
    return true;
  }

  [[nodiscard]] std::size_t capacity() const noexcept {
    return static_cast<std::size_t>(capacity_);
  }

  // Live telemetry for CaptureStatus. occupancy() approximates the current depth: a
  // claimed-but-unpublished producer slot counts as occupied. consumed_count() is the
  // total number of popped elements. high_water() is the consumer-sampled occupancy
  // maximum (full-queue drops pin it at capacity).
  [[nodiscard]] std::uint64_t occupancy() const noexcept {
    const std::uint64_t enqueued = enqueue_.value.load(std::memory_order_acquire);
    const std::uint64_t dequeued = dequeue_.value.load(std::memory_order_acquire);
    const std::uint64_t depth = enqueued - dequeued;
    return depth > capacity_ ? capacity_ : depth;
  }

  [[nodiscard]] std::uint64_t consumed_count() const noexcept {
    return dequeue_.value.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::uint64_t high_water() const noexcept {
    return high_water_.value.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::uint64_t dropped_count() const noexcept {
    return dropped_.value.load(std::memory_order_relaxed);
  }

  [[nodiscard]] std::uint64_t take_dropped_count() noexcept {
    return dropped_.value.exchange(0U, std::memory_order_acq_rel);
  }

  // The caller must ensure that no producer or consumer is using the queue. Only the
  // slots a previous lap actually wrote are re-zeroed (see the class comment), so a
  // reset of a mostly-untouched ring does not commit its pages.
  void reset_quiescent() noexcept {
    enqueue_.value.store(0U, std::memory_order_relaxed);
    dequeue_.value.store(0U, std::memory_order_relaxed);
    dropped_.value.store(0U, std::memory_order_relaxed);
    high_water_.value.store(0U, std::memory_order_relaxed);
    const std::uint64_t touched = touched_watermark_.value.load(std::memory_order_relaxed);
    for (std::uint64_t index = 0U; index < touched; ++index) {
      slots_[static_cast<std::size_t>(index)].sequence.store(0U, std::memory_order_relaxed);
    }
    touched_watermark_.value.store(0U, std::memory_order_relaxed);
  }

 private:
  static constexpr std::size_t kCacheLineSize = 64U;

  struct Slot {
    std::atomic<std::uint64_t> sequence{0U};
    T value{};
  };

  // Reservation, consumption, and loss accounting are independently contended cache lines.
  struct alignas(kCacheLineSize) AtomicCacheLine {
    std::atomic<std::uint64_t> value{0U};
    std::byte padding[kCacheLineSize - sizeof(value)]{};
  };

  static_assert(sizeof(AtomicCacheLine) == kCacheLineSize);
  static constexpr std::size_t kMetadataSize =
      sizeof(std::uint64_t) * 2U + sizeof(Slot*) + sizeof(StorageDeleter);
  static_assert(kMetadataSize < kCacheLineSize);

  static void delete_heap_slots(void* slots, std::size_t) noexcept {
    delete[] static_cast<Slot*>(slots);
  }

  [[nodiscard]] static std::uint64_t validate_capacity(std::size_t capacity) {
    const auto converted = static_cast<std::uint64_t>(capacity);
    if (capacity < 2U || (capacity & (capacity - 1U)) != 0U ||
        converted > std::numeric_limits<std::uint64_t>::max() / 2U) {
      throw std::invalid_argument{"MPSC queue capacity must be a power of two of at least two"};
    }
    return converted;
  }

  void note_drop() noexcept {
    // A drop means the ring was full: pin the occupancy high water at the capacity.
    std::uint64_t high = high_water_.value.load(std::memory_order_relaxed);
    while (high < capacity_ &&
           !high_water_.value.compare_exchange_weak(high, capacity_, std::memory_order_relaxed,
                                                    std::memory_order_relaxed)) {
      // compare_exchange refreshes high before the next attempt.
    }
    std::uint64_t current = dropped_.value.load(std::memory_order_relaxed);
    while (current != std::numeric_limits<std::uint64_t>::max() &&
           !dropped_.value.compare_exchange_weak(current, current + 1U, std::memory_order_relaxed,
                                                 std::memory_order_relaxed)) {
      // compare_exchange refreshes current before the next saturating attempt.
    }
  }

  // Consumer-side occupancy sample at pop time: cheap (no producer-path RMW) and exact
  // for the consumer's own dequeue position. Producer bursts between pops that fill the
  // ring surface as drops, which pin the high water separately.
  void note_occupancy_high_water(std::uint64_t position) noexcept {
    const std::uint64_t enqueued = enqueue_.value.load(std::memory_order_relaxed);
    const std::uint64_t depth = enqueued - position;
    std::uint64_t high = high_water_.value.load(std::memory_order_relaxed);
    while (depth > high && !high_water_.value.compare_exchange_weak(
                               high, depth, std::memory_order_relaxed, std::memory_order_relaxed)) {
      // compare_exchange refreshes high before the next attempt.
    }
  }

  // Tracks one past the highest lap-0 position ever claimed since the last reset; only
  // that prefix of the slot array can hold a non-zero sequence. Lap-0 claims are a tiny
  // fraction of all claims, so the max-CAS stays off the steady-state hot path.
  void note_touched(std::uint64_t next) noexcept {
    std::uint64_t watermark = touched_watermark_.value.load(std::memory_order_relaxed);
    while (next > watermark &&
           !touched_watermark_.value.compare_exchange_weak(
               watermark, next, std::memory_order_relaxed, std::memory_order_relaxed)) {
      // compare_exchange refreshes watermark before the next attempt.
    }
  }

  AtomicCacheLine enqueue_;
  AtomicCacheLine dequeue_;
  AtomicCacheLine dropped_;
  AtomicCacheLine high_water_;
  AtomicCacheLine touched_watermark_;
  const std::uint64_t capacity_;
  const std::uint64_t mask_;
  Slot* slots_;
  StorageDeleter storage_deleter_;
  std::byte metadata_padding_[kCacheLineSize - kMetadataSize]{};
};

}  // namespace noleax::agent
