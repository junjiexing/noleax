#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace noleax::agent {

template <typename T>
class BoundedMpscQueue final {
  static_assert(std::is_trivially_copyable_v<T>);
  static_assert(std::is_nothrow_default_constructible_v<T>);
  static_assert(std::is_nothrow_copy_assignable_v<T>);
  static_assert(std::is_trivially_destructible_v<T>);
  static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

 public:
  explicit BoundedMpscQueue(std::size_t capacity)
      : capacity_{validate_capacity(capacity)},
        mask_{capacity_ - 1U},
        slots_{std::make_unique<Slot[]>(static_cast<std::size_t>(capacity_))} {
    reset_quiescent();
  }

  ~BoundedMpscQueue() = default;

  BoundedMpscQueue(const BoundedMpscQueue&) = delete;
  BoundedMpscQueue& operator=(const BoundedMpscQueue&) = delete;
  BoundedMpscQueue(BoundedMpscQueue&&) = delete;
  BoundedMpscQueue& operator=(BoundedMpscQueue&&) = delete;

  template <typename Producer>
    requires std::is_nothrow_invocable_v<Producer&, T&, std::uint64_t>
  [[nodiscard]] bool try_emplace(Producer&& producer) noexcept {
    std::uint64_t position = enqueue_.value.load(std::memory_order_relaxed);
    Slot* slot = nullptr;

    for (;;) {
      if (position == std::numeric_limits<std::uint64_t>::max()) {
        note_drop();
        return false;
      }

      slot = &slots_[static_cast<std::size_t>(position & mask_)];
      const std::uint64_t sequence = slot->sequence.load(std::memory_order_acquire);
      const std::uint64_t distance = sequence - position;
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

    std::forward<Producer>(producer)(slot->value, position + 1U);
    slot->sequence.store(position + 1U, std::memory_order_release);
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
    Slot& slot = slots_[static_cast<std::size_t>(position & mask_)];
    if (slot.sequence.load(std::memory_order_acquire) != position + 1U) {
      return false;
    }

    note_occupancy_high_water(position);
    value = slot.value;
    slot.sequence.store(position + capacity_, std::memory_order_release);
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

  // The caller must ensure that no producer or consumer is using the queue.
  void reset_quiescent() noexcept {
    enqueue_.value.store(0U, std::memory_order_relaxed);
    dequeue_.value.store(0U, std::memory_order_relaxed);
    dropped_.value.store(0U, std::memory_order_relaxed);
    high_water_.value.store(0U, std::memory_order_relaxed);
    for (std::uint64_t index = 0U; index < capacity_; ++index) {
      slots_[static_cast<std::size_t>(index)].sequence.store(index, std::memory_order_relaxed);
    }
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
      sizeof(std::uint64_t) * 2U + sizeof(std::unique_ptr<Slot[]>);
  static_assert(kMetadataSize < kCacheLineSize);

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

  AtomicCacheLine enqueue_;
  AtomicCacheLine dequeue_;
  AtomicCacheLine dropped_;
  AtomicCacheLine high_water_;
  const std::uint64_t capacity_;
  const std::uint64_t mask_;
  std::unique_ptr<Slot[]> slots_;
  std::byte metadata_padding_[kCacheLineSize - kMetadataSize]{};
};

}  // namespace noleax::agent
