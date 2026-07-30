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
    if (dequeue_.value == std::numeric_limits<std::uint64_t>::max()) {
      return false;
    }
    Slot& slot = slots_[static_cast<std::size_t>(dequeue_.value & mask_)];
    if (slot.sequence.load(std::memory_order_acquire) != dequeue_.value + 1U) {
      return false;
    }

    value = slot.value;
    slot.sequence.store(dequeue_.value + capacity_, std::memory_order_release);
    ++dequeue_.value;
    return true;
  }

  [[nodiscard]] std::size_t capacity() const noexcept {
    return static_cast<std::size_t>(capacity_);
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
    dequeue_.value = 0U;
    dropped_.value.store(0U, std::memory_order_relaxed);
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

  struct alignas(kCacheLineSize) ConsumerCacheLine {
    std::uint64_t value{0U};
    std::byte padding[kCacheLineSize - sizeof(value)]{};
  };

  static_assert(sizeof(AtomicCacheLine) == kCacheLineSize);
  static_assert(sizeof(ConsumerCacheLine) == kCacheLineSize);
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
    std::uint64_t current = dropped_.value.load(std::memory_order_relaxed);
    while (current != std::numeric_limits<std::uint64_t>::max() &&
           !dropped_.value.compare_exchange_weak(current, current + 1U, std::memory_order_relaxed,
                                                 std::memory_order_relaxed)) {
      // compare_exchange refreshes current before the next saturating attempt.
    }
  }

  AtomicCacheLine enqueue_;
  ConsumerCacheLine dequeue_;
  AtomicCacheLine dropped_;
  const std::uint64_t capacity_;
  const std::uint64_t mask_;
  std::unique_ptr<Slot[]> slots_;
  std::byte metadata_padding_[kCacheLineSize - kMetadataSize]{};
};

}  // namespace noleax::agent
