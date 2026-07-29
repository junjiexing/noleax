#pragma once

#include <atomic>
#include <cstdint>
#include <exception>
#include <limits>
#include <thread>

namespace noleax::agent {

enum class ReplacementRoute : std::uint8_t {
  kTarget,
  kOriginal,
  kRecord,
};

class ReplacementLifecycle final {
 public:
  class Entry final {
   public:
    ~Entry() noexcept { lifecycle_->leave(); }

    Entry(const Entry&) = delete;
    Entry& operator=(const Entry&) = delete;
    Entry(Entry&&) = delete;
    Entry& operator=(Entry&&) = delete;

    [[nodiscard]] ReplacementRoute route() const noexcept { return route_; }
    [[nodiscard]] bool should_record() const noexcept {
      return route_ == ReplacementRoute::kRecord;
    }

   private:
    friend class ReplacementLifecycle;

    Entry(ReplacementLifecycle& lifecycle, ReplacementRoute route) noexcept
        : lifecycle_{&lifecycle}, route_{route} {}

    ReplacementLifecycle* lifecycle_;
    ReplacementRoute route_;
  };

  ReplacementLifecycle() = default;

  ReplacementLifecycle(const ReplacementLifecycle&) = delete;
  ReplacementLifecycle& operator=(const ReplacementLifecycle&) = delete;
  ReplacementLifecycle(ReplacementLifecycle&&) = delete;
  ReplacementLifecycle& operator=(ReplacementLifecycle&&) = delete;

  [[nodiscard]] Entry enter() noexcept {
    const std::uint64_t previous = in_flight_.fetch_add(1U, std::memory_order_seq_cst);
    if (previous == std::numeric_limits<std::uint64_t>::max()) {
      std::terminate();
    }
    return Entry{*this, route_.load(std::memory_order_seq_cst)};
  }

  void start_recording() noexcept {
    route_.store(ReplacementRoute::kRecord, std::memory_order_seq_cst);
  }

  void stop_recording() noexcept {
    route_.store(ReplacementRoute::kOriginal, std::memory_order_seq_cst);
  }

  void route_to_target() noexcept {
    route_.store(ReplacementRoute::kTarget, std::memory_order_seq_cst);
  }

  [[nodiscard]] ReplacementRoute route() const noexcept {
    return route_.load(std::memory_order_seq_cst);
  }

  [[nodiscard]] std::uint64_t in_flight() const noexcept {
    return in_flight_.load(std::memory_order_seq_cst);
  }

  [[nodiscard]] bool wait_for_quiescence(std::uint32_t max_yields) const noexcept {
    for (std::uint32_t yielded = 0U;; ++yielded) {
      if (in_flight_.load(std::memory_order_seq_cst) == 0U) {
        return true;
      }
      if (yielded == max_yields) {
        return false;
      }
      std::this_thread::yield();
    }
  }

 private:
  void leave() noexcept {
    const std::uint64_t previous = in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
    if (previous == 0U) {
      std::terminate();
    }
  }

  static_assert(std::atomic<ReplacementRoute>::is_always_lock_free);
  static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

  std::atomic<ReplacementRoute> route_{ReplacementRoute::kTarget};
  std::atomic<std::uint64_t> in_flight_{0U};
};

}  // namespace noleax::agent
