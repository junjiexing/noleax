#pragma once

#include <atomic>
#include <cstdint>
#include <exception>
#include <limits>
#include <thread>

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/hook_section.hpp"

namespace noleax::agent {

namespace detail {

inline constexpr std::uint32_t kReplacementGateCoordinatorDepth = 2U;

inline std::atomic<bool> replacement_gate_closed{false};
inline std::atomic<std::uint64_t> replacement_gate_epoch{0U};
inline std::atomic<std::uint64_t> replacement_gate_transitions{0U};
inline std::atomic<std::uint64_t> replacement_active_calls{0U};
inline std::atomic<std::uint64_t> replacement_gate_waiters{0U};

// The uncounted window between a replacement's first instruction and the lifecycle counters
// lives in the dedicated ".nlxhk" section so the patch rendezvous can prove the section is
// empty before the module reference is released. Keep the section limited to these helpers and
// the unscoped entry/exit pair below; everything else must stay out to avoid rendezvous false
// positives from unrelated agent code.
NOLEAX_HOOK_SECTION_PUSH

NOLEAX_HOOK_SECTION
inline void increment_or_terminate(std::atomic<std::uint64_t>& value) noexcept {
  if (value.fetch_add(1U, std::memory_order_seq_cst) == std::numeric_limits<std::uint64_t>::max()) {
    std::terminate();
  }
}

NOLEAX_HOOK_SECTION
inline void decrement_or_terminate(std::atomic<std::uint64_t>& value) noexcept {
  if (value.fetch_sub(1U, std::memory_order_seq_cst) == 0U) {
    std::terminate();
  }
}

NOLEAX_HOOK_SECTION
inline void enter_replacement_gate() noexcept {
  // Read the guard depths through the dedicated probe: it is called only from here, so it can
  // live in ".nlxhk" with the rest of the gate. Calling the shared guard queries instead would
  // let an in-transit thread sit in their out-of-section bodies, invisible to the rendezvous.
  const HookGuardThreadState guard_state = probe_hook_guard_thread_state();
  // Nested hook calls must finish their outer callback. The coordinator owns two internal scopes
  // so it alone can service IPC and teardown while ordinary internal workers are parked.
  if (guard_state.hook_depth != 0U ||
      guard_state.internal_depth >= kReplacementGateCoordinatorDepth) {
    increment_or_terminate(replacement_active_calls);
    return;
  }
  for (;;) {
    increment_or_terminate(replacement_gate_transitions);
    const bool closed = replacement_gate_closed.load(std::memory_order_seq_cst);
    if (!closed) {
      increment_or_terminate(replacement_active_calls);
      decrement_or_terminate(replacement_gate_transitions);
      return;
    }
    decrement_or_terminate(replacement_gate_transitions);
    increment_or_terminate(replacement_gate_waiters);
    for (;;) {
      const std::uint64_t epoch = replacement_gate_epoch.load(std::memory_order_acquire);
      const bool still_closed = replacement_gate_closed.load(std::memory_order_seq_cst);
      if (!still_closed) {
        break;
      }
      replacement_gate_epoch.wait(epoch, std::memory_order_acquire);
    }
    decrement_or_terminate(replacement_gate_waiters);
  }
}

NOLEAX_HOOK_SECTION
inline void leave_replacement_gate() noexcept { decrement_or_terminate(replacement_active_calls); }

NOLEAX_HOOK_SECTION_POP

}  // namespace detail

class ReplacementGateCoordinatorScope final {
 public:
  ReplacementGateCoordinatorScope() noexcept = default;

  ReplacementGateCoordinatorScope(const ReplacementGateCoordinatorScope&) = delete;
  ReplacementGateCoordinatorScope& operator=(const ReplacementGateCoordinatorScope&) = delete;
  ReplacementGateCoordinatorScope(ReplacementGateCoordinatorScope&&) = delete;
  ReplacementGateCoordinatorScope& operator=(ReplacementGateCoordinatorScope&&) = delete;

 private:
  InternalThreadScope internal_scope_;
  InternalThreadScope coordinator_scope_;
};

class ReplacementQuiescenceGate final {
 public:
  [[nodiscard]] static bool close_and_wait(std::uint32_t max_yields) noexcept {
    detail::replacement_gate_closed.store(true, std::memory_order_seq_cst);
    for (std::uint32_t yielded = 0U;; ++yielded) {
      if (detail::replacement_gate_transitions.load(std::memory_order_seq_cst) == 0U &&
          detail::replacement_active_calls.load(std::memory_order_seq_cst) == 0U) {
        return true;
      }
      if (yielded == max_yields) {
        return false;
      }
      std::this_thread::yield();
    }
  }

  static void open() noexcept {
    detail::replacement_gate_closed.store(false, std::memory_order_seq_cst);
    detail::replacement_gate_epoch.fetch_add(1U, std::memory_order_release);
    detail::replacement_gate_epoch.notify_all();
  }

  // Waits until every thread parked in the gate has woken and fully left its replacement call.
  // Must only be called with the gate open and no way for new threads to enter a replacement
  // (targets reverted); otherwise the counters can never be trusted to stay at zero.
  [[nodiscard]] static bool wait_for_drain(std::uint32_t max_yields) noexcept {
    for (std::uint32_t yielded = 0U;; ++yielded) {
      if (detail::replacement_gate_waiters.load(std::memory_order_seq_cst) == 0U &&
          detail::replacement_gate_transitions.load(std::memory_order_seq_cst) == 0U &&
          detail::replacement_active_calls.load(std::memory_order_seq_cst) == 0U) {
        return true;
      }
      if (yielded == max_yields) {
        return false;
      }
      std::this_thread::yield();
    }
  }

  [[nodiscard]] static bool is_closed() noexcept {
    return detail::replacement_gate_closed.load(std::memory_order_seq_cst);
  }

  [[nodiscard]] static std::uint64_t active_call_count() noexcept {
    return detail::replacement_active_calls.load(std::memory_order_seq_cst);
  }

  [[nodiscard]] static std::uint64_t transition_count() noexcept {
    return detail::replacement_gate_transitions.load(std::memory_order_seq_cst);
  }

  [[nodiscard]] static std::uint64_t waiter_count() noexcept {
    return detail::replacement_gate_waiters.load(std::memory_order_seq_cst);
  }
};

enum class ReplacementRoute : std::uint8_t {
  kTarget,
  kOriginal,
  kRecord,
};

class ReplacementLifecycle final {
 public:
  class Entry final {
   public:
    ~Entry() noexcept { lifecycle_->leave_unscoped(route_); }

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

  [[nodiscard]] Entry enter() noexcept { return Entry{*this, enter_unscoped()}; }

  // The unscoped pair exists for Windows replacements that require SEH __finally cleanup.
  // Every successful enter must be paired with exactly one leave. Both are defined below the
  // class inside the ".nlxhk" section together with the gate helpers.
  [[nodiscard]] ReplacementRoute enter_unscoped() noexcept;

  void leave_unscoped(ReplacementRoute route) noexcept;

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

  [[nodiscard]] std::uint64_t recording_in_flight() const noexcept {
    return recording_in_flight_.load(std::memory_order_seq_cst);
  }

  [[nodiscard]] bool wait_for_quiescence(std::uint32_t max_yields) const noexcept {
    for (std::uint32_t yielded = 0U;; ++yielded) {
      if (entry_transitions_.load(std::memory_order_seq_cst) == 0U &&
          in_flight_.load(std::memory_order_seq_cst) == 0U) {
        return true;
      }
      if (yielded == max_yields) {
        return false;
      }
      std::this_thread::yield();
    }
  }

  [[nodiscard]] bool wait_for_recording_quiescence(std::uint32_t max_yields) const noexcept {
    for (std::uint32_t yielded = 0U;; ++yielded) {
      if (entry_transitions_.load(std::memory_order_seq_cst) == 0U &&
          recording_in_flight_.load(std::memory_order_seq_cst) == 0U) {
        return true;
      }
      if (yielded == max_yields) {
        return false;
      }
      std::this_thread::yield();
    }
  }

 private:
  static_assert(std::atomic<ReplacementRoute>::is_always_lock_free);
  static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

  std::atomic<ReplacementRoute> route_{ReplacementRoute::kTarget};
  std::atomic<std::uint64_t> entry_transitions_{0U};
  std::atomic<std::uint64_t> in_flight_{0U};
  std::atomic<std::uint64_t> recording_in_flight_{0U};
};

NOLEAX_HOOK_SECTION_PUSH

NOLEAX_HOOK_SECTION
inline ReplacementRoute ReplacementLifecycle::enter_unscoped() noexcept {
  detail::enter_replacement_gate();
  const std::uint64_t previous_transition =
      entry_transitions_.fetch_add(1U, std::memory_order_seq_cst);
  if (previous_transition == std::numeric_limits<std::uint64_t>::max()) {
    std::terminate();
  }
  const ReplacementRoute route = route_.load(std::memory_order_seq_cst);
  const std::uint64_t previous = in_flight_.fetch_add(1U, std::memory_order_seq_cst);
  if (previous == std::numeric_limits<std::uint64_t>::max()) {
    std::terminate();
  }
  if (route == ReplacementRoute::kRecord) {
    const std::uint64_t previous_recording =
        recording_in_flight_.fetch_add(1U, std::memory_order_seq_cst);
    if (previous_recording == std::numeric_limits<std::uint64_t>::max()) {
      std::terminate();
    }
  }
  if (entry_transitions_.fetch_sub(1U, std::memory_order_seq_cst) == 0U) {
    std::terminate();
  }
  return route;
}

NOLEAX_HOOK_SECTION
inline void ReplacementLifecycle::leave_unscoped(ReplacementRoute route) noexcept {
  if (route == ReplacementRoute::kRecord) {
    const std::uint64_t previous_recording =
        recording_in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
    if (previous_recording == 0U) {
      std::terminate();
    }
  }
  const std::uint64_t previous = in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
  if (previous == 0U) {
    std::terminate();
  }
  detail::leave_replacement_gate();
}

NOLEAX_HOOK_SECTION_POP

}  // namespace noleax::agent
