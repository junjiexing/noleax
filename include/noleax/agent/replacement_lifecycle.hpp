#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <thread>

#if defined(__linux__)
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <ctime>
#endif

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

// Quiescence wait epoch (H1-A, docs/HARDENING_PLAN.md): every wait on a lifecycle/gate
// counter sleeps on this epoch with an absolute deadline instead of spinning a yield
// counter. Any watched counter that reaches zero bumps the epoch and notifies, so a
// waiter wakes as soon as quiescence is possible. 32 bits so the Linux wait can be a
// direct futex word; wraparound is harmless because waiters re-evaluate the real
// predicate after every wake. quiescence_waiters gates the notify off the replacement
// hot path: it is only bumped when a counter reaches zero, and only notifies when a
// waiter is registered.
inline std::atomic<std::uint32_t> quiescence_epoch{0U};
inline std::atomic<std::uint32_t> quiescence_waiters{0U};

// The uncounted window between a replacement's first instruction and the lifecycle counters
// lives in the dedicated ".nlxhk" section so the patch rendezvous can prove the section is
// empty before the module reference is released. Keep the section limited to these helpers and
// the unscoped entry/exit pair below; everything else must stay out to avoid rendezvous false
// positives from unrelated agent code.
NOLEAX_HOOK_IMM_SECTION_PUSH

NOLEAX_HOOK_IMM_SECTION
inline void increment_or_terminate(std::atomic<std::uint64_t>& value) noexcept {
  if (value.fetch_add(1U, std::memory_order_seq_cst) == std::numeric_limits<std::uint64_t>::max()) {
    std::terminate();
  }
}

NOLEAX_HOOK_IMM_SECTION
inline void notify_quiescence_epoch() noexcept {
  if (quiescence_waiters.load(std::memory_order_acquire) == 0U) {
    return;
  }
  quiescence_epoch.fetch_add(1U, std::memory_order_release);
  // Wake the deadline-waiters with the platform primitive directly: std::atomic
  // ::notify_all may skip the wake syscall entirely when the standard library tracks no
  // waiters of its own (libstdc++ does), and our waiters sleep on the raw futex word.
  // Windows polls the portable fallback below (1 ms slices) — the WaitOnAddress variant
  // proved unverifiable without a Windows toolchain (linkage + import-lib drift across
  // SDKs); these are teardown paths, so the poll cost is noise either way.
  // Same out-of-section call class as the gate's epoch.wait above — the wake lands in
  // CRT/kernel code, never in noleax code the rendezvous scans.
#if defined(__linux__)
  static_cast<void>(::syscall(SYS_futex, reinterpret_cast<std::uint32_t*>(&quiescence_epoch),
                              FUTEX_WAKE | FUTEX_PRIVATE_FLAG, __INT_MAX__, nullptr, nullptr));
#else
  quiescence_epoch.notify_all();
#endif
}

NOLEAX_HOOK_IMM_SECTION
inline void decrement_or_terminate(std::atomic<std::uint64_t>& value) noexcept {
  const std::uint64_t previous = value.fetch_sub(1U, std::memory_order_seq_cst);
  if (previous == 0U) {
    std::terminate();
  }
  // A counter reaching zero can complete a close_and_wait/wait_for_drain predicate:
  // wake the sleepers. Same out-of-section call class as the gate's epoch.wait above —
  // the notify lands in CRT/futex code, never in noleax code the rendezvous scans.
  if (previous == 1U) {
    notify_quiescence_epoch();
  }
}

NOLEAX_HOOK_IMM_SECTION
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

NOLEAX_HOOK_IMM_SECTION
inline void leave_replacement_gate() noexcept { decrement_or_terminate(replacement_active_calls); }

NOLEAX_HOOK_IMM_SECTION_POP

// Sleeps until the quiescence epoch differs from `expected` or the deadline passes.
// Returns false only on timeout; a wake (notify, value change, signal, spurious) returns
// true so the caller re-evaluates the predicate. This is the C++20 counterpart of the
// untimed std::atomic::wait the gate uses: a deadline-aware wait that never spins.
[[nodiscard]] inline bool quiescence_epoch_wait(
    std::uint32_t expected, std::chrono::steady_clock::time_point deadline) noexcept {
#if defined(__linux__)
  // FUTEX_WAIT_BITSET with an absolute CLOCK_MONOTONIC timeout (steady_clock). The notify
  // path issues FUTEX_WAKE on the same word directly.
  const std::int64_t nanoseconds =
      std::chrono::duration_cast<std::chrono::nanoseconds>(deadline.time_since_epoch()).count();
  const timespec timeout{static_cast<time_t>(nanoseconds / 1'000'000'000LL),
                         static_cast<long>(nanoseconds % 1'000'000'000LL)};
  const long result = ::syscall(SYS_futex, reinterpret_cast<std::uint32_t*>(&quiescence_epoch),
                                FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, expected, &timeout, nullptr,
                                FUTEX_BITSET_MATCH_ANY);
  if (result == 0) {
    return true;
  }
  return errno != ETIMEDOUT;
#else
  // Portable fallback: spin-yield until the deadline. A 1 ms sleep poll is NOT an option:
  // under continuous allocation churn the all-zero window of the watched counters can be
  // microseconds brief, and a sleep sampler misses it indefinitely (the notify path is a
  // no-op for sleepers) — the caller then burns its whole budget and the controller's pipe
  // read times out first. Yield-rate sampling matches the pre-deadline behavior; the
  // deadline keeps it bounded. These are teardown paths, so the spin cost is noise.
  static_cast<void>(expected);
  if (std::chrono::steady_clock::now() >= deadline) {
    return false;
  }
  std::this_thread::yield();
  return true;
#endif
}

// Registers the calling thread as a quiescence waiter for the scope, enabling the notify
// path on zero-transitions. Registration must happen-before the predicate read that
// decides to sleep (the notify side reads the waiter count only after its own
// zero-transition; the sequenced chain registration -> predicate read -> zero-transition
// -> waiter read then guarantees the notify fires).
class QuiescenceWaiterRegistration final {
 public:
  QuiescenceWaiterRegistration() noexcept {
    quiescence_waiters.fetch_add(1U, std::memory_order_acq_rel);
  }
  ~QuiescenceWaiterRegistration() noexcept {
    quiescence_waiters.fetch_sub(1U, std::memory_order_acq_rel);
  }

  QuiescenceWaiterRegistration(const QuiescenceWaiterRegistration&) = delete;
  QuiescenceWaiterRegistration& operator=(const QuiescenceWaiterRegistration&) = delete;
  QuiescenceWaiterRegistration(QuiescenceWaiterRegistration&&) = delete;
  QuiescenceWaiterRegistration& operator=(QuiescenceWaiterRegistration&&) = delete;
};

// Evaluates `condition` (a set of atomic counters all being zero) until it holds or the
// absolute deadline passes. Sleeps on the quiescence epoch between checks; the zero
// transition of any watched counter notifies the epoch. An already-expired deadline still
// gets one condition evaluation, preserving the old zero-yield probe semantics.
template <typename Predicate>
[[nodiscard]] inline bool wait_until_quiescent(
    Predicate&& condition, std::chrono::steady_clock::time_point deadline) noexcept {
  if (condition()) {
    return true;
  }
  const QuiescenceWaiterRegistration registration;
  for (;;) {
    // Load the epoch before the predicate: a notify that lands between the check and the
    // wait leaves the loaded value stale, and the wait then returns immediately.
    const std::uint32_t epoch = quiescence_epoch.load(std::memory_order_acquire);
    if (condition()) {
      return true;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      return condition();
    }
    static_cast<void>(quiescence_epoch_wait(epoch, deadline));
  }
}

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
  // Closes the gate, then sleeps until every in-transition thread has settled and no
  // replacement call is active, or the deadline passes (false; the gate stays closed and
  // the caller decides whether to reopen). Waiters sleep on the quiescence epoch — the
  // zero transitions of the watched counters notify it — never on a yield spin.
  [[nodiscard]] static bool close_and_wait(
      std::chrono::steady_clock::time_point deadline) noexcept {
    detail::replacement_gate_closed.store(true, std::memory_order_seq_cst);
    return detail::wait_until_quiescent(
        [] {
          return detail::replacement_gate_transitions.load(std::memory_order_seq_cst) == 0U &&
                 detail::replacement_active_calls.load(std::memory_order_seq_cst) == 0U;
        },
        deadline);
  }

  static void open() noexcept {
    detail::replacement_gate_closed.store(false, std::memory_order_seq_cst);
    detail::replacement_gate_epoch.fetch_add(1U, std::memory_order_release);
    detail::replacement_gate_epoch.notify_all();
  }

  // Waits until every thread parked in the gate has woken and fully left its replacement call.
  // Must only be called with the gate open and no way for new threads to enter a replacement
  // (targets reverted); otherwise the counters can never be trusted to stay at zero.
  [[nodiscard]] static bool wait_for_drain(
      std::chrono::steady_clock::time_point deadline) noexcept {
    return detail::wait_until_quiescent(
        [] {
          return detail::replacement_gate_waiters.load(std::memory_order_seq_cst) == 0U &&
                 detail::replacement_gate_transitions.load(std::memory_order_seq_cst) == 0U &&
                 detail::replacement_active_calls.load(std::memory_order_seq_cst) == 0U;
        },
        deadline);
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

  // Sleeps on the quiescence epoch until no entry is mid-transition and no replacement call
  // is in flight, or the deadline passes (false).
  [[nodiscard]] bool wait_for_quiescence(
      std::chrono::steady_clock::time_point deadline) const noexcept {
    return detail::wait_until_quiescent(
        [this] {
          return entry_transitions_.load(std::memory_order_seq_cst) == 0U &&
                 in_flight_.load(std::memory_order_seq_cst) == 0U;
        },
        deadline);
  }

  [[nodiscard]] bool wait_for_recording_quiescence(
      std::chrono::steady_clock::time_point deadline) const noexcept {
    return detail::wait_until_quiescent(
        [this] {
          return entry_transitions_.load(std::memory_order_seq_cst) == 0U &&
                 recording_in_flight_.load(std::memory_order_seq_cst) == 0U;
        },
        deadline);
  }

 private:
  static_assert(std::atomic<ReplacementRoute>::is_always_lock_free);
  static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

  std::atomic<ReplacementRoute> route_{ReplacementRoute::kTarget};
  std::atomic<std::uint64_t> entry_transitions_{0U};
  std::atomic<std::uint64_t> in_flight_{0U};
  std::atomic<std::uint64_t> recording_in_flight_{0U};
};

NOLEAX_HOOK_IMM_SECTION_PUSH

NOLEAX_HOOK_IMM_SECTION
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
  if (entry_transitions_.fetch_sub(1U, std::memory_order_seq_cst) == 1U) {
    detail::notify_quiescence_epoch();
  }
  return route;
}

NOLEAX_HOOK_IMM_SECTION
inline void ReplacementLifecycle::leave_unscoped(ReplacementRoute route) noexcept {
  if (route == ReplacementRoute::kRecord) {
    const std::uint64_t previous_recording =
        recording_in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
    if (previous_recording == 0U) {
      std::terminate();
    }
    if (previous_recording == 1U) {
      detail::notify_quiescence_epoch();
    }
  }
  const std::uint64_t previous = in_flight_.fetch_sub(1U, std::memory_order_seq_cst);
  if (previous == 0U) {
    std::terminate();
  }
  if (previous == 1U) {
    detail::notify_quiescence_epoch();
  }
  detail::leave_replacement_gate();
}

NOLEAX_HOOK_IMM_SECTION_POP

}  // namespace noleax::agent
