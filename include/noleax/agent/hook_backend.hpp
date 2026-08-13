#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace noleax::agent {

// Absolute steady_clock deadline bounding one quiescence operation (H1-A,
// docs/HARDENING_PLAN.md): every wait in the hook stack sleeps on the quiescence epoch
// (see replacement_lifecycle.hpp) and reports failure at its deadline instead of spinning
// a yield counter. Callers that do not care get kDefaultQuiescenceBudget; the capture
// drain is not retryable, so it waits out slow in-flight calls under the larger
// kDrainQuiescenceBudget.
using QuiescenceDeadline = std::chrono::steady_clock::time_point;
inline constexpr std::chrono::milliseconds kDefaultQuiescenceBudget{30'000};
inline constexpr std::chrono::milliseconds kDrainQuiescenceBudget{120'000};

[[nodiscard]] inline QuiescenceDeadline quiescence_deadline_after(
    std::chrono::steady_clock::duration budget = kDefaultQuiescenceBudget) noexcept {
  return std::chrono::steady_clock::now() + budget;
}

namespace detail {

// Test seam (H1-A): millisecond override of kDrainQuiescenceBudget, armed by the agent
// bootstrap from NOLEAX_DRAIN_BUDGET_MS so integration tests can force a drain timeout
// against a slow in-flight call. 0 keeps the named constant. Process-global; set once
// before any capture starts, read at each drain.
inline std::atomic<std::int64_t> drain_quiescence_budget_override_ms{0};

}  // namespace detail

[[nodiscard]] inline QuiescenceDeadline drain_quiescence_deadline() noexcept {
  const std::int64_t override_ms =
      detail::drain_quiescence_budget_override_ms.load(std::memory_order_acquire);
  return quiescence_deadline_after(override_ms > 0 ? std::chrono::milliseconds{override_ms}
                                                   : kDrainQuiescenceBudget);
}

using OriginalTrampolineSlot = std::atomic<void*>;

enum class HookInstallStatus : std::uint8_t {
  kInstalled,
  kInvalidArgument,
  kAlreadyInstalled,
  kAlreadyReplaced,
  kWrongSignature,
  kPolicyViolation,
  kWrongType,
  kMissingOriginal,
  kTeardownPending,
  kBackendStopped,
};

[[nodiscard]] std::string_view hook_install_status_name(HookInstallStatus status) noexcept;

struct FastHookResult {
  HookInstallStatus status{HookInstallStatus::kBackendStopped};
  void* original{nullptr};

  [[nodiscard]] bool installed() const noexcept { return status == HookInstallStatus::kInstalled; }
};

enum class HookUninstallStatus : std::uint8_t {
  kUninstalled,
  kNotInstalled,
  kTeardownPending,
  kBackendStopped,
};

[[nodiscard]] std::string_view hook_uninstall_status_name(HookUninstallStatus status) noexcept;

class HookBackendError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class HookBackend {
 public:
  // Marks the current thread's patch transactions as protected by an out-of-process
  // stop-the-world mechanism such as a ptrace seizure (thread-local in hoox). While set,
  // hoox skips its in-process peer park entirely — only ever set this while every peer
  // thread is provably frozen, and clear it before that freeze ends.
  static void set_external_thread_suspension(bool enabled) noexcept;

  HookBackend();
  ~HookBackend();

  HookBackend(const HookBackend&) = delete;
  HookBackend& operator=(const HookBackend&) = delete;
  HookBackend(HookBackend&&) = delete;
  HookBackend& operator=(HookBackend&&) = delete;

  [[nodiscard]] FastHookResult install_fast(void* target, void* replacement,
                                            OriginalTrampolineSlot* original_slot = nullptr);
  // Same as install_fast but with HOOX_RELOCATION_FORCED for targets whose prologue
  // fails the checked relocation (for example a relative call inside the copied bytes).
  [[nodiscard]] FastHookResult install_fast_forced(void* target, void* replacement,
                                                   OriginalTrampolineSlot* original_slot = nullptr);
  // Reverts the target, then retries the pending-trampoline flush until the deadline. An
  // already-expired deadline (std::chrono::steady_clock::now()) makes no flush attempt at
  // all, preserving the old "revert only" zero-attempt spelling.
  [[nodiscard]] HookUninstallStatus uninstall(
      void* target, QuiescenceDeadline deadline = quiescence_deadline_after()) noexcept;
  [[nodiscard]] bool flush(QuiescenceDeadline deadline = quiescence_deadline_after()) noexcept;
  [[nodiscard]] bool shutdown(QuiescenceDeadline deadline = quiescence_deadline_after()) noexcept;

  // A direct replacement can be paused before it enters the Hoox trampoline. While a lease is
  // held, revert is allowed but flush/deinit must retain the trampoline for that replacement.
  [[nodiscard]] bool acquire_trampoline_lifetime_lease() noexcept;
  void release_trampoline_lifetime_lease() noexcept;

  [[nodiscard]] bool is_active() const noexcept;
  [[nodiscard]] bool has_pending_teardown() const noexcept;
  [[nodiscard]] std::size_t installed_count() const noexcept;
  [[nodiscard]] std::size_t trampoline_lifetime_lease_count() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace noleax::agent
