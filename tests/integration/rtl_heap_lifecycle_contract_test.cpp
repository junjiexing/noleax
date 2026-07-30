#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/windows/rtl_heap_hooks.hpp"

namespace {

using RtlCreateHeapFunction = PVOID(NTAPI*)(ULONG flags, PVOID heap_base, SIZE_T reserve_size,
                                            SIZE_T commit_size, PVOID lock, PVOID parameters);
using RtlDestroyHeapFunction = PVOID(NTAPI*)(PVOID heap);

constexpr DWORD kLastErrorSentinel = 0x5a17c3e9U;
constexpr SIZE_T kFixedReserve = 1024U * 1024U;
constexpr SIZE_T kFixedCommit = 64U * 1024U;
constexpr SIZE_T kImpossibleReserve =
    (std::numeric_limits<SIZE_T>::max)() - static_cast<SIZE_T>(65'535U);
constexpr std::uint32_t kOverflowPairs = 32U;

struct CallObservation {
  PVOID result{nullptr};
  DWORD exception_status{0U};
  DWORD last_error{0U};
  bool returned{false};
};

[[nodiscard]] LONG capture_exception(EXCEPTION_POINTERS* pointers, DWORD* status) noexcept {
  if (pointers != nullptr && pointers->ExceptionRecord != nullptr) {
    *status = pointers->ExceptionRecord->ExceptionCode;
  }
  return EXCEPTION_EXECUTE_HANDLER;
}

[[nodiscard]] CallObservation invoke_create(RtlCreateHeapFunction create, ULONG flags,
                                            SIZE_T reserve_size, SIZE_T commit_size) noexcept {
  CallObservation observation;
  SetLastError(kLastErrorSentinel);
  __try {
    observation.result = create(flags, nullptr, reserve_size, commit_size, nullptr, nullptr);
    observation.returned = true;
  } __except (capture_exception(GetExceptionInformation(), &observation.exception_status)) {
  }
  observation.last_error = GetLastError();
  return observation;
}

[[nodiscard]] CallObservation invoke_destroy(RtlDestroyHeapFunction destroy, PVOID heap) noexcept {
  CallObservation observation;
  SetLastError(kLastErrorSentinel);
  __try {
    observation.result = destroy(heap);
    observation.returned = true;
  } __except (capture_exception(GetExceptionInformation(), &observation.exception_status)) {
  }
  observation.last_error = GetLastError();
  return observation;
}

[[nodiscard]] bool same_outcome(const CallObservation& baseline,
                                const CallObservation& hooked) noexcept {
  return baseline.returned == hooked.returned &&
         baseline.exception_status == hooked.exception_status &&
         baseline.last_error == hooked.last_error &&
         (baseline.result == nullptr) == (hooked.result == nullptr);
}

[[nodiscard]] bool successful_create(const CallObservation& observation) noexcept {
  return observation.returned && observation.exception_status == 0U &&
         observation.result != nullptr;
}

[[nodiscard]] bool successful_destroy(const CallObservation& observation) noexcept {
  return observation.returned && observation.exception_status == 0U &&
         observation.result == nullptr;
}

[[nodiscard]] bool finish_uninstall(noleax::agent::windows::RtlHeapHooks& hooks) noexcept {
  if (hooks.uninstall(0U)) {
    return true;
  }
  return hooks.flush(100'000U) && hooks.uninstall(0U);
}

[[nodiscard]] bool finish_uninstall(
    noleax::agent::windows::RtlAllocateHeapHook& hook) noexcept {
  const auto status = hook.uninstall(0U);
  if (status == noleax::agent::HookUninstallStatus::kUninstalled ||
      status == noleax::agent::HookUninstallStatus::kNotInstalled) {
    return true;
  }
  return hook.flush(100'000U);
}

[[nodiscard]] int run_partial_install_rollback() {
  noleax::agent::HookBackend blocker_backend;
  noleax::agent::windows::RtlAllocateHeapHook blocker{blocker_backend, 8U, 0U};
  const auto blocker_result = blocker.install();
  if (!blocker_result.installed()) {
    return 20;
  }

  noleax::agent::HookBackend coordinator_backend;
  noleax::agent::windows::RtlHeapHooks hooks{coordinator_backend, 8U, 0U};
  const auto result = hooks.install();
  const bool expected_failure =
      result.allocate.status == noleax::agent::HookInstallStatus::kAlreadyReplaced ||
      result.allocate.status == noleax::agent::HookInstallStatus::kBackendStopped;
  const bool rolled_back =
      result.create.installed() && expected_failure &&
      !hooks.create_hook().is_installed() && !hooks.create_hook().has_pending_teardown() &&
      coordinator_backend.installed_count() == 0U &&
      coordinator_backend.trampoline_lifetime_lease_count() == 0U;

  const bool coordinator_uninstalled = hooks.uninstall();
  const bool coordinator_shutdown = coordinator_backend.shutdown();
  const bool blocker_uninstalled = finish_uninstall(blocker);
  const bool blocker_shutdown = blocker_backend.shutdown();
  if (!rolled_back || !coordinator_uninstalled || !coordinator_shutdown ||
      !blocker_uninstalled || !blocker_shutdown) {
    std::fprintf(stderr,
                 "partial install rollback failed: create=%u allocate=%u installed=%u "
                 "pending=%u backend=%zu leases=%zu coordinator=%u/%u blocker=%u/%u\n",
                 static_cast<unsigned int>(result.create.status),
                 static_cast<unsigned int>(result.allocate.status),
                 hooks.create_hook().is_installed() ? 1U : 0U,
                 hooks.create_hook().has_pending_teardown() ? 1U : 0U,
                 coordinator_backend.installed_count(),
                 coordinator_backend.trampoline_lifetime_lease_count(),
                 coordinator_uninstalled ? 1U : 0U, coordinator_shutdown ? 1U : 0U,
                 blocker_uninstalled ? 1U : 0U, blocker_shutdown ? 1U : 0U);
    return 21;
  }
  return 0;
}

[[nodiscard]] bool verify_partial_install_rollback_in_child() {
  std::vector<wchar_t> executable(32'768U, L'\0');
  const DWORD length =
      GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
  if (length == 0U || length >= executable.size()) {
    return false;
  }
  const std::wstring command_text =
      L"\"" + std::wstring{executable.data(), length} + L"\" --partial-install-rollback";
  std::vector<wchar_t> command(command_text.begin(), command_text.end());
  command.push_back(L'\0');

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, 0U, nullptr, nullptr,
                     &startup, &process) == FALSE) {
    return false;
  }
  const DWORD wait = WaitForSingleObject(process.hProcess, 120'000U);
  DWORD exit_code = std::numeric_limits<DWORD>::max();
  const bool exited =
      wait == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return exited && exit_code == 0U;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::string{argv[1]} == "--partial-install-rollback") {
    return run_partial_install_rollback();
  }
  if (argc != 1 || !verify_partial_install_rollback_in_child()) {
    return 1;
  }

  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto create =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlCreateHeapFunction>(GetProcAddress(ntdll, "RtlCreateHeap"));
  const auto destroy =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlDestroyHeapFunction>(GetProcAddress(ntdll, "RtlDestroyHeap"));
  if (create == nullptr || destroy == nullptr) {
    return 2;
  }

  const CallObservation baseline_growable = invoke_create(create, HEAP_GROWABLE, 0U, 0U);
  const CallObservation baseline_growable_destroy =
      successful_create(baseline_growable) ? invoke_destroy(destroy, baseline_growable.result)
                                           : CallObservation{};
  const CallObservation baseline_fixed = invoke_create(create, 0U, kFixedReserve, kFixedCommit);
  const CallObservation baseline_fixed_destroy =
      successful_create(baseline_fixed) ? invoke_destroy(destroy, baseline_fixed.result)
                                        : CallObservation{};
  const CallObservation baseline_failure =
      invoke_create(create, HEAP_GROWABLE, kImpossibleReserve, 0U);
  const CallObservation baseline_exception =
      invoke_create(create, HEAP_GROWABLE | HEAP_GENERATE_EXCEPTIONS, kImpossibleReserve, 0U);
  const bool baseline_exception_mode_valid =
      baseline_exception.result == nullptr &&
      ((baseline_exception.returned && baseline_exception.exception_status == 0U) ||
       (!baseline_exception.returned && baseline_exception.exception_status != 0U));
  if (!successful_create(baseline_growable) || !successful_destroy(baseline_growable_destroy) ||
      !successful_create(baseline_fixed) || !successful_destroy(baseline_fixed_destroy) ||
      !baseline_failure.returned || baseline_failure.result != nullptr ||
      baseline_failure.exception_status != 0U || !baseline_exception_mode_valid) {
    std::fprintf(stderr,
                 "baseline heap lifecycle is unsupported: grow=%u/%u fixed=%u/%u "
                 "failure=%u/%p/0x%08lx exception=%u/0x%08lx\n",
                 successful_create(baseline_growable) ? 1U : 0U,
                 successful_destroy(baseline_growable_destroy) ? 1U : 0U,
                 successful_create(baseline_fixed) ? 1U : 0U,
                 successful_destroy(baseline_fixed_destroy) ? 1U : 0U,
                 baseline_failure.returned ? 1U : 0U, baseline_failure.result,
                 static_cast<unsigned long>(baseline_failure.exception_status),
                 baseline_exception.returned ? 1U : 0U,
                 static_cast<unsigned long>(baseline_exception.exception_status));
    return 3;
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlHeapHooks hooks{backend, 8U, 16U};
  noleax::agent::windows::RtlCreateHeapHook duplicate_create{backend, 8U, 0U};
  noleax::agent::windows::RtlDestroyHeapHook duplicate_destroy{backend, 8U, 0U};
  const auto installed = hooks.install();
  if (!installed.installed()) {
    return 4;
  }
  const auto duplicate_create_result = duplicate_create.install();
  const auto duplicate_destroy_result = duplicate_destroy.install();

  const CallObservation hooked_growable = invoke_create(create, HEAP_GROWABLE, 0U, 0U);
  const CallObservation hooked_growable_destroy =
      successful_create(hooked_growable) ? invoke_destroy(destroy, hooked_growable.result)
                                         : CallObservation{};
  const CallObservation hooked_fixed = invoke_create(create, 0U, kFixedReserve, kFixedCommit);
  const CallObservation hooked_fixed_destroy = successful_create(hooked_fixed)
                                                   ? invoke_destroy(destroy, hooked_fixed.result)
                                                   : CallObservation{};
  const CallObservation hooked_failure =
      invoke_create(create, HEAP_GROWABLE, kImpossibleReserve, 0U);
  const CallObservation hooked_exception =
      invoke_create(create, HEAP_GROWABLE | HEAP_GENERATE_EXCEPTIONS, kImpossibleReserve, 0U);

  auto& create_hook = hooks.create_hook();
  auto& destroy_hook = hooks.destroy_hook();
  const std::uint64_t create_recursive_before = create_hook.recursive_call_count();
  const std::uint64_t create_recordable_before_recursive = create_hook.recordable_call_count();
  PVOID recursive_heap = nullptr;
  {
    const noleax::agent::HookInvocationGuard simulated_outer_hook;
    recursive_heap = create(HEAP_GROWABLE, nullptr, 0U, 0U, nullptr, nullptr);
  }
  const std::uint64_t destroy_recursive_before = destroy_hook.recursive_call_count();
  const std::uint64_t destroy_recordable_before_recursive = destroy_hook.recordable_call_count();
  PVOID recursive_destroy_result = nullptr;
  if (recursive_heap != nullptr) {
    const noleax::agent::HookInvocationGuard simulated_outer_hook;
    recursive_destroy_result = destroy(recursive_heap);
  }

  const std::uint64_t create_internal_before = create_hook.internal_call_count();
  const std::uint64_t create_recordable_before_internal = create_hook.recordable_call_count();
  PVOID internal_heap = nullptr;
  {
    const noleax::agent::InternalThreadScope internal_thread;
    internal_heap = create(HEAP_GROWABLE, nullptr, 0U, 0U, nullptr, nullptr);
  }
  const std::uint64_t destroy_internal_before = destroy_hook.internal_call_count();
  const std::uint64_t destroy_recordable_before_internal = destroy_hook.recordable_call_count();
  PVOID internal_destroy_result = nullptr;
  if (internal_heap != nullptr) {
    const noleax::agent::InternalThreadScope internal_thread;
    internal_destroy_result = destroy(internal_heap);
  }

  bool saw_growable_create = false;
  bool saw_fixed_create = false;
  bool saw_failure_create = false;
  bool saw_exception_create = false;
  std::uint64_t successful_destroy_events = 0U;
  std::uint64_t initial_events = 0U;
  noleax::agent::windows::RtlHeapEvent event;
  while (hooks.event_queue().try_pop(event)) {
    ++initial_events;
    if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kCreate) {
      saw_growable_create |=
          event.flags == HEAP_GROWABLE && event.requested_size == 0U && event.raw_result == 0U &&
          event.heap_handle == 0U && event.address == 0U && event.auxiliary_address == 0U &&
          event.result_address == static_cast<std::uint64_t>(
                                      reinterpret_cast<std::uintptr_t>(hooked_growable.result)) &&
          event.status == noleax::agent::windows::RtlHeapEventStatus::kSuccess;
      saw_fixed_create |=
          event.flags == 0U && event.requested_size == kFixedReserve &&
          event.raw_result == kFixedCommit &&
          event.result_address ==
              static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(hooked_fixed.result)) &&
          event.status == noleax::agent::windows::RtlHeapEventStatus::kSuccess;
      saw_failure_create |= event.flags == HEAP_GROWABLE &&
                            event.requested_size == kImpossibleReserve &&
                            event.result_address == 0U &&
                            event.status == noleax::agent::windows::RtlHeapEventStatus::kFailure;
      saw_exception_create |=
          event.flags == (HEAP_GROWABLE | HEAP_GENERATE_EXCEPTIONS) &&
          event.requested_size == kImpossibleReserve && event.auxiliary_address == 0U &&
          event.result_address == 0U &&
          event.exception_status == hooked_exception.exception_status &&
          event.status == (hooked_exception.exception_status == 0U
                               ? noleax::agent::windows::RtlHeapEventStatus::kFailure
                               : noleax::agent::windows::RtlHeapEventStatus::kException);
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kDestroy &&
               event.status == noleax::agent::windows::RtlHeapEventStatus::kSuccess &&
               event.raw_result == 0U) {
      ++successful_destroy_events;
    }
  }

  for (std::uint32_t index = 0U; index < kOverflowPairs; ++index) {
    PVOID heap = create(HEAP_GROWABLE, nullptr, 0U, 0U, nullptr, nullptr);
    if (heap == nullptr || destroy(heap) != nullptr) {
      return 5;
    }
  }

  std::uint64_t overflow_events = 0U;
  while (hooks.event_queue().try_pop(event)) {
    ++overflow_events;
  }
  const std::uint64_t create_dropped = create_hook.dropped_event_count();
  const std::uint64_t destroy_dropped = destroy_hook.dropped_event_count();
  const bool outcomes_match = same_outcome(baseline_growable, hooked_growable) &&
                              same_outcome(baseline_growable_destroy, hooked_growable_destroy) &&
                              same_outcome(baseline_fixed, hooked_fixed) &&
                              same_outcome(baseline_fixed_destroy, hooked_fixed_destroy) &&
                              same_outcome(baseline_failure, hooked_failure) &&
                              same_outcome(baseline_exception, hooked_exception);
  const bool guard_valid =
      recursive_heap != nullptr && recursive_destroy_result == nullptr &&
      internal_heap != nullptr && internal_destroy_result == nullptr &&
      create_hook.recursive_call_count() > create_recursive_before &&
      create_hook.recordable_call_count() == create_recordable_before_recursive + kOverflowPairs &&
      destroy_hook.recursive_call_count() > destroy_recursive_before &&
      destroy_hook.recordable_call_count() ==
          destroy_recordable_before_recursive + kOverflowPairs &&
      create_hook.internal_call_count() > create_internal_before &&
      create_recordable_before_internal == create_recordable_before_recursive &&
      destroy_hook.internal_call_count() > destroy_internal_before &&
      destroy_recordable_before_internal == destroy_recordable_before_recursive;
  const std::uint64_t total_dropped = create_dropped + destroy_dropped;
  const bool queue_valid = initial_events == 6U && overflow_events == 8U &&
                           successful_destroy_events == 2U && create_dropped != 0U &&
                           destroy_dropped != 0U &&
                           hooks.event_queue().dropped_count() == total_dropped;
  const bool counters_valid =
      create_hook.successful_call_count() + create_hook.failed_call_count() ==
          create_hook.recordable_call_count() &&
      destroy_hook.successful_call_count() + destroy_hook.failed_call_count() ==
          destroy_hook.recordable_call_count() &&
      create_hook.exceptional_call_count() == (hooked_exception.exception_status == 0U ? 0U : 1U) &&
      destroy_hook.exceptional_call_count() == 0U;
  const bool duplicate_diagnostics =
      duplicate_create_result.status == noleax::agent::HookInstallStatus::kBackendStopped &&
      duplicate_destroy_result.status == noleax::agent::HookInstallStatus::kBackendStopped;

  const bool uninstalled = finish_uninstall(hooks);
  const bool shutdown = backend.shutdown();
  if (!outcomes_match || !guard_valid || !queue_valid || !counters_valid ||
      !duplicate_diagnostics || !saw_growable_create || !saw_fixed_create || !saw_failure_create ||
      !saw_exception_create || !uninstalled || !shutdown) {
    std::fprintf(stderr,
                 "heap lifecycle contract failed: outcomes=%u guard=%u queue=%u counters=%u "
                 "duplicates=%u events=%llu/%llu drops=%llu/%llu raw=%u%u%u%u uninstall=%u "
                 "shutdown=%u\n",
                 outcomes_match ? 1U : 0U, guard_valid ? 1U : 0U, queue_valid ? 1U : 0U,
                 counters_valid ? 1U : 0U, duplicate_diagnostics ? 1U : 0U,
                 static_cast<unsigned long long>(initial_events),
                 static_cast<unsigned long long>(overflow_events),
                 static_cast<unsigned long long>(create_dropped),
                 static_cast<unsigned long long>(destroy_dropped), saw_growable_create ? 1U : 0U,
                 saw_fixed_create ? 1U : 0U, saw_failure_create ? 1U : 0U,
                 saw_exception_create ? 1U : 0U, uninstalled ? 1U : 0U, shutdown ? 1U : 0U);
    return 6;
  }

  std::printf(
      "status=ok create=4 destroy=2 exception-mode=matched recursive=2 internal=2 "
      "overflow=%llu last-error=preserved\n",
      static_cast<unsigned long long>(total_dropped));
  return 0;
}
