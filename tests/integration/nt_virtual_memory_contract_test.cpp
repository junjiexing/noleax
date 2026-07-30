#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/windows/nt_memory_hooks.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"

namespace {

using NtAllocateVirtualMemoryFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID* base_address,
                                                         ULONG_PTR zero_bits, PSIZE_T region_size,
                                                         ULONG allocation_type, ULONG protect);
using NtFreeVirtualMemoryFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID* base_address,
                                                     PSIZE_T region_size, ULONG free_type);

constexpr DWORD kLastErrorSentinel = 0x5a17c3e9U;
constexpr SIZE_T kPageSize = 4096U;

struct CallResult {
  NTSTATUS status{0};
  DWORD last_error{0U};
  PVOID base{nullptr};
  SIZE_T size{0U};
};

struct WorkloadSummary {
  std::array<std::uint32_t, 12U> statuses{};
  std::array<DWORD, 12U> last_errors{};
  std::array<std::uint64_t, 6U> sizes{};
  std::array<bool, 7U> outcomes{};

  bool operator==(const WorkloadSummary&) const = default;
};

struct WorkloadArtifacts {
  PVOID reservation{nullptr};
  PVOID committed_page{nullptr};
  PVOID combined{nullptr};
  PVOID real_handle_reservation{nullptr};
};

[[nodiscard]] bool nt_success(NTSTATUS status) noexcept { return status >= 0; }

[[nodiscard]] CallResult allocate(NtAllocateVirtualMemoryFunction function, HANDLE process,
                                  PVOID requested_base, SIZE_T requested_size,
                                  ULONG allocation_type, ULONG protection) {
  PVOID base = requested_base;
  SIZE_T size = requested_size;
  SetLastError(kLastErrorSentinel);
  const NTSTATUS status = function(process, &base, 0U, &size, allocation_type, protection);
  return {status, GetLastError(), base, size};
}

[[nodiscard]] CallResult free_memory(NtFreeVirtualMemoryFunction function, HANDLE process,
                                     PVOID requested_base, SIZE_T requested_size, ULONG free_type) {
  PVOID base = requested_base;
  SIZE_T size = requested_size;
  SetLastError(kLastErrorSentinel);
  const NTSTATUS status = function(process, &base, &size, free_type);
  return {status, GetLastError(), base, size};
}

[[nodiscard]] bool release_if_needed(NtFreeVirtualMemoryFunction free_function, HANDLE process,
                                     PVOID base) {
  return base == nullptr ||
         nt_success(free_memory(free_function, process, base, 0U, MEM_RELEASE).status);
}

[[nodiscard]] WorkloadSummary run_workload(NtAllocateVirtualMemoryFunction allocate_function,
                                           NtFreeVirtualMemoryFunction free_function,
                                           WorkloadArtifacts& artifacts) {
  WorkloadSummary summary;
  std::size_t call = 0U;
  const HANDLE current = GetCurrentProcess();

  const CallResult reserve =
      allocate(allocate_function, current, nullptr, 3U * kPageSize, MEM_RESERVE, PAGE_READWRITE);
  artifacts.reservation = reserve.base;
  summary.statuses[call] = static_cast<std::uint32_t>(reserve.status);
  summary.last_errors[call++] = reserve.last_error;
  summary.sizes[0] = reserve.size;

  PVOID requested_commit =
      reserve.base == nullptr
          ? nullptr
          : static_cast<PVOID>(static_cast<std::byte*>(reserve.base) + kPageSize);
  const CallResult commit =
      allocate(allocate_function, current, requested_commit, kPageSize, MEM_COMMIT, PAGE_READWRITE);
  artifacts.committed_page = commit.base;
  summary.statuses[call] = static_cast<std::uint32_t>(commit.status);
  summary.last_errors[call++] = commit.last_error;
  summary.sizes[1] = commit.size;

  const CallResult decommit =
      free_memory(free_function, current, commit.base, kPageSize, MEM_DECOMMIT);
  summary.statuses[call] = static_cast<std::uint32_t>(decommit.status);
  summary.last_errors[call++] = decommit.last_error;
  summary.sizes[2] = decommit.size;

  const CallResult release = free_memory(free_function, current, reserve.base, 0U, MEM_RELEASE);
  summary.statuses[call] = static_cast<std::uint32_t>(release.status);
  summary.last_errors[call++] = release.last_error;

  const CallResult combined = allocate(allocate_function, current, nullptr, 2U * kPageSize + 1U,
                                       MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  artifacts.combined = combined.base;
  summary.statuses[call] = static_cast<std::uint32_t>(combined.status);
  summary.last_errors[call++] = combined.last_error;
  summary.sizes[3] = combined.size;
  const CallResult combined_release =
      free_memory(free_function, current, combined.base, 0U, MEM_RELEASE);
  summary.statuses[call] = static_cast<std::uint32_t>(combined_release.status);
  summary.last_errors[call++] = combined_release.last_error;

  const CallResult zero_size =
      allocate(allocate_function, current, nullptr, 0U, MEM_RESERVE, PAGE_READWRITE);
  summary.statuses[call] = static_cast<std::uint32_t>(zero_size.status);
  summary.last_errors[call++] = zero_size.last_error;

  SIZE_T invalid_pointer_size = kPageSize;
  SetLastError(kLastErrorSentinel);
  const NTSTATUS invalid_pointer_status =
      allocate_function(current, nullptr, 0U, &invalid_pointer_size, MEM_RESERVE, PAGE_READWRITE);
  summary.statuses[call] = static_cast<std::uint32_t>(invalid_pointer_status);
  summary.last_errors[call++] = GetLastError();

  HANDLE real_current = OpenProcess(PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                    GetCurrentProcessId());
  const CallResult real_handle =
      real_current == nullptr
          ? CallResult{static_cast<NTSTATUS>(0xC0000001L), GetLastError(), nullptr, 0U}
          : allocate(allocate_function, real_current, nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT,
                     PAGE_READWRITE);
  artifacts.real_handle_reservation = real_handle.base;
  summary.statuses[call] = static_cast<std::uint32_t>(real_handle.status);
  summary.last_errors[call++] = real_handle.last_error;
  summary.sizes[4] = real_handle.size;
  const CallResult real_handle_release =
      real_current == nullptr
          ? CallResult{static_cast<NTSTATUS>(0xC0000001L), GetLastError(), nullptr, 0U}
          : free_memory(free_function, real_current, real_handle.base, 0U, MEM_RELEASE);
  summary.statuses[call] = static_cast<std::uint32_t>(real_handle_release.status);
  summary.last_errors[call++] = real_handle_release.last_error;
  if (real_current != nullptr) {
    CloseHandle(real_current);
  }

  SetLastError(kLastErrorSentinel);
  PVOID wrapper = VirtualAlloc(nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  const DWORD wrapper_allocate_error = GetLastError();
  SetLastError(kLastErrorSentinel);
  const BOOL wrapper_freed = wrapper == nullptr ? FALSE : VirtualFree(wrapper, 0U, MEM_RELEASE);
  const DWORD wrapper_free_error = GetLastError();
  summary.statuses[call] = wrapper == nullptr ? 0U : 1U;
  summary.last_errors[call++] = wrapper_allocate_error;
  summary.statuses[call] = wrapper_freed == FALSE ? 0U : 1U;
  summary.last_errors[call++] = wrapper_free_error;

  summary.outcomes = {
      nt_success(reserve.status) && reserve.base != nullptr,
      nt_success(commit.status) && commit.base == requested_commit,
      nt_success(decommit.status),
      nt_success(release.status),
      nt_success(combined.status) && combined.base != nullptr,
      nt_success(real_handle.status) && nt_success(real_handle_release.status),
      wrapper != nullptr && wrapper_freed != FALSE,
  };
  summary.sizes[5] = invalid_pointer_size;

  static_cast<void>(release_if_needed(free_function, current,
                                      nt_success(release.status) ? nullptr : reserve.base));
  static_cast<void>(release_if_needed(
      free_function, current, nt_success(combined_release.status) ? nullptr : combined.base));
  return summary;
}

[[nodiscard]] bool finish_uninstall(noleax::agent::windows::NtMemoryHooks& hooks) noexcept {
  if (hooks.uninstall(0U)) {
    return true;
  }
  return hooks.flush(100'000U) && hooks.uninstall(0U);
}

}  // namespace

int main() {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto allocate_function = ntdll == nullptr
                                     ? nullptr
                                     : reinterpret_cast<NtAllocateVirtualMemoryFunction>(
                                           GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
  const auto free_function = ntdll == nullptr ? nullptr
                                              : reinterpret_cast<NtFreeVirtualMemoryFunction>(
                                                    GetProcAddress(ntdll, "NtFreeVirtualMemory"));
  if (allocate_function == nullptr || free_function == nullptr) {
    return 2;
  }

  WorkloadArtifacts baseline_artifacts;
  const WorkloadSummary baseline =
      run_workload(allocate_function, free_function, baseline_artifacts);
  for (bool outcome : baseline.outcomes) {
    if (!outcome) {
      return 3;
    }
  }

  noleax::agent::HookBackend backend;
  noleax::agent::HookBackend heap_backend;
  noleax::agent::windows::NtMemoryHooks hooks{backend, 4096U, 16U};
  noleax::agent::windows::RtlAllocateHeapHook heap_hook{heap_backend, 256U, 0U};
  const auto installed = hooks.install();
  const auto heap_installed = heap_hook.install();
  if (!installed.installed() || !heap_installed.installed()) {
    return 4;
  }

  WorkloadArtifacts hooked_artifacts;
  const WorkloadSummary hooked = run_workload(allocate_function, free_function, hooked_artifacts);

  const auto allocate_before_recursive = hooks.allocate_statistics();
  PVOID recursive = nullptr;
  {
    const noleax::agent::HookInvocationGuard outer;
    recursive = VirtualAlloc(nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  }
  if (recursive != nullptr) {
    const noleax::agent::HookInvocationGuard outer;
    static_cast<void>(VirtualFree(recursive, 0U, MEM_RELEASE));
  }
  const auto allocate_before_internal = hooks.allocate_statistics();
  PVOID internal = nullptr;
  {
    const noleax::agent::InternalThreadScope scope;
    internal = VirtualAlloc(nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  }
  if (internal != nullptr) {
    const noleax::agent::InternalThreadScope scope;
    static_cast<void>(VirtualFree(internal, 0U, MEM_RELEASE));
  }

  const HANDLE private_heap = HeapCreate(0U, 0U, 0U);
  const auto allocate_before_nested_heap = hooks.allocate_statistics();
  PVOID large_heap_block =
      private_heap == nullptr ? nullptr : HeapAlloc(private_heap, 0U, 64U * 1024U * 1024U);
  const auto allocate_after_nested_heap = hooks.allocate_statistics();
  if (large_heap_block != nullptr) {
    static_cast<void>(HeapFree(private_heap, 0U, large_heap_block));
  }
  if (private_heap != nullptr) {
    static_cast<void>(HeapDestroy(private_heap));
  }

  bool saw_reserve = false;
  bool saw_commit = false;
  bool saw_decommit = false;
  bool saw_release = false;
  bool saw_failure = false;
  bool saw_real_handle = false;
  bool stacks_valid = true;
  std::array<std::uint64_t, 4U> event_counts{};
  std::array<noleax::agent::windows::NtVirtualMemoryEvent, 32U> event_samples{};
  std::size_t event_sample_count = 0U;
  noleax::agent::windows::NtVirtualMemoryEvent event;
  while (hooks.try_dequeue_event(event)) {
    if (event_sample_count < event_samples.size()) {
      event_samples[event_sample_count++] = event;
    }
    stacks_valid &= noleax::agent::windows::stack_capture_succeeded(event.stack) ||
                    event.stack.status == noleax::agent::windows::StackCaptureStatus::kFailed;
    if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kVmAllocate) {
      ++event_counts[0];
      saw_reserve |=
          event.flags == MEM_RESERVE && event.address == 0U &&
          event.result_address == reinterpret_cast<std::uintptr_t>(hooked_artifacts.reservation) &&
          event.requested_size == 3U * kPageSize && event.raw_result == 3U * kPageSize &&
          event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kSuccess;
      saw_commit |=
          event.flags == MEM_COMMIT &&
          event.address == reinterpret_cast<std::uintptr_t>(hooked_artifacts.committed_page) &&
          event.result_address ==
              reinterpret_cast<std::uintptr_t>(hooked_artifacts.committed_page) &&
          event.secondary_flags == PAGE_READWRITE &&
          event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kSuccess;
      saw_failure |= event.requested_size == 0U &&
                     event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kFailure &&
                     static_cast<NTSTATUS>(event.operation_result) < 0;
      saw_real_handle |= event.result_address == reinterpret_cast<std::uintptr_t>(
                                                     hooked_artifacts.real_handle_reservation) &&
                         event.heap_handle != reinterpret_cast<std::uintptr_t>(GetCurrentProcess());
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kVmFree) {
      ++event_counts[1];
      saw_decommit |=
          event.flags == MEM_DECOMMIT &&
          event.address == reinterpret_cast<std::uintptr_t>(hooked_artifacts.committed_page) &&
          event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kSuccess;
      saw_release |=
          event.flags == MEM_RELEASE &&
          event.address == reinterpret_cast<std::uintptr_t>(hooked_artifacts.reservation) &&
          event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kSuccess;
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kSectionMap) {
      ++event_counts[2];
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kSectionUnmap) {
      ++event_counts[3];
    } else {
      stacks_valid = false;
    }
  }

  const auto allocate_statistics = hooks.allocate_statistics();
  const auto free_statistics = hooks.free_statistics();
  const auto map_statistics = hooks.map_statistics();
  const auto unmap_statistics = hooks.unmap_statistics();
  const bool summary_matches = baseline == hooked;
  const bool guard_valid =
      recursive != nullptr && internal != nullptr &&
      allocate_statistics.recursive_calls > allocate_before_recursive.recursive_calls &&
      allocate_before_internal.recordable_calls == allocate_before_recursive.recordable_calls &&
      allocate_statistics.internal_calls > allocate_before_internal.internal_calls;
  const bool nested_heap_suppressed =
      large_heap_block != nullptr &&
      allocate_after_nested_heap.recursive_calls > allocate_before_nested_heap.recursive_calls &&
      allocate_after_nested_heap.recordable_calls == allocate_before_nested_heap.recordable_calls;
  const bool counters_valid =
      allocate_statistics.successful_calls + allocate_statistics.failed_calls ==
          allocate_statistics.recordable_calls &&
      free_statistics.successful_calls + free_statistics.failed_calls ==
          free_statistics.recordable_calls &&
      map_statistics.successful_calls + map_statistics.failed_calls ==
          map_statistics.recordable_calls &&
      unmap_statistics.successful_calls + unmap_statistics.failed_calls ==
          unmap_statistics.recordable_calls &&
      allocate_statistics.recordable_calls ==
          event_counts[0] + allocate_statistics.dropped_events &&
      free_statistics.recordable_calls == event_counts[1] + free_statistics.dropped_events &&
      map_statistics.recordable_calls == event_counts[2] + map_statistics.dropped_events &&
      unmap_statistics.recordable_calls == event_counts[3] + unmap_statistics.dropped_events;

  const auto heap_uninstall_status = heap_hook.uninstall(100'000U);
  const bool heap_uninstalled =
      heap_uninstall_status == noleax::agent::HookUninstallStatus::kUninstalled ||
      heap_uninstall_status == noleax::agent::HookUninstallStatus::kNotInstalled;
  const bool uninstalled = finish_uninstall(hooks);
  const bool heap_shutdown = heap_backend.shutdown();
  const bool shutdown = backend.shutdown();
  if (!summary_matches || !guard_valid || !nested_heap_suppressed || !counters_valid ||
      !stacks_valid || !saw_reserve || !saw_commit || !saw_decommit || !saw_release ||
      !saw_failure || !saw_real_handle || !heap_uninstalled || !uninstalled || !heap_shutdown ||
      !shutdown) {
    for (std::size_t index = 0U; index < event_sample_count; ++index) {
      const auto& sample = event_samples[index];
      std::fprintf(stderr,
                   "sample[%zu]=op:%u flags:%08lx secondary:%08lx status:%u "
                   "address:%llx result:%llx requested:%llu raw:%llu\n",
                   index, static_cast<unsigned int>(sample.operation),
                   static_cast<unsigned long>(sample.flags),
                   static_cast<unsigned long>(sample.secondary_flags),
                   static_cast<unsigned int>(sample.status),
                   static_cast<unsigned long long>(sample.address),
                   static_cast<unsigned long long>(sample.result_address),
                   static_cast<unsigned long long>(sample.requested_size),
                   static_cast<unsigned long long>(sample.raw_result));
    }
    std::fprintf(stderr,
                 "NT VM contract failed: summary=%u guard=%u nested=%u counters=%u stacks=%u "
                 "raw=%u%u%u%u%u%u events=%llu/%llu uninstall=%u shutdown=%u\n",
                 summary_matches ? 1U : 0U, guard_valid ? 1U : 0U, nested_heap_suppressed ? 1U : 0U,
                 counters_valid ? 1U : 0U, stacks_valid ? 1U : 0U, saw_reserve ? 1U : 0U,
                 saw_commit ? 1U : 0U, saw_decommit ? 1U : 0U, saw_release ? 1U : 0U,
                 saw_failure ? 1U : 0U, saw_real_handle ? 1U : 0U,
                 static_cast<unsigned long long>(event_counts[0]),
                 static_cast<unsigned long long>(event_counts[1]), uninstalled ? 1U : 0U,
                 shutdown ? 1U : 0U);
    return 5;
  }

  std::printf(
      "status=ok reserve=1 commit=1 decommit=1 release=1 remote-handle=classified "
      "last-error=preserved events=%llu/%llu/%llu/%llu\n",
      static_cast<unsigned long long>(event_counts[0]),
      static_cast<unsigned long long>(event_counts[1]),
      static_cast<unsigned long long>(event_counts[2]),
      static_cast<unsigned long long>(event_counts[3]));
  return 0;
}
