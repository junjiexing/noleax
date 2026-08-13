#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <thread>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/nt_memory_hooks.hpp"

namespace {

using NtAllocateVirtualMemoryFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID* base_address,
                                                         ULONG_PTR zero_bits, PSIZE_T region_size,
                                                         ULONG allocation_type, ULONG protect);
using NtFreeVirtualMemoryFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID* base_address,
                                                     PSIZE_T region_size, ULONG free_type);
using NtMapViewOfSectionFunction = NTSTATUS(NTAPI*)(HANDLE section, HANDLE process,
                                                    PVOID* base_address, ULONG_PTR zero_bits,
                                                    SIZE_T commit_size,
                                                    PLARGE_INTEGER section_offset,
                                                    PSIZE_T view_size, ULONG inherit_disposition,
                                                    ULONG allocation_type, ULONG protect);
using NtUnmapViewOfSectionFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID base_address);

constexpr std::size_t kWorkerCount = 4U;
constexpr std::uint64_t kOperationsBeforeUninstall = 2'000U;
constexpr std::uint64_t kOperationsAfterUninstall = 2'000U;
constexpr std::uint64_t kThreadCreationsBeforeUninstall = 50U;
constexpr ULONGLONG kWaitTimeoutMilliseconds = 30'000U;

struct MitigationStatus {
  bool cfg_queried{false};
  bool cfg_enabled{false};
  bool cet_queried{false};
  bool cet_enabled{false};
};

[[nodiscard]] MitigationStatus query_mitigations() noexcept {
  MitigationStatus status;
  PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
  status.cfg_queried =
      GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &cfg,
                                 sizeof(cfg)) != FALSE;
  status.cfg_enabled = status.cfg_queried && cfg.EnableControlFlowGuard != 0U;
  PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY cet{};
  status.cet_queried = GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy,
                                                  &cet, sizeof(cet)) != FALSE;
  status.cet_enabled = status.cet_queried && cet.EnableUserShadowStack != 0U;
  return status;
}

[[nodiscard]] bool wait_for_at_least(const std::atomic<std::uint64_t>& value,
                                     std::uint64_t expected) noexcept {
  const ULONGLONG deadline = GetTickCount64() + kWaitTimeoutMilliseconds;
  while (value.load(std::memory_order_acquire) < expected) {
    if (GetTickCount64() >= deadline) {
      return false;
    }
    SwitchToThread();
  }
  return true;
}

}  // namespace

int main() {
  const MitigationStatus mitigations = query_mitigations();
#if defined(NOLEAX_WINDOWS_HARDENED_TESTING)
  if (!mitigations.cfg_queried || !mitigations.cfg_enabled) {
    return 10;
  }
#endif
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto allocate = ntdll == nullptr ? nullptr
                                         : reinterpret_cast<NtAllocateVirtualMemoryFunction>(
                                               GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
  const auto free_memory = ntdll == nullptr ? nullptr
                                            : reinterpret_cast<NtFreeVirtualMemoryFunction>(
                                                  GetProcAddress(ntdll, "NtFreeVirtualMemory"));
  const auto map_view = ntdll == nullptr ? nullptr
                                         : reinterpret_cast<NtMapViewOfSectionFunction>(
                                               GetProcAddress(ntdll, "NtMapViewOfSection"));
  const auto unmap_view = ntdll == nullptr ? nullptr
                                           : reinterpret_cast<NtUnmapViewOfSectionFunction>(
                                                 GetProcAddress(ntdll, "NtUnmapViewOfSection"));
  const HANDLE section =
      CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0U, 64U * 1024U, nullptr);
  if (allocate == nullptr || free_memory == nullptr || map_view == nullptr ||
      unmap_view == nullptr || section == nullptr) {
    return 2;
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::NtMemoryHooks hooks{backend, 1024U, 0U};
  const auto installed = hooks.install();
  if (!installed.installed() || !hooks.replacement_module_is_referenced()) {
    return 3;
  }

  std::atomic<std::uint64_t> ready{0U};
  std::atomic<std::uint64_t> operations{0U};
  std::atomic<std::uint64_t> thread_creations{0U};
  std::atomic<std::uint64_t> failures{0U};
  std::atomic<bool> start{false};
  std::atomic<bool> stop{false};
  const auto run_operation = [&] {
    PVOID base = nullptr;
    SIZE_T size = 2U * 4096U;
    const NTSTATUS allocated =
        allocate(GetCurrentProcess(), &base, 0U, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (allocated < 0 || base == nullptr || size < 2U * 4096U) {
      failures.fetch_add(1U, std::memory_order_relaxed);
      return;
    }
    auto* bytes = static_cast<std::byte*>(base);
    bytes[0] = std::byte{0x5a};
    bytes[size - 1U] = std::byte{0xa5};
    PVOID release_base = base;
    SIZE_T release_size = 0U;
    const NTSTATUS released =
        free_memory(GetCurrentProcess(), &release_base, &release_size, MEM_RELEASE);
    if (released < 0) {
      failures.fetch_add(1U, std::memory_order_relaxed);
      return;
    }
    PVOID view = nullptr;
    SIZE_T view_size = 4096U;
    const NTSTATUS mapped = map_view(section, GetCurrentProcess(), &view, 0U, 0U, nullptr,
                                     &view_size, 2U, 0U, PAGE_READWRITE);
    if (mapped < 0 || view == nullptr || view_size < 4096U) {
      failures.fetch_add(1U, std::memory_order_relaxed);
      return;
    }
    auto* view_bytes = static_cast<std::byte*>(view);
    view_bytes[0] = std::byte{0x3c};
    view_bytes[4095U] = std::byte{0xc3};
    if (unmap_view(GetCurrentProcess(), view) < 0) {
      failures.fetch_add(1U, std::memory_order_relaxed);
      return;
    }
    PVOID wrapper_view = MapViewOfFile(section, FILE_MAP_WRITE, 0U, 0U, 4096U);
    if (wrapper_view == nullptr) {
      failures.fetch_add(1U, std::memory_order_relaxed);
      return;
    }
    static_cast<std::byte*>(wrapper_view)[0] = std::byte{0x69};
    if (UnmapViewOfFile(wrapper_view) == FALSE) {
      failures.fetch_add(1U, std::memory_order_relaxed);
      return;
    }
    operations.fetch_add(1U, std::memory_order_release);
  };

  std::array<std::thread, kWorkerCount> workers;
  for (auto& worker : workers) {
    worker = std::thread{[&] {
      ready.fetch_add(1U, std::memory_order_release);
      while (!start.load(std::memory_order_acquire)) {
        SwitchToThread();
      }
      while (!stop.load(std::memory_order_acquire)) {
        run_operation();
      }
    }};
  }
  std::thread churner{[&] {
    while (!start.load(std::memory_order_acquire)) {
      SwitchToThread();
    }
    while (!stop.load(std::memory_order_acquire)) {
      std::thread short_lived{run_operation};
      short_lived.join();
      thread_creations.fetch_add(1U, std::memory_order_release);
    }
  }};

  const bool all_ready = wait_for_at_least(ready, kWorkerCount);
  start.store(true, std::memory_order_release);
  const bool reached_pre_uninstall =
      all_ready && wait_for_at_least(operations, kOperationsBeforeUninstall) &&
      wait_for_at_least(thread_creations, kThreadCreationsBeforeUninstall);

  bool uninstalled = false;
  if (reached_pre_uninstall) {
    uninstalled = hooks.uninstall(std::chrono::steady_clock::now());
    for (std::uint32_t retry = 0U; retry < 16U && !uninstalled; ++retry) {
      uninstalled = hooks.flush();
    }
  }

  const auto allocate_after_uninstall = hooks.allocate_statistics();
  const auto free_after_uninstall = hooks.free_statistics();
  const auto map_after_uninstall = hooks.map_statistics();
  const auto unmap_after_uninstall = hooks.unmap_statistics();
  const std::uint64_t post_goal =
      operations.load(std::memory_order_acquire) + kOperationsAfterUninstall;
  const bool reached_post_uninstall = uninstalled && wait_for_at_least(operations, post_goal);
  const auto allocate_after_post = hooks.allocate_statistics();
  const auto free_after_post = hooks.free_statistics();
  const auto map_after_post = hooks.map_statistics();
  const auto unmap_after_post = hooks.unmap_statistics();

  stop.store(true, std::memory_order_release);
  start.store(true, std::memory_order_release);
  for (auto& worker : workers) {
    worker.join();
  }
  churner.join();

  std::array<std::uint64_t, 4U> dequeued{};
  noleax::agent::windows::NtVirtualMemoryEvent event;
  while (hooks.try_dequeue_event(event)) {
    if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kVmAllocate) {
      ++dequeued[0];
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kVmFree) {
      ++dequeued[1];
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kSectionMap) {
      ++dequeued[2];
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kSectionUnmap) {
      ++dequeued[3];
    } else {
      return 4;
    }
  }
  const auto allocate_statistics = hooks.allocate_statistics();
  const auto free_statistics = hooks.free_statistics();
  const auto map_statistics = hooks.map_statistics();
  const auto unmap_statistics = hooks.unmap_statistics();
  const std::array<std::uint64_t, 4U> dropped{
      allocate_statistics.dropped_events, free_statistics.dropped_events,
      map_statistics.dropped_events, unmap_statistics.dropped_events};
  const std::array<std::uint64_t, 4U> recordable{
      allocate_statistics.recordable_calls, free_statistics.recordable_calls,
      map_statistics.recordable_calls, unmap_statistics.recordable_calls};
  const std::array<std::uint64_t, 4U> successful{
      allocate_statistics.successful_calls, free_statistics.successful_calls,
      map_statistics.successful_calls, unmap_statistics.successful_calls};
  const std::array<std::uint64_t, 4U> failed{
      allocate_statistics.failed_calls, free_statistics.failed_calls, map_statistics.failed_calls,
      unmap_statistics.failed_calls};
  bool accounting_valid = true;
  std::uint64_t total_dequeued = 0U;
  std::uint64_t total_dropped = 0U;
  for (std::size_t index = 0U; index < recordable.size(); ++index) {
    accounting_valid &= dequeued[index] <= recordable[index] &&
                        dropped[index] == recordable[index] - dequeued[index] &&
                        successful[index] + failed[index] == recordable[index];
    total_dequeued += dequeued[index];
    total_dropped += dropped[index];
  }
  accounting_valid &= hooks.event_queue().dropped_count() == total_dropped;
  const bool counters_stable = allocate_after_uninstall.calls == allocate_after_post.calls &&
                               free_after_uninstall.calls == free_after_post.calls &&
                               map_after_uninstall.calls == map_after_post.calls &&
                               unmap_after_uninstall.calls == unmap_after_post.calls;
  const bool quiescent = hooks.replacement_in_flight_count() == 0U;
  const auto reinstall = hooks.install();
  const bool shutdown = backend.shutdown();
  const bool section_closed = CloseHandle(section) != FALSE;
  if (!all_ready || !reached_pre_uninstall || !reached_post_uninstall || !uninstalled ||
      failures.load(std::memory_order_relaxed) != 0U || !counters_stable || !accounting_valid ||
      !quiescent || backend.trampoline_lifetime_lease_count() != 0U ||
      reinstall.allocate.status != noleax::agent::HookInstallStatus::kBackendStopped || !shutdown ||
      !section_closed) {
    std::fprintf(stderr,
                 "NT VM quiescence failed: ready=%llu operations=%llu churn=%llu failures=%llu "
                 "uninstall=%u stable=%u accounting=%u quiescent=%u dequeued=%llu dropped=%llu "
                 "reinstall=%u shutdown=%u\n",
                 static_cast<unsigned long long>(ready.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(operations.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(thread_creations.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(failures.load(std::memory_order_relaxed)),
                 uninstalled ? 1U : 0U, counters_stable ? 1U : 0U, accounting_valid ? 1U : 0U,
                 quiescent ? 1U : 0U, static_cast<unsigned long long>(total_dequeued),
                 static_cast<unsigned long long>(total_dropped),
                 static_cast<unsigned int>(reinstall.allocate.status), shutdown ? 1U : 0U);
    return 5;
  }

  std::printf(
      "status=ok operations=%llu thread_creations=%llu dequeued=%llu dropped=%llu "
      "cfg=%u cet=%u cet_query=%u\n",
      static_cast<unsigned long long>(operations.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(thread_creations.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(total_dequeued),
      static_cast<unsigned long long>(total_dropped), mitigations.cfg_enabled ? 1U : 0U,
      mitigations.cet_enabled ? 1U : 0U, mitigations.cet_queried ? 1U : 0U);
  return 0;
}
