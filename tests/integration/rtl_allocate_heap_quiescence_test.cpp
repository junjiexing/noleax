#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID allocation);

constexpr std::size_t kWorkerCount = 8U;
constexpr std::uint64_t kOperationsBeforeUninstall = 20'000U;
constexpr std::uint64_t kOperationsAfterUninstall = 20'000U;
constexpr std::uint64_t kThreadCreationsBeforeUninstall = 100U;
constexpr ULONGLONG kWaitTimeoutMilliseconds = 15'000U;

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
    std::fprintf(stderr, "hardened image did not start with Control Flow Guard enabled\n");
    return 10;
  }
#endif
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const HANDLE heap = GetProcessHeap();
  if (ntdll == nullptr || heap == nullptr) {
    return 2;
  }
  const auto allocate =
      reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  const auto free_heap =
      reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  if (allocate == nullptr || free_heap == nullptr) {
    return 3;
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlAllocateHeapHook hook{backend, 1024U, 0U};
  const auto installed = hook.install();
  if (!installed.installed() || !hook.replacement_module_is_pinned()) {
    return 4;
  }

  std::atomic<std::uint64_t> ready{0U};
  std::atomic<std::uint64_t> operations{0U};
  std::atomic<std::uint64_t> thread_creations{0U};
  std::atomic<std::uint64_t> failures{0U};
  std::atomic<bool> start{false};
  std::atomic<bool> stop{false};
  // Leave scheduling headroom so the thread churner is not starved on small-core machines.
  const std::size_t hardware_threads =
      static_cast<std::size_t>(std::thread::hardware_concurrency());
  const std::size_t worker_count =
      hardware_threads > 3U ? std::min(kWorkerCount, hardware_threads - 2U) : 2U;
  std::array<std::thread, kWorkerCount> workers;
  for (std::size_t worker_index = 0U; worker_index < worker_count; ++worker_index) {
    workers[worker_index] = std::thread{[&, worker_index] {
      ready.fetch_add(1U, std::memory_order_release);
      while (!start.load(std::memory_order_acquire)) {
        SwitchToThread();
      }
      std::uint64_t iteration = static_cast<std::uint64_t>(worker_index) + 1U;
      while (!stop.load(std::memory_order_acquire)) {
        const SIZE_T size = static_cast<SIZE_T>(16U + (iteration & 255U));
        void* const allocation = allocate(heap, 0U, size);
        if (allocation == nullptr) {
          failures.fetch_add(1U, std::memory_order_relaxed);
          break;
        }
        std::memset(allocation, static_cast<int>(iteration & 0xffU), size);
        if (free_heap(heap, 0U, allocation) == FALSE) {
          failures.fetch_add(1U, std::memory_order_relaxed);
          break;
        }
        operations.fetch_add(1U, std::memory_order_release);
        ++iteration;
      }
    }};
  }

  std::thread thread_churner{[&] {
    while (!start.load(std::memory_order_acquire)) {
      SwitchToThread();
    }
    while (!stop.load(std::memory_order_acquire)) {
      std::thread short_lived{[&] {
        void* const allocation = allocate(heap, 0U, 48U);
        if (allocation == nullptr || free_heap(heap, 0U, allocation) == FALSE) {
          failures.fetch_add(1U, std::memory_order_relaxed);
        }
      }};
      short_lived.join();
      thread_creations.fetch_add(1U, std::memory_order_release);
    }
  }};

  const bool all_ready = wait_for_at_least(ready, worker_count);
  start.store(true, std::memory_order_release);
  bool reached_pre_uninstall = false;
  if (all_ready) {
    reached_pre_uninstall = wait_for_at_least(operations, kOperationsBeforeUninstall) &&
                            wait_for_at_least(thread_creations, kThreadCreationsBeforeUninstall);
  }

  auto uninstall_status = noleax::agent::HookUninstallStatus::kTeardownPending;
  if (reached_pre_uninstall) {
    uninstall_status = hook.uninstall(0U);
    if (uninstall_status != noleax::agent::HookUninstallStatus::kTeardownPending) {
      failures.fetch_add(1U, std::memory_order_relaxed);
    }
    for (std::uint32_t retry = 0U;
         retry < 16U && uninstall_status == noleax::agent::HookUninstallStatus::kTeardownPending;
         ++retry) {
      if (hook.flush(100'000U)) {
        uninstall_status = noleax::agent::HookUninstallStatus::kUninstalled;
      }
    }
  }

  const std::uint64_t calls_after_uninstall = hook.call_count();
  const std::uint64_t post_uninstall_goal =
      operations.load(std::memory_order_acquire) + kOperationsAfterUninstall;
  const bool reached_post_uninstall =
      uninstall_status == noleax::agent::HookUninstallStatus::kUninstalled &&
      wait_for_at_least(operations, post_uninstall_goal);
  const std::uint64_t calls_after_post_run = hook.call_count();

  stop.store(true, std::memory_order_release);
  start.store(true, std::memory_order_release);
  for (std::size_t worker_index = 0U; worker_index < worker_count; ++worker_index) {
    workers[worker_index].join();
  }
  thread_churner.join();

  std::uint64_t dequeued = 0U;
  noleax::agent::windows::RtlAllocateHeapEvent event;
  while (hook.try_dequeue_event(event)) {
    ++dequeued;
  }
  const std::uint64_t dropped = hook.dropped_event_count();
  const std::uint64_t recordable = hook.recordable_call_count();
  const bool accounting_valid =
      dequeued <= recordable && dropped == recordable - dequeued &&
      hook.successful_call_count() + hook.failed_call_count() == recordable;
  const auto reinstall = hook.install();
  const bool shutdown = backend.shutdown();

  if (!all_ready || !reached_pre_uninstall || !reached_post_uninstall ||
      uninstall_status != noleax::agent::HookUninstallStatus::kUninstalled ||
      hook.replacement_in_flight_count() != 0U || failures.load(std::memory_order_relaxed) != 0U ||
      calls_after_uninstall != calls_after_post_run || !accounting_valid ||
      backend.trampoline_lifetime_lease_count() != 0U ||
      reinstall.status != noleax::agent::HookInstallStatus::kBackendStopped || !shutdown) {
    std::fprintf(stderr,
                 "quiescence race failed: ready=%llu operations=%llu thread_creations=%llu "
                 "failures=%llu "
                 "uninstall=%u in_flight=%llu calls=%llu/%llu recordable=%llu dequeued=%llu "
                 "dropped=%llu reinstall=%u shutdown=%u\n",
                 static_cast<unsigned long long>(ready.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(operations.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(thread_creations.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(failures.load(std::memory_order_relaxed)),
                 static_cast<unsigned int>(uninstall_status),
                 static_cast<unsigned long long>(hook.replacement_in_flight_count()),
                 static_cast<unsigned long long>(calls_after_uninstall),
                 static_cast<unsigned long long>(calls_after_post_run),
                 static_cast<unsigned long long>(recordable),
                 static_cast<unsigned long long>(dequeued),
                 static_cast<unsigned long long>(dropped),
                 static_cast<unsigned int>(reinstall.status), shutdown ? 1U : 0U);
    return 5;
  }

  std::printf(
      "status=ok operations=%llu thread_creations=%llu recordable=%llu dequeued=%llu "
      "dropped=%llu cfg=%u cet=%u cet_query=%u\n",
      static_cast<unsigned long long>(operations.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(thread_creations.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(recordable), static_cast<unsigned long long>(dequeued),
      static_cast<unsigned long long>(dropped), mitigations.cfg_enabled ? 1U : 0U,
      mitigations.cet_enabled ? 1U : 0U, mitigations.cet_queried ? 1U : 0U);
  return 0;
}
