#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_heap_hooks.hpp"

namespace {

using RtlCreateHeapFunction = PVOID(NTAPI*)(ULONG flags, PVOID heap_base, SIZE_T reserve_size,
                                            SIZE_T commit_size, PVOID lock, PVOID parameters);
using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlReAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, PVOID address,
                                                SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID address);
using RtlDestroyHeapFunction = PVOID(NTAPI*)(PVOID heap);

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
    std::fprintf(stderr, "hardened image did not start with Control Flow Guard enabled\n");
    return 10;
  }
#endif
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    return 2;
  }
  const auto create =
      reinterpret_cast<RtlCreateHeapFunction>(GetProcAddress(ntdll, "RtlCreateHeap"));
  const auto allocate =
      reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  const auto reallocate =
      reinterpret_cast<RtlReAllocateHeapFunction>(GetProcAddress(ntdll, "RtlReAllocateHeap"));
  const auto free_heap =
      reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  const auto destroy =
      reinterpret_cast<RtlDestroyHeapFunction>(GetProcAddress(ntdll, "RtlDestroyHeap"));
  if (create == nullptr || allocate == nullptr || reallocate == nullptr || free_heap == nullptr ||
      destroy == nullptr) {
    return 3;
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlHeapHooks hooks{backend, 1024U, 0U};
  const auto installed = hooks.install();
  if (!installed.installed() || !hooks.create_hook().replacement_module_is_pinned() ||
      !hooks.allocate_hook().replacement_module_is_pinned() ||
      !hooks.reallocate_hook().replacement_module_is_pinned() ||
      !hooks.free_hook().replacement_module_is_pinned() ||
      !hooks.destroy_hook().replacement_module_is_pinned()) {
    return 4;
  }

  std::atomic<std::uint64_t> ready{0U};
  std::atomic<std::uint64_t> operations{0U};
  std::atomic<std::uint64_t> thread_creations{0U};
  std::atomic<std::uint64_t> failures{0U};
  std::atomic<bool> start{false};
  std::atomic<bool> stop{false};
  const auto run_operation = [&] {
    PVOID heap = create(HEAP_GROWABLE, nullptr, 0U, 0U, nullptr, nullptr);
    if (heap == nullptr) {
      failures.fetch_add(1U, std::memory_order_relaxed);
      return;
    }
    constexpr SIZE_T kOriginalSize = 64U;
    constexpr SIZE_T kNewSize = 128U;
    PVOID address = allocate(heap, 0U, kOriginalSize);
    if (address == nullptr) {
      failures.fetch_add(1U, std::memory_order_relaxed);
      static_cast<void>(destroy(heap));
      return;
    }
    std::memset(address, 0x5a, kOriginalSize);
    PVOID resized = reallocate(heap, 0U, address, kNewSize);
    bool content_valid = resized != nullptr;
    const auto* bytes = static_cast<const unsigned char*>(resized);
    for (std::size_t index = 0U; content_valid && index < kOriginalSize; ++index) {
      content_valid = bytes[index] == 0x5aU;
    }
    if (resized == nullptr || !content_valid) {
      failures.fetch_add(1U, std::memory_order_relaxed);
      if (resized == nullptr) {
        static_cast<void>(free_heap(heap, 0U, address));
      }
      static_cast<void>(destroy(heap));
      return;
    }
    if (free_heap(heap, 0U, resized) == FALSE || destroy(heap) != nullptr) {
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
  std::thread thread_churner{[&] {
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
    uninstalled = hooks.uninstall(0U);
    for (std::uint32_t retry = 0U; retry < 16U && !uninstalled; ++retry) {
      uninstalled = hooks.flush(100'000U);
    }
  }

  const std::array<std::uint64_t, 5U> calls_after_uninstall{
      hooks.create_hook().call_count(), hooks.allocate_hook().call_count(),
      hooks.reallocate_hook().call_count(), hooks.free_hook().call_count(),
      hooks.destroy_hook().call_count()};
  const std::uint64_t post_uninstall_goal =
      operations.load(std::memory_order_acquire) + kOperationsAfterUninstall;
  const bool reached_post_uninstall =
      uninstalled && wait_for_at_least(operations, post_uninstall_goal);
  const std::array<std::uint64_t, 5U> calls_after_post_run{
      hooks.create_hook().call_count(), hooks.allocate_hook().call_count(),
      hooks.reallocate_hook().call_count(), hooks.free_hook().call_count(),
      hooks.destroy_hook().call_count()};

  stop.store(true, std::memory_order_release);
  start.store(true, std::memory_order_release);
  for (auto& worker : workers) {
    worker.join();
  }
  thread_churner.join();

  std::array<std::uint64_t, 5U> dequeued{};
  noleax::agent::windows::RtlHeapEvent event;
  while (hooks.event_queue().try_pop(event)) {
    const std::size_t index = static_cast<std::size_t>(event.operation);
    if (index >= dequeued.size()) {
      return 5;
    }
    ++dequeued[index];
  }
  const std::array<std::uint64_t, 5U> dropped{
      hooks.create_hook().dropped_event_count(), hooks.allocate_hook().dropped_event_count(),
      hooks.reallocate_hook().dropped_event_count(), hooks.free_hook().dropped_event_count(),
      hooks.destroy_hook().dropped_event_count()};
  const std::array<std::uint64_t, 5U> recordable{
      hooks.create_hook().recordable_call_count(), hooks.allocate_hook().recordable_call_count(),
      hooks.reallocate_hook().recordable_call_count(), hooks.free_hook().recordable_call_count(),
      hooks.destroy_hook().recordable_call_count()};
  const std::array<std::uint64_t, 5U> successful{
      hooks.create_hook().successful_call_count(), hooks.allocate_hook().successful_call_count(),
      hooks.reallocate_hook().successful_call_count(), hooks.free_hook().successful_call_count(),
      hooks.destroy_hook().successful_call_count()};
  const std::array<std::uint64_t, 5U> failed{
      hooks.create_hook().failed_call_count(), hooks.allocate_hook().failed_call_count(),
      hooks.reallocate_hook().failed_call_count(), hooks.free_hook().failed_call_count(),
      hooks.destroy_hook().failed_call_count()};
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
  const bool quiescent = hooks.create_hook().replacement_in_flight_count() == 0U &&
                         hooks.allocate_hook().replacement_in_flight_count() == 0U &&
                         hooks.reallocate_hook().replacement_in_flight_count() == 0U &&
                         hooks.free_hook().replacement_in_flight_count() == 0U &&
                         hooks.destroy_hook().replacement_in_flight_count() == 0U;
  const auto reinstall = hooks.install();
  const bool shutdown = backend.shutdown();

  if (!all_ready || !reached_pre_uninstall || !reached_post_uninstall || !uninstalled ||
      failures.load(std::memory_order_relaxed) != 0U ||
      calls_after_uninstall != calls_after_post_run || !accounting_valid || !quiescent ||
      backend.trampoline_lifetime_lease_count() != 0U ||
      reinstall.create.status != noleax::agent::HookInstallStatus::kBackendStopped || !shutdown) {
    std::fprintf(stderr,
                 "heap lifecycle quiescence failed: ready=%llu operations=%llu churn=%llu "
                 "failures=%llu uninstall=%u stable=%u accounting=%u quiescent=%u "
                 "dequeued=%llu dropped=%llu reinstall=%u shutdown=%u\n",
                 static_cast<unsigned long long>(ready.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(operations.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(thread_creations.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(failures.load(std::memory_order_relaxed)),
                 uninstalled ? 1U : 0U, calls_after_uninstall == calls_after_post_run ? 1U : 0U,
                 accounting_valid ? 1U : 0U, quiescent ? 1U : 0U,
                 static_cast<unsigned long long>(total_dequeued),
                 static_cast<unsigned long long>(total_dropped),
                 static_cast<unsigned int>(reinstall.create.status), shutdown ? 1U : 0U);
    return 6;
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
