#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <chrono>
#include <cstdint>
#include <cstdio>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID allocation);

constexpr std::uint32_t kFlushRetries = 16U;

[[nodiscard]] bool uninstall_fully(noleax::agent::windows::RtlAllocateHeapHook& hook) noexcept {
  auto status = hook.uninstall(std::chrono::steady_clock::now());
  for (std::uint32_t retry = 0U;
       retry < kFlushRetries && status == noleax::agent::HookUninstallStatus::kTeardownPending;
       ++retry) {
    if (hook.flush()) {
      status = noleax::agent::HookUninstallStatus::kUninstalled;
    }
  }
  return status == noleax::agent::HookUninstallStatus::kUninstalled;
}

[[nodiscard]] bool exercise_heap(RtlAllocateHeapFunction allocate, RtlFreeHeapFunction free_heap,
                                 HANDLE heap) noexcept {
  for (std::uint32_t iteration = 0U; iteration < 64U; ++iteration) {
    void* const allocation = allocate(heap, 0U, 32U + iteration);
    if (allocation == nullptr || free_heap(heap, 0U, allocation) == FALSE) {
      return false;
    }
  }
  return true;
}

}  // namespace

int main() {
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
  std::uint64_t first_calls = 0U;
  {
    noleax::agent::windows::RtlAllocateHeapHook hook{backend, 1024U, 0U};
    const auto installed = hook.install();
    if (!installed.installed() || !hook.replacement_module_is_referenced()) {
      return 4;
    }
    if (!exercise_heap(allocate, free_heap, heap)) {
      return 5;
    }
    first_calls = hook.call_count();
    if (first_calls == 0U) {
      return 6;
    }
    if (!uninstall_fully(hook)) {
      return 7;
    }
    if (hook.replacement_module_is_referenced() || hook.replacement_in_flight_count() != 0U) {
      return 8;
    }
    // The retired instance stays refused even though the process-wide flag was reset.
    const auto reinstall = hook.install();
    if (reinstall.status != noleax::agent::HookInstallStatus::kBackendStopped) {
      return 9;
    }
  }

  std::uint64_t second_calls = 0U;
  {
    noleax::agent::windows::RtlAllocateHeapHook hook{backend, 1024U, 0U};
    const auto installed = hook.install();
    if (!installed.installed() || !hook.replacement_module_is_referenced()) {
      return 10;
    }
    if (!exercise_heap(allocate, free_heap, heap)) {
      return 11;
    }
    second_calls = hook.call_count();
    if (second_calls == 0U) {
      return 12;
    }
    if (!uninstall_fully(hook)) {
      return 13;
    }
    if (hook.replacement_module_is_referenced()) {
      return 14;
    }
  }

  const bool shutdown = backend.shutdown();
  if (!shutdown || backend.trampoline_lifetime_lease_count() != 0U) {
    return 15;
  }
  std::printf("status=ok first=%llu second=%llu\n", static_cast<unsigned long long>(first_calls),
              static_cast<unsigned long long>(second_calls));
  return 0;
}
