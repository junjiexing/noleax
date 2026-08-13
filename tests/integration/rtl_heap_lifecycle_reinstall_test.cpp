#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <chrono>
#include <cstdint>
#include <cstdio>

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

constexpr std::uint32_t kFlushRetries = 16U;

struct HeapApis {
  RtlCreateHeapFunction create{nullptr};
  RtlAllocateHeapFunction allocate{nullptr};
  RtlReAllocateHeapFunction reallocate{nullptr};
  RtlFreeHeapFunction free_heap{nullptr};
  RtlDestroyHeapFunction destroy{nullptr};
};

[[nodiscard]] bool uninstall_fully(noleax::agent::windows::RtlHeapHooks& hooks) noexcept {
  if (hooks.uninstall(std::chrono::steady_clock::now())) {
    return true;
  }
  for (std::uint32_t retry = 0U; retry < kFlushRetries; ++retry) {
    if (hooks.flush()) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] bool all_referenced(const noleax::agent::windows::RtlHeapHooks& hooks) noexcept {
  return hooks.create_hook().replacement_module_is_referenced() &&
         hooks.allocate_hook().replacement_module_is_referenced() &&
         hooks.reallocate_hook().replacement_module_is_referenced() &&
         hooks.free_hook().replacement_module_is_referenced() &&
         hooks.destroy_hook().replacement_module_is_referenced();
}

[[nodiscard]] bool exercise_heap(const HeapApis& apis) noexcept {
  PVOID private_heap = apis.create(HEAP_GROWABLE, nullptr, 0U, 0U, nullptr, nullptr);
  if (private_heap == nullptr) {
    return false;
  }
  void* allocation = apis.allocate(private_heap, 0U, 48U);
  if (allocation != nullptr) {
    allocation = apis.reallocate(private_heap, 0U, allocation, 96U);
  }
  const bool freed = allocation != nullptr && apis.free_heap(private_heap, 0U, allocation) != FALSE;
  return freed && apis.destroy(private_heap) == nullptr;
}

}  // namespace

int main() {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    return 2;
  }
  HeapApis apis;
  apis.create = reinterpret_cast<RtlCreateHeapFunction>(GetProcAddress(ntdll, "RtlCreateHeap"));
  apis.allocate =
      reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  apis.reallocate =
      reinterpret_cast<RtlReAllocateHeapFunction>(GetProcAddress(ntdll, "RtlReAllocateHeap"));
  apis.free_heap = reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  apis.destroy = reinterpret_cast<RtlDestroyHeapFunction>(GetProcAddress(ntdll, "RtlDestroyHeap"));
  if (apis.create == nullptr || apis.allocate == nullptr || apis.reallocate == nullptr ||
      apis.free_heap == nullptr || apis.destroy == nullptr) {
    return 3;
  }

  noleax::agent::HookBackend backend;
  std::uint64_t first_calls = 0U;
  {
    noleax::agent::windows::RtlHeapHooks hooks{backend, 1024U, 0U};
    const auto installed = hooks.install();
    if (!installed.installed() || !all_referenced(hooks)) {
      return 4;
    }
    if (!exercise_heap(apis)) {
      return 5;
    }
    first_calls = hooks.create_hook().call_count() + hooks.allocate_hook().call_count() +
                  hooks.reallocate_hook().call_count() + hooks.free_hook().call_count() +
                  hooks.destroy_hook().call_count();
    if (first_calls == 0U || hooks.create_hook().call_count() == 0U ||
        hooks.destroy_hook().call_count() == 0U) {
      return 6;
    }
    if (!uninstall_fully(hooks)) {
      return 7;
    }
    if (all_referenced(hooks) || hooks.has_pending_teardown()) {
      return 8;
    }
    const auto reinstall = hooks.install();
    if (reinstall.installed()) {
      return 9;
    }
  }

  std::uint64_t second_calls = 0U;
  {
    noleax::agent::windows::RtlHeapHooks hooks{backend, 1024U, 0U};
    const auto installed = hooks.install();
    if (!installed.installed() || !all_referenced(hooks)) {
      return 10;
    }
    if (!exercise_heap(apis)) {
      return 11;
    }
    second_calls = hooks.create_hook().call_count() + hooks.allocate_hook().call_count() +
                   hooks.reallocate_hook().call_count() + hooks.free_hook().call_count() +
                   hooks.destroy_hook().call_count();
    if (second_calls == 0U) {
      return 12;
    }
    if (!uninstall_fully(hooks)) {
      return 13;
    }
    if (all_referenced(hooks)) {
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
