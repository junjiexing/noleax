#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <cstdio>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/nt_memory_hooks.hpp"

namespace {

using NtAllocateVirtualMemoryFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID* base_address,
                                                         ULONG_PTR zero_bits, PSIZE_T region_size,
                                                         ULONG allocation_type, ULONG protect);
using NtFreeVirtualMemoryFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID* base_address,
                                                     PSIZE_T region_size, ULONG free_type);

constexpr std::uint32_t kFlushRetries = 16U;

[[nodiscard]] bool uninstall_fully(noleax::agent::windows::NtMemoryHooks& hooks) noexcept {
  if (hooks.uninstall(0U)) {
    return true;
  }
  for (std::uint32_t retry = 0U; retry < kFlushRetries; ++retry) {
    if (hooks.flush(100'000U)) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] bool exercise_virtual_memory(NtAllocateVirtualMemoryFunction allocate,
                                           NtFreeVirtualMemoryFunction free_vm) noexcept {
  for (std::uint32_t iteration = 0U; iteration < 16U; ++iteration) {
    PVOID base = nullptr;
    SIZE_T region_size = 64U * 1024U;
    if (allocate(GetCurrentProcess(), &base, 0U, &region_size, MEM_RESERVE | MEM_COMMIT,
                 PAGE_READWRITE) < 0 ||
        base == nullptr) {
      return false;
    }
    SIZE_T free_size = 0U;
    if (free_vm(GetCurrentProcess(), &base, &free_size, MEM_RELEASE) < 0) {
      return false;
    }
  }
  return true;
}

}  // namespace

int main() {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    return 2;
  }
  const auto allocate = reinterpret_cast<NtAllocateVirtualMemoryFunction>(
      GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
  const auto free_vm =
      reinterpret_cast<NtFreeVirtualMemoryFunction>(GetProcAddress(ntdll, "NtFreeVirtualMemory"));
  if (allocate == nullptr || free_vm == nullptr) {
    return 3;
  }

  noleax::agent::HookBackend backend;
  std::uint64_t first_calls = 0U;
  {
    noleax::agent::windows::NtMemoryHooks hooks{backend, 1024U, 0U};
    const auto installed = hooks.install();
    if (!installed.installed() || !hooks.replacement_module_is_referenced()) {
      return 4;
    }
    if (!exercise_virtual_memory(allocate, free_vm)) {
      return 5;
    }
    first_calls = hooks.allocate_statistics().calls;
    if (first_calls == 0U || hooks.free_statistics().calls == 0U) {
      return 6;
    }
    if (!uninstall_fully(hooks)) {
      return 7;
    }
    if (hooks.replacement_module_is_referenced() || hooks.replacement_in_flight_count() != 0U) {
      return 8;
    }
    const auto reinstall = hooks.install();
    if (reinstall.installed()) {
      return 9;
    }
  }

  std::uint64_t second_calls = 0U;
  {
    noleax::agent::windows::NtMemoryHooks hooks{backend, 1024U, 0U};
    const auto installed = hooks.install();
    if (!installed.installed() || !hooks.replacement_module_is_referenced()) {
      return 10;
    }
    if (!exercise_virtual_memory(allocate, free_vm)) {
      return 11;
    }
    second_calls = hooks.allocate_statistics().calls;
    if (second_calls == 0U) {
      return 12;
    }
    if (!uninstall_fully(hooks)) {
      return 13;
    }
    if (hooks.replacement_module_is_referenced()) {
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
