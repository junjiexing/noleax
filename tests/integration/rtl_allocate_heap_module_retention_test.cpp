#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>

namespace {

using AbiVersion = std::uint32_t (*)() noexcept;
using Install = std::uint32_t (*)() noexcept;
using Stop = std::uint32_t (*)() noexcept;
using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID allocation);

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (argc != 2) {
    return 2;
  }
  HMODULE module = LoadLibraryW(std::filesystem::path{argv[1]}.c_str());
  if (module == nullptr) {
    return 3;
  }
  const auto abi_version = reinterpret_cast<AbiVersion>(
      GetProcAddress(module, "noleax_test_rtl_allocate_heap_hook_abi_version"));
  const auto install = reinterpret_cast<Install>(
      GetProcAddress(module, "noleax_test_rtl_allocate_heap_hook_install"));
  const auto stop =
      reinterpret_cast<Stop>(GetProcAddress(module, "noleax_test_rtl_allocate_heap_hook_stop"));
  if (abi_version == nullptr || install == nullptr || stop == nullptr || abi_version() != 1U ||
      install() != 0U) {
    FreeLibrary(module);
    return 4;
  }
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const HANDLE heap = GetProcessHeap();
  const auto allocate =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  const auto free_heap =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  if (heap == nullptr || allocate == nullptr || free_heap == nullptr) {
    return 5;
  }
  for (std::uint32_t iteration = 0U; iteration < 1024U; ++iteration) {
    void* const allocation = allocate(heap, 0U, 32U + iteration % 64U);
    if (allocation == nullptr || free_heap(heap, 0U, allocation) == FALSE) {
      return 6;
    }
  }
  if (stop() != 0U) {
    return 7;
  }
  if (FreeLibrary(module) == FALSE) {
    return 8;
  }

  HMODULE retained_module = nullptr;
  const DWORD flags =
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
  if (GetModuleHandleExW(flags, reinterpret_cast<LPCWSTR>(abi_version), &retained_module) ==
          FALSE ||
      retained_module != module || abi_version() != 1U) {
    return 9;
  }

  std::printf("status=ok module-retained=1\n");
  return 0;
}
