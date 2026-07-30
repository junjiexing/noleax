#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <bit>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_reallocate_heap_hook.hpp"

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlReAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, PVOID address,
                                                SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID address);

[[nodiscard]] int run_child(std::string_view test_case, bool hooked) {
  static_cast<void>(SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX));
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto allocate =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  const auto reallocate =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlReAllocateHeapFunction>(GetProcAddress(ntdll, "RtlReAllocateHeap"));
  const auto free_heap =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  const HANDLE process_heap = GetProcessHeap();
  if (allocate == nullptr || reallocate == nullptr || free_heap == nullptr ||
      process_heap == nullptr) {
    return 10;
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlReAllocateHeapHook hook{backend, 64U, 0U};
  if (hooked && !hook.install().installed()) {
    return 11;
  }

  PVOID heap = process_heap;
  PVOID address = nullptr;
  if (test_case == "bad-address") {
    address = std::bit_cast<PVOID>(std::uintptr_t{1U});
  } else if (test_case == "wrong-heap") {
    const HANDLE allocation_heap = HeapCreate(0U, 0U, 0U);
    const HANDLE other_heap = HeapCreate(0U, 0U, 0U);
    if (allocation_heap == nullptr || other_heap == nullptr) {
      return 12;
    }
    address = allocate(allocation_heap, 0U, 64U);
    heap = other_heap;
  } else if (test_case == "freed-address") {
    address = allocate(process_heap, 0U, 64U);
    if (address == nullptr || free_heap(process_heap, 0U, address) == FALSE) {
      return 13;
    }
  } else {
    return 14;
  }

  if (address == nullptr) {
    return 15;
  }
  const PVOID unexpected = reallocate(heap, 0U, address, 128U);
  return unexpected == nullptr ? 16 : 17;
}

[[nodiscard]] bool child_exit_code(const std::wstring& executable, std::string_view test_case,
                                   bool hooked, DWORD& exit_code) {
  const std::wstring wide_case{test_case.begin(), test_case.end()};
  std::wstring command =
      L"\"" + executable + L"\" --child " + wide_case + (hooked ? L" hooked" : L" baseline");
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                     nullptr, nullptr, &startup, &process) == FALSE) {
    return false;
  }
  CloseHandle(process.hThread);
  const DWORD wait_status = WaitForSingleObject(process.hProcess, 30'000U);
  bool valid =
      wait_status == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
  if (wait_status == WAIT_TIMEOUT) {
    static_cast<void>(TerminateProcess(process.hProcess, 0xdeadc0deU));
    static_cast<void>(WaitForSingleObject(process.hProcess, 5'000U));
    valid = false;
  }
  CloseHandle(process.hProcess);
  return valid;
}

[[nodiscard]] std::wstring executable_path() {
  std::wstring path(32'768U, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0U || length >= path.size()) {
    return {};
  }
  path.resize(length);
  return path;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc == 4 && std::string_view{argv[1]} == "--child") {
    const std::string_view mode{argv[3]};
    if (mode != "baseline" && mode != "hooked") {
      return 2;
    }
    return run_child(argv[2], mode == "hooked");
  }
  if (argc != 1) {
    return 3;
  }

  const std::wstring executable = executable_path();
  if (executable.empty()) {
    return 4;
  }
  constexpr std::array<std::string_view, 3U> cases{"bad-address", "wrong-heap", "freed-address"};
  std::array<DWORD, cases.size()> exit_codes{};
  for (std::size_t index = 0U; index < cases.size(); ++index) {
    DWORD baseline = 0U;
    DWORD hooked = 0U;
    if (!child_exit_code(executable, cases[index], false, baseline) ||
        !child_exit_code(executable, cases[index], true, hooked)) {
      std::fprintf(stderr, "cannot run isolated %.*s child\n",
                   static_cast<int>(cases[index].size()), cases[index].data());
      return 5;
    }
    if (baseline != hooked || (baseline & 0x80000000U) == 0U) {
      std::fprintf(stderr, "%.*s exit mismatch: baseline=0x%08lx hooked=0x%08lx\n",
                   static_cast<int>(cases[index].size()), cases[index].data(),
                   static_cast<unsigned long>(baseline), static_cast<unsigned long>(hooked));
      return 6;
    }
    exit_codes[index] = baseline;
  }

  std::printf("status=ok cases=3 exits=0x%08lx,0x%08lx,0x%08lx baseline=hooked\n",
              static_cast<unsigned long>(exit_codes[0]), static_cast<unsigned long>(exit_codes[1]),
              static_cast<unsigned long>(exit_codes[2]));
  return 0;
}
