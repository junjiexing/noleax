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
#include "noleax/agent/windows/rtl_destroy_heap_hook.hpp"

namespace {

using RtlDestroyHeapFunction = PVOID(NTAPI*)(PVOID heap);

[[nodiscard]] int run_child(std::string_view test_case, bool hooked) {
  static_cast<void>(SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX));
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto destroy =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlDestroyHeapFunction>(GetProcAddress(ntdll, "RtlDestroyHeap"));
  if (destroy == nullptr) {
    return 10;
  }

  PVOID heap = nullptr;
  if (test_case == "null") {
    heap = nullptr;
  } else if (test_case == "bad-handle") {
    heap = std::bit_cast<PVOID>(std::uintptr_t{1U});
  } else if (test_case == "double-destroy") {
    heap = HeapCreate(0U, 0U, 0U);
    if (heap == nullptr) {
      return 11;
    }
  } else {
    return 12;
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlDestroyHeapHook hook{backend, 16U, 0U};
  if (hooked && !hook.install().installed()) {
    return 13;
  }
  if (test_case == "double-destroy" && destroy(heap) != nullptr) {
    return 14;
  }

  const PVOID result = destroy(heap);
  return result == nullptr ? 20 : 21;
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
  constexpr std::array<std::string_view, 3U> cases{"null", "bad-handle", "double-destroy"};
  std::array<DWORD, cases.size()> exits{};
  for (std::size_t index = 0U; index < cases.size(); ++index) {
    DWORD baseline = 0U;
    DWORD hooked = 0U;
    if (!child_exit_code(executable, cases[index], false, baseline) ||
        !child_exit_code(executable, cases[index], true, hooked)) {
      std::fprintf(stderr, "cannot run isolated %.*s child\n",
                   static_cast<int>(cases[index].size()), cases[index].data());
      return 5;
    }
    if (baseline != hooked || baseline == 10U || baseline == 11U || baseline == 12U ||
        baseline == 13U || baseline == 14U) {
      std::fprintf(stderr, "%.*s exit mismatch: baseline=0x%08lx hooked=0x%08lx\n",
                   static_cast<int>(cases[index].size()), cases[index].data(),
                   static_cast<unsigned long>(baseline), static_cast<unsigned long>(hooked));
      return 6;
    }
    exits[index] = baseline;
  }

  std::printf("status=ok cases=3 exits=0x%08lx,0x%08lx,0x%08lx baseline=hooked\n",
              static_cast<unsigned long>(exits[0]), static_cast<unsigned long>(exits[1]),
              static_cast<unsigned long>(exits[2]));
  return 0;
}
