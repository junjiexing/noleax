#include "noleax/controller/windows/thread_hijack_injector.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

using namespace std::chrono_literals;

constexpr wchar_t kDelayEnvVar[] = L"NOLEAX_SLOW_BOOTSTRAP_MS";

[[nodiscard]] noleax::agent::windows::BootstrapParameters standalone_bootstrap() {
  noleax::agent::windows::BootstrapParameters params;
  const wchar_t name[] = L"nlx-hijack-timeout-test";
  std::memcpy(params.pipe_name.data(), name, sizeof(name));
  params.session_token = noleax::agent::windows::kStandaloneMagic;
  return params;
}

[[nodiscard]] bool wait_for_file(const std::filesystem::path& path,
                                 std::chrono::milliseconds timeout) {
  const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout.count());
  do {
    std::error_code error;
    if (std::filesystem::is_regular_file(path, error) && !error) {
      return true;
    }
    Sleep(5U);
  } while (GetTickCount64() < deadline);
  return false;
}

class ChildProcess final {
 public:
  ChildProcess() = default;
  ~ChildProcess() {
    if (handle_ != nullptr) {
      static_cast<void>(TerminateProcess(handle_, 0U));
      static_cast<void>(CloseHandle(handle_));
    }
  }

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  ChildProcess(ChildProcess&& other) noexcept : handle_{other.handle_}, id_{other.id_} {
    other.handle_ = nullptr;
  }

  [[nodiscard]] HANDLE handle() const noexcept { return handle_; }
  [[nodiscard]] std::uint32_t id() const noexcept { return id_; }

  // Spawns this test binary in --child mode and waits until the child signals that
  // it is fully initialized and parked in Sleep; hijacking before that point races
  // the child's own loader startup.
  [[nodiscard]] static ChildProcess spawn(const wchar_t* exe_path, const wchar_t* delay_ms,
                                          const std::filesystem::path& ready_marker) {
    ChildProcess child;
    static_cast<void>(SetEnvironmentVariableW(kDelayEnvVar, delay_ms));
    std::array<wchar_t, 1024> command{};
    const int written = swprintf_s(command.data(), command.size(), L"\"%s\" --child \"%s\"",
                                   exe_path, ready_marker.c_str());
    if (written <= 0) {
      return child;
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION information{};
    if (CreateProcessW(exe_path, command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                       &startup, &information) == FALSE) {
      return child;
    }
    static_cast<void>(CloseHandle(information.hThread));
    // The marker proves the child is up; the settle window lets it leave any CRT
    // frame and park inside the wait primitive, which is the only provably
    // lock-free state to hijack (a statically linked CRT frame would be chosen as
    // an "application frame" but can still hold the heap lock).
    if (!wait_for_file(ready_marker, 10s)) {
      static_cast<void>(TerminateProcess(information.hProcess, 0U));
      static_cast<void>(CloseHandle(information.hProcess));
      return child;
    }
    Sleep(500U);
    child.handle_ = information.hProcess;
    child.id_ = information.dwProcessId;
    return child;
  }

 private:
  HANDLE handle_{nullptr};
  std::uint32_t id_{0U};
};

[[nodiscard]] bool message_contains(const std::exception& error, const char* needle) {
  return std::string{error.what()}.find(needle) != std::string::npos;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc >= 3 && std::strcmp(argv[1], "--child") == 0) {
    {
      std::ofstream marker{argv[2]};
      marker << "ready\n";
    }
    // Park in a user-mode spin: the hijack selection takes it as an application
    // frame, which provably resumes into the stub (a thread suspended inside a
    // blocking ntdll wait does not return to user mode for the redirected RIP).
    volatile bool spinning = true;
    while (spinning) {
      YieldProcessor();
    }
    return 0;
  }
  if (argc != 3) {
    return 2;
  }
  const std::filesystem::path fixture = std::filesystem::absolute(argv[1]);
  const std::filesystem::path workdir = std::filesystem::absolute(argv[2]);
  std::error_code directory_error;
  std::filesystem::create_directories(workdir, directory_error);
  std::array<wchar_t, MAX_PATH> self_path{};
  if (GetModuleFileNameW(nullptr, self_path.data(), static_cast<DWORD>(self_path.size())) == 0U) {
    return 3;
  }

  // A bootstrap slower than the configured timeout still completes: the extended
  // budget lets the stub unwind instead of abandoning the bootstrap frame. The
  // delays are generous because a fresh child's first DLL loads can be slow under
  // real-time AV scanning.
  {
    const auto marker = workdir / "slow.ready";
    std::error_code remove_error;
    static_cast<void>(std::filesystem::remove(marker, remove_error));
    auto child = ChildProcess::spawn(self_path.data(), L"3000", marker);
    if (child.handle() == nullptr) {
      return 4;
    }
    noleax::controller::windows::ThreadHijack hijack{
        child.handle(), child.id(), fixture, standalone_bootstrap(), {}};
    hijack.start();
    const auto begin = std::chrono::steady_clock::now();
    std::uintptr_t module = 0U;
    try {
      module = hijack.finish(2000ms);
    } catch (const std::exception& error) {
      DWORD exit_code = 0U;
      const BOOL alive = GetExitCodeProcess(child.handle(), &exit_code);
      std::fprintf(stderr, "A exception: %s (child alive=%d exit=%lu/0x%lx)\n", error.what(),
                   alive != FALSE ? 1 : 0, exit_code, exit_code);
      return 9;
    }
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    if (module == 0U) {
      return 5;
    }
    // Well past the first 2000ms budget: the finish path waited for the bootstrap
    // to return instead of restoring the context at the first timeout.
    if (elapsed < 2200ms) {
      return 6;
    }
  }

  // When even the extended budget expires inside the loader or the bootstrap, the
  // restore is forced and the error names the stub stage and the residual lock risk.
  {
    const auto marker = workdir / "stuck.ready";
    std::error_code remove_error;
    static_cast<void>(std::filesystem::remove(marker, remove_error));
    auto child = ChildProcess::spawn(self_path.data(), L"30000", marker);
    if (child.handle() == nullptr) {
      return 7;
    }
    noleax::controller::windows::ThreadHijack hijack{
        child.handle(), child.id(), fixture, standalone_bootstrap(), {}};
    hijack.start();
    bool saw_timeout = false;
    try {
      static_cast<void>(hijack.finish(500ms));
    } catch (const noleax::controller::windows::InjectionError& error) {
      saw_timeout =
          message_contains(error, "stage ") && message_contains(error, "locks may remain held");
    }
    if (!saw_timeout) {
      return 8;
    }
  }

  static_cast<void>(SetEnvironmentVariableW(kDelayEnvVar, nullptr));
  std::printf("status=ok waited=1 forced=1\n");
  return 0;
}
