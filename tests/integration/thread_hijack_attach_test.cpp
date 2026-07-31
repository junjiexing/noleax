#include "noleax/controller/windows/thread_hijack_injector.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <thread>
#include <vector>

#include "noleax/agent/windows/bootstrap.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/controller/windows/controller.hpp"
#include "noleax/controller/windows/process.hpp"
#include "noleax/ipc/protocol.hpp"

namespace {

using namespace std::chrono_literals;

constexpr std::wstring_view kIterations = L"2000000000";

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

[[nodiscard]] std::string read_text(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  return std::string{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

[[nodiscard]] std::uint32_t start_target(const std::filesystem::path& target,
                                         const std::filesystem::path& digest,
                                         const std::filesystem::path& marker) {
  std::error_code error;
  static_cast<void>(std::filesystem::remove(digest, error));
  error.clear();
  static_cast<void>(std::filesystem::remove(marker, error));
  std::wstring command = L"\"" + target.native() + L"\" \"" + digest.native() + L"\" " +
                         std::wstring{kIterations} + L" \"" + marker.native() + L"\"";
  std::vector<wchar_t> mutable_command{command.begin(), command.end()};
  mutable_command.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION information{};
  if (CreateProcessW(target.c_str(), mutable_command.data(), nullptr, nullptr, FALSE, 0U, nullptr,
                     nullptr, &startup, &information) == FALSE) {
    throw std::runtime_error{"cannot start the register workload target"};
  }
  static_cast<void>(CloseHandle(information.hThread));
  const DWORD pid = information.dwProcessId;
  static_cast<void>(CloseHandle(information.hProcess));
  return static_cast<std::uint32_t>(pid);
}

struct TargetRun {
  std::uint32_t pid{0U};
  std::filesystem::path digest;
  std::filesystem::path marker;
};

[[nodiscard]] TargetRun launch_workload(const std::filesystem::path& target,
                                        const std::filesystem::path& directory,
                                        std::string_view name) {
  TargetRun run;
  run.digest = directory / (std::string{name} + ".digest");
  run.marker = directory / (std::string{name} + ".started");
  run.pid = start_target(target, run.digest, run.marker);
  if (!wait_for_file(run.marker, 10s)) {
    throw std::runtime_error{"workload target did not signal its start"};
  }
  return run;
}

[[nodiscard]] std::string await_digest(const TargetRun& run) {
  const HANDLE process =
      OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, run.pid);
  if (process == nullptr) {
    throw std::runtime_error{"cannot reopen the workload target"};
  }
  const DWORD wait = WaitForSingleObject(process, 90'000U);
  DWORD exit_code = 0xFFFFFFFFU;
  static_cast<void>(GetExitCodeProcess(process, &exit_code));
  static_cast<void>(CloseHandle(process));
  if (wait != WAIT_OBJECT_0 || exit_code != 0U) {
    throw std::runtime_error{"workload target did not exit cleanly (exit " +
                             std::to_string(exit_code) + ")"};
  }
  return read_text(run.digest);
}

[[nodiscard]] noleax::controller::windows::CaptureOptions make_capture(
    const std::filesystem::path& agent, const std::filesystem::path& trace) {
  noleax::controller::windows::CaptureOptions capture;
  capture.agent_path = agent;
  capture.timeout = 15s;
  capture.method = noleax::controller::windows::InjectionMethod::kThreadHijack;
  capture.start.hook_profile = noleax::ipc::HookProfile::kWindowsNative;
  capture.start.maximum_stack_depth = 16U;
  capture.start.buffer_size = 8U * 1024U * 1024U;
  capture.start.maximum_trace_size = 64U * 1024U * 1024U;
  capture.start.flush_interval_ns = 5U * 1000U * 1000U;
  capture.start.trace_path_utf8 = noleax::controller::windows::wide_to_utf8(trace.native());
  return capture;
}

}  // namespace

int run(int argc, char* argv[]) {
  if (argc != 5) {
    return 2;
  }
  const std::filesystem::path agent = std::filesystem::absolute(argv[1]);
  const std::filesystem::path no_bootstrap = std::filesystem::absolute(argv[2]);
  const std::filesystem::path target = std::filesystem::absolute(argv[3]);
  const std::filesystem::path directory = std::filesystem::absolute(argv[4]);
  std::error_code directory_error;
  static_cast<void>(std::filesystem::create_directories(directory, directory_error));

  // 1. Baseline digest without any injection.
  const TargetRun baseline = launch_workload(target, directory, "hijack-baseline");
  const std::string baseline_digest = await_digest(baseline);
  if (baseline_digest.find("digest=") != 0U) {
    std::fprintf(stderr, "baseline digest missing: %s\n", baseline_digest.c_str());
    return 3;
  }

  // 2. Attach with thread hijack; the hijacked run must produce the same
  //    digest and a valid trace.
  const TargetRun hijacked = launch_workload(target, directory, "hijack-attach");
  const std::filesystem::path trace = directory / "hijack-attach.nlx";
  {
    const auto capture = make_capture(agent, trace);
    auto session = noleax::controller::windows::CaptureSession::attach(hijacked.pid, capture);
    std::this_thread::sleep_for(400ms);
    const auto live = session.query_status();
    const auto final = session.stop();
    if (live.state != noleax::ipc::AgentState::kCapturing ||
        final.state != noleax::ipc::AgentState::kFinalized || final.written_events == 0U) {
      std::fprintf(stderr, "hijack attach capture failed: live=%u final=%u written=%llu\n",
                   static_cast<unsigned int>(live.state), static_cast<unsigned int>(final.state),
                   static_cast<unsigned long long>(final.written_events));
      return 4;
    }
  }
  const std::string hijacked_digest = await_digest(hijacked);
  if (hijacked_digest != baseline_digest) {
    std::fprintf(stderr, "hijacked digest diverged: baseline=%s hijacked=%s\n",
                 baseline_digest.c_str(), hijacked_digest.c_str());
    return 5;
  }
  std::ifstream trace_input{trace, std::ios::binary};
  if (!trace_input) {
    return 6;
  }
  const auto analyzed = noleax::analyzer::analyze_event_stream(trace_input);
  if (analyzed.event_count == 0U || !analyzed.end_of_trace.has_value() ||
      analyzed.capture_scope.started_at_process_start ||
      !analyzed.capture_scope.preexisting_allocations_unknown) {
    std::fprintf(stderr, "hijack attach trace invalid: events=%llu scope=%u/%u\n",
                 static_cast<unsigned long long>(analyzed.event_count),
                 analyzed.capture_scope.started_at_process_start ? 1U : 0U,
                 analyzed.capture_scope.preexisting_allocations_unknown ? 1U : 0U);
    return 7;
  }

  // 3. Rollback: an agent image without the bootstrap export must be rejected
  //    before any thread is modified; the target finishes untouched.
  const TargetRun rejected = launch_workload(target, directory, "hijack-reject");
  bool rejected_with_export_error = false;
  try {
    const auto capture = make_capture(no_bootstrap, directory / "hijack-reject.nlx");
    [[maybe_unused]] auto session =
        noleax::controller::windows::CaptureSession::attach(rejected.pid, capture);
  } catch (const noleax::controller::windows::InjectionError& error) {
    rejected_with_export_error = std::string{error.what()}.find("GetProcAddress") !=
                                 std::string::npos;
  }
  if (!rejected_with_export_error) {
    std::fprintf(stderr, "no-bootstrap agent was not rejected with the export error\n");
    return 8;
  }
  if (await_digest(rejected) != baseline_digest) {
    std::fprintf(stderr, "no-bootstrap digest diverged\n");
    return 9;
  }

  // 4. Rollback: bootstrap with an unreachable pipe forces the stub ready-wait
  //    to time out; finish() must restore the hijacked thread and the target
  //    must still produce the baseline digest.
  const TargetRun timed_out = launch_workload(target, directory, "hijack-timeout");
  {
    const HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                           PROCESS_VM_OPERATION | PROCESS_VM_READ |
                                           PROCESS_VM_WRITE | SYNCHRONIZE,
                                       FALSE, timed_out.pid);
    if (process == nullptr) {
      return 10;
    }
    noleax::agent::windows::BootstrapParameters bootstrap{};
    const std::wstring bogus_pipe = L"\\\\.\\pipe\\noleax-hijack-ready-timeout-test";
    std::ranges::copy(bogus_pipe, bootstrap.pipe_name.begin());
    bootstrap.connect_timeout_ms = 500U;
    bootstrap.controller_process_id = GetCurrentProcessId();
    bool timeout_error = false;
    try {
      noleax::controller::windows::ThreadHijack hijack{process, timed_out.pid, agent, bootstrap,
                                                       {nullptr, true}};
      hijack.start();
      static_cast<void>(hijack.finish(60s));
    } catch (const noleax::controller::windows::InjectionError& error) {
      timeout_error = std::string{error.what()}.find("ready") != std::string::npos;
    }
    static_cast<void>(CloseHandle(process));
    if (!timeout_error) {
      std::fprintf(stderr, "ready-timeout hijack did not fail with the ready error\n");
      return 11;
    }
  }
  if (await_digest(timed_out) != baseline_digest) {
    std::fprintf(stderr, "ready-timeout digest diverged\n");
    return 12;
  }

  std::printf("status=ok baseline=1 attach=1 reject=1 timeout=1 digest=4 events=%llu\n",
              static_cast<unsigned long long>(analyzed.event_count));
  return 0;
}

int main(int argc, char* argv[]) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "thread hijack attach exception: %s\n", error.what());
    return 20;
  }
}
