#include "noleax/controller/windows/pe_patch.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <vector>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/controller/windows/controller.hpp"
#include "noleax/controller/windows/process.hpp"
#include "noleax/ipc/protocol.hpp"

namespace {

using namespace std::chrono_literals;

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

[[nodiscard]] std::uint32_t run_plain(const std::filesystem::path& executable,
                                      const std::filesystem::path& marker,
                                      std::uint32_t duration_ms) {
  std::wstring command = L"\"" + executable.native() + L"\" \"" + marker.native() + L"\" " +
                         std::to_wstring(duration_ms) + L" 0";
  std::vector<wchar_t> mutable_command{command.begin(), command.end()};
  mutable_command.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION information{};
  if (CreateProcessW(executable.c_str(), mutable_command.data(), nullptr, nullptr, FALSE, 0U,
                     nullptr, nullptr, &startup, &information) == FALSE) {
    throw std::runtime_error{"cannot start the patched target"};
  }
  static_cast<void>(CloseHandle(information.hThread));
  const DWORD wait = WaitForSingleObject(information.hProcess, 30'000U);
  DWORD exit_code = 0xFFFFFFFFU;
  static_cast<void>(GetExitCodeProcess(information.hProcess, &exit_code));
  static_cast<void>(CloseHandle(information.hProcess));
  if (wait != WAIT_OBJECT_0) {
    throw std::runtime_error{"the patched target did not exit in time"};
  }
  return static_cast<std::uint32_t>(exit_code);
}

}  // namespace

// P7C end-to-end: patch a copy of the controller target, verify it, run it
// standalone (bootstrap disabled), then capture it through
// --inject-method static-pe-patch.
int run(int argc, char* argv[]) {
  if (argc != 5) {
    return 2;
  }
  const std::filesystem::path agent = std::filesystem::absolute(argv[1]);
  const std::filesystem::path target = std::filesystem::absolute(argv[2]);
  const std::filesystem::path directory = std::filesystem::absolute(argv[3]);
  const std::filesystem::path trace = std::filesystem::absolute(argv[4]);
  std::error_code directory_error;
  static_cast<void>(std::filesystem::create_directories(directory, directory_error));

  const std::filesystem::path input = directory / "pe-target.exe";
  const std::filesystem::path patched = directory / "pe-target-patched.exe";
  std::error_code copy_error;
  static_cast<void>(std::filesystem::remove(input, copy_error));
  static_cast<void>(std::filesystem::remove(patched, copy_error));
  if (!std::filesystem::copy_file(target, input, copy_error)) {
    std::fprintf(stderr, "cannot copy the target: %s\n", copy_error.message().c_str());
    return 3;
  }
  // The patched image loads the agent by bare file name through the standard
  // DLL search order, so the agent must sit next to it.
  const std::filesystem::path agent_copy = directory / "noleax-agent.dll";
  static_cast<void>(std::filesystem::remove(agent_copy, copy_error));
  if (!std::filesystem::copy_file(agent, agent_copy, copy_error)) {
    std::fprintf(stderr, "cannot copy the agent: %s\n", copy_error.message().c_str());
    return 4;
  }

  noleax::controller::windows::PePatchOptions options;
  options.input = input;
  options.output = patched;
  const auto result = noleax::controller::windows::patch_pe_image(options);
  const auto info = noleax::controller::windows::read_static_patch_info(patched);
  if (!info.has_value() || info->entry_rva != result.entry_rva) {
    std::fprintf(stderr, "patched image failed the info check\n");
    return 5;
  }

  // Standalone run: the zeroed parameters keep the capture disabled, the stub
  // must jump to the original entrypoint and the target exits 0 (expects
  // ready=0 and observes it).
  const std::filesystem::path plain_marker = directory / "pe-plain.ready";
  std::error_code remove_error;
  static_cast<void>(std::filesystem::remove(plain_marker, remove_error));
  const std::uint32_t plain_exit = run_plain(patched, plain_marker, 1000U);
  if (plain_exit != 0U) {
    std::fprintf(stderr, "patched image did not run standalone (exit=%lu)\n",
                 static_cast<unsigned long>(plain_exit));
    return 6;
  }

  // Captured run through the controller.
  const std::filesystem::path marker = directory / "pe-capture.ready";
  static_cast<void>(std::filesystem::remove(marker, remove_error));
  static_cast<void>(std::filesystem::remove(trace, remove_error));
  noleax::controller::windows::CaptureOptions capture;
  capture.agent_path = agent_copy;
  capture.timeout = 15s;
  capture.method = noleax::controller::windows::InjectionMethod::kStaticPePatch;
  capture.start.hook_profile = noleax::ipc::HookProfile::kWindowsNative;
  capture.start.maximum_stack_depth = 16U;
  capture.start.buffer_size = 8U * 1024U * 1024U;
  capture.start.maximum_trace_size = 64U * 1024U * 1024U;
  capture.start.flush_interval_ns = 5U * 1000U * 1000U;
  capture.start.trace_path_utf8 = noleax::controller::windows::wide_to_utf8(trace.native());

  noleax::controller::windows::LaunchOptions launch;
  launch.executable = patched;
  launch.arguments = {noleax::controller::windows::wide_to_utf8(marker.native()), "1500"};
  launch.working_directory = directory;
  auto session = noleax::controller::windows::CaptureSession::launch(launch, capture);
  const bool marker_created = wait_for_file(marker, 4s);
  if (!session.launched_target() || session.stopped() || !marker_created) {
    std::fprintf(stderr, "static patch launch precondition failed: launched=%u marker=%u\n",
                 session.launched_target() ? 1U : 0U, marker_created ? 1U : 0U);
    return 7;
  }
  std::ifstream marker_input{marker};
  std::string marker_text;
  std::getline(marker_input, marker_text);
  const bool ready_before_main = marker_text.find("ready=1") != std::string::npos;
  Sleep(100U);
  const auto live = session.query_status();
  const auto final = session.stop();
  if (!ready_before_main || live.state != noleax::ipc::AgentState::kCapturing ||
      final.state != noleax::ipc::AgentState::kFinalized || final.written_events == 0U) {
    std::fprintf(stderr, "static patch capture failed: ready=%u live=%u final=%u written=%llu\n",
                 ready_before_main ? 1U : 0U, static_cast<unsigned int>(live.state),
                 static_cast<unsigned int>(final.state),
                 static_cast<unsigned long long>(final.written_events));
    return 8;
  }
  if (!session.wait_for_target(8s) || session.target_exit_code() != 0U) {
    return 9;
  }
  std::ifstream input_stream{trace, std::ios::binary};
  if (!input_stream) {
    return 10;
  }
  const auto analyzed = noleax::analyzer::analyze_event_stream(input_stream);
  if (!analyzed.capture_scope.started_at_process_start || analyzed.event_count == 0U ||
      !analyzed.end_of_trace.has_value() || !analyzed.end_of_trace->normal_stop) {
    return 11;
  }

  // An unpatched image must be rejected before any process is created.
  bool rejected = false;
  try {
    noleax::controller::windows::LaunchOptions plain_launch = launch;
    plain_launch.executable = input;
    [[maybe_unused]] auto plain_session =
        noleax::controller::windows::CaptureSession::launch(plain_launch, capture);
  } catch (const std::exception& error) {
    rejected =
        std::string{error.what()}.find("not a noleax-patched executable") != std::string::npos;
  }
  if (!rejected) {
    std::fprintf(stderr, "unpatched target was not rejected\n");
    return 12;
  }

  std::printf("status=ok patched=1 standalone=1 capture=1 rejected=1 events=%llu\n",
              static_cast<unsigned long long>(analyzed.event_count));
  return 0;
}

int main(int argc, char* argv[]) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "pe patch e2e exception: %s\n", error.what());
    return 20;
  }
}
