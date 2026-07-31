#include "noleax/controller/windows/entrypoint_injector.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <string>

#include "noleax/agent/windows/bootstrap.hpp"
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

[[nodiscard]] noleax::controller::windows::CaptureOptions make_capture(
    const std::filesystem::path& agent, const std::filesystem::path& trace) {
  noleax::controller::windows::CaptureOptions capture;
  capture.agent_path = agent;
  capture.timeout = 10s;
  capture.method = noleax::controller::windows::InjectionMethod::kEntrypointCode;
  capture.start.hook_profile = noleax::ipc::HookProfile::kWindowsNative;
  capture.start.maximum_stack_depth = 16U;
  capture.start.buffer_size = 8U * 1024U * 1024U;
  capture.start.maximum_trace_size = 64U * 1024U * 1024U;
  capture.start.flush_interval_ns = 5U * 1000U * 1000U;
  capture.start.trace_path_utf8 = noleax::controller::windows::wide_to_utf8(trace.native());
  return capture;
}

}  // namespace

// Rollback coverage for entrypoint-code injection:
//  1. an agent image without the bootstrap export is rejected before the
//     target is resumed, and the terminated target never ran;
//  2. a bootstrap with an unreachable pipe forces the stub ready-wait to time
//     out; the stub still restores the original entry bytes and the target
//     keeps running uninstrumented.
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

  // 1. Local export validation must happen before any target memory change.
  const std::filesystem::path reject_marker = directory / "entrypoint-reject.ready";
  std::error_code remove_error;
  static_cast<void>(std::filesystem::remove(reject_marker, remove_error));
  bool rejected = false;
  try {
    noleax::controller::windows::LaunchOptions launch;
    launch.executable = target;
    launch.arguments = {noleax::controller::windows::wide_to_utf8(reject_marker.native()), "500"};
    launch.working_directory = target.parent_path();
    [[maybe_unused]] auto session = noleax::controller::windows::CaptureSession::launch(
        launch, make_capture(no_bootstrap, directory / "entrypoint-reject.nlx"));
  } catch (const std::exception& error) {
    rejected = std::string{error.what()}.find("GetProcAddress") != std::string::npos;
  }
  if (!rejected || wait_for_file(reject_marker, 1s)) {
    std::fprintf(stderr, "no-bootstrap rollback failed: rejected=%u marker-created=%u\n",
                 rejected ? 1U : 0U, wait_for_file(reject_marker, 0s) ? 1U : 0U);
    return 3;
  }

  // 2. Bootstrap with a bogus pipe: the stub loads the agent, the ready-wait
  //    times out, the stub restores the original entry bytes and jumps to the
  //    original entrypoint. The target (argc==3 expects ready=1, observes
  //    ready=0) must exit with code 5, proving it ran uninstrumented.
  const std::filesystem::path timeout_marker = directory / "entrypoint-timeout.ready";
  remove_error.clear();
  static_cast<void>(std::filesystem::remove(timeout_marker, remove_error));
  noleax::controller::windows::SuspendedProcess process =
      noleax::controller::windows::SuspendedProcess::create(
          target, {noleax::controller::windows::wide_to_utf8(timeout_marker.native()), "3000"},
          target.parent_path());
  bool ready_timeout = false;
  {
    noleax::agent::windows::BootstrapParameters bootstrap{};
    const std::wstring bogus_pipe = L"\\\\.\\pipe\\noleax-entrypoint-ready-timeout-test";
    std::ranges::copy(bogus_pipe, bootstrap.pipe_name.begin());
    bootstrap.connect_timeout_ms = 500U;
    noleax::controller::windows::EntrypointInjection injection{
        process.process_handle(), process.process_id(), target.filename().native(), agent,
        bootstrap};
    process.resume_main_thread();
    try {
      static_cast<void>(injection.finish(60s));
    } catch (const noleax::controller::windows::InjectionError& error) {
      ready_timeout = std::string{error.what()}.find("ready") != std::string::npos;
    }
    process.note_main_thread_resumed();
  }
  if (!ready_timeout) {
    std::fprintf(stderr, "entrypoint stub did not report the ready timeout\n");
    process.terminate(20U);
    return 4;
  }
  if (!process.wait(15s) || process.exit_code() != 5U) {
    std::fprintf(stderr, "target did not continue with its restored entrypoint (exit=%lu)\n",
                 static_cast<unsigned long>(process.exit_code()));
    process.terminate(21U);
    return 5;
  }
  if (!wait_for_file(timeout_marker, 1s)) {
    std::fprintf(stderr, "target marker was not written after entrypoint restore\n");
    return 6;
  }

  std::printf("status=ok reject=1 ready-timeout=1 entry-restored=1\n");
  return 0;
}

int main(int argc, char* argv[]) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "entrypoint rollback exception: %s\n", error.what());
    return 20;
  }
}
