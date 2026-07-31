#include "noleax/controller/windows/controller.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <string>

#include "noleax/analyzer/event_stream.hpp"
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

}  // namespace

int run(int argc, char* argv[]) {
  if (argc != 5) {
    return 2;
  }
  const std::filesystem::path agent = std::filesystem::absolute(argv[1]);
  const std::filesystem::path target = std::filesystem::absolute(argv[2]);
  const std::filesystem::path trace = std::filesystem::absolute(argv[3]);
  const std::filesystem::path marker = std::filesystem::absolute(argv[4]);
  std::error_code remove_error;
  static_cast<void>(std::filesystem::remove(trace, remove_error));
  remove_error.clear();
  static_cast<void>(std::filesystem::remove(marker, remove_error));

  noleax::controller::windows::CaptureOptions capture;
  capture.agent_path = agent;
  capture.timeout = 10s;
  capture.method = noleax::controller::windows::InjectionMethod::kThreadHijack;
  capture.start.hook_profile = noleax::ipc::HookProfile::kWindowsNative;
  capture.start.maximum_stack_depth = 16U;
  capture.start.buffer_size = 8U * 1024U * 1024U;
  capture.start.maximum_trace_size = 64U * 1024U * 1024U;
  capture.start.flush_interval_ns = 5U * 1000U * 1000U;
  capture.start.trace_path_utf8 = noleax::controller::windows::wide_to_utf8(trace.native());

  noleax::controller::windows::LaunchOptions launch;
  launch.executable = target;
  launch.arguments = {noleax::controller::windows::wide_to_utf8(marker.native()), "1500"};
  launch.working_directory = target.parent_path();
  auto session = noleax::controller::windows::CaptureSession::launch(launch, capture);
  const bool marker_created = wait_for_file(marker, 4s);
  if (!session.launched_target() || session.stopped() || !marker_created) {
    std::fprintf(stderr, "hijack launch precondition failed: launched=%u stopped=%u marker=%u\n",
                 session.launched_target() ? 1U : 0U, session.stopped() ? 1U : 0U,
                 marker_created ? 1U : 0U);
    return 3;
  }
  std::ifstream marker_input{marker};
  std::string marker_text;
  std::getline(marker_input, marker_text);
  const bool ready_before_main = marker_text.find("ready=1") != std::string::npos;
  Sleep(100U);
  const auto live = session.query_status();
  const auto final = session.stop();
  if (!ready_before_main || live.state != noleax::ipc::AgentState::kCapturing ||
      final.state != noleax::ipc::AgentState::kFinalized || final.observed_calls == 0U ||
      final.written_events == 0U || final.dropped_events != 0U) {
    std::fprintf(stderr,
                 "hijack launch capture failed: ready=%u live=%u final=%u observed=%llu "
                 "written=%llu dropped=%llu\n",
                 ready_before_main ? 1U : 0U, static_cast<unsigned int>(live.state),
                 static_cast<unsigned int>(final.state),
                 static_cast<unsigned long long>(final.observed_calls),
                 static_cast<unsigned long long>(final.written_events),
                 static_cast<unsigned long long>(final.dropped_events));
    return 4;
  }
  if (!session.wait_for_target(8s) || session.target_exit_code() != 0U) {
    return 5;
  }

  std::ifstream input{trace, std::ios::binary};
  if (!input) {
    return 6;
  }
  const auto analyzed = noleax::analyzer::analyze_event_stream(input);
  if (!analyzed.capture_scope.started_at_process_start ||
      analyzed.capture_scope.preexisting_allocations_unknown || analyzed.event_count == 0U ||
      !analyzed.end_of_trace.has_value() || !analyzed.end_of_trace->normal_stop) {
    return 7;
  }
  std::printf("status=ok kind=launch-hijack ready-before-main=1 state=finalized events=%llu\n",
              static_cast<unsigned long long>(analyzed.event_count));
  return 0;
}

int main(int argc, char* argv[]) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "thread hijack launch exception: %s\n", error.what());
    return 20;
  }
}
