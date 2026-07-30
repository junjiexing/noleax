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
#include <utility>

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
    Sleep(2U);
  } while (GetTickCount64() < deadline);
  return false;
}

[[nodiscard]] bool same_status(const noleax::ipc::CaptureStatus& left,
                               const noleax::ipc::CaptureStatus& right) noexcept {
  return left.state == right.state && left.observed_calls == right.observed_calls &&
         left.filtered_calls == right.filtered_calls &&
         left.dropped_events == right.dropped_events &&
         left.written_events == right.written_events && left.bytes_written == right.bytes_written;
}

class StopSignal final {
 public:
  explicit StopSignal(std::filesystem::path path) : path_{std::move(path)} {}
  ~StopSignal() { signal(); }

  StopSignal(const StopSignal&) = delete;
  StopSignal& operator=(const StopSignal&) = delete;

  void signal() noexcept {
    if (!signaled_) {
      std::ofstream output{path_};
      output << "stop\n";
      signaled_ = true;
    }
  }

 private:
  std::filesystem::path path_;
  bool signaled_{false};
};

}  // namespace

int run(int argc, char* argv[]) {
  if (argc != 5) {
    return 2;
  }
  const std::filesystem::path agent = std::filesystem::absolute(argv[1]);
  const std::filesystem::path target = std::filesystem::absolute(argv[2]);
  const std::filesystem::path trace = std::filesystem::absolute(argv[3]);
  const std::filesystem::path marker = std::filesystem::absolute(argv[4]);
  std::filesystem::path stop_path = marker;
  stop_path += L".stop";
  std::error_code remove_error;
  static_cast<void>(std::filesystem::remove(trace, remove_error));
  remove_error.clear();
  static_cast<void>(std::filesystem::remove(marker, remove_error));
  remove_error.clear();
  static_cast<void>(std::filesystem::remove(stop_path, remove_error));
  StopSignal stop_signal{stop_path};

  noleax::controller::windows::CaptureOptions capture;
  capture.agent_path = agent;
  capture.timeout = 10s;
  capture.start.hook_profile = noleax::ipc::HookProfile::kWindowsNtHeap;
  capture.start.maximum_stack_depth = 16U;
  capture.start.buffer_size = 64U * 1024U * 1024U;
  capture.start.maximum_trace_size = 128U * 1024U * 1024U;
  capture.start.flush_interval_ns = 5U * 1000U * 1000U;
  capture.start.trace_path_utf8 = noleax::controller::windows::wide_to_utf8(trace.native());

  noleax::controller::windows::LaunchOptions launch;
  launch.executable = target;
  launch.arguments = {noleax::controller::windows::wide_to_utf8(marker.native()), "10000",
                      noleax::controller::windows::wide_to_utf8(stop_path.native())};
  launch.working_directory = target.parent_path();
  auto session = noleax::controller::windows::CaptureSession::launch(launch, capture);
  if (!wait_for_file(marker, 2s)) {
    return 3;
  }

  noleax::ipc::CaptureStatus status;
  std::uint64_t previous_observed = 0U;
  bool monotonic = true;
  std::uint32_t status_queries = 0U;
  const ULONGLONG status_deadline = GetTickCount64() + 2'000U;
  const char* stage = "status";
  try {
    do {
      status = session.query_status();
      monotonic = monotonic && status.state == noleax::ipc::AgentState::kCapturing &&
                  status.observed_calls >= previous_observed;
      previous_observed = status.observed_calls;
      ++status_queries;
      if (status.observed_calls >= 10'000U && status_queries >= 2U) {
        break;
      }
      Sleep(2U);
    } while (GetTickCount64() < status_deadline);

    const bool target_active_during_stop = !session.wait_for_target(0ms);
    stage = "stop";
    const auto final = session.stop();
    stage = "repeated-stop";
    const auto repeated_final = session.stop();
    stop_signal.signal();
    bool status_rejected_after_stop = false;
    try {
      static_cast<void>(session.query_status());
    } catch (const noleax::controller::windows::ControllerError&) {
      status_rejected_after_stop = true;
    }
    const bool statistics_conserved =
        final.observed_calls == final.filtered_calls + final.dropped_events + final.written_events;
    if (!monotonic || status_queries < 2U || status.observed_calls < 10'000U ||
        !target_active_during_stop || final.state != noleax::ipc::AgentState::kFinalized ||
        !statistics_conserved || !same_status(final, repeated_final) ||
        !status_rejected_after_stop) {
      std::fprintf(stderr,
                   "lifecycle validation failed: monotonic=%u queries=%lu observed=%llu active=%u "
                   "state=%u dropped=%llu conserved=%u idempotent=%u rejected=%u written=%llu\n",
                   monotonic ? 1U : 0U, static_cast<unsigned long>(status_queries),
                   static_cast<unsigned long long>(status.observed_calls),
                   target_active_during_stop ? 1U : 0U, static_cast<unsigned int>(final.state),
                   static_cast<unsigned long long>(final.dropped_events),
                   statistics_conserved ? 1U : 0U, same_status(final, repeated_final) ? 1U : 0U,
                   status_rejected_after_stop ? 1U : 0U,
                   static_cast<unsigned long long>(final.written_events));
      return 4;
    }
    if (!session.wait_for_target(5s) || session.target_exit_code() != 0U) {
      return 5;
    }

  } catch (const std::exception& error) {
    const bool exited = session.wait_for_target(0ms);
    std::fprintf(stderr, "lifecycle stage=%s failed: %s target-exited=%u exit=%lu\n", stage,
                 error.what(), exited ? 1U : 0U,
                 static_cast<unsigned long>(session.target_exit_code()));
    throw;
  }

  std::ifstream input{trace, std::ios::binary};
  if (!input) {
    return 6;
  }
  const auto analyzed = noleax::analyzer::analyze_event_stream(input);
  if (analyzed.event_count == 0U || !analyzed.end_of_trace.has_value() ||
      !analyzed.end_of_trace->normal_stop) {
    return 7;
  }
  std::printf(
      "status=ok lifecycle=finalized queries=%lu active-stop=1 idempotent=1 conserved=1 "
      "events=%llu\n",
      static_cast<unsigned long>(status_queries),
      static_cast<unsigned long long>(analyzed.event_count));
  return 0;
}

int main(int argc, char* argv[]) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "controller lifecycle exception: %s\n", error.what());
    return 20;
  }
}
