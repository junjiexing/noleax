#include "noleax/controller/windows/controller.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: tlhelp32.h requires the Windows base types.
#include <windows.h>
#include <tlhelp32.h>
// clang-format on

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <string_view>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/controller/windows/process.hpp"
#include "noleax/ipc/protocol.hpp"

namespace {

using namespace std::chrono_literals;

[[nodiscard]] bool wait_for_marker(const std::filesystem::path& path, std::string_view content,
                                   std::chrono::milliseconds timeout) {
  const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout.count());
  do {
    std::ifstream input{path};
    std::string marker;
    if (input && std::getline(input, marker) && marker.find(content) != std::string::npos) {
      return true;
    }
    Sleep(5U);
  } while (GetTickCount64() < deadline);
  return false;
}

[[nodiscard]] bool module_present(std::uint32_t process_id, const wchar_t* module_name) {
  const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return true;  // fail-closed: cannot prove absence
  }
  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  bool found = false;
  for (BOOL scanning = Module32FirstW(snapshot, &entry); scanning != FALSE && !found;
       scanning = Module32NextW(snapshot, &entry)) {
    const wchar_t* base = wcsrchr(entry.szExePath, L'\\');
    const wchar_t* name = base != nullptr ? base + 1 : entry.szExePath;
    found = _wcsicmp(name, module_name) == 0;
  }
  static_cast<void>(CloseHandle(snapshot));
  return found;
}

[[nodiscard]] bool wait_for_module_absent(std::uint32_t process_id, const wchar_t* module_name,
                                          std::chrono::milliseconds timeout) {
  const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout.count());
  do {
    if (!module_present(process_id, module_name)) {
      return true;
    }
    Sleep(100U);
  } while (GetTickCount64() < deadline);
  return false;
}

[[nodiscard]] bool trace_is_complete(const std::filesystem::path& trace) {
  std::ifstream input{trace, std::ios::binary};
  if (!input) {
    return false;
  }
  const auto analyzed = noleax::analyzer::analyze_event_stream(input);
  return analyzed.event_count > 0U && analyzed.end_of_trace.has_value() &&
         analyzed.end_of_trace->normal_stop;
}

}  // namespace

int run(int argc, char* argv[]) {
  if (argc != 5) {
    return 2;
  }
  const std::filesystem::path agent = std::filesystem::absolute(argv[1]);
  const std::filesystem::path target = std::filesystem::absolute(argv[2]);
  const std::filesystem::path workdir = std::filesystem::absolute(argv[3]);
  const std::filesystem::path marker = std::filesystem::absolute(argv[4]);
  std::error_code path_error;
  std::filesystem::create_directories(workdir, path_error);

  // Scenario 1: live (pipe) attach with --unload-on-stop. After finalize the agent
  // must unmap itself while the target keeps running.
  const auto live_trace = workdir / "attach-unload-live.nlx";
  std::error_code remove_error;
  static_cast<void>(std::filesystem::remove(live_trace, remove_error));
  remove_error.clear();
  static_cast<void>(std::filesystem::remove(marker, remove_error));
  auto process = noleax::controller::windows::SuspendedProcess::create(
      target, {noleax::controller::windows::wide_to_utf8(marker.native()), "30000", "0"},
      target.parent_path());
  process.resume_main_thread();
  if (!wait_for_marker(marker, "ready=0", 2s)) {
    process.terminate(10U);
    return 3;
  }

  noleax::controller::windows::CaptureOptions capture;
  capture.agent_path = agent;
  capture.timeout = 10s;
  capture.start.hook_profile = noleax::ipc::HookProfile::kWindowsNative;
  capture.start.maximum_stack_depth = 16U;
  capture.start.buffer_size = 8U * 1024U * 1024U;
  capture.start.maximum_trace_size = 64U * 1024U * 1024U;
  capture.start.flush_interval_ns = 5U * 1000U * 1000U;
  capture.start.trace_path_utf8 = noleax::controller::windows::wide_to_utf8(live_trace.native());
  capture.start.unload_on_stop = true;

  auto session = noleax::controller::windows::CaptureSession::attach(process.process_id(), capture);
  Sleep(100U);
  const auto final = session.stop();
  if (final.state != noleax::ipc::AgentState::kFinalized || final.observed_calls == 0U) {
    process.terminate(11U);
    return 4;
  }
  if (!wait_for_module_absent(process.process_id(), L"noleax-agent.dll", 10s)) {
    process.terminate(12U);
    return 5;
  }
  if (!trace_is_complete(live_trace)) {
    process.terminate(13U);
    return 6;
  }
  // The target is still running with the agent unmapped; it must exit cleanly on its own.
  process.terminate(0U);

  // Scenario 2: direct-write attach (standalone agent) with a duration and
  // injection.unload_on_stop in the agent configuration.
  const auto direct_trace = workdir / "attach-unload-direct.nlx";
  const auto agent_config = workdir / "attach-unload-agent.toml";
  static_cast<void>(std::filesystem::remove(direct_trace, remove_error));
  remove_error.clear();
  static_cast<void>(std::filesystem::remove(marker, remove_error));
  static_cast<void>(std::filesystem::remove(agent_config, remove_error));
  {
    std::ofstream config{agent_config};
    config << "schema_version = 1\n"
              "\n"
              "[injection]\n"
              "unload_on_stop = true\n"
              "\n"
              "[capture]\n"
              "hook_profile = \"windows-native\"\n"
              "max_stack_depth = 16\n"
              "duration = \"2s\"\n"
              "\n"
              "[trace]\n"
              "path = \""
           << noleax::controller::windows::wide_to_utf8(direct_trace.generic_wstring())
           << "\"\n"
              "buffer_size = \"8MiB\"\n"
              "max_file_size = \"64MiB\"\n"
              "flush_interval = \"5ms\"\n";
  }
  auto direct_process = noleax::controller::windows::SuspendedProcess::create(
      target, {noleax::controller::windows::wide_to_utf8(marker.native()), "30000", "0"},
      target.parent_path());
  direct_process.resume_main_thread();
  if (!wait_for_marker(marker, "ready=0", 2s)) {
    direct_process.terminate(15U);
    return 8;
  }
  auto attached = noleax::controller::windows::attach_agent_capture(direct_process.process_id(),
                                                                    capture, agent_config);
  if (!wait_for_module_absent(direct_process.process_id(), L"noleax-agent.dll", 20s)) {
    direct_process.terminate(16U);
    return 9;
  }
  if (!trace_is_complete(direct_trace)) {
    direct_process.terminate(17U);
    return 10;
  }
  direct_process.terminate(0U);

  std::printf("status=ok live=1 direct=1\n");
  return 0;
}

int main(int argc, char* argv[]) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "controller attach unload exception: %s\n", error.what());
    return 20;
  }
}
