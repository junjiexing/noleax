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

void remove_file(const std::filesystem::path& path) {
  std::error_code error;
  static_cast<void>(std::filesystem::remove(path, error));
}

void write_config(const std::filesystem::path& path, const std::string& trace_name) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  output
      << "schema_version = 1\n\n[capture]\nhook_profile = \"windows-nt-heap\"\n\n[trace]\npath = \""
      << trace_name << "\"\ncompression = \"none\"\n";
  if (!output) {
    throw std::runtime_error{"cannot write the standalone config"};
  }
}

[[nodiscard]] std::uint32_t run_target(const std::filesystem::path& executable,
                                       const std::filesystem::path& marker,
                                       std::uint32_t duration_ms, const wchar_t* expected_ready) {
  std::wstring command = L"\"" + executable.native() + L"\" \"" + marker.native() + L"\" " +
                         std::to_wstring(duration_ms) + L" " + expected_ready;
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

[[nodiscard]] bool trace_is_complete(const std::filesystem::path& trace,
                                     std::uint64_t minimum_events) {
  std::ifstream input{trace, std::ios::binary};
  if (!input) {
    return false;
  }
  const auto analyzed = noleax::analyzer::analyze_event_stream(input);
  return analyzed.capture_scope.started_at_process_start &&
         analyzed.event_count >= minimum_events && analyzed.end_of_trace.has_value() &&
         analyzed.end_of_trace->normal_stop &&
         analyzed.completeness.overall_state() == noleax::trace::CompletenessState::kComplete;
}

class EnvironmentVariable final {
 public:
  EnvironmentVariable(const wchar_t* name, const wchar_t* value) : name_{name} {
    if (value == nullptr) {
      static_cast<void>(SetEnvironmentVariableW(name, nullptr));
    } else {
      if (SetEnvironmentVariableW(name, value) == FALSE) {
        throw std::runtime_error{"cannot set the environment override"};
      }
    }
  }
  ~EnvironmentVariable() { static_cast<void>(SetEnvironmentVariableW(name_, nullptr)); }

  EnvironmentVariable(const EnvironmentVariable&) = delete;
  EnvironmentVariable& operator=(const EnvironmentVariable&) = delete;

 private:
  const wchar_t* name_;
};

}  // namespace

// Standalone capture: `patch --standalone` bakes activation into the image, the agent then
// records without a controller by reading noleax-agent.toml (or NOLEAX_AGENT_CONFIG).
int main(int argc, char* argv[]) {
  if (argc != 5) {
    return 2;
  }
  try {
    const std::filesystem::path agent = std::filesystem::absolute(argv[1]);
    const std::filesystem::path target = std::filesystem::absolute(argv[2]);
    const std::filesystem::path directory = std::filesystem::absolute(argv[3]);
    const std::filesystem::path pipe_trace = std::filesystem::absolute(argv[4]);
    std::error_code directory_error;
    static_cast<void>(std::filesystem::create_directories(directory, directory_error));

    const std::filesystem::path input = directory / "standalone-target.exe";
    const std::filesystem::path patched = directory / "standalone-patched.exe";
    const std::filesystem::path agent_copy = directory / "noleax-agent.dll";
    std::error_code copy_error;
    remove_file(input);
    remove_file(patched);
    remove_file(agent_copy);
    if (!std::filesystem::copy_file(target, input, copy_error) ||
        !std::filesystem::copy_file(agent, agent_copy, copy_error)) {
      std::fprintf(stderr, "cannot stage the target or agent\n");
      return 3;
    }

    noleax::controller::windows::PePatchOptions patch;
    patch.input = input;
    patch.output = patched;
    patch.standalone = true;
    static_cast<void>(noleax::controller::windows::patch_pe_image(patch));

    // Sibling configuration: direct run records a complete trace without a controller.
    const auto config_path = directory / "noleax-agent.toml";
    const auto sibling_trace = directory / "standalone.nlx";
    const auto plain_marker = directory / "standalone.ready";
    write_config(config_path, "standalone.nlx");
    remove_file(sibling_trace);
    remove_file(plain_marker);
    const std::uint32_t recorded_exit = run_target(patched, plain_marker, 1200U, L"1");
    if (recorded_exit != 0U || !trace_is_complete(sibling_trace, 1U)) {
      std::fprintf(stderr, "standalone capture did not produce a complete trace (exit=%lu)\n",
                   static_cast<unsigned long>(recorded_exit));
      return 4;
    }
    std::ifstream marker_input{plain_marker};
    std::string marker_text;
    std::getline(marker_input, marker_text);
    if (marker_text.find("ready=1") == std::string::npos) {
      std::fprintf(stderr, "standalone capture was not ready before main\n");
      return 5;
    }

    // NOLEAX_AGENT_CONFIG takes precedence over the sibling file.
    const auto env_trace = directory / "env-override.nlx";
    remove_file(env_trace);
    {
      const auto env_config = directory / "env-config.toml";
      write_config(env_config, "env-override.nlx");
      EnvironmentVariable override{L"NOLEAX_AGENT_CONFIG", env_config.c_str()};
      const std::uint32_t env_exit = run_target(patched, directory / "env.ready", 800U, L"1");
      if (env_exit != 0U || !trace_is_complete(env_trace, 1U)) {
        std::fprintf(stderr, "NOLEAX_AGENT_CONFIG did not take precedence (exit=%lu)\n",
                     static_cast<unsigned long>(env_exit));
        return 6;
      }
    }

    // Without any configuration the target still runs but nothing is recorded.
    remove_file(config_path);
    const auto default_trace = directory / "standalone-patched.nlx";
    remove_file(default_trace);
    const std::uint32_t plain_exit = run_target(patched, directory / "plain.ready", 500U, L"1");
    std::error_code exists_error;
    if (plain_exit != 0U ||
        (std::filesystem::exists(default_trace, exists_error) && !exists_error)) {
      std::fprintf(stderr, "missing configuration did not disable standalone capture\n");
      return 7;
    }

    // The controller still overrides the baked parameters in pipe mode.
    remove_file(pipe_trace);
    const auto pipe_marker = directory / "pipe.ready";
    remove_file(pipe_marker);
    noleax::controller::windows::CaptureOptions capture;
    capture.agent_path = agent_copy;
    capture.timeout = 15s;
    capture.method = noleax::controller::windows::InjectionMethod::kStaticPePatch;
    capture.start.hook_profile = noleax::ipc::HookProfile::kWindowsNtHeap;
    capture.start.maximum_stack_depth = 16U;
    capture.start.buffer_size = 8U * 1024U * 1024U;
    capture.start.maximum_trace_size = 64U * 1024U * 1024U;
    capture.start.flush_interval_ns = 5U * 1000U * 1000U;
    capture.start.trace_path_utf8 = noleax::controller::windows::wide_to_utf8(pipe_trace.native());
    noleax::controller::windows::LaunchOptions launch;
    launch.executable = patched;
    launch.arguments = {noleax::controller::windows::wide_to_utf8(pipe_marker.native()), "1500"};
    launch.working_directory = directory;
    auto session = noleax::controller::windows::CaptureSession::launch(launch, capture);
    if (!wait_for_file(pipe_marker, 4s)) {
      std::fprintf(stderr, "pipe mode on a standalone image did not become ready\n");
      return 8;
    }
    const auto final = session.stop();
    if (final.state != noleax::ipc::AgentState::kFinalized || !trace_is_complete(pipe_trace, 1U)) {
      std::fprintf(stderr, "pipe mode on a standalone image did not finalize\n");
      return 9;
    }

    std::printf("status=ok standalone=1 sibling=1 env=1 disabled=1 pipe=1\n");
    return 0;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "standalone capture test failed: %s\n", error.what());
    return 1;
  }
}
