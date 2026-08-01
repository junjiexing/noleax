#include "noleax/controller/windows/process.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "support/csv_table.hpp"
#include "support/json_dom.hpp"

namespace {

using namespace std::chrono_literals;

class Handle final {
 public:
  explicit Handle(HANDLE value = nullptr) noexcept : value_{value} {}
  ~Handle() {
    if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
      static_cast<void>(CloseHandle(value_));
    }
  }

  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : value_{std::exchange(other.value_, nullptr)} {}
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
        static_cast<void>(CloseHandle(value_));
      }
      value_ = std::exchange(other.value_, nullptr);
    }
    return *this;
  }
  [[nodiscard]] HANDLE get() const noexcept { return value_; }
  [[nodiscard]] bool valid() const noexcept {
    return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
  }

 private:
  HANDLE value_{nullptr};
};

struct ChildResult {
  std::uint32_t exit_code{0U};
  std::string log;
};

[[nodiscard]] bool analysis_completed(std::uint32_t exit_code) noexcept {
  return exit_code == 0U || exit_code == 2U;
}

[[nodiscard]] std::string read_file(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  if (!input) {
    throw std::runtime_error{"cannot read test output"};
  }
  std::ostringstream output;
  output << input.rdbuf();
  return output.str();
}

void write_file(const std::filesystem::path& path, std::string_view contents) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  if (!output) {
    throw std::runtime_error{"cannot create test input"};
  }
  output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  if (!output) {
    throw std::runtime_error{"cannot write test input"};
  }
}

void remove_file(const std::filesystem::path& path) {
  std::error_code error;
  static_cast<void>(std::filesystem::remove(path, error));
  if (error) {
    throw std::runtime_error{"cannot remove stale test output"};
  }
}

[[nodiscard]] std::wstring command_line(const std::filesystem::path& executable,
                                        const std::vector<std::string>& arguments) {
  std::wstring result = noleax::controller::windows::quote_windows_argument(executable.native());
  for (const auto& argument : arguments) {
    result.push_back(L' ');
    result.append(noleax::controller::windows::quote_windows_argument(
        noleax::controller::windows::utf8_to_wide(argument)));
  }
  return result;
}

[[nodiscard]] ChildResult run_child(const std::filesystem::path& executable,
                                    const std::vector<std::string>& arguments,
                                    const std::filesystem::path& log_path) {
  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;
  Handle log{CreateFileW(log_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr)};
  if (!log.valid()) {
    throw std::runtime_error{"cannot create child log"};
  }
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = log.get();
  startup.hStdError = log.get();

  std::wstring text = command_line(executable, arguments);
  std::vector<wchar_t> mutable_text{text.begin(), text.end()};
  mutable_text.push_back(L'\0');
  PROCESS_INFORMATION process{};
  if (CreateProcessW(executable.c_str(), mutable_text.data(), nullptr, nullptr, TRUE,
                     CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &startup,
                     &process) == FALSE) {
    throw std::runtime_error{"cannot start noleax child process"};
  }
  Handle process_handle{process.hProcess};
  Handle thread_handle{process.hThread};
  const DWORD wait = WaitForSingleObject(process_handle.get(), 60'000U);
  if (wait != WAIT_OBJECT_0) {
    static_cast<void>(TerminateProcess(process_handle.get(), 99U));
    throw std::runtime_error{"noleax child process timed out"};
  }
  DWORD exit_code = 0U;
  if (GetExitCodeProcess(process_handle.get(), &exit_code) == FALSE) {
    throw std::runtime_error{"cannot query noleax child exit code"};
  }
  log = Handle{};
  return {exit_code, read_file(log_path)};
}

[[nodiscard]] bool wait_for_marker(const std::filesystem::path& path, std::string_view content,
                                   std::chrono::milliseconds timeout) {
  const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout.count());
  do {
    std::error_code error;
    if (std::filesystem::is_regular_file(path, error) && !error) {
      try {
        if (read_file(path).find(content) != std::string::npos) {
          return true;
        }
      } catch (const std::runtime_error&) {
      }
    }
    Sleep(5U);
  } while (GetTickCount64() < deadline);
  return false;
}

[[nodiscard]] std::uint32_t marker_pid(const std::filesystem::path& path) {
  const std::string marker = read_file(path);
  const std::size_t begin = marker.find("pid=");
  if (begin == std::string::npos) {
    throw std::runtime_error{"target marker does not contain a PID"};
  }
  const std::size_t digits = begin + 4U;
  const std::size_t end = marker.find(' ', digits);
  const unsigned long value = std::stoul(marker.substr(digits, end - digits));
  if (value == 0UL || value > std::numeric_limits<std::uint32_t>::max()) {
    throw std::runtime_error{"target marker PID is invalid"};
  }
  return static_cast<std::uint32_t>(value);
}

void wait_for_pid(std::uint32_t process_id) {
  Handle process{OpenProcess(SYNCHRONIZE, FALSE, process_id)};
  if (process.valid() && WaitForSingleObject(process.get(), 10'000U) != WAIT_OBJECT_0) {
    throw std::runtime_error{"launched target did not exit"};
  }
}

[[nodiscard]] std::string utf8_path(const std::filesystem::path& path) {
  return noleax::controller::windows::wide_to_utf8(path.native());
}

[[nodiscard]] std::vector<std::string> outstanding_arguments(const std::filesystem::path& trace,
                                                             const std::filesystem::path& output,
                                                             std::string format) {
  return {"analyze",
          "--mode",
          "outstanding",
          "--format",
          std::move(format),
          "--output",
          utf8_path(output),
          "--a",
          "0ns",
          "--b",
          "900ms",
          "--min-size",
          "123457B",
          "--max-size",
          "123457B",
          "--api",
          "RtlAllocateHeap",
          "--stack-module",
          "noleax-cli-e2e-target.exe",
          utf8_path(trace)};
}

void verify_outstanding_json(const std::filesystem::path& path, bool attach) {
  const auto document = noleax::testing::parse_json(read_file(path));
  if (document.at("mode").scalar() != "outstanding" ||
      document.at("summary").at("outstanding").unsigned_value() != 1U ||
      document.at("metadata").at("capture").at("preexisting_allocations_unknown").boolean_value() !=
          attach) {
    throw std::runtime_error{"outstanding JSON result does not match the expected allocation"};
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  try {
    if (argc != 5) {
      std::cerr << "usage: cli_end_to_end_test NOLEAX AGENT TARGET OUTPUT_DIR\n";
      return 2;
    }
    const std::filesystem::path noleax = std::filesystem::absolute(argv[1]);
    const std::filesystem::path agent = std::filesystem::absolute(argv[2]);
    const std::filesystem::path target = std::filesystem::absolute(argv[3]);
    const std::filesystem::path output_directory = std::filesystem::absolute(argv[4]);
    static_cast<void>(std::filesystem::create_directories(output_directory));

    const auto run_trace = output_directory / "cli-run.nlx";
    const auto run_marker = output_directory / "cli-run.ready";
    const auto run_log = output_directory / "cli-run.log";
    const auto run_json = output_directory / "cli-run.json";
    const auto run_console = output_directory / "cli-run.txt";
    const auto run_csv = output_directory / "cli-run.csv";
    for (const auto& path : {run_trace, run_marker, run_log, run_json, run_console, run_csv}) {
      remove_file(path);
    }

    const ChildResult run =
        run_child(noleax,
                  {"run", "--agent", utf8_path(agent), "--trace", utf8_path(run_trace),
                   "--capture-duration", "1s", "--hook-profile", "windows-nt-heap", "--compression",
                   "none", "--", utf8_path(target), utf8_path(run_marker), "1800", "launch"},
                  run_log);
    if (run.exit_code != 0U || run.log.find("capture finalized:") == std::string::npos ||
        !wait_for_marker(run_marker, "ready=1", 2s)) {
      throw std::runtime_error{"noleax run did not complete a capture: " + run.log};
    }
    wait_for_pid(marker_pid(run_marker));

    const ChildResult outstanding =
        run_child(noleax, outstanding_arguments(run_trace, run_json, "json"), run_log);
    if (!analysis_completed(outstanding.exit_code)) {
      throw std::runtime_error{"run outstanding analysis failed: " + outstanding.log};
    }
    verify_outstanding_json(run_json, false);

    const ChildResult console = run_child(
        noleax,
        {"analyze", "--mode", "events", "--format", "console", "--output", utf8_path(run_console),
         "--event", "alloc", "--api", "RtlAllocateHeap", utf8_path(run_trace)},
        run_log);
    const std::string console_text = read_file(run_console);
    if (!analysis_completed(console.exit_code) ||
        console_text.find("ntdll.dll!RtlAllocateHeap") == std::string::npos ||
        console_text.find("noleax-cli-e2e-target.exe") == std::string::npos) {
      throw std::runtime_error{"console analysis omitted API or stack metadata"};
    }

    const ChildResult csv =
        run_child(noleax,
                  {"analyze", "--mode", "events", "--format", "csv", "--output", utf8_path(run_csv),
                   "--event", "alloc", "--api", "RtlAllocateHeap", utf8_path(run_trace)},
                  run_log);
    const auto csv_table = noleax::testing::parse_csv(read_file(run_csv));
    const bool csv_has_target =
        std::any_of(csv_table.rows.begin(), csv_table.rows.end(), [&csv_table](const auto& row) {
          const std::size_t type_column = csv_table.column("record_type");
          const std::size_t api_column = csv_table.column("api_name");
          const std::size_t stack_column = csv_table.column("stack_frames");
          return row.at(type_column) == "event" && row.at(api_column) == "RtlAllocateHeap" &&
                 row.at(stack_column).find("noleax-cli-e2e-target.exe") != std::string::npos;
        });
    if (!analysis_completed(csv.exit_code) || !csv_has_target) {
      throw std::runtime_error{"CSV analysis omitted API or stack metadata"};
    }

    const auto attach_trace = output_directory / "cli-attach.nlx";
    const auto attach_marker = output_directory / "cli-attach.ready";
    const auto attach_log = output_directory / "cli-attach.log";
    const auto attach_json = output_directory / "cli-attach.json";
    for (const auto& path : {attach_trace, attach_marker, attach_log, attach_json}) {
      remove_file(path);
    }
    auto target_process = noleax::controller::windows::SuspendedProcess::create(
        target, {utf8_path(attach_marker), "2200", "attach"}, target.parent_path());
    target_process.resume_main_thread();
    if (!wait_for_marker(attach_marker, "ready=0", 2s)) {
      target_process.terminate(20U);
      throw std::runtime_error{"attach target did not expose its pre-injection state"};
    }

    const ChildResult attach =
        run_child(noleax,
                  {"attach", "--pid", std::to_string(target_process.process_id()), "--agent",
                   utf8_path(agent), "--trace", utf8_path(attach_trace), "--capture-duration", "1s",
                   "--hook-profile", "windows-nt-heap", "--compression", "none"},
                  attach_log);
    if (attach.exit_code != 0U || attach.log.find("capture finalized:") == std::string::npos ||
        !wait_for_marker(attach_marker, "ready=1", 2s)) {
      target_process.terminate(21U);
      throw std::runtime_error{"noleax attach did not complete a capture: " + attach.log};
    }
    if (!target_process.wait(5s) || target_process.exit_code() != 0U) {
      target_process.terminate(22U);
      throw std::runtime_error{"attach target did not exit cleanly"};
    }

    const ChildResult attach_analysis =
        run_child(noleax, outstanding_arguments(attach_trace, attach_json, "json"), attach_log);
    if (attach_analysis.exit_code != 2U) {
      throw std::runtime_error{"attach analysis did not report its incomplete scope: " +
                               attach_analysis.log};
    }
    verify_outstanding_json(attach_json, true);

    const auto exit_trace = output_directory / "cli-exit.nlx";
    const auto exit_marker = output_directory / "cli-exit.ready";
    const auto exit_log = output_directory / "cli-exit.log";
    for (const auto& path : {exit_trace, exit_marker, exit_log}) {
      remove_file(path);
    }
    const ChildResult exit_run =
        run_child(noleax,
                  {"run", "--agent", utf8_path(agent), "--trace", utf8_path(exit_trace),
                   "--hook-profile", "windows-nt-heap", "--compression", "none", "--",
                   utf8_path(target), utf8_path(exit_marker), "300", "launch"},
                  exit_log);
    if (exit_run.exit_code != 2U || exit_run.log.find("target_exit_code=0") == std::string::npos ||
        exit_run.log.find("cannot finalize capture") != std::string::npos) {
      throw std::runtime_error{"noleax run did not handle a self-exiting target: " + exit_run.log};
    }

    const auto corrupt_trace = output_directory / "cli-corrupt.nlx";
    const auto error_log = output_directory / "cli-error.log";
    write_file(corrupt_trace, "not a Noleax trace");
    const ChildResult corrupt = run_child(noleax, {"analyze", utf8_path(corrupt_trace)}, error_log);
    if (corrupt.exit_code != 4U ||
        corrupt.log.find("cannot scan input trace") == std::string::npos) {
      throw std::runtime_error{"corrupt trace did not produce exit code 4"};
    }

    const ChildResult hijack_run = run_child(
        noleax,
        {"run", "--inject-method", "thread-hijack", "--agent", utf8_path(agent), "--trace",
         utf8_path(output_directory / "cli-hijack.nlx"), "--capture-duration", "1s",
         "--hook-profile", "windows-nt-heap", "--compression", "none", "--", utf8_path(target),
         utf8_path(output_directory / "cli-hijack.ready"), "1800", "launch"},
        run_log);
    if (hijack_run.exit_code != 0U ||
        hijack_run.log.find("capture finalized:") == std::string::npos ||
        !wait_for_marker(output_directory / "cli-hijack.ready", "ready=1", 2s)) {
      throw std::runtime_error{"noleax run with thread-hijack did not complete a capture: " +
                               hijack_run.log};
    }
    wait_for_pid(marker_pid(output_directory / "cli-hijack.ready"));

    const ChildResult entrypoint_run = run_child(
        noleax,
        {"run", "--inject-method", "entrypoint-code", "--agent", utf8_path(agent), "--trace",
         utf8_path(output_directory / "cli-entrypoint.nlx"), "--capture-duration", "1s",
         "--hook-profile", "windows-nt-heap", "--compression", "none", "--", utf8_path(target),
         utf8_path(output_directory / "cli-entrypoint.ready"), "1800", "launch"},
        run_log);
    if (entrypoint_run.exit_code != 0U ||
        entrypoint_run.log.find("capture finalized:") == std::string::npos ||
        !wait_for_marker(output_directory / "cli-entrypoint.ready", "ready=1", 2s)) {
      throw std::runtime_error{"noleax run with entrypoint-code did not complete a capture: " +
                               entrypoint_run.log};
    }
    wait_for_pid(marker_pid(output_directory / "cli-entrypoint.ready"));

    const auto patched_target = output_directory / "cli-patched.exe";
    const auto agent_copy = output_directory / "noleax-agent.dll";
    remove_file(patched_target);
    remove_file(agent_copy);
    std::filesystem::copy_file(agent, agent_copy);
    const ChildResult patch =
        run_child(noleax,
                  {"patch", "--input", utf8_path(target), "--output", utf8_path(patched_target),
                   "--agent-name", "noleax-agent.dll"},
                  run_log);
    if (patch.exit_code != 0U || patch.log.find("patched:") == std::string::npos ||
        !std::filesystem::is_regular_file(patched_target)) {
      throw std::runtime_error{"noleax patch did not produce the patched target: " + patch.log};
    }
    const ChildResult static_run =
        run_child(noleax,
                  {"run", "--inject-method", "static-pe-patch", "--agent", utf8_path(agent_copy),
                   "--trace", utf8_path(output_directory / "cli-static.nlx"), "--capture-duration",
                   "1s", "--hook-profile", "windows-nt-heap", "--compression", "none", "--",
                   utf8_path(patched_target), utf8_path(output_directory / "cli-static.ready"),
                   "1800", "launch"},
                  run_log);
    if (static_run.exit_code != 0U ||
        static_run.log.find("capture finalized:") == std::string::npos ||
        !wait_for_marker(output_directory / "cli-static.ready", "ready=1", 2s)) {
      throw std::runtime_error{"noleax run with static-pe-patch did not complete a capture: " +
                               static_run.log};
    }
    wait_for_pid(marker_pid(output_directory / "cli-static.ready"));

    const ChildResult unsupported_method =
        run_child(noleax,
                  {"attach", "--pid", "1234", "--inject-method", "entrypoint-code", "--agent",
                   utf8_path(agent), "--trace", utf8_path(output_directory / "unsupported.nlx"),
                   "--capture-duration", "1ms"},
                  error_log);
    if (unsupported_method.exit_code != 1U ||
        unsupported_method.log.find("attach supports remote-thread and thread-hijack") ==
            std::string::npos) {
      throw std::runtime_error{"unsupported attach injection method did not produce exit code 1"};
    }

    std::cout << "status=ok run=1 attach=1 hijack=1 entrypoint=1 patch=1 static=1 outstanding=1 "
                 "console=1 json=1 csv=1 stacks=1 errors=1\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "status=error message=" << error.what() << '\n';
    return 1;
  }
}
