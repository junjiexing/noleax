// Standalone-mode hook-profile routing test (Linux): LD_PRELOAD + NOLEAX_AGENT_CONFIG
// launches the deterministic workload with each linux-* profile, then reads the
// resulting trace and asserts on the actual recorded event types — never on the TOML
// parse result alone. A Windows profile must be rejected before any hook installs,
// without disturbing the target.

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <system_error>
#include <thread>

#include "noleax/agent/linux/hook_registry.hpp"
#include "noleax/analyzer/event_stream.hpp"

namespace {

using namespace std::chrono_literals;

[[nodiscard]] std::filesystem::path unique_path(const std::string& name) {
  const auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  return std::filesystem::temp_directory_path() / ("noleax-standalone-" + name + "-" + stamp);
}

void write_config(const std::filesystem::path& path, const std::string& profile,
                  const std::filesystem::path& trace) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  output << "schema_version = 1\n\n[capture]\nhook_profile = \"" << profile
         << "\"\n\n[trace]\npath = \"" << trace.string() << "\"\ncompression = \"none\"\n";
  if (!output) {
    FAIL("cannot write the standalone config");
  }
}

struct StandaloneRun {
  int exit_code{-1};
  std::string agent_stderr;
};

// Runs the workload with the agent preloaded in standalone mode; the workload exits 42
// and the exit hook finalizes the trace before the process dies.
[[nodiscard]] StandaloneRun run_standalone(const std::filesystem::path& config,
                                           const std::filesystem::path& stderr_capture) {
  const pid_t pid = ::fork();
  if (pid == 0) {
    const int fd = ::open(stderr_capture.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      static_cast<void>(::dup2(fd, STDERR_FILENO));
      ::close(fd);
    }
    ::setenv("LD_PRELOAD", NOLEAX_AGENT_PATH, 1);
    ::setenv("NOLEAX_AGENT_CONFIG", config.c_str(), 1);
    ::execl(NOLEAX_WORKLOAD_PATH, "noleax-linux-workload-target", static_cast<char*>(nullptr));
    _exit(127);
  }
  int status = 0;
  if (::waitpid(pid, &status, 0) < 0) {
    FAIL("waitpid failed for the standalone target");
  }
  StandaloneRun run;
  if (WIFEXITED(status)) {
    run.exit_code = WEXITSTATUS(status);
  }
  std::ifstream stderr_stream{stderr_capture};
  run.agent_stderr.assign(std::istreambuf_iterator<char>{stderr_stream},
                          std::istreambuf_iterator<char>{});
  return run;
}

struct ObservedApis {
  bool heap{false};
  bool virtual_memory{false};
};

[[nodiscard]] ObservedApis observe_trace(const std::filesystem::path& trace,
                                         noleax::analyzer::EventStreamResult& result) {
  std::ifstream input{trace, std::ios::binary};
  if (!input) {
    FAIL("cannot open the standalone trace");
  }
  ObservedApis observed;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_event = [&observed](const noleax::trace::Event& event) {
    const auto* const api = noleax::agent::linux::find_linux_hook(event.header.api_id);
    if (api == nullptr) {
      return;
    }
    switch (api->group) {
      case noleax::agent::linux::LinuxHookApiGroup::kGlibcHeap:
        observed.heap = true;
        break;
      case noleax::agent::linux::LinuxHookApiGroup::kVirtualMemory:
        observed.virtual_memory = true;
        break;
      default:
        break;
    }
  };
  result = noleax::analyzer::analyze_event_stream(input, callbacks);
  return observed;
}

void check_clean_finalize(const noleax::analyzer::EventStreamResult& result) {
  CHECK(result.end_of_trace.has_value());
  CHECK(result.custom_hook_failures.empty());
  CHECK(result.event_count > 0U);
  REQUIRE(result.statistics.has_value());
  CHECK(result.statistics->dropped_events == 0U);
  CHECK_FALSE(result.completeness.has(noleax::trace::CompletenessIssue::kEventLoss));
  CHECK_FALSE(result.completeness.has(noleax::trace::CompletenessIssue::kCustomHookInstallFailed));
}

void run_profile_case(const std::string& profile, bool expect_heap, bool expect_vm) {
  const auto config = unique_path("config.toml");
  const auto trace = unique_path("trace.nlx");
  const auto stderr_capture = unique_path("stderr.txt");
  write_config(config, profile, trace);

  const StandaloneRun run = run_standalone(config, stderr_capture);
  INFO(run.agent_stderr);
  CHECK(run.exit_code == 42);

  noleax::analyzer::EventStreamResult result;
  const ObservedApis observed = observe_trace(trace, result);
  CHECK(observed.heap == expect_heap);
  CHECK(observed.virtual_memory == expect_vm);
  check_clean_finalize(result);

  std::error_code error;
  std::filesystem::remove(config, error);
  std::filesystem::remove(trace, error);
  std::filesystem::remove(stderr_capture, error);
}

}  // namespace

TEST_CASE("standalone capture honors the linux-glibc-heap profile", "[linux][standalone]") {
  run_profile_case("linux-glibc-heap", true, false);
}

TEST_CASE("standalone capture honors the linux-virtual-memory profile", "[linux][standalone]") {
  run_profile_case("linux-virtual-memory", false, true);
}

TEST_CASE("standalone capture honors the linux-native profile", "[linux][standalone]") {
  run_profile_case("linux-native", true, true);
}

TEST_CASE("standalone rejects a Windows hook profile without disturbing the target",
          "[linux][standalone]") {
  const auto config = unique_path("config.toml");
  const auto trace = unique_path("trace.nlx");
  const auto stderr_capture = unique_path("stderr.txt");
  write_config(config, "windows-nt-heap", trace);

  const StandaloneRun run = run_standalone(config, stderr_capture);
  CHECK(run.exit_code == 42);
  CHECK(run.agent_stderr.find("standalone requires a linux-* hook profile") != std::string::npos);
  std::error_code error;
  CHECK(!std::filesystem::exists(trace, error));

  std::filesystem::remove(config, error);
  std::filesystem::remove(stderr_capture, error);
}
