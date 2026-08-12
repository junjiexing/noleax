// Standalone-mode hook-profile routing test (Linux): LD_PRELOAD + NOLEAX_AGENT_CONFIG
// launches the deterministic workload with each linux-* profile, then reads the
// resulting trace and asserts on the actual recorded event types — never on the TOML
// parse result alone. A Windows profile must be rejected before any hook installs,
// without disturbing the target.

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <csignal>
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
                  const std::filesystem::path& trace, const std::string& capture_extra = "",
                  const std::string& trace_extra = "") {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  output << "schema_version = 1\n\n[capture]\nhook_profile = \"" << profile << "\"\n"
         << capture_extra << "\n[trace]\npath = \"" << trace.string()
         << "\"\ncompression = \"none\"\n"
         << trace_extra;
  if (!output) {
    FAIL("cannot write the standalone config");
  }
}

struct StandaloneRun {
  int exit_code{-1};
  std::string agent_stderr;
  pid_t pid{-1};  // still-running child when wait was not requested
};

// Runs a target with the agent preloaded in standalone mode. When wait is false the caller
// owns the child (check liveness, then waitpid); the workload exits 42 on success and the
// exit hook finalizes the trace before the process dies.
[[nodiscard]] StandaloneRun run_standalone(const std::filesystem::path& config,
                                           const std::filesystem::path& stderr_capture,
                                           const char* executable = NOLEAX_WORKLOAD_PATH,
                                           const char* argument = nullptr, bool wait = true) {
  const pid_t pid = ::fork();
  if (pid == 0) {
    const int fd = ::open(stderr_capture.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      static_cast<void>(::dup2(fd, STDERR_FILENO));
      ::close(fd);
    }
    ::setenv("LD_PRELOAD", NOLEAX_AGENT_PATH, 1);
    ::setenv("NOLEAX_AGENT_CONFIG", config.c_str(), 1);
    if (argument == nullptr) {
      ::execl(executable, executable, static_cast<char*>(nullptr));
    } else {
      ::execl(executable, executable, argument, static_cast<char*>(nullptr));
    }
    _exit(127);
  }
  StandaloneRun run;
  run.pid = pid;
  if (!wait) {
    return run;
  }
  int status = 0;
  if (::waitpid(pid, &status, 0) < 0) {
    FAIL("waitpid failed for the standalone target");
  }
  run.pid = -1;
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

// ---- standalone configuration alignment (supported fields take effect, the rest reject) ----

TEST_CASE("standalone max_stack_depth limits recorded stacks", "[linux][standalone]") {
  const auto config = unique_path("config.toml");
  const auto trace = unique_path("trace.nlx");
  const auto stderr_capture = unique_path("stderr.txt");
  write_config(config, "linux-glibc-heap", trace, "max_stack_depth = 1\n");

  const StandaloneRun run = run_standalone(config, stderr_capture);
  INFO(run.agent_stderr);
  REQUIRE(run.exit_code == 42);

  std::ifstream input{trace, std::ios::binary};
  REQUIRE(input);
  std::size_t deepest = 0;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_stack_definition = [&deepest](const noleax::trace::StackDefinition& stack) {
    deepest = std::max(deepest, stack.frames.size());
  };
  const auto result = noleax::analyzer::analyze_event_stream(input, callbacks);
  CHECK(result.stack_definition_count > 0U);
  CHECK(deepest <= 1U);

  std::error_code error;
  std::filesystem::remove(config, error);
  std::filesystem::remove(trace, error);
  std::filesystem::remove(stderr_capture, error);
}

TEST_CASE("standalone min_size filters small allocations", "[linux][standalone]") {
  const auto baseline_config = unique_path("config.toml");
  const auto baseline_trace = unique_path("trace.nlx");
  const auto filtered_config = unique_path("config.toml");
  const auto filtered_trace = unique_path("trace.nlx");
  const auto stderr_capture = unique_path("stderr.txt");
  write_config(baseline_config, "linux-glibc-heap", baseline_trace);
  write_config(filtered_config, "linux-glibc-heap", filtered_trace, "min_size = \"1KiB\"\n");

  CHECK(run_standalone(baseline_config, stderr_capture).exit_code == 42);
  CHECK(run_standalone(filtered_config, stderr_capture).exit_code == 42);

  std::ifstream baseline_input{baseline_trace, std::ios::binary};
  const auto baseline = noleax::analyzer::analyze_event_stream(baseline_input);
  std::ifstream filtered_input{filtered_trace, std::ios::binary};
  const auto filtered = noleax::analyzer::analyze_event_stream(filtered_input);
  CHECK(filtered.event_count > 0U);
  CHECK(filtered.event_count < baseline.event_count);

  std::error_code error;
  for (const auto& path :
       {baseline_config, baseline_trace, filtered_config, filtered_trace, stderr_capture}) {
    std::filesystem::remove(path, error);
  }
}

TEST_CASE("standalone duration finalizes while the target keeps running", "[linux][standalone]") {
  const auto config = unique_path("config.toml");
  const auto trace = unique_path("trace.nlx");
  const auto stderr_capture = unique_path("stderr.txt");
  write_config(config, "linux-glibc-heap", trace,
               "duration = \"1s\"\nmemory_counters_interval = \"200ms\"\n");

  StandaloneRun run = run_standalone(config, stderr_capture, "/bin/sleep", "10", /*wait=*/false);
  // Poll for the finalized trace while the child should still be alive. The file is
  // visible before the writer finishes flushing it, so a parse error just means
  // "not finalized yet" — keep polling.
  bool finalized = false;
  for (int attempt = 0; attempt != 100 && !finalized; ++attempt) {
    std::this_thread::sleep_for(100ms);
    std::error_code error;
    if (!std::filesystem::is_regular_file(trace, error)) {
      continue;
    }
    try {
      std::ifstream input{trace, std::ios::binary};
      const auto result = noleax::analyzer::analyze_event_stream(input);
      finalized = result.end_of_trace.has_value();
    } catch (const std::exception&) {
      // Any parse/read failure (truncated header, partial chunk) = not finalized yet.
    }
  }
  CHECK(finalized);
  CHECK(run.pid > 0);
  CHECK(::kill(run.pid, 0) == 0);  // the target outlives the capture

  std::ifstream input{trace, std::ios::binary};
  const auto result = noleax::analyzer::analyze_event_stream(input);
  CHECK(result.memory_counters_count >= 2U);

  ::kill(run.pid, SIGTERM);
  int status = 0;
  static_cast<void>(::waitpid(run.pid, &status, 0));

  std::error_code error;
  std::filesystem::remove(config, error);
  std::filesystem::remove(trace, error);
  std::filesystem::remove(stderr_capture, error);
}

TEST_CASE("standalone rejects unsupported non-default fields", "[linux][standalone]") {
  const struct {
    std::string_view name;
    std::string capture_extra;
    std::string trace_extra;
    std::string_view expected_field;
  } cases[] = {
      {"rotate", "", "on_full = \"rotate\"\n", "trace.on_full"},
      {"maxfiles", "", "max_files = 2\n", "trace.max_files"},
      {"method", "", "", "injection.method"},
      {"custom", "", "", "custom_hooks"},
  };
  for (const auto& test_case : cases) {
    const auto config = unique_path("config.toml");
    const auto trace = unique_path("trace.nlx");
    const auto stderr_capture = unique_path("stderr.txt");
    write_config(config, "linux-glibc-heap", trace, test_case.capture_extra, test_case.trace_extra);
    if (test_case.name == "method") {
      std::ofstream append{config, std::ios::app};
      append << "\n[injection]\nmethod = \"ptrace\"\n";
    } else if (test_case.name == "custom") {
      std::ofstream append{config, std::ios::app};
      append << "\n[[custom_hooks]]\nmodule = \"libc.so.6\"\nalloc = \"malloc\"\nfree = \"free\"\n";
    }

    const StandaloneRun run = run_standalone(config, stderr_capture);
    INFO(std::string{test_case.name} + ": " + run.agent_stderr);
    CHECK(run.exit_code == 42);
    CHECK(run.agent_stderr.find(test_case.expected_field) != std::string::npos);
    std::error_code error;
    CHECK(!std::filesystem::exists(trace, error));

    std::filesystem::remove(config, error);
    std::filesystem::remove(stderr_capture, error);
  }
}
