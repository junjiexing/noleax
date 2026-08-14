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
#include <optional>
#include <set>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include "noleax/agent/linux/hook_registry.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/trace/custom_hook.hpp"
#include "noleax/trace/event.hpp"

namespace {

using namespace std::chrono_literals;

[[nodiscard]] std::filesystem::path unique_path(const std::string& name) {
  const auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  return std::filesystem::temp_directory_path() / ("noleax-standalone-" + name + "-" + stamp);
}

void write_config(const std::filesystem::path& path, const std::string& profile,
                  const std::filesystem::path& trace, const std::string& capture_extra = "",
                  const std::string& trace_extra = "", const std::string& tail_extra = "") {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  output << "schema_version = 1\n\n[capture]\nhook_profile = \"" << profile << "\"\n"
         << capture_extra << "\n[trace]\npath = \"" << trace.string()
         << "\"\ncompression = \"none\"\n"
         << trace_extra << tail_extra;
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
// exit hook finalizes the trace before the process dies. extra_env, when set, is added to
// the child environment (the H1-A drain-budget test seam uses it).
[[nodiscard]] StandaloneRun run_standalone(
    const std::filesystem::path& config, const std::filesystem::path& stderr_capture,
    const char* executable = NOLEAX_WORKLOAD_PATH, const char* argument = nullptr, bool wait = true,
    const std::pair<std::string, std::string>* extra_env = nullptr) {
  const pid_t pid = ::fork();
  if (pid == 0) {
    const int fd = ::open(stderr_capture.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      static_cast<void>(::dup2(fd, STDERR_FILENO));
      ::close(fd);
    }
    ::setenv("LD_PRELOAD", NOLEAX_AGENT_PATH, 1);
    ::setenv("NOLEAX_AGENT_CONFIG", config.c_str(), 1);
    if (extra_env != nullptr) {
      ::setenv(extra_env->first.c_str(), extra_env->second.c_str(), 1);
    }
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
      {"unloadonstop", "", "", "injection.unload_on_stop"},
  };
  for (const auto& test_case : cases) {
    const auto config = unique_path("config.toml");
    const auto trace = unique_path("trace.nlx");
    const auto stderr_capture = unique_path("stderr.txt");
    write_config(config, "linux-glibc-heap", trace, test_case.capture_extra, test_case.trace_extra);
    if (test_case.name == "method") {
      std::ofstream append{config, std::ios::app};
      append << "\n[injection]\nmethod = \"ptrace\"\n";
    }
    if (test_case.name == "unloadonstop") {
      std::ofstream append{config, std::ios::app};
      append << "\n[injection]\nunload_on_stop = true\n";
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

namespace {

// ---- standalone custom hooks (_sym ELF locators, per-role argument model) ----

struct CustomHookTrace {
  std::vector<noleax::trace::Event> events;
  noleax::analyzer::EventStreamResult result;
};

// Reads a standalone trace and collects every event stamped with a custom hook api_id.
[[nodiscard]] CustomHookTrace collect_custom_events(const std::filesystem::path& trace) {
  std::ifstream input{trace, std::ios::binary};
  if (!input) {
    FAIL("cannot open the standalone trace");
  }
  CustomHookTrace collected;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_event = [&collected](const noleax::trace::Event& event) {
    if (event.header.api_id >= noleax::trace::kCustomHookApiIdBase) {
      collected.events.push_back(event);
    }
  };
  collected.result = noleax::analyzer::analyze_event_stream(input, callbacks);
  return collected;
}

void remove_all(const std::filesystem::path& config, const std::filesystem::path& trace,
                const std::filesystem::path& stderr_capture) {
  std::error_code error;
  std::filesystem::remove(config, error);
  std::filesystem::remove(trace, error);
  std::filesystem::remove(stderr_capture, error);
}

}  // namespace

TEST_CASE("standalone custom hooks record a C++ member allocator through per-role arguments",
          "[linux][standalone][custom-hook]") {
  const auto config = unique_path("config.toml");
  const auto trace = unique_path("trace.nlx");
  const auto stderr_capture = unique_path("stderr.txt");
  // CxxAllocator's `this` occupies argument 0, so every semantic slot shifts by one:
  // Malloc(size, align) reads its size at 1, Realloc(ptr, size, align) its pointer at 1 and
  // its size at 2, Free(ptr) its pointer at 1.
  write_config(config, "linux-glibc-heap", trace, "", "",
               R"toml(
[[custom_hooks]]
module = "noleax-linux-workload-target"
alloc_sym = "_ZN12CxxAllocator6MallocEmm"
realloc_sym = "_ZN12CxxAllocator7ReallocEPvmm"
free_sym = "_ZN12CxxAllocator4FreeEPv"
alloc_size_arg = 1
realloc_ptr_arg = 1
realloc_size_arg = 2
free_ptr_arg = 1
)toml");

  const StandaloneRun run = run_standalone(config, stderr_capture);
  INFO(run.agent_stderr);
  REQUIRE(run.exit_code == 42);

  const CustomHookTrace collected = collect_custom_events(trace);
  check_clean_finalize(collected.result);
  REQUIRE(collected.result.custom_hooks.size() == 1U);
  CHECK(collected.result.custom_hooks.front().module_name == "noleax-linux-workload-target");
  CHECK(collected.result.custom_hooks.front().label == "_ZN12CxxAllocator6MallocEmm");

  std::optional<noleax::trace::AllocationEvent> allocation;
  std::optional<noleax::trace::ReallocationEvent> reallocation;
  std::optional<noleax::trace::FreeEvent> free_event;
  for (const noleax::trace::Event& event : collected.events) {
    if (const auto* payload = std::get_if<noleax::trace::AllocationEvent>(&event.payload)) {
      allocation = *payload;
    } else if (const auto* payload =
                   std::get_if<noleax::trace::ReallocationEvent>(&event.payload)) {
      reallocation = *payload;
    } else if (const auto* payload = std::get_if<noleax::trace::FreeEvent>(&event.payload)) {
      free_event = *payload;
    }
  }
  REQUIRE(allocation.has_value());
  CHECK(allocation->requested_size == 1024U);
  REQUIRE(reallocation.has_value());
  CHECK(reallocation->old_address == allocation->result_address);
  CHECK(reallocation->requested_size == 1536U);
  REQUIRE(free_event.has_value());
  CHECK(free_event->address == reallocation->result_address);

  remove_all(config, trace, stderr_capture);
}

TEST_CASE("standalone custom hooks resolve symtab-only symbols",
          "[linux][standalone][custom-hook]") {
  const auto config = unique_path("config.toml");
  const auto trace = unique_path("trace.nlx");
  const auto stderr_capture = unique_path("stderr.txt");
  // hidden_alloc/hidden_free carry hidden visibility: absent from .dynsym, so only the
  // .symtab scan can resolve them.
  write_config(config, "linux-glibc-heap", trace, "", "",
               R"toml(
[[custom_hooks]]
module = "noleax-linux-workload-target"
alloc_sym = "_Z12hidden_allocm"
free_sym = "_Z11hidden_freePv"
)toml");

  const StandaloneRun run = run_standalone(config, stderr_capture);
  INFO(run.agent_stderr);
  REQUIRE(run.exit_code == 42);

  const CustomHookTrace collected = collect_custom_events(trace);
  check_clean_finalize(collected.result);
  REQUIRE(collected.result.custom_hooks.size() == 1U);
  CHECK(collected.result.custom_hooks.front().label == "_Z12hidden_allocm");

  std::optional<noleax::trace::AllocationEvent> allocation;
  std::optional<noleax::trace::FreeEvent> free_event;
  for (const noleax::trace::Event& event : collected.events) {
    if (const auto* payload = std::get_if<noleax::trace::AllocationEvent>(&event.payload)) {
      allocation = *payload;
    } else if (const auto* payload = std::get_if<noleax::trace::FreeEvent>(&event.payload)) {
      free_event = *payload;
    }
  }
  REQUIRE(allocation.has_value());
  CHECK(allocation->requested_size == 512U);
  REQUIRE(free_event.has_value());
  CHECK(free_event->address == allocation->result_address);

  remove_all(config, trace, stderr_capture);
}

// ---- drain quiescence (H1-A): the capture stop waits out slow in-flight calls ----

namespace {

// Custom hook on the workload's slow_alloc/slow_free: the 500 ms sleep inside slow_alloc
// spans the 100 ms capture duration, so the drain always starts with the call in flight.
void write_slow_hook_config(const std::filesystem::path& path, const std::filesystem::path& trace) {
  write_config(path, "linux-glibc-heap", trace, "duration = \"100ms\"\n", "",
               R"toml(
[[custom_hooks]]
module = "noleax-linux-workload-target"
alloc = "slow_alloc"
free = "slow_free"
)toml");
}

}  // namespace

TEST_CASE("standalone drain waits out an in-flight custom hook call",
          "[linux][standalone][custom-hook][quiescence]") {
  const auto config = unique_path("config.toml");
  const auto trace = unique_path("trace.nlx");
  const auto stderr_capture = unique_path("stderr.txt");
  write_slow_hook_config(config, trace);

  const StandaloneRun run =
      run_standalone(config, stderr_capture, NOLEAX_WORKLOAD_PATH, "--slow-custom-alloc");
  INFO(run.agent_stderr);
  REQUIRE(run.exit_code == 42);

  // The drain started at 100 ms with the 500 ms slow_alloc in flight and still produced
  // exactly one correctly recorded event with a clean EndOfTrace: the stop waited for the
  // call instead of cutting it off.
  const CustomHookTrace collected = collect_custom_events(trace);
  check_clean_finalize(collected.result);
  std::optional<noleax::trace::AllocationEvent> allocation;
  for (const noleax::trace::Event& event : collected.events) {
    if (const auto* payload = std::get_if<noleax::trace::AllocationEvent>(&event.payload)) {
      CHECK_FALSE(allocation.has_value());
      allocation = *payload;
    }
  }
  REQUIRE(allocation.has_value());
  CHECK(allocation->requested_size == 2048U);

  remove_all(config, trace, stderr_capture);
}

TEST_CASE("standalone drain timeout reports incomplete and never spins",
          "[linux][standalone][custom-hook][quiescence]") {
  const auto config = unique_path("config.toml");
  const auto trace = unique_path("trace.nlx");
  const auto stderr_capture = unique_path("stderr.txt");
  write_slow_hook_config(config, trace);

  // The test seam shrinks the drain budget below the 500 ms in-flight call: the stop
  // times out, reports the incomplete drain on the target's stderr, and the target keeps
  // running normally (bounded well under the 500 ms slow path plus slack).
  const std::pair<std::string, std::string> budget{"NOLEAX_DRAIN_BUDGET_MS", "50"};
  const auto begin = std::chrono::steady_clock::now();
  const StandaloneRun run = run_standalone(config, stderr_capture, NOLEAX_WORKLOAD_PATH,
                                           "--slow-custom-alloc", true, &budget);
  const auto elapsed = std::chrono::steady_clock::now() - begin;
  INFO(run.agent_stderr);
  REQUIRE(run.exit_code == 42);
  CHECK(elapsed < std::chrono::seconds{20});
  CHECK(run.agent_stderr.find("did not reach replacement quiescence") != std::string::npos);

  // The writer cannot reconcile a capture cut off mid-flight (the in-flight call counted
  // recordable at entry but never completed), so it fails closed through the error tail:
  // no atomic rename, and the .partial keeps everything up to the stop with an abnormal
  // EndOfTrace. The late event lands after the writer closed and is never recorded.
  std::error_code error;
  CHECK(!std::filesystem::exists(trace, error));
  const std::filesystem::path partial = trace.string() + ".partial";
  REQUIRE(std::filesystem::exists(partial, error));
  const CustomHookTrace collected = collect_custom_events(partial);
  CHECK(collected.events.empty());
  REQUIRE(collected.result.end_of_trace.has_value());
  CHECK_FALSE(collected.result.end_of_trace->normal_stop);
  CHECK(collected.result.completeness.has(noleax::trace::CompletenessIssue::kAbnormalStop));

  std::filesystem::remove(config, error);
  std::filesystem::remove(partial, error);
  std::filesystem::remove(stderr_capture, error);
}
