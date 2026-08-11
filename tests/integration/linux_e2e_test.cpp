// End-to-end capture test for the Linux port (M3): drives the real CLI against the
// deterministic workload target and asserts on the analyzer output. Flow under test:
//   noleax run --hook-profile linux-glibc-heap --trace T -- workload
//   noleax analyze --mode events|leaks T

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace {

[[nodiscard]] std::string read_all(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  std::ostringstream content;
  content << input.rdbuf();
  return content.str();
}

struct CommandResult {
  int exit_code{-1};
};

[[nodiscard]] CommandResult run_shell(const std::string& command) {
  return CommandResult{std::system(command.c_str())};
}

}  // namespace

TEST_CASE("linux end-to-end run captures an analyzable trace", "[linux][e2e]") {
  const auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const std::filesystem::path trace =
      std::filesystem::temp_directory_path() / ("noleax-e2e-" + stamp + ".nlx");
  const std::filesystem::path run_log =
      std::filesystem::temp_directory_path() / ("noleax-e2e-run-" + stamp + ".log");
  const std::filesystem::path events_out =
      std::filesystem::temp_directory_path() / ("noleax-e2e-events-" + stamp + ".txt");
  const std::filesystem::path leaks_out =
      std::filesystem::temp_directory_path() / ("noleax-e2e-leaks-" + stamp + ".txt");

  const std::string run_command =
      "\"" NOLEAX_CLI_PATH "\" run --hook-profile linux-glibc-heap --trace \"" + trace.string() +
      "\" -- \"" NOLEAX_WORKLOAD_PATH "\" > \"" + run_log.string() + "\" 2>&1";
  const CommandResult run = run_shell(run_command);
  const std::string run_output = read_all(run_log);
  INFO(run_output);
  REQUIRE(run.exit_code == 0);
  CHECK(run_output.find("capture finalized") != std::string::npos);
  CHECK(run_output.find("target_exit_code=42") != std::string::npos);
  CHECK(run_output.find("dropped=0") != std::string::npos);

  const CommandResult events =
      run_shell("\"" NOLEAX_CLI_PATH "\" analyze --mode events --group-by stack \"" +
                trace.string() + "\" > \"" + events_out.string() + "\" 2>&1");
  REQUIRE(events.exit_code == 0);
  const std::string events_output = read_all(events_out);
  INFO(events_output);
  CHECK(events_output.find("platform=linux") != std::string::npos);
  // The paired workload: exactly 400 mallocs from one stack.
  CHECK(events_output.find("calls=400") != std::string::npos);
  CHECK(events_output.find("malloc") != std::string::npos);

  const CommandResult leaks =
      run_shell("\"" NOLEAX_CLI_PATH "\" analyze --mode leaks \"" + trace.string() + "\" > \"" +
                leaks_out.string() + "\" 2>&1");
  REQUIRE(leaks.exit_code == 0);
  const std::string leaks_output = read_all(leaks_out);
  INFO(leaks_output);
  // The retained blocks: 8 blocks of 4096+i*512 bytes (4096, 4608, 5120, ...).
  CHECK(leaks_output.find("size=4096B") != std::string::npos);
  CHECK(leaks_output.find("size=4608B") != std::string::npos);
  CHECK(leaks_output.find("completeness: complete") != std::string::npos);

  std::filesystem::remove(trace);
  std::filesystem::remove(run_log);
  std::filesystem::remove(events_out);
  std::filesystem::remove(leaks_out);
}

TEST_CASE("linux end-to-end native profile captures VM events and memory snapshots",
          "[linux][e2e]") {
  const auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const std::filesystem::path trace =
      std::filesystem::temp_directory_path() / ("noleax-e2e-vm-" + stamp + ".nlx");
  const std::filesystem::path events_out =
      std::filesystem::temp_directory_path() / ("noleax-e2e-vm-events-" + stamp + ".txt");
  const std::filesystem::path memory_out =
      std::filesystem::temp_directory_path() / ("noleax-e2e-vm-memory-" + stamp + ".txt");

  const CommandResult run =
      run_shell("\"" NOLEAX_CLI_PATH "\" run --hook-profile linux-native --trace \"" +
                trace.string() + "\" -- \"" NOLEAX_WORKLOAD_PATH "\"");
  REQUIRE(run.exit_code == 0);

  const CommandResult events =
      run_shell("\"" NOLEAX_CLI_PATH "\" analyze --mode events \"" + trace.string() + "\" > \"" +
                events_out.string() + "\" 2>&1");
  REQUIRE(events.exit_code == 0);
  const std::string events_output = read_all(events_out);
  INFO(events_output);
  CHECK(events_output.find("mmap") != std::string::npos);
  CHECK(events_output.find("munmap") != std::string::npos);
  CHECK(events_output.find("mremap") != std::string::npos);

  const CommandResult memory =
      run_shell("\"" NOLEAX_CLI_PATH "\" analyze --mode memory \"" + trace.string() + "\" > \"" +
                memory_out.string() + "\" 2>&1");
  REQUIRE(memory.exit_code == 0);
  const std::string memory_output = read_all(memory_out);
  INFO(memory_output);
  CHECK(memory_output.find("snapshots:") != std::string::npos);
  CHECK(memory_output.find("working-set=") != std::string::npos);
  CHECK(memory_output.find("regions=") != std::string::npos);

  std::filesystem::remove(trace);
  std::filesystem::remove(events_out);
  std::filesystem::remove(memory_out);
}
