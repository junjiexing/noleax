#include "noleax/config/configuration.hpp"

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "noleax/config/config_io.hpp"

namespace {

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    static std::atomic<std::uint64_t> sequence{0};
    const auto suffix =
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" +
        std::to_string(sequence.fetch_add(1));
    path_ = std::filesystem::temp_directory_path() / ("noleax-config-test-" + suffix);
    if (!std::filesystem::create_directory(path_)) {
      throw std::runtime_error{"cannot create test directory"};
    }
  }

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  ~TemporaryDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

void write_file(const std::filesystem::path& path, std::string_view contents = {}) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  if (!output) {
    throw std::runtime_error{"cannot create test file"};
  }
  output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  if (!output) {
    throw std::runtime_error{"cannot write test file"};
  }
}

[[nodiscard]] std::string read_file(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  if (!input) {
    throw std::runtime_error{"cannot open test fixture"};
  }
  std::ostringstream result;
  result << input.rdbuf();
  return result.str();
}

[[nodiscard]] std::string normalize_newlines(const std::string& value) {
  std::string normalized;
  normalized.reserve(value.size());
  for (const char character : value) {
    if (character != '\r') {
      normalized.push_back(character);
    }
  }
  return normalized;
}

[[nodiscard]] std::string replace_all(std::string value, std::string_view from,
                                      std::string_view to) {
  std::string::size_type position = 0U;
  while ((position = value.find(from, position)) != std::string::npos) {
    value.replace(position, from.size(), to);
    position += to.size();
  }
  return value;
}

[[nodiscard]] noleax::config::WindowBound time_bound(std::chrono::nanoseconds time) {
  noleax::config::WindowBound bound;
  bound.time = time;
  return bound;
}

[[nodiscard]] noleax::config::WindowBound sequence_bound(std::uint64_t sequence) {
  noleax::config::WindowBound bound;
  bound.sequence = sequence;
  return bound;
}

}  // namespace

TEST_CASE("default configuration has stable values and serialization", "[config]") {
  using namespace std::chrono_literals;
  const auto configuration = noleax::config::make_default_configuration();

  CHECK(configuration.schema_version.value == 1U);
  CHECK_FALSE(configuration.operation.value.has_value());
#if defined(_WIN32)
  CHECK(configuration.capture.hook_profile.value == noleax::config::HookProfile::kWindowsNative);
#else
  CHECK(configuration.capture.hook_profile.value == noleax::config::HookProfile::kLinuxGlibcHeap);
#endif
  CHECK(configuration.capture.max_stack_depth.value == 64U);
  CHECK(configuration.injection.timeout.value == 10s);
  CHECK(configuration.trace.buffer_size.value == 16U * 1024U * 1024U);
  CHECK(configuration.trace.max_file_size.value == 256U * 1024U * 1024U);
  CHECK(configuration.trace.flush_interval.value == 250ms);
  CHECK(configuration.trace.compression.value == noleax::config::Compression::kLz4);
  CHECK(configuration.patch.verify.value);
  CHECK(configuration.diagnostics.log_level.source == noleax::config::ValueSource::kDefault);

  const auto fixture = std::filesystem::path{NOLEAX_TEST_SOURCE_DIR} / "tests" / "fixtures" /
                       "default-effective.toml";
  std::string expected = normalize_newlines(read_file(fixture));
#if !defined(_WIN32)
  // Platform-aware defaults: the fixture records the Windows values.
  expected = replace_all(expected, "method = \"remote-thread\"", "method = \"ld-preload\"");
  expected = replace_all(expected, "hook_profile = \"windows-native\"",
                         "hook_profile = \"linux-glibc-heap\"");
#endif
  CHECK(noleax::config::serialize_effective_config(configuration) == expected);
}

TEST_CASE("TOML loader maps every schema field and resolves relative paths", "[config][toml]") {
  TemporaryDirectory temporary;
  const auto config_path = temporary.path() / "noleax.toml";
  write_file(config_path, R"toml(schema_version = 1
operation = "analyze"

[target]
path = "bin/app.exe"
args = ["--one", "two"]
working_directory = "work"
pid = 77

[injection]
method = "thread-hijack"
agent_path = "agent/noleax-agent.dll"
timeout = "2s"
unload_on_stop = true

[capture]
hook_profile = "windows-nt-heap"
max_stack_depth = 128
min_size = "4KiB"
duration = "3m"
live = true
memory_counters_interval = "500ms"
memory_map_interval = "2s"

[trace]
path = "traces/app.nlx"
buffer_size = "8MiB"
max_file_size = "64MiB"
max_files = 3
on_full = "rotate"
flush_interval = "10ms"
compression = "zstd"
compression_level = 1

[analysis]
inputs = ["one.nlx", "two.nlx"]
mode = "leaks"
format = "json"
output = "result.json"
from = "1s"
to = "2s"
end = "3s"
group_by = "stack"
sort = "calls"
trim_agent_frames = false

[filters]
min_size = "16B"
max_size = "1MiB"
events = ["alloc", "realloc"]
threads = [1, 2]
apis = ["RtlAllocateHeap"]
modules = ["app*"]
stack_modules = ["engine*"]
allocation_ids = [10, 11]
statuses = ["success", "unmatched", "preexisting"]

[symbols]
mode = "auto"
paths = ["symbols"]
servers = ["https://symbols.example.test"]

[symbol_listing]
input = "app.dll"
format = "csv"
output = "symbols.csv"
name = ["*alloc*", "?free*"]
match_case = true
kind = ["function", "public"]
fields = ["name", "rva"]

[patch]
input = "input.exe"
output = "output.exe"
method = "entrypoint-section"
agent_name = "custom-agent.dll"
allow_break_signature = true
verify = false
standalone = true

[diagnostics]
log_level = "debug"
color = "always"
)toml");

  const auto overrides = noleax::config::load_toml_config(config_path);
  CHECK(overrides.schema_version.specified);
  CHECK(overrides.operation.specified);
  CHECK(overrides.target.path.specified);
  CHECK(overrides.target.args.specified);
  CHECK(overrides.target.working_directory.specified);
  CHECK(overrides.target.pid.specified);
  CHECK(overrides.injection.method.specified);
  CHECK(overrides.injection.agent_path.specified);
  CHECK(overrides.injection.timeout.specified);
  CHECK(overrides.injection.unload_on_stop.specified);
  CHECK(overrides.capture.hook_profile.specified);
  CHECK(overrides.capture.max_stack_depth.specified);
  CHECK(overrides.capture.min_size.specified);
  CHECK(overrides.capture.duration.specified);
  CHECK(overrides.capture.live.specified);
  CHECK(overrides.capture.memory_counters_interval.specified);
  CHECK(overrides.capture.memory_map_interval.specified);
  CHECK(overrides.trace.path.specified);
  CHECK(overrides.trace.buffer_size.specified);
  CHECK(overrides.trace.max_file_size.specified);
  CHECK(overrides.trace.max_files.specified);
  CHECK(overrides.trace.on_full.specified);
  CHECK(overrides.trace.flush_interval.specified);
  CHECK(overrides.trace.compression.specified);
  CHECK(overrides.trace.compression_level.specified);
  CHECK(overrides.analysis.inputs.specified);
  CHECK(overrides.analysis.mode.specified);
  CHECK(overrides.analysis.format.specified);
  CHECK(overrides.analysis.output.specified);
  CHECK(overrides.analysis.from.specified);
  CHECK(overrides.analysis.to.specified);
  CHECK(overrides.analysis.end.specified);
  CHECK(overrides.analysis.group_by.specified);
  CHECK(overrides.analysis.sort.specified);
  CHECK(overrides.analysis.trim_agent_frames.specified);
  CHECK(overrides.filters.min_size.specified);
  CHECK(overrides.filters.max_size.specified);
  CHECK(overrides.filters.events.specified);
  CHECK(overrides.filters.threads.specified);
  CHECK(overrides.filters.apis.specified);
  CHECK(overrides.filters.modules.specified);
  CHECK(overrides.filters.stack_modules.specified);
  CHECK(overrides.filters.allocation_ids.specified);
  CHECK(overrides.filters.statuses.specified);
  CHECK(overrides.symbols.mode.specified);
  CHECK(overrides.symbols.paths.specified);
  CHECK(overrides.symbols.servers.specified);
  CHECK(overrides.symbol_listing.input.specified);
  CHECK(overrides.symbol_listing.format.specified);
  CHECK(overrides.symbol_listing.output.specified);
  CHECK(overrides.symbol_listing.name.specified);
  CHECK(overrides.symbol_listing.match_case.specified);
  CHECK(overrides.symbol_listing.kind.specified);
  CHECK(overrides.symbol_listing.fields.specified);
  CHECK(overrides.patch.input.specified);
  CHECK(overrides.patch.output.specified);
  CHECK(overrides.patch.method.specified);
  CHECK(overrides.patch.agent_name.specified);
  CHECK(overrides.patch.allow_break_signature.specified);
  CHECK(overrides.patch.verify.specified);
  CHECK(overrides.patch.standalone.specified);
  CHECK(overrides.diagnostics.log_level.specified);
  CHECK(overrides.diagnostics.color.specified);

  CHECK(overrides.operation.value == noleax::config::Operation::kAnalyze);
  CHECK(overrides.target.path.value == temporary.path() / "bin" / "app.exe");
  CHECK(overrides.target.args.value == std::vector<std::string>{"--one", "two"});
  CHECK(overrides.target.pid.value == std::optional<std::uint32_t>{77U});
  CHECK(overrides.capture.min_size.value == 4U * 1024U);
  CHECK(overrides.capture.memory_counters_interval.value == std::chrono::milliseconds{500});
  CHECK(overrides.capture.memory_map_interval.value == std::chrono::seconds{2});
  CHECK(overrides.trace.compression.value == noleax::config::Compression::kZstd);
  CHECK(overrides.analysis.inputs.value.front() == temporary.path() / "one.nlx");
  CHECK_FALSE(overrides.analysis.trim_agent_frames.value);
  CHECK(overrides.filters.events.value ==
        std::vector{noleax::config::EventType::kAlloc, noleax::config::EventType::kRealloc});
  CHECK(overrides.filters.statuses.value == std::vector{noleax::config::EventStatus::kSuccess,
                                                        noleax::config::EventStatus::kUnmatched,
                                                        noleax::config::EventStatus::kPreexisting});
  CHECK(overrides.symbol_listing.input.value == temporary.path() / "app.dll");
  CHECK(overrides.symbol_listing.format.value == noleax::config::OutputFormat::kCsv);
  CHECK(overrides.symbol_listing.output.value == temporary.path() / "symbols.csv");
  CHECK(overrides.symbol_listing.name.value == std::vector<std::string>{"*alloc*", "?free*"});
  CHECK(overrides.symbol_listing.match_case.value);
  CHECK(overrides.symbol_listing.kind.value == std::vector{noleax::analyzer::SymbolKind::kFunction,
                                                           noleax::analyzer::SymbolKind::kPublic});
  CHECK(overrides.symbol_listing.fields.value ==
        std::vector{noleax::analyzer::SymbolListingField::kName,
                    noleax::analyzer::SymbolListingField::kRva});
  CHECK_FALSE(overrides.patch.verify.value);
}

TEST_CASE("TOML loader rejects missing schema, unknown keys, and wrong types", "[config][toml]") {
  TemporaryDirectory temporary;
  const auto config_path = temporary.path() / "bad.toml";

  constexpr std::string_view invalidDocuments[]{
      "operation = \"doctor\"\n",
      "schema_version = 2\noperation = \"doctor\"\n",
      "schema_version = 1\nunknown = true\n",
      "schema_version = 1\noperation = 7\n",
      "schema_version = 1\n[capture]\nmax_stack_depth = \"64\"\n",
      "schema_version = 1\n[trace]\nunknown = true\n",
      "schema_version = 1\n[filters]\nevents = [\"ALLOC\"]\n",
      "schema_version = 1\n[target]\nargs = [\"ok\", 7]\n",
      "schema_version = 1\nschema_version = 1\n",
      "schema_version = 1\n[symbol_listing]\nunknown = true\n",
      "schema_version = 1\n[symbol_listing]\nkind = [\"bogus\"]\n",
  };

  for (const auto document : invalidDocuments) {
    CAPTURE(document);
    write_file(config_path, document);
    CHECK_THROWS_AS(noleax::config::load_toml_config(config_path), noleax::config::ConfigError);
  }
}

TEST_CASE("effective TOML is accepted as a complete current-schema configuration",
          "[config][toml]") {
  TemporaryDirectory temporary;
  auto configuration = noleax::config::make_default_configuration();
  configuration.operation.value = noleax::config::Operation::kDoctor;
  configuration.operation.source = noleax::config::ValueSource::kCommandLine;

  const auto path = temporary.path() / "effective.toml";
  write_file(path, noleax::config::serialize_effective_config(configuration));
  const auto overrides = noleax::config::load_toml_config(path);
  auto round_trip = noleax::config::make_default_configuration();
  noleax::config::apply_overrides(round_trip, overrides, noleax::config::ValueSource::kConfig);

  CHECK(round_trip.operation.value == noleax::config::Operation::kDoctor);
  CHECK(round_trip.operation.source == noleax::config::ValueSource::kConfig);
  CHECK_NOTHROW(noleax::config::validate_configuration(round_trip));
}

TEST_CASE("TOML loader parses time and sequence window bounds", "[config][toml]") {
  using namespace std::chrono_literals;
  TemporaryDirectory temporary;
  const auto config_path = temporary.path() / "windows.toml";
  write_file(config_path, R"toml(schema_version = 1
operation = "analyze"

[analysis]
from = "#123"
to = "10s"
end = "#999"
)toml");

  const auto overrides = noleax::config::load_toml_config(config_path);
  REQUIRE(overrides.analysis.from.specified);
  CHECK(overrides.analysis.from.value->sequence == 123U);
  CHECK_FALSE(overrides.analysis.from.value->time.has_value());
  CHECK(overrides.analysis.to.value->time == 10s);
  CHECK_FALSE(overrides.analysis.to.value->sequence.has_value());
  CHECK(overrides.analysis.end.value->sequence == 999U);
}

TEST_CASE("effective TOML round-trips sequence window bounds", "[config][toml]") {
  using namespace std::chrono_literals;
  TemporaryDirectory temporary;
  auto configuration = noleax::config::make_default_configuration();
  configuration.operation.value = noleax::config::Operation::kDoctor;
  configuration.analysis.from.value = sequence_bound(123U);
  configuration.analysis.to.value = time_bound(10s);

  const auto path = temporary.path() / "effective.toml";
  write_file(path, noleax::config::serialize_effective_config(configuration));
  const auto serialized = normalize_newlines(read_file(path));
  CHECK(serialized.find("from = \"#123\"") != std::string::npos);
  CHECK(serialized.find("to = \"10s\"") != std::string::npos);

  const auto overrides = noleax::config::load_toml_config(path);
  REQUIRE(overrides.analysis.from.specified);
  CHECK(overrides.analysis.from.value->sequence == 123U);
  CHECK(overrides.analysis.to.value->time == 10s);
}

TEST_CASE("analysis window validation orders only same-kind bounds", "[config]") {
  using namespace std::chrono_literals;
  TemporaryDirectory temporary;
  const auto trace = temporary.path() / "input.nlx";
  write_file(trace);

  auto configuration = noleax::config::make_default_configuration();
  configuration.operation.value = noleax::config::Operation::kAnalyze;
  configuration.analysis.inputs.value = {trace};
  configuration.analysis.mode.value = noleax::config::AnalysisMode::kOutstanding;

  // Different kinds have no defined order and pass.
  configuration.analysis.from.value = time_bound(10s);
  configuration.analysis.to.value = sequence_bound(5U);
  configuration.analysis.end.value = time_bound(1s);
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  // Same-kind sequence bounds must be ordered.
  configuration.analysis.from.value = sequence_bound(9U);
  configuration.analysis.to.value = sequence_bound(5U);
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.from.value = sequence_bound(5U);
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  configuration.analysis.end.value = sequence_bound(4U);
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.end.value = sequence_bound(5U);
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  // events mode still rejects analysis.end.
  configuration.analysis.mode.value = noleax::config::AnalysisMode::kEvents;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
}

TEST_CASE("configuration layers preserve precedence, source, and array replacement", "[config]") {
  auto configuration = noleax::config::make_default_configuration();

  noleax::config::ConfigurationOverrides file;
  file.capture.max_stack_depth.set(32U);
  file.target.args.set({"from-config", "second"});
  file.patch.verify.set(false);
  noleax::config::apply_overrides(configuration, file, noleax::config::ValueSource::kConfig);

  noleax::config::ConfigurationOverrides cli;
  cli.capture.max_stack_depth.set(96U);
  cli.target.args.set({"from-cli"});
  cli.patch.verify.set(true);
  noleax::config::apply_overrides(configuration, cli, noleax::config::ValueSource::kCommandLine);

  CHECK(configuration.capture.max_stack_depth.value == 96U);
  CHECK(configuration.capture.max_stack_depth.source == noleax::config::ValueSource::kCommandLine);
  CHECK(configuration.target.args.value == std::vector<std::string>{"from-cli"});
  CHECK(configuration.target.args.source == noleax::config::ValueSource::kCommandLine);
  CHECK(configuration.patch.verify.value);
  CHECK(configuration.patch.verify.source == noleax::config::ValueSource::kCommandLine);
  CHECK(configuration.trace.compression.source == noleax::config::ValueSource::kDefault);
}

TEST_CASE("operation validation checks capture, injection, and relevance rules", "[config]") {
  TemporaryDirectory temporary;
  const auto target = temporary.path() / "app.exe";
  write_file(target);

  auto run = noleax::config::make_default_configuration();
  run.operation.value = noleax::config::Operation::kRun;
  run.target.path.value = target;
  CHECK_NOTHROW(noleax::config::validate_configuration(run));

  run.capture.max_stack_depth.value = 0U;
  CHECK_THROWS_AS(noleax::config::validate_configuration(run), noleax::config::ConfigError);
  run.capture.max_stack_depth.value = 64U;
  run.capture.duration.value = std::chrono::nanoseconds::zero();
  CHECK_THROWS_AS(noleax::config::validate_configuration(run), noleax::config::ConfigError);
  run.capture.duration.value = std::nullopt;
  run.analysis.mode.value = noleax::config::AnalysisMode::kOutstanding;
  CHECK_THROWS_AS(noleax::config::validate_configuration(run), noleax::config::ConfigError);
  run.analysis.mode.value = noleax::config::AnalysisMode::kEvents;
  run.target.working_directory.value = target;
  CHECK_THROWS_AS(noleax::config::validate_configuration(run), noleax::config::ConfigError);

  auto attach = noleax::config::make_default_configuration();
  attach.operation.value = noleax::config::Operation::kAttach;
  attach.target.pid.value = 42U;
#if !defined(_WIN32)
  // The Linux default injection method (ld-preload) has no attach channel; pin a
  // schema-valid one here — platform capability is enforced at execution, not validation.
  attach.injection.method.value = noleax::config::InjectionMethod::kThreadHijack;
#endif
  CHECK_NOTHROW(noleax::config::validate_configuration(attach));
  attach.injection.method.value = noleax::config::InjectionMethod::kEntrypointCode;
  CHECK_THROWS_AS(noleax::config::validate_configuration(attach), noleax::config::ConfigError);

  auto doctor = noleax::config::make_default_configuration();
  doctor.operation.value = noleax::config::Operation::kDoctor;
  CHECK_NOTHROW(noleax::config::validate_configuration(doctor));
  doctor.trace.max_files.value = 2U;
  CHECK_THROWS_AS(noleax::config::validate_configuration(doctor), noleax::config::ConfigError);
}

TEST_CASE("analysis validation enforces window sort and group rules", "[config]") {
  using namespace std::chrono_literals;
  TemporaryDirectory temporary;
  const auto trace = temporary.path() / "input.nlx";
  write_file(trace);

  auto configuration = noleax::config::make_default_configuration();
  configuration.operation.value = noleax::config::Operation::kAnalyze;
  configuration.analysis.inputs.value = {trace};
  configuration.analysis.mode.value = noleax::config::AnalysisMode::kOutstanding;
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  configuration.analysis.from.value = time_bound(1s);
  configuration.analysis.to.value = time_bound(2s);
  configuration.analysis.end.value = time_bound(3s);
  configuration.filters.min_size.value = 16U;
  configuration.filters.max_size.value = 1024U;
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  configuration.analysis.from.value = time_bound(3s);
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.from.value = time_bound(1s);
  configuration.analysis.end.value = time_bound(1s);
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.end.value = time_bound(3s);
  configuration.filters.min_size.value = 2048U;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);

  configuration.filters.min_size.value = 16U;
  configuration.analysis.mode.value = noleax::config::AnalysisMode::kEvents;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.end.value.reset();
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  configuration.analysis.sort.value = noleax::config::AnalysisSort::kCalls;
  configuration.analysis.sort.source = noleax::config::ValueSource::kCommandLine;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);

  configuration.analysis.group_by.value = noleax::config::AnalysisGroupBy::kStack;
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
  configuration.analysis.sort.value = noleax::config::AnalysisSort::kBytes;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);

  configuration.analysis.mode.value = noleax::config::AnalysisMode::kOutstanding;
  configuration.analysis.end.value = time_bound(2s);
  configuration.analysis.end.source = noleax::config::ValueSource::kCommandLine;
  configuration.analysis.from.value = time_bound(3s);
  configuration.analysis.to.value.reset();
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.from.value = time_bound(1s);
  configuration.analysis.end.value.reset();
  configuration.analysis.to.value = time_bound(2s);

  configuration.analysis.mode.value = noleax::config::AnalysisMode::kOutstanding;
  configuration.analysis.sort.value = noleax::config::AnalysisSort::kCalls;
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
  configuration.analysis.sort.value = noleax::config::AnalysisSort::kAllocBytes;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);

  // leaks + group_by without an explicit sort must stay valid (defaults to bytes).
  configuration.analysis.sort.value = noleax::config::AnalysisSort::kAllocBytes;
  configuration.analysis.sort.source = noleax::config::ValueSource::kDefault;
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  // symbols.mode off conflicts with explicitly configured paths or servers.
  configuration.symbols.mode.value = noleax::config::SymbolMode::kOff;
  configuration.symbols.paths.value = {temporary.path() / "symbols"};
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.symbols.paths.value = {};
  configuration.symbols.servers.value = {"https://symbols.example"};
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.symbols.servers.value = {};
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  configuration.symbols.mode.value = noleax::config::SymbolMode::kRequired;
  configuration.symbols.servers.value = {"https://symbols.example"};
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
}

TEST_CASE("memory snapshot capture intervals are validated", "[config]") {
  using namespace std::chrono_literals;
  TemporaryDirectory temporary;
  const auto target = temporary.path() / "app.exe";
  write_file(target);

  auto run = noleax::config::make_default_configuration();
  run.operation.value = noleax::config::Operation::kRun;
  run.target.path.value = target;
  CHECK(run.capture.memory_counters_interval.value == 1s);
  CHECK(run.capture.memory_map_interval.value == 1s);
  CHECK_NOTHROW(noleax::config::validate_configuration(run));

  // 0s disables a sampler; 1h is the upper bound.
  run.capture.memory_counters_interval.value = 0ns;
  run.capture.memory_map_interval.value = 1h;
  CHECK_NOTHROW(noleax::config::validate_configuration(run));
  run.capture.memory_counters_interval.value = 1h + 1ns;
  CHECK_THROWS_AS(noleax::config::validate_configuration(run), noleax::config::ConfigError);
  run.capture.memory_counters_interval.value = 1s;
  run.capture.memory_map_interval.value = 1h + 1ns;
  CHECK_THROWS_AS(noleax::config::validate_configuration(run), noleax::config::ConfigError);
  run.capture.memory_map_interval.value = 1s;
  CHECK_NOTHROW(noleax::config::validate_configuration(run));

  // Non-capture operations reject the snapshot interval keys.
  auto doctor = noleax::config::make_default_configuration();
  doctor.operation.value = noleax::config::Operation::kDoctor;
  doctor.capture.memory_counters_interval.value = 2s;
  CHECK_THROWS_AS(noleax::config::validate_configuration(doctor), noleax::config::ConfigError);
  doctor.capture.memory_counters_interval.value = 1s;
  doctor.capture.memory_map_interval.value = 0ns;
  CHECK_THROWS_AS(noleax::config::validate_configuration(doctor), noleax::config::ConfigError);
}

TEST_CASE("memory analysis mode rejects event-only settings", "[config]") {
  using namespace std::chrono_literals;
  TemporaryDirectory temporary;
  const auto trace = temporary.path() / "input.nlx";
  write_file(trace);

  auto configuration = noleax::config::make_default_configuration();
  configuration.operation.value = noleax::config::Operation::kAnalyze;
  configuration.analysis.inputs.value = {trace};
  configuration.analysis.mode.value = noleax::config::AnalysisMode::kMemory;
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  // Time windows stay valid; sequence windows do not (snapshots have no sequence).
  configuration.analysis.from.value = time_bound(1s);
  configuration.analysis.to.value = time_bound(2s);
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
  configuration.analysis.from.value = sequence_bound(1U);
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.from.value = time_bound(1s);
  configuration.analysis.to.value = sequence_bound(2U);
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.to.value = time_bound(2s);

  configuration.analysis.end.value = time_bound(3s);
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.end.value.reset();

  configuration.analysis.group_by.value = noleax::config::AnalysisGroupBy::kStack;
  configuration.analysis.group_by.source = noleax::config::ValueSource::kCommandLine;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.group_by.value.reset();
  configuration.analysis.group_by.source = noleax::config::ValueSource::kDefault;

  configuration.analysis.sort.source = noleax::config::ValueSource::kCommandLine;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.sort.source = noleax::config::ValueSource::kDefault;

  configuration.analysis.trim_agent_frames.value = false;
  configuration.analysis.trim_agent_frames.source = noleax::config::ValueSource::kCommandLine;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.trim_agent_frames.value = true;
  configuration.analysis.trim_agent_frames.source = noleax::config::ValueSource::kDefault;

  configuration.filters.apis.value = {"RtlAllocateHeap"};
  configuration.filters.apis.source = noleax::config::ValueSource::kCommandLine;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.filters.apis.value = {};
  configuration.filters.apis.source = noleax::config::ValueSource::kDefault;
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
}

TEST_CASE("symbols listing validation enforces input fields and symbol mode rules", "[config]") {
  TemporaryDirectory temporary;
  const auto input = temporary.path() / "foo.dll";
  write_file(input);

  auto configuration = noleax::config::make_default_configuration();
  configuration.operation.value = noleax::config::Operation::kSymbols;

  // symbol_listing.input is required and must exist.
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.symbol_listing.input.value = temporary.path() / "missing.dll";
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.symbol_listing.input.value = input;
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  // symbol_listing.output must differ from the input.
  configuration.symbol_listing.output.value = input;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.symbol_listing.output.value = temporary.path() / "symbols.json";
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
  configuration.symbol_listing.output.value.reset();

  // An explicitly empty fields selection is invalid; duplicates are rejected.
  configuration.symbol_listing.fields.source = noleax::config::ValueSource::kCommandLine;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.symbol_listing.fields.value = {noleax::analyzer::SymbolListingField::kName,
                                               noleax::analyzer::SymbolListingField::kName};
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.symbol_listing.fields.value = {noleax::analyzer::SymbolListingField::kName,
                                               noleax::analyzer::SymbolListingField::kRva};
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
  configuration.symbol_listing.fields.value = {};
  configuration.symbol_listing.fields.source = noleax::config::ValueSource::kDefault;

  // symbols.mode off conflicts with the enumeration this command performs.
  configuration.symbols.mode.value = noleax::config::SymbolMode::kOff;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.symbols.mode.value = noleax::config::SymbolMode::kRequired;
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
  configuration.symbols.mode.value = noleax::config::SymbolMode::kAuto;
  configuration.symbols.paths.value = {temporary.path()};
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
  configuration.symbols.paths.value = {};

  // Sections that are irrelevant to symbols must stay at their defaults.
  configuration.analysis.mode.value = noleax::config::AnalysisMode::kOutstanding;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.analysis.mode.value = noleax::config::AnalysisMode::kEvents;
  configuration.capture.live.value = true;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.capture.live.value = false;
  configuration.patch.verify.value = false;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  configuration.patch.verify.value = true;
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  // Other operations reject symbol_listing overrides.
  auto doctor = noleax::config::make_default_configuration();
  doctor.operation.value = noleax::config::Operation::kDoctor;
  doctor.symbol_listing.format.value = noleax::config::OutputFormat::kJson;
  CHECK_THROWS_AS(noleax::config::validate_configuration(doctor), noleax::config::ConfigError);
}
