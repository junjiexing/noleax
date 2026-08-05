#include "noleax/cli/command_line.hpp"

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"

namespace {

[[nodiscard]] noleax::cli::ParsedCommandLine parse(std::vector<std::string> arguments,
                                                   const std::filesystem::path& current_directory) {
  arguments.insert(arguments.begin(), "noleax");
  std::vector<const char*> argv;
  argv.reserve(arguments.size());
  for (const auto& argument : arguments) {
    argv.push_back(argument.c_str());
  }
  return noleax::cli::parse_command_line(static_cast<int>(argv.size()), argv.data(),
                                         current_directory);
}

}  // namespace

TEST_CASE("run CLI maps every capture option and target operands", "[cli][config]") {
  using namespace std::chrono_literals;
  const auto working_directory = std::filesystem::current_path();
  const auto parsed = parse({"--log-level",
                             "debug",
                             "--color",
                             "never",
                             "run",
                             "--working-directory",
                             "work",
                             "--inject-method",
                             "thread-hijack",
                             "--agent",
                             "agent.dll",
                             "--inject-timeout",
                             "2s",
                             "--hook-profile",
                             "windows-nt-heap",
                             "--max-stack-depth",
                             "96",
                             "--capture-min-size",
                             "4KiB",
                             "--buffer-size",
                             "8MiB",
                             "--max-trace-size",
                             "64MiB",
                             "--max-trace-files",
                             "3",
                             "--on-trace-full",
                             "rotate",
                             "--flush-interval",
                             "10ms",
                             "--compression",
                             "zstd",
                             "--compression-level",
                             "1",
                             "--trace",
                             "trace.nlx",
                             "--capture-duration",
                             "5m",
                             "--memory-counters-interval",
                             "500ms",
                             "--memory-map-interval",
                             "0s",
                             "--",
                             "app.exe",
                             "--target-flag"},
                            working_directory);

  const auto& overrides = parsed.overrides;
  CHECK(overrides.operation.value == noleax::config::Operation::kRun);
  CHECK(overrides.diagnostics.log_level.value == noleax::config::LogLevel::kDebug);
  CHECK(overrides.diagnostics.color.value == noleax::config::ColorMode::kNever);
  CHECK(overrides.target.path.value == working_directory / "app.exe");
  CHECK(overrides.target.args.value == std::vector<std::string>{"--target-flag"});
  CHECK(overrides.target.working_directory.value == working_directory / "work");
  CHECK(overrides.injection.method.value == noleax::config::InjectionMethod::kThreadHijack);
  CHECK(overrides.injection.agent_path.value == working_directory / "agent.dll");
  CHECK(overrides.injection.timeout.value == 2s);
  CHECK(overrides.capture.hook_profile.value == noleax::config::HookProfile::kWindowsNtHeap);
  CHECK(overrides.capture.max_stack_depth.value == 96U);
  CHECK(overrides.capture.min_size.value == 4U * 1024U);
  CHECK(overrides.capture.duration.value == 5min);
  CHECK(overrides.capture.memory_counters_interval.value == 500ms);
  CHECK(overrides.capture.memory_map_interval.value == 0ns);
  CHECK(overrides.trace.path.value == working_directory / "trace.nlx");
  CHECK(overrides.trace.buffer_size.value == 8U * 1024U * 1024U);
  CHECK(overrides.trace.max_file_size.value == 64U * 1024U * 1024U);
  CHECK(overrides.trace.max_files.value == 3U);
  CHECK(overrides.trace.on_full.value == noleax::config::TraceFullPolicy::kRotate);
  CHECK(overrides.trace.flush_interval.value == 10ms);
  CHECK(overrides.trace.compression.value == noleax::config::Compression::kZstd);
  CHECK(overrides.trace.compression_level.value == 1);
}

TEST_CASE("attach and patch expose positive and negative boolean overrides", "[cli][config]") {
  const auto current_directory = std::filesystem::current_path();

  const auto attach_true = parse({"attach", "--pid", "7", "--unload-on-stop"}, current_directory);
  CHECK(attach_true.overrides.target.pid.value == 7U);
  CHECK(attach_true.overrides.injection.unload_on_stop.specified);
  CHECK(attach_true.overrides.injection.unload_on_stop.value);

  const auto attach_false =
      parse({"attach", "--pid", "7", "--no-unload-on-stop"}, current_directory);
  CHECK(attach_false.overrides.injection.unload_on_stop.specified);
  CHECK_FALSE(attach_false.overrides.injection.unload_on_stop.value);

  const auto patch = parse(
      {"patch", "--input", "in.exe", "--output", "out.exe", "--patch-method", "entrypoint-section",
       "--agent-name", "agent.dll", "--allow-break-signature", "--no-verify"},
      current_directory);
  CHECK(patch.overrides.operation.value == noleax::config::Operation::kPatch);
  CHECK(patch.overrides.patch.input.value == current_directory / "in.exe");
  CHECK(patch.overrides.patch.output.value == current_directory / "out.exe");
  CHECK(patch.overrides.patch.allow_break_signature.value);
  CHECK_FALSE(patch.overrides.patch.verify.value);
}

TEST_CASE("doctor CLI maps optional read-only probes", "[cli][config][doctor]") {
  const auto current_directory = std::filesystem::current_path();
  const auto parsed = parse({"doctor", "--target", "app.exe", "--pid", "42", "--inject-method",
                             "remote-thread", "--agent", "agent.dll"},
                            current_directory);

  CHECK(parsed.overrides.operation.value == noleax::config::Operation::kDoctor);
  CHECK(parsed.overrides.target.path.value == current_directory / "app.exe");
  CHECK(parsed.overrides.target.pid.value == 42U);
  CHECK(parsed.overrides.injection.method.value == noleax::config::InjectionMethod::kRemoteThread);
  CHECK(parsed.overrides.injection.agent_path.value == current_directory / "agent.dll");
}

TEST_CASE("analyze CLI replaces arrays and maps all filters", "[cli][config]") {
  using namespace std::chrono_literals;
  const auto current_directory = std::filesystem::current_path();
  const auto parsed = parse({"analyze",
                             "--mode",
                             "leaks",
                             "--format",
                             "csv",
                             "--output",
                             "result.csv",
                             "--from",
                             "1s",
                             "--to",
                             "2s",
                             "--end",
                             "3s",
                             "--group-by",
                             "stack",
                             "--sort",
                             "calls",
                             "--min-size",
                             "16B",
                             "--max-size",
                             "1MiB",
                             "--event",
                             "alloc",
                             "--event",
                             "realloc",
                             "--thread",
                             "10",
                             "--thread",
                             "11",
                             "--api",
                             "malloc",
                             "--module",
                             "app*",
                             "--stack-module",
                             "engine*",
                             "--allocation-id",
                             "99",
                             "--status",
                             "success",
                             "--status",
                             "preexisting",
                             "--symbols",
                             "auto",
                             "--symbol-path",
                             "symbols",
                             "--symbol-server",
                             "https://server",
                             "one.nlx",
                             "two.nlx"},
                            current_directory);

  const auto& overrides = parsed.overrides;
  CHECK(overrides.operation.value == noleax::config::Operation::kAnalyze);
  CHECK(overrides.analysis.inputs.value ==
        std::vector<std::filesystem::path>{current_directory / "one.nlx",
                                           current_directory / "two.nlx"});
  CHECK(overrides.analysis.mode.value == noleax::config::AnalysisMode::kOutstanding);
  CHECK(overrides.analysis.format.value == noleax::config::OutputFormat::kCsv);
  CHECK(overrides.analysis.output.value == current_directory / "result.csv");
  CHECK(overrides.analysis.from.value->time == 1s);
  CHECK(overrides.analysis.to.value->time == 2s);
  CHECK(overrides.analysis.end.value->time == 3s);
  CHECK(overrides.analysis.group_by.value == noleax::config::AnalysisGroupBy::kStack);
  CHECK(overrides.analysis.sort.value == noleax::config::AnalysisSort::kCalls);
  CHECK(overrides.filters.min_size.value == 16U);
  CHECK(overrides.filters.max_size.value == 1024U * 1024U);
  CHECK(overrides.filters.events.value ==
        std::vector{noleax::config::EventType::kAlloc, noleax::config::EventType::kRealloc});
  CHECK(overrides.filters.threads.value == std::vector<std::uint64_t>{10U, 11U});
  CHECK(overrides.filters.apis.value == std::vector<std::string>{"malloc"});
  CHECK(overrides.filters.modules.value == std::vector<std::string>{"app*"});
  CHECK(overrides.filters.stack_modules.value == std::vector<std::string>{"engine*"});
  CHECK(overrides.filters.allocation_ids.value == std::vector<std::uint64_t>{99U});
  CHECK(overrides.filters.statuses.value == std::vector{noleax::config::EventStatus::kSuccess,
                                                        noleax::config::EventStatus::kPreexisting});
  CHECK(overrides.symbols.paths.value ==
        std::vector<std::filesystem::path>{current_directory / "symbols"});
  CHECK(overrides.symbols.servers.value == std::vector<std::string>{"https://server"});
}

TEST_CASE("analyze CLI parses the memory mode", "[cli][config]") {
  const auto current_directory = std::filesystem::current_path();
  const auto parsed =
      parse({"analyze", "--mode", "memory", "--from", "1s", "one.nlx"}, current_directory);
  CHECK(parsed.overrides.analysis.mode.value == noleax::config::AnalysisMode::kMemory);
  CHECK(parsed.overrides.analysis.from.value->time == std::chrono::seconds{1});
}

TEST_CASE("analyze CLI parses time and sequence window bounds", "[cli][config]") {
  using namespace std::chrono_literals;
  const auto current_directory = std::filesystem::current_path();

  const auto time = parse({"analyze", "--from", "10s", "--to", "20s", "--end", "30s", "one.nlx"},
                          current_directory);
  REQUIRE(time.overrides.analysis.from.value.has_value());
  CHECK(time.overrides.analysis.from.value->time == 10s);
  CHECK_FALSE(time.overrides.analysis.from.value->sequence.has_value());
  CHECK(time.overrides.analysis.to.value->time == 20s);
  CHECK(time.overrides.analysis.end.value->time == 30s);

  const auto sequence = parse(
      {"analyze", "--from", "#123", "--to", "#456", "--end", "#789", "one.nlx"}, current_directory);
  REQUIRE(sequence.overrides.analysis.from.value.has_value());
  CHECK(sequence.overrides.analysis.from.value->sequence == 123U);
  CHECK_FALSE(sequence.overrides.analysis.from.value->time.has_value());
  CHECK(sequence.overrides.analysis.to.value->sequence == 456U);
  CHECK(sequence.overrides.analysis.end.value->sequence == 789U);

  for (const auto* invalid : {"#", "#abc", "#18446744073709551616"}) {
    CAPTURE(invalid);
    CHECK_THROWS_AS(parse({"analyze", "--from", invalid, "one.nlx"}, current_directory),
                    noleax::config::ConfigError);
  }
}

TEST_CASE("config commands and command line diagnostics are explicit", "[cli][config]") {
  const auto current_directory = std::filesystem::current_path();
  const auto parsed =
      parse({"--config", "noleax.toml", "config", "print-effective"}, current_directory);
  CHECK(parsed.config_path == current_directory / "noleax.toml");
  CHECK(parsed.meta_command == noleax::cli::MetaCommand::kPrintEffectiveConfig);

  try {
    static_cast<void>(parse({"--help"}, current_directory));
    FAIL("--help should request an early CLI exit");
  } catch (const noleax::cli::CommandLineExit& exit) {
    CHECK(exit.exit_code() == 0);
    CHECK(exit.standard_output().find("Hook-based memory event capture") != std::string::npos);
  }

  try {
    static_cast<void>(parse({"run", "--unknown"}, current_directory));
    FAIL("unknown options must fail");
  } catch (const noleax::cli::CommandLineExit& exit) {
    CHECK(exit.exit_code() == 1);
    CHECK_FALSE(exit.standard_error().empty());
  }

  CHECK_THROWS_AS(parse({"patch", "--verify=false"}, current_directory),
                  noleax::cli::CommandLineExit);
}

TEST_CASE("omitted CLI options preserve config values while present arrays replace them",
          "[cli][config]") {
  const auto current_directory = std::filesystem::current_path();
  auto configuration = noleax::config::make_default_configuration();

  noleax::config::ConfigurationOverrides file;
  file.analysis.inputs.set({current_directory / "from-config.nlx"});
  file.analysis.format.set(noleax::config::OutputFormat::kJson);
  file.filters.apis.set({"config-api-1", "config-api-2"});
  noleax::config::apply_overrides(configuration, file, noleax::config::ValueSource::kConfig);

  const auto parsed = parse({"analyze", "--api", "cli-api", "from-cli.nlx"}, current_directory);
  noleax::config::apply_overrides(configuration, parsed.overrides,
                                  noleax::config::ValueSource::kCommandLine);

  CHECK(configuration.analysis.inputs.value ==
        std::vector<std::filesystem::path>{current_directory / "from-cli.nlx"});
  CHECK(configuration.analysis.inputs.source == noleax::config::ValueSource::kCommandLine);
  CHECK(configuration.analysis.format.value == noleax::config::OutputFormat::kJson);
  CHECK(configuration.analysis.format.source == noleax::config::ValueSource::kConfig);
  CHECK(configuration.filters.apis.value == std::vector<std::string>{"cli-api"});
  CHECK(configuration.filters.apis.source == noleax::config::ValueSource::kCommandLine);
}

TEST_CASE("analyze CLI maps trim-agent-frames boolean options", "[cli][config]") {
  const auto current_directory = std::filesystem::current_path();

  const auto trimmed = parse({"analyze", "--trim-agent-frames", "one.nlx"}, current_directory);
  CHECK(trimmed.overrides.analysis.trim_agent_frames.specified);
  CHECK(trimmed.overrides.analysis.trim_agent_frames.value);

  const auto untrimmed = parse({"analyze", "--no-trim-agent-frames", "one.nlx"}, current_directory);
  CHECK(untrimmed.overrides.analysis.trim_agent_frames.specified);
  CHECK_FALSE(untrimmed.overrides.analysis.trim_agent_frames.value);
}

TEST_CASE("analyze CLI maps symbol modes", "[cli][config]") {
  const auto current_directory = std::filesystem::current_path();

  const auto off = parse({"analyze", "--symbols", "off", "one.nlx"}, current_directory);
  CHECK(off.overrides.symbols.mode.value == noleax::config::SymbolMode::kOff);

  const auto required = parse({"analyze", "--symbols", "required", "one.nlx"}, current_directory);
  CHECK(required.overrides.symbols.mode.value == noleax::config::SymbolMode::kRequired);
}

TEST_CASE("run and attach CLI parse --custom-hook declarations", "[cli][config][custom-hook]") {
  using namespace std::chrono_literals;
  const auto current_directory = std::filesystem::current_path();

  const auto parsed = parse(
      {"run", "--custom-hook", "myalloc.dll:alloc=my_malloc,free=my_free", "--custom-hook",
       "jealloc.dll:alloc_pdb=jealloc!je_malloc,free_rva=0x1a210,realloc=je_realloc,size_arg=1,"
       "ptr_arg=2,result_arg=0,kind=calloc,count_arg=3,free_size_arg=4,forced=true,"
       "wait_module=10s",
       "app.exe"},
      current_directory);
  REQUIRE(parsed.overrides.custom_hooks.specified);
  REQUIRE(parsed.overrides.custom_hooks.value.size() == 2U);

  const auto& first = parsed.overrides.custom_hooks.value.at(0U);
  CHECK(first.module == "myalloc.dll");
  CHECK(first.alloc.export_name == "my_malloc");
  CHECK(first.free.export_name == "my_free");
  CHECK_FALSE(first.realloc.declared());
  CHECK(first.size_arg == 0U);
  CHECK(first.wait_module == 0ns);

  const auto& second = parsed.overrides.custom_hooks.value.at(1U);
  CHECK(second.module == "jealloc.dll");
  CHECK(second.alloc.pdb_symbol == "jealloc!je_malloc");
  CHECK(second.free.rva == 0x1a210U);
  CHECK(second.realloc.export_name == "je_realloc");
  CHECK(second.size_arg == 1U);
  CHECK(second.ptr_arg == 2U);
  CHECK(second.result_arg == 0U);
  CHECK(second.kind == noleax::config::CustomHookKind::kCalloc);
  CHECK(second.count_arg == 3U);
  CHECK(second.free_size_arg == 4U);
  CHECK(second.forced);
  CHECK(second.wait_module == 10s);

  const auto attached =
      parse({"attach", "--pid", "42", "--custom-hook", "m.dll:alloc=a,free=f"}, current_directory);
  REQUIRE(attached.overrides.custom_hooks.specified);
  CHECK(attached.overrides.custom_hooks.value.size() == 1U);
}

TEST_CASE("custom-hook CLI rejects malformed specs and other subcommands",
          "[cli][config][custom-hook]") {
  const auto current_directory = std::filesystem::current_path();

  CHECK_THROWS_AS(parse({"run", "--custom-hook", "myalloc.dll", "app.exe"}, current_directory),
                  noleax::config::ConfigError);
  CHECK_THROWS_AS(parse({"run", "--custom-hook", ":alloc=a,free=f", "app.exe"}, current_directory),
                  noleax::config::ConfigError);
  CHECK_THROWS_AS(parse({"run", "--custom-hook", "m.dll:alloc", "app.exe"}, current_directory),
                  noleax::config::ConfigError);
  CHECK_THROWS_AS(
      parse({"run", "--custom-hook", "m.dll:alloc=a,alloc=b,free=f", "app.exe"}, current_directory),
      noleax::config::ConfigError);
  CHECK_THROWS_AS(parse({"run", "--custom-hook", "m.dll:alloc=a,free=f,size_arg=8", "app.exe"},
                        current_directory),
                  noleax::config::ConfigError);
  CHECK_THROWS_AS(
      parse({"run", "--custom-hook", "m.dll:alloc=a,free=f,bogus=1", "app.exe"}, current_directory),
      noleax::config::ConfigError);
  CHECK_THROWS_AS(parse({"run", "--custom-hook", "m.dll:alloc=a,free=f,wait_module=5x", "app.exe"},
                        current_directory),
                  noleax::config::ConfigError);
  CHECK_THROWS_AS(parse({"run", "--custom-hook", "m.dll:alloc=a,free=f,alloc_rva=0xzz", "app.exe"},
                        current_directory),
                  noleax::config::ConfigError);

  // The option is not registered on patch/analyze/doctor.
  CHECK_THROWS_AS(
      parse({"analyze", "--custom-hook", "m.dll:alloc=a,free=f", "x.nlx"}, current_directory),
      noleax::cli::CommandLineExit);
}

TEST_CASE("symbols CLI maps every listing option and the symbol search path", "[cli][config]") {
  const auto current_directory = std::filesystem::current_path();
  const auto parsed =
      parse({"symbols",       "--format",      "json",    "--output",        "symbols.json",
             "--name",        "*alloc*",       "--name",  "?free*",          "--match-case",
             "--kind",        "function",      "--kind",  "public",          "--fields",
             "name,rva,kind", "--symbol-path", "symbols", "--symbol-server", "https://server",
             "foo.dll"},
            current_directory);

  const auto& overrides = parsed.overrides;
  CHECK(overrides.operation.value == noleax::config::Operation::kSymbols);
  CHECK(overrides.symbol_listing.input.value == current_directory / "foo.dll");
  CHECK(overrides.symbol_listing.format.value == noleax::config::OutputFormat::kJson);
  CHECK(overrides.symbol_listing.output.value == current_directory / "symbols.json");
  CHECK(overrides.symbol_listing.name.value == std::vector<std::string>{"*alloc*", "?free*"});
  CHECK(overrides.symbol_listing.match_case.specified);
  CHECK(overrides.symbol_listing.match_case.value);
  CHECK(overrides.symbol_listing.kind.value == std::vector{noleax::analyzer::SymbolKind::kFunction,
                                                           noleax::analyzer::SymbolKind::kPublic});
  CHECK(overrides.symbol_listing.fields.value ==
        std::vector{noleax::analyzer::SymbolListingField::kName,
                    noleax::analyzer::SymbolListingField::kRva,
                    noleax::analyzer::SymbolListingField::kKind});
  CHECK(overrides.symbols.paths.value ==
        std::vector<std::filesystem::path>{current_directory / "symbols"});
  CHECK(overrides.symbols.servers.value == std::vector<std::string>{"https://server"});
}

TEST_CASE("symbols CLI defaults and boolean overrides", "[cli][config]") {
  const auto current_directory = std::filesystem::current_path();

  const auto minimal = parse({"symbols", "foo.dll"}, current_directory);
  CHECK(minimal.overrides.operation.value == noleax::config::Operation::kSymbols);
  CHECK(minimal.overrides.symbol_listing.input.value == current_directory / "foo.dll");
  CHECK_FALSE(minimal.overrides.symbol_listing.format.specified);
  CHECK_FALSE(minimal.overrides.symbol_listing.output.specified);
  CHECK_FALSE(minimal.overrides.symbol_listing.name.specified);
  CHECK_FALSE(minimal.overrides.symbol_listing.match_case.specified);
  CHECK_FALSE(minimal.overrides.symbol_listing.kind.specified);
  CHECK_FALSE(minimal.overrides.symbol_listing.fields.specified);

  const auto insensitive = parse({"symbols", "--no-match-case", "foo.dll"}, current_directory);
  CHECK(insensitive.overrides.symbol_listing.match_case.specified);
  CHECK_FALSE(insensitive.overrides.symbol_listing.match_case.value);
}

TEST_CASE("symbols CLI rejects malformed options", "[cli][config]") {
  const auto current_directory = std::filesystem::current_path();

  CHECK_THROWS_AS(parse({"symbols", "one.dll", "two.dll"}, current_directory),
                  noleax::config::ConfigError);
  CHECK_THROWS_AS(parse({"symbols", "--format", "yaml", "foo.dll"}, current_directory),
                  noleax::config::ConfigError);
  CHECK_THROWS_AS(parse({"symbols", "--kind", "bogus", "foo.dll"}, current_directory),
                  noleax::config::ConfigError);
  CHECK_THROWS_AS(parse({"symbols", "--fields", "name,bogus", "foo.dll"}, current_directory),
                  noleax::config::ConfigError);
  CHECK_THROWS_AS(parse({"symbols", "--fields", "", "foo.dll"}, current_directory),
                  noleax::config::ConfigError);
  CHECK_THROWS_AS(parse({"symbols", "--fields", "name,", "foo.dll"}, current_directory),
                  noleax::config::ConfigError);

  // Unknown option and an option registered only on other subcommands.
  CHECK_THROWS_AS(parse({"symbols", "--bogus", "foo.dll"}, current_directory),
                  noleax::cli::CommandLineExit);
  CHECK_THROWS_AS(parse({"symbols", "--symbols", "off", "foo.dll"}, current_directory),
                  noleax::cli::CommandLineExit);
}
