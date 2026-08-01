#include "noleax/cli/command_line.hpp"

#include <CLI/CLI.hpp>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"
#include "noleax/config/value_parser.hpp"
#include "noleax/version.hpp"

namespace noleax::cli {
namespace {

struct TextOption {
  std::string value;
  CLI::Option* option{nullptr};
};

struct ListOption {
  std::vector<std::string> values;
  CLI::Option* option{nullptr};
};

struct BooleanOption {
  bool positive{false};
  bool negative{false};
  CLI::Option* positive_option{nullptr};
  CLI::Option* negative_option{nullptr};
};

struct InjectionBindings {
  TextOption method;
  TextOption agent_path;
  TextOption timeout;
};

struct CaptureBindings {
  TextOption hook_profile;
  TextOption max_stack_depth;
  TextOption min_size;
  TextOption buffer_size;
  TextOption max_trace_size;
  TextOption max_trace_files;
  TextOption on_trace_full;
  TextOption flush_interval;
  TextOption compression;
  TextOption compression_level;
  TextOption trace_path;
  TextOption duration;
};

struct RunBindings {
  TextOption working_directory;
  InjectionBindings injection;
  CaptureBindings capture;
  std::vector<std::string> target_and_args;
};

struct AttachBindings {
  TextOption pid;
  InjectionBindings injection;
  CaptureBindings capture;
  BooleanOption unload_on_stop;
};

struct PatchBindings {
  TextOption input;
  TextOption output;
  TextOption method;
  TextOption agent_name;
  BooleanOption allow_break_signature;
  BooleanOption verify;
};

struct AnalyzeBindings {
  TextOption mode;
  TextOption format;
  TextOption output;
  TextOption from;
  TextOption to;
  TextOption end;
  TextOption group_by;
  TextOption sort;
  TextOption min_size;
  TextOption max_size;
  ListOption events;
  ListOption threads;
  ListOption apis;
  ListOption modules;
  ListOption stack_modules;
  ListOption allocation_ids;
  ListOption statuses;
  TextOption symbols;
  ListOption symbol_paths;
  ListOption symbol_servers;
  std::vector<std::string> inputs;
};

struct DoctorBindings {
  TextOption target;
  TextOption pid;
  TextOption injection_method;
  TextOption agent_path;
};

[[nodiscard]] bool was_set(const TextOption& binding) {
  return binding.option != nullptr && binding.option->count() != 0U;
}

[[nodiscard]] bool was_set(const ListOption& binding) {
  return binding.option != nullptr && binding.option->count() != 0U;
}

void add_text_option(CLI::App& app, TextOption& binding, std::string name,
                     std::string description) {
  binding.option = app.add_option(std::move(name), binding.value, std::move(description));
}

void add_list_option(CLI::App& app, ListOption& binding, std::string name,
                     std::string description) {
  binding.option = app.add_option(std::move(name), binding.values, std::move(description));
  binding.option->allow_extra_args(false);
}

void add_boolean_option(CLI::App& app, BooleanOption& binding, std::string positive_name,
                        std::string negative_name, const std::string& description) {
  binding.positive_option = app.add_flag(std::move(positive_name), binding.positive, description);
  binding.negative_option =
      app.add_flag(std::move(negative_name), binding.negative, "Disable: " + description);
  binding.positive_option->disable_flag_override();
  binding.negative_option->disable_flag_override();
  binding.positive_option->excludes(binding.negative_option);
  binding.negative_option->excludes(binding.positive_option);
}

[[nodiscard]] std::optional<bool> boolean_value(const BooleanOption& binding) {
  if (binding.positive_option->count() != 0U) {
    return true;
  }
  if (binding.negative_option->count() != 0U) {
    return false;
  }
  return std::nullopt;
}

void add_injection_options(CLI::App& app, InjectionBindings& bindings) {
  add_text_option(app, bindings.method, "--inject-method", "Agent injection method");
  add_text_option(app, bindings.agent_path, "--agent", "Path to the Noleax agent");
  add_text_option(app, bindings.timeout, "--inject-timeout", "Agent initialization timeout");
}

void add_capture_options(CLI::App& app, CaptureBindings& bindings) {
  add_text_option(app, bindings.hook_profile, "--hook-profile", "Memory API hook profile");
  add_text_option(app, bindings.max_stack_depth, "--max-stack-depth",
                  "Maximum captured stack depth");
  add_text_option(app, bindings.min_size, "--capture-min-size",
                  "Minimum allocation size to capture");
  add_text_option(app, bindings.buffer_size, "--buffer-size", "In-process trace buffer size");
  add_text_option(app, bindings.max_trace_size, "--max-trace-size", "Maximum trace file size");
  add_text_option(app, bindings.max_trace_files, "--max-trace-files",
                  "Maximum number of rotated trace files");
  add_text_option(app, bindings.on_trace_full, "--on-trace-full", "Trace full policy");
  add_text_option(app, bindings.flush_interval, "--flush-interval", "Trace flush interval");
  add_text_option(app, bindings.compression, "--compression", "Trace compression codec");
  add_text_option(app, bindings.compression_level, "--compression-level",
                  "Trace compression level");
  add_text_option(app, bindings.trace_path, "--trace", "Trace output path");
  add_text_option(app, bindings.duration, "--capture-duration", "Maximum capture duration");
}

[[noreturn]] void conversion_error(std::string_view option, const std::exception& error) {
  throw config::ConfigError{"command line option '" + std::string{option} + "': " + error.what()};
}

template <typename Enum>
[[nodiscard]] Enum parse_cli_enum(std::string_view value, std::string_view option) {
  try {
    return config::parse_enum_value<Enum>(value);
  } catch (const config::ValueParseError& error) {
    conversion_error(option, error);
  }
}

[[nodiscard]] std::uint64_t parse_cli_size(std::string_view value, std::string_view option) {
  try {
    return config::parse_byte_size(value);
  } catch (const config::ValueParseError& error) {
    conversion_error(option, error);
  }
}

[[nodiscard]] std::chrono::nanoseconds parse_cli_duration(std::string_view value,
                                                          std::string_view option) {
  try {
    return config::parse_duration(value);
  } catch (const config::ValueParseError& error) {
    conversion_error(option, error);
  }
}

[[nodiscard]] std::uint64_t parse_cli_unsigned(std::string_view value, std::uint64_t maximum,
                                               std::string_view option) {
  try {
    return config::parse_unsigned_integer(value, maximum, option);
  } catch (const config::ValueParseError& error) {
    conversion_error(option, error);
  }
}

[[nodiscard]] std::int64_t parse_cli_signed(std::string_view value, std::int64_t minimum,
                                            std::int64_t maximum, std::string_view option) {
  try {
    return config::parse_signed_integer(value, minimum, maximum, option);
  } catch (const config::ValueParseError& error) {
    conversion_error(option, error);
  }
}

[[nodiscard]] std::filesystem::path parse_cli_path(std::string_view value, std::string_view option,
                                                   const std::filesystem::path& current_directory) {
  if (value.empty()) {
    throw config::ConfigError{"command line option '" + std::string{option} +
                              "': path must not be empty"};
  }
  try {
    return config::normalize_path(value, current_directory);
  } catch (const std::exception& error) {
    conversion_error(option, error);
  }
}

[[nodiscard]] std::vector<std::filesystem::path> parse_cli_paths(
    const std::vector<std::string>& values, std::string_view option,
    const std::filesystem::path& current_directory) {
  std::vector<std::filesystem::path> result;
  result.reserve(values.size());
  for (const auto& value : values) {
    result.push_back(parse_cli_path(value, option, current_directory));
  }
  return result;
}

template <typename Enum>
[[nodiscard]] std::vector<Enum> parse_cli_enums(const std::vector<std::string>& values,
                                                std::string_view option) {
  std::vector<Enum> result;
  result.reserve(values.size());
  for (const auto& value : values) {
    result.push_back(parse_cli_enum<Enum>(value, option));
  }
  return result;
}

[[nodiscard]] std::vector<std::uint64_t> parse_cli_unsigned_list(
    const std::vector<std::string>& values, std::string_view option) {
  std::vector<std::uint64_t> result;
  result.reserve(values.size());
  for (const auto& value : values) {
    result.push_back(parse_cli_unsigned(value, std::numeric_limits<std::uint64_t>::max(), option));
  }
  return result;
}

void apply_injection_bindings(const InjectionBindings& bindings,
                              config::InjectionOverrides& overrides,
                              const std::filesystem::path& current_directory) {
  if (was_set(bindings.method)) {
    overrides.method.set(
        parse_cli_enum<config::InjectionMethod>(bindings.method.value, "--inject-method"));
  }
  if (was_set(bindings.agent_path)) {
    overrides.agent_path.set(
        parse_cli_path(bindings.agent_path.value, "--agent", current_directory));
  }
  if (was_set(bindings.timeout)) {
    overrides.timeout.set(parse_cli_duration(bindings.timeout.value, "--inject-timeout"));
  }
}

void apply_capture_bindings(const CaptureBindings& bindings, config::CaptureOverrides& capture,
                            config::TraceOverrides& trace,
                            const std::filesystem::path& current_directory) {
  if (was_set(bindings.hook_profile)) {
    capture.hook_profile.set(
        parse_cli_enum<config::HookProfile>(bindings.hook_profile.value, "--hook-profile"));
  }
  if (was_set(bindings.max_stack_depth)) {
    capture.max_stack_depth.set(static_cast<std::uint16_t>(
        parse_cli_unsigned(bindings.max_stack_depth.value,
                           std::numeric_limits<std::uint16_t>::max(), "--max-stack-depth")));
  }
  if (was_set(bindings.min_size)) {
    capture.min_size.set(parse_cli_size(bindings.min_size.value, "--capture-min-size"));
  }
  if (was_set(bindings.duration)) {
    capture.duration.set(parse_cli_duration(bindings.duration.value, "--capture-duration"));
  }
  if (was_set(bindings.trace_path)) {
    trace.path.set(parse_cli_path(bindings.trace_path.value, "--trace", current_directory));
  }
  if (was_set(bindings.buffer_size)) {
    trace.buffer_size.set(parse_cli_size(bindings.buffer_size.value, "--buffer-size"));
  }
  if (was_set(bindings.max_trace_size)) {
    trace.max_file_size.set(parse_cli_size(bindings.max_trace_size.value, "--max-trace-size"));
  }
  if (was_set(bindings.max_trace_files)) {
    trace.max_files.set(static_cast<std::uint32_t>(
        parse_cli_unsigned(bindings.max_trace_files.value,
                           std::numeric_limits<std::uint32_t>::max(), "--max-trace-files")));
  }
  if (was_set(bindings.on_trace_full)) {
    trace.on_full.set(
        parse_cli_enum<config::TraceFullPolicy>(bindings.on_trace_full.value, "--on-trace-full"));
  }
  if (was_set(bindings.flush_interval)) {
    trace.flush_interval.set(parse_cli_duration(bindings.flush_interval.value, "--flush-interval"));
  }
  if (was_set(bindings.compression)) {
    trace.compression.set(
        parse_cli_enum<config::Compression>(bindings.compression.value, "--compression"));
  }
  if (was_set(bindings.compression_level)) {
    trace.compression_level.set(static_cast<std::int32_t>(
        parse_cli_signed(bindings.compression_level.value, std::numeric_limits<std::int32_t>::min(),
                         std::numeric_limits<std::int32_t>::max(), "--compression-level")));
  }
}

void apply_run_bindings(const RunBindings& bindings, config::ConfigurationOverrides& overrides,
                        const std::filesystem::path& current_directory) {
  overrides.operation.set(config::Operation::kRun);
  if (was_set(bindings.working_directory)) {
    overrides.target.working_directory.set(
        parse_cli_path(bindings.working_directory.value, "--working-directory", current_directory));
  }
  if (!bindings.target_and_args.empty()) {
    overrides.target.path.set(
        parse_cli_path(bindings.target_and_args.front(), "run target operand", current_directory));
    overrides.target.args.set(
        {bindings.target_and_args.begin() + 1, bindings.target_and_args.end()});
  }
  apply_injection_bindings(bindings.injection, overrides.injection, current_directory);
  apply_capture_bindings(bindings.capture, overrides.capture, overrides.trace, current_directory);
}

void apply_attach_bindings(const AttachBindings& bindings,
                           config::ConfigurationOverrides& overrides,
                           const std::filesystem::path& current_directory) {
  overrides.operation.set(config::Operation::kAttach);
  if (was_set(bindings.pid)) {
    const auto pid =
        parse_cli_unsigned(bindings.pid.value, std::numeric_limits<std::uint32_t>::max(), "--pid");
    overrides.target.pid.set(static_cast<std::uint32_t>(pid));
  }
  apply_injection_bindings(bindings.injection, overrides.injection, current_directory);
  apply_capture_bindings(bindings.capture, overrides.capture, overrides.trace, current_directory);
  if (const auto value = boolean_value(bindings.unload_on_stop)) {
    overrides.injection.unload_on_stop.set(*value);
  }
}

void apply_patch_bindings(const PatchBindings& bindings, config::ConfigurationOverrides& overrides,
                          const std::filesystem::path& current_directory) {
  overrides.operation.set(config::Operation::kPatch);
  if (was_set(bindings.input)) {
    overrides.patch.input.set(parse_cli_path(bindings.input.value, "--input", current_directory));
  }
  if (was_set(bindings.output)) {
    overrides.patch.output.set(
        parse_cli_path(bindings.output.value, "--output", current_directory));
  }
  if (was_set(bindings.method)) {
    overrides.patch.method.set(
        parse_cli_enum<config::PatchMethod>(bindings.method.value, "--patch-method"));
  }
  if (was_set(bindings.agent_name)) {
    overrides.patch.agent_name.set(bindings.agent_name.value);
  }
  if (const auto value = boolean_value(bindings.allow_break_signature)) {
    overrides.patch.allow_break_signature.set(*value);
  }
  if (const auto value = boolean_value(bindings.verify)) {
    overrides.patch.verify.set(*value);
  }
}

void apply_analyze_bindings(const AnalyzeBindings& bindings,
                            config::ConfigurationOverrides& overrides,
                            const std::filesystem::path& current_directory) {
  overrides.operation.set(config::Operation::kAnalyze);
  if (!bindings.inputs.empty()) {
    overrides.analysis.inputs.set(
        parse_cli_paths(bindings.inputs, "analyze trace operand", current_directory));
  }
  if (was_set(bindings.mode)) {
    overrides.analysis.mode.set(
        parse_cli_enum<config::AnalysisMode>(bindings.mode.value, "--mode"));
  }
  if (was_set(bindings.format)) {
    overrides.analysis.format.set(
        parse_cli_enum<config::OutputFormat>(bindings.format.value, "--format"));
  }
  if (was_set(bindings.output)) {
    overrides.analysis.output.set(
        parse_cli_path(bindings.output.value, "--output", current_directory));
  }
  if (was_set(bindings.from)) {
    overrides.analysis.from.set(parse_cli_duration(bindings.from.value, "--from"));
  }
  if (was_set(bindings.to)) {
    overrides.analysis.to.set(parse_cli_duration(bindings.to.value, "--to"));
  }
  if (was_set(bindings.end)) {
    overrides.analysis.end.set(parse_cli_duration(bindings.end.value, "--end"));
  }
  if (was_set(bindings.group_by)) {
    overrides.analysis.group_by.set(
        parse_cli_enum<config::AnalysisGroupBy>(bindings.group_by.value, "--group-by"));
  }
  if (was_set(bindings.sort)) {
    overrides.analysis.sort.set(
        parse_cli_enum<config::AnalysisSort>(bindings.sort.value, "--sort"));
  }
  if (was_set(bindings.min_size)) {
    overrides.filters.min_size.set(parse_cli_size(bindings.min_size.value, "--min-size"));
  }
  if (was_set(bindings.max_size)) {
    overrides.filters.max_size.set(parse_cli_size(bindings.max_size.value, "--max-size"));
  }
  if (was_set(bindings.events)) {
    overrides.filters.events.set(
        parse_cli_enums<config::EventType>(bindings.events.values, "--event"));
  }
  if (was_set(bindings.threads)) {
    overrides.filters.threads.set(parse_cli_unsigned_list(bindings.threads.values, "--thread"));
  }
  if (was_set(bindings.apis)) {
    overrides.filters.apis.set(bindings.apis.values);
  }
  if (was_set(bindings.modules)) {
    overrides.filters.modules.set(bindings.modules.values);
  }
  if (was_set(bindings.stack_modules)) {
    overrides.filters.stack_modules.set(bindings.stack_modules.values);
  }
  if (was_set(bindings.allocation_ids)) {
    overrides.filters.allocation_ids.set(
        parse_cli_unsigned_list(bindings.allocation_ids.values, "--allocation-id"));
  }
  if (was_set(bindings.statuses)) {
    overrides.filters.statuses.set(
        parse_cli_enums<config::EventStatus>(bindings.statuses.values, "--status"));
  }
  if (was_set(bindings.symbols)) {
    overrides.symbols.mode.set(
        parse_cli_enum<config::SymbolMode>(bindings.symbols.value, "--symbols"));
  }
  if (was_set(bindings.symbol_paths)) {
    overrides.symbols.paths.set(
        parse_cli_paths(bindings.symbol_paths.values, "--symbol-path", current_directory));
  }
  if (was_set(bindings.symbol_servers)) {
    overrides.symbols.servers.set(bindings.symbol_servers.values);
  }
}

void apply_doctor_bindings(const DoctorBindings& bindings,
                           config::ConfigurationOverrides& overrides,
                           const std::filesystem::path& current_directory) {
  overrides.operation.set(config::Operation::kDoctor);
  if (was_set(bindings.target)) {
    overrides.target.path.set(parse_cli_path(bindings.target.value, "--target", current_directory));
  }
  if (was_set(bindings.pid)) {
    const auto pid =
        parse_cli_unsigned(bindings.pid.value, std::numeric_limits<std::uint32_t>::max(), "--pid");
    overrides.target.pid.set(static_cast<std::uint32_t>(pid));
  }
  if (was_set(bindings.injection_method)) {
    overrides.injection.method.set(parse_cli_enum<config::InjectionMethod>(
        bindings.injection_method.value, "--inject-method"));
  }
  if (was_set(bindings.agent_path)) {
    overrides.injection.agent_path.set(
        parse_cli_path(bindings.agent_path.value, "--agent", current_directory));
  }
}

}  // namespace

CommandLineExit::CommandLineExit(int exit_code, std::string standard_output,
                                 std::string standard_error)
    : exit_code_{exit_code},
      standard_output_{std::move(standard_output)},
      standard_error_{std::move(standard_error)},
      message_{standard_error_.empty() ? standard_output_ : standard_error_} {}

int CommandLineExit::exit_code() const noexcept { return exit_code_; }

const std::string& CommandLineExit::standard_output() const noexcept { return standard_output_; }

const std::string& CommandLineExit::standard_error() const noexcept { return standard_error_; }

const char* CommandLineExit::what() const noexcept { return message_.c_str(); }

ParsedCommandLine parse_command_line(int argc, const char* const* argv,
                                     const std::filesystem::path& current_directory) {
  if (argc < 1 || argv == nullptr || argv[0] == nullptr) {
    throw config::ConfigError{"command line does not contain a program name"};
  }
  std::vector<std::string> parser_arguments;
  parser_arguments.reserve(static_cast<std::size_t>(argc));
  for (int index = 0; index < argc; ++index) {
    if (argv[index] == nullptr) {
      throw config::ConfigError{"command line contains a null argument"};
    }
    parser_arguments.emplace_back(argv[index]);
  }

  std::vector<std::string> delimited_run_arguments;
  const auto delimiter =
      std::find(parser_arguments.begin() + 1, parser_arguments.end(), std::string{"--"});
  if (delimiter != parser_arguments.end()) {
    const auto run_token = std::find(parser_arguments.begin() + 1, delimiter, std::string{"run"});
    if (run_token != delimiter) {
      delimited_run_arguments.assign(delimiter + 1, parser_arguments.end());
      parser_arguments.erase(delimiter, parser_arguments.end());
    }
  }

  std::vector<const char*> parser_argv;
  parser_argv.reserve(parser_arguments.size());
  for (const auto& argument : parser_arguments) {
    parser_argv.push_back(argument.c_str());
  }

  CLI::App app{"Hook-based memory event capture and analysis tool", "noleax"};
  app.require_subcommand(0, 1);
  app.set_version_flag("--version", std::string{noleax::version_string()});

  TextOption config_path;
  TextOption log_level;
  TextOption color;
  add_text_option(app, config_path, "--config", "TOML configuration file");
  add_text_option(app, log_level, "--log-level", "Diagnostic log level");
  add_text_option(app, color, "--color", "Diagnostic color mode");

  RunBindings run_bindings;
  CLI::App* const run =
      app.add_subcommand("run", "Start a target process and capture memory events");
  add_text_option(*run, run_bindings.working_directory, "--working-directory",
                  "Target working directory");
  add_injection_options(*run, run_bindings.injection);
  add_capture_options(*run, run_bindings.capture);
  run->add_option("target", run_bindings.target_and_args, "Target executable and arguments")
      ->expected(0, -1);

  AttachBindings attach_bindings;
  CLI::App* const attach =
      app.add_subcommand("attach", "Attach to a running process and capture memory events");
  add_text_option(*attach, attach_bindings.pid, "--pid", "Target process identifier");
  add_injection_options(*attach, attach_bindings.injection);
  add_capture_options(*attach, attach_bindings.capture);
  add_boolean_option(*attach, attach_bindings.unload_on_stop, "--unload-on-stop",
                     "--no-unload-on-stop", "Unload the agent when capture stops");

  PatchBindings patch_bindings;
  CLI::App* const patch = app.add_subcommand("patch", "Create a patched target executable");
  add_text_option(*patch, patch_bindings.input, "--input", "Input executable path");
  add_text_option(*patch, patch_bindings.output, "--output", "Output executable path");
  add_text_option(*patch, patch_bindings.method, "--patch-method", "Static patch method");
  add_text_option(*patch, patch_bindings.agent_name, "--agent-name", "Runtime agent file name");
  add_boolean_option(*patch, patch_bindings.allow_break_signature, "--allow-break-signature",
                     "--no-allow-break-signature", "Allow invalidating an existing signature");
  add_boolean_option(*patch, patch_bindings.verify, "--verify", "--no-verify",
                     "Verify the patched output");

  AnalyzeBindings analyze_bindings;
  CLI::App* const analyze = app.add_subcommand("analyze", "Analyze one or more Noleax traces");
  add_text_option(*analyze, analyze_bindings.mode, "--mode", "Analysis mode");
  add_text_option(*analyze, analyze_bindings.format, "--format", "Output format");
  add_text_option(*analyze, analyze_bindings.output, "--output", "Output path");
  add_text_option(*analyze, analyze_bindings.from, "--from", "Allocation window start time");
  add_text_option(*analyze, analyze_bindings.to, "--to", "Allocation window end time");
  add_text_option(*analyze, analyze_bindings.end, "--end", "Observation time for leaks");
  add_text_option(*analyze, analyze_bindings.group_by, "--group-by",
                  "Group results by this dimension");
  add_text_option(*analyze, analyze_bindings.sort, "--sort", "Group sort order");
  add_text_option(*analyze, analyze_bindings.min_size, "--min-size", "Minimum allocation size");
  add_text_option(*analyze, analyze_bindings.max_size, "--max-size", "Maximum allocation size");
  add_list_option(*analyze, analyze_bindings.events, "--event", "Event type filter");
  add_list_option(*analyze, analyze_bindings.threads, "--thread", "Thread identifier filter");
  add_list_option(*analyze, analyze_bindings.apis, "--api", "API name filter");
  add_list_option(*analyze, analyze_bindings.modules, "--module", "Module name filter");
  add_list_option(*analyze, analyze_bindings.stack_modules, "--stack-module",
                  "Stack module filter");
  add_list_option(*analyze, analyze_bindings.allocation_ids, "--allocation-id",
                  "Allocation identifier filter");
  add_list_option(*analyze, analyze_bindings.statuses, "--status", "Event status filter");
  add_text_option(*analyze, analyze_bindings.symbols, "--symbols", "Symbol resolution mode");
  add_list_option(*analyze, analyze_bindings.symbol_paths, "--symbol-path", "Local symbol path");
  add_list_option(*analyze, analyze_bindings.symbol_servers, "--symbol-server",
                  "Symbol server URL");
  analyze->add_option("trace", analyze_bindings.inputs, "Input trace paths")->expected(0, -1);

  CLI::App* const config_command =
      app.add_subcommand("config", "Validate or print Noleax configuration");
  config_command->require_subcommand(1, 1);
  CLI::App* const validate =
      config_command->add_subcommand("validate", "Validate the effective configuration");
  CLI::App* const print_effective = config_command->add_subcommand(
      "print-effective", "Print effective TOML with value source annotations");

  DoctorBindings doctor_bindings;
  CLI::App* const doctor = app.add_subcommand("doctor", "Run read-only environment diagnostics");
  add_text_option(*doctor, doctor_bindings.target, "--target", "Target executable to inspect");
  add_text_option(*doctor, doctor_bindings.pid, "--pid", "Running target process to inspect");
  add_text_option(*doctor, doctor_bindings.injection_method, "--inject-method",
                  "Injection method to diagnose");
  add_text_option(*doctor, doctor_bindings.agent_path, "--agent", "Agent DLL to inspect");

  try {
    app.parse(static_cast<int>(parser_argv.size()), parser_argv.data());
  } catch (const CLI::ParseError& error) {
    std::ostringstream standard_output;
    std::ostringstream standard_error;
    const int cli_exit_code = app.exit(error, standard_output, standard_error);
    throw CommandLineExit{cli_exit_code == 0 ? 0 : 1, standard_output.str(), standard_error.str()};
  }

  ParsedCommandLine result;
  result.top_level_help = app.help();
  if (was_set(config_path)) {
    result.config_path = parse_cli_path(config_path.value, "--config", current_directory);
  }
  if (was_set(log_level)) {
    result.overrides.diagnostics.log_level.set(
        parse_cli_enum<config::LogLevel>(log_level.value, "--log-level"));
  }
  if (was_set(color)) {
    result.overrides.diagnostics.color.set(
        parse_cli_enum<config::ColorMode>(color.value, "--color"));
  }

  if (*run) {
    if (!delimited_run_arguments.empty()) {
      if (!run_bindings.target_and_args.empty()) {
        throw config::ConfigError{"run target operands cannot appear both before and after '--'"};
      }
      run_bindings.target_and_args = std::move(delimited_run_arguments);
    }
    apply_run_bindings(run_bindings, result.overrides, current_directory);
  } else if (*attach) {
    apply_attach_bindings(attach_bindings, result.overrides, current_directory);
  } else if (*patch) {
    apply_patch_bindings(patch_bindings, result.overrides, current_directory);
  } else if (*analyze) {
    apply_analyze_bindings(analyze_bindings, result.overrides, current_directory);
  } else if (*validate) {
    result.meta_command = MetaCommand::kValidateConfig;
  } else if (*print_effective) {
    result.meta_command = MetaCommand::kPrintEffectiveConfig;
  } else if (*doctor) {
    apply_doctor_bindings(doctor_bindings, result.overrides, current_directory);
  }
  return result;
}

}  // namespace noleax::cli
