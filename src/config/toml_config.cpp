#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <toml++/toml.hpp>
#include <type_traits>
#include <utility>
#include <vector>

#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"
#include "noleax/config/value_parser.hpp"

namespace noleax::config {
namespace {

constexpr std::uintmax_t kMaximumConfigFileSize = 4U * 1024U * 1024U;

[[nodiscard]] std::string key_error(std::string_view key, std::string_view cli_option,
                                    std::string_view detail) {
  std::string message{"configuration key '"};
  message.append(key);
  message.append("'");
  if (!cli_option.empty()) {
    message.append(" (");
    message.append(cli_option);
    message.push_back(')');
  }
  message.append(": ");
  message.append(detail);
  return message;
}

template <typename Key, std::size_t Size>
void reject_unknown_keys(const toml::table& table, const std::array<Key, Size>& allowed_keys,
                         std::string_view table_name) {
  for (const auto& [key, node] : table) {
    static_cast<void>(node);
    const std::string_view name = key.str();
    bool allowed = false;
    for (const std::string_view candidate : allowed_keys) {
      if (candidate == name) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      std::string full_key;
      if (!table_name.empty()) {
        full_key.append(table_name);
        full_key.push_back('.');
      }
      full_key.append(name);
      throw ConfigError{key_error(full_key, {}, "unknown key")};
    }
  }
}

[[nodiscard]] const toml::table* optional_table(const toml::table& root, std::string_view name) {
  const toml::node* const node = root.get(name);
  if (node == nullptr) {
    return nullptr;
  }
  const toml::table* const table = node->as_table();
  if (table == nullptr) {
    throw ConfigError{key_error(name, {}, "expected a table")};
  }
  return table;
}

[[nodiscard]] const toml::node* optional_node(const toml::table& table, std::string_view key) {
  return table.get(key);
}

[[nodiscard]] std::string read_string(const toml::node& node, std::string_view key,
                                      std::string_view cli_option) {
  const auto value = node.value<std::string>();
  if (!value.has_value()) {
    throw ConfigError{key_error(key, cli_option, "expected a string")};
  }
  return *value;
}

[[nodiscard]] bool read_boolean(const toml::node& node, std::string_view key,
                                std::string_view cli_option) {
  const auto value = node.value<bool>();
  if (!value.has_value()) {
    throw ConfigError{key_error(key, cli_option, "expected a boolean")};
  }
  return *value;
}

template <typename Integer>
[[nodiscard]] Integer read_integer(const toml::node& node, std::string_view key,
                                   std::string_view cli_option, Integer minimum, Integer maximum) {
  static_assert(std::is_integral_v<Integer>);
  const auto value = node.value<std::int64_t>();
  if (!value.has_value()) {
    throw ConfigError{key_error(key, cli_option, "expected an integer")};
  }

  if constexpr (std::is_unsigned_v<Integer>) {
    if (*value < 0 || static_cast<std::uint64_t>(*value) < static_cast<std::uint64_t>(minimum) ||
        static_cast<std::uint64_t>(*value) > static_cast<std::uint64_t>(maximum)) {
      throw ConfigError{key_error(key, cli_option, "integer is out of range")};
    }
  } else {
    if (*value < static_cast<std::int64_t>(minimum) ||
        *value > static_cast<std::int64_t>(maximum)) {
      throw ConfigError{key_error(key, cli_option, "integer is out of range")};
    }
  }
  return static_cast<Integer>(*value);
}

[[nodiscard]] std::vector<std::string> read_string_array(const toml::node& node,
                                                         std::string_view key,
                                                         std::string_view cli_option) {
  const toml::array* const array = node.as_array();
  if (array == nullptr) {
    throw ConfigError{key_error(key, cli_option, "expected an array of strings")};
  }

  std::vector<std::string> result;
  result.reserve(array->size());
  for (const auto& element : *array) {
    const auto value = element.value<std::string>();
    if (!value.has_value()) {
      throw ConfigError{key_error(key, cli_option, "expected an array of strings")};
    }
    result.push_back(*value);
  }
  return result;
}

[[nodiscard]] std::vector<std::uint64_t> read_unsigned_array(const toml::node& node,
                                                             std::string_view key,
                                                             std::string_view cli_option) {
  const toml::array* const array = node.as_array();
  if (array == nullptr) {
    throw ConfigError{key_error(key, cli_option, "expected an array of unsigned integers")};
  }

  std::vector<std::uint64_t> result;
  result.reserve(array->size());
  for (const auto& element : *array) {
    const auto value = element.value<std::int64_t>();
    if (!value.has_value() || *value < 0) {
      throw ConfigError{key_error(key, cli_option, "expected an array of unsigned integers")};
    }
    result.push_back(static_cast<std::uint64_t>(*value));
  }
  return result;
}

template <typename Enum>
[[nodiscard]] std::vector<Enum> read_enum_array(const toml::node& node, std::string_view key,
                                                std::string_view cli_option) {
  const auto strings = read_string_array(node, key, cli_option);
  std::vector<Enum> result;
  result.reserve(strings.size());
  for (const auto& value : strings) {
    try {
      result.push_back(parse_enum_value<Enum>(value));
    } catch (const ValueParseError& error) {
      throw ConfigError{key_error(key, cli_option, error.what())};
    }
  }
  return result;
}

template <typename Enum>
[[nodiscard]] Enum read_enum(const toml::node& node, std::string_view key,
                             std::string_view cli_option) {
  const auto value = read_string(node, key, cli_option);
  try {
    return parse_enum_value<Enum>(value);
  } catch (const ValueParseError& error) {
    throw ConfigError{key_error(key, cli_option, error.what())};
  }
}

[[nodiscard]] std::uint64_t read_size(const toml::node& node, std::string_view key,
                                      std::string_view cli_option) {
  const auto value = read_string(node, key, cli_option);
  try {
    return parse_byte_size(value);
  } catch (const ValueParseError& error) {
    throw ConfigError{key_error(key, cli_option, error.what())};
  }
}

[[nodiscard]] std::optional<std::uint64_t> read_optional_size(const toml::node& node,
                                                              std::string_view key,
                                                              std::string_view cli_option) {
  const auto value = read_string(node, key, cli_option);
  if (value.empty()) {
    return std::nullopt;
  }
  try {
    return parse_byte_size(value);
  } catch (const ValueParseError& error) {
    throw ConfigError{key_error(key, cli_option, error.what())};
  }
}

[[nodiscard]] std::chrono::nanoseconds read_duration(const toml::node& node, std::string_view key,
                                                     std::string_view cli_option) {
  const auto value = read_string(node, key, cli_option);
  try {
    return parse_duration(value);
  } catch (const ValueParseError& error) {
    throw ConfigError{key_error(key, cli_option, error.what())};
  }
}

[[nodiscard]] std::optional<std::chrono::nanoseconds> read_optional_duration(
    const toml::node& node, std::string_view key, std::string_view cli_option) {
  const auto value = read_string(node, key, cli_option);
  if (value.empty()) {
    return std::nullopt;
  }
  try {
    return parse_duration(value);
  } catch (const ValueParseError& error) {
    throw ConfigError{key_error(key, cli_option, error.what())};
  }
}

[[nodiscard]] std::optional<std::filesystem::path> read_optional_path(
    const toml::node& node, std::string_view key, std::string_view cli_option,
    const std::filesystem::path& base_directory) {
  const auto value = read_string(node, key, cli_option);
  if (value.empty()) {
    return std::nullopt;
  }
  return normalize_path(value, base_directory);
}

[[nodiscard]] std::vector<std::filesystem::path> read_path_array(
    const toml::node& node, std::string_view key, std::string_view cli_option,
    const std::filesystem::path& base_directory) {
  const auto strings = read_string_array(node, key, cli_option);
  std::vector<std::filesystem::path> result;
  result.reserve(strings.size());
  for (const auto& value : strings) {
    if (value.empty()) {
      throw ConfigError{key_error(key, cli_option, "path entries must not be empty")};
    }
    result.push_back(normalize_path(value, base_directory));
  }
  return result;
}

[[nodiscard]] std::string read_config_file(const std::filesystem::path& path) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  if (error) {
    throw ConfigError{"cannot inspect configuration file '" + path_to_utf8(path) +
                      "': " + error.message()};
  }
  if (size > kMaximumConfigFileSize) {
    throw ConfigError{"configuration file exceeds the 4 MiB limit: " + path_to_utf8(path)};
  }

  std::ifstream input{path, std::ios::binary};
  if (!input) {
    throw ConfigError{"cannot open configuration file: " + path_to_utf8(path)};
  }
  std::ostringstream contents;
  contents << input.rdbuf();
  if (input.bad()) {
    throw ConfigError{"cannot read configuration file: " + path_to_utf8(path)};
  }
  auto result = contents.str();
  if (result.size() > kMaximumConfigFileSize) {
    throw ConfigError{"configuration file exceeds the 4 MiB limit: " + path_to_utf8(path)};
  }
  return result;
}

void load_target(const toml::table& table, ConfigurationOverrides& result,
                 const std::filesystem::path& base_directory) {
  constexpr std::array allowed{"path", "args", "working_directory", "pid"};
  reject_unknown_keys(table, allowed, "target");

  if (const auto* node = optional_node(table, "path")) {
    result.target.path.set(
        read_optional_path(*node, "target.path", "run target operand", base_directory));
  }
  if (const auto* node = optional_node(table, "args")) {
    result.target.args.set(read_string_array(*node, "target.args", "run target operand"));
  }
  if (const auto* node = optional_node(table, "working_directory")) {
    result.target.working_directory.set(read_optional_path(*node, "target.working_directory",
                                                           "--working-directory", base_directory));
  }
  if (const auto* node = optional_node(table, "pid")) {
    const auto pid = read_integer<std::uint32_t>(*node, "target.pid", "--pid", 0U,
                                                 std::numeric_limits<std::uint32_t>::max());
    result.target.pid.set(pid == 0U ? std::nullopt : std::optional{pid});
  }
}

void load_injection(const toml::table& table, ConfigurationOverrides& result,
                    const std::filesystem::path& base_directory) {
  constexpr std::array allowed{"method", "agent_path", "timeout", "unload_on_stop"};
  reject_unknown_keys(table, allowed, "injection");

  if (const auto* node = optional_node(table, "method")) {
    result.injection.method.set(
        read_enum<InjectionMethod>(*node, "injection.method", "--inject-method"));
  }
  if (const auto* node = optional_node(table, "agent_path")) {
    result.injection.agent_path.set(
        read_optional_path(*node, "injection.agent_path", "--agent", base_directory));
  }
  if (const auto* node = optional_node(table, "timeout")) {
    result.injection.timeout.set(read_duration(*node, "injection.timeout", "--inject-timeout"));
  }
  if (const auto* node = optional_node(table, "unload_on_stop")) {
    result.injection.unload_on_stop.set(
        read_boolean(*node, "injection.unload_on_stop", "--unload-on-stop"));
  }
}

void load_capture(const toml::table& table, ConfigurationOverrides& result) {
  constexpr std::array allowed{"hook_profile", "max_stack_depth", "min_size", "duration"};
  reject_unknown_keys(table, allowed, "capture");

  if (const auto* node = optional_node(table, "hook_profile")) {
    result.capture.hook_profile.set(
        read_enum<HookProfile>(*node, "capture.hook_profile", "--hook-profile"));
  }
  if (const auto* node = optional_node(table, "max_stack_depth")) {
    result.capture.max_stack_depth.set(
        read_integer<std::uint16_t>(*node, "capture.max_stack_depth", "--max-stack-depth", 0U,
                                    std::numeric_limits<std::uint16_t>::max()));
  }
  if (const auto* node = optional_node(table, "min_size")) {
    result.capture.min_size.set(read_size(*node, "capture.min_size", "--capture-min-size"));
  }
  if (const auto* node = optional_node(table, "duration")) {
    result.capture.duration.set(
        read_optional_duration(*node, "capture.duration", "--capture-duration"));
  }
}

void load_trace(const toml::table& table, ConfigurationOverrides& result,
                const std::filesystem::path& base_directory) {
  constexpr std::array allowed{"path",    "buffer_size",    "max_file_size", "max_files",
                               "on_full", "flush_interval", "compression",   "compression_level"};
  reject_unknown_keys(table, allowed, "trace");

  if (const auto* node = optional_node(table, "path")) {
    result.trace.path.set(read_optional_path(*node, "trace.path", "--trace", base_directory));
  }
  if (const auto* node = optional_node(table, "buffer_size")) {
    result.trace.buffer_size.set(read_size(*node, "trace.buffer_size", "--buffer-size"));
  }
  if (const auto* node = optional_node(table, "max_file_size")) {
    result.trace.max_file_size.set(read_size(*node, "trace.max_file_size", "--max-trace-size"));
  }
  if (const auto* node = optional_node(table, "max_files")) {
    result.trace.max_files.set(
        read_integer<std::uint32_t>(*node, "trace.max_files", "--max-trace-files", 0U,
                                    std::numeric_limits<std::uint32_t>::max()));
  }
  if (const auto* node = optional_node(table, "on_full")) {
    result.trace.on_full.set(read_enum<TraceFullPolicy>(*node, "trace.on_full", "--on-trace-full"));
  }
  if (const auto* node = optional_node(table, "flush_interval")) {
    result.trace.flush_interval.set(
        read_duration(*node, "trace.flush_interval", "--flush-interval"));
  }
  if (const auto* node = optional_node(table, "compression")) {
    result.trace.compression.set(
        read_enum<Compression>(*node, "trace.compression", "--compression"));
  }
  if (const auto* node = optional_node(table, "compression_level")) {
    result.trace.compression_level.set(read_integer<std::int32_t>(
        *node, "trace.compression_level", "--compression-level",
        std::numeric_limits<std::int32_t>::min(), std::numeric_limits<std::int32_t>::max()));
  }
}

void load_analysis(const toml::table& table, ConfigurationOverrides& result,
                   const std::filesystem::path& base_directory) {
  constexpr std::array allowed{"inputs", "mode", "format", "output", "a", "b", "c"};
  reject_unknown_keys(table, allowed, "analysis");

  if (const auto* node = optional_node(table, "inputs")) {
    result.analysis.inputs.set(
        read_path_array(*node, "analysis.inputs", "analyze trace operand", base_directory));
  }
  if (const auto* node = optional_node(table, "mode")) {
    result.analysis.mode.set(read_enum<AnalysisMode>(*node, "analysis.mode", "--mode"));
  }
  if (const auto* node = optional_node(table, "format")) {
    result.analysis.format.set(read_enum<OutputFormat>(*node, "analysis.format", "--format"));
  }
  if (const auto* node = optional_node(table, "output")) {
    result.analysis.output.set(
        read_optional_path(*node, "analysis.output", "--output", base_directory));
  }
  if (const auto* node = optional_node(table, "a")) {
    result.analysis.a.set(read_optional_duration(*node, "analysis.a", "--a"));
  }
  if (const auto* node = optional_node(table, "b")) {
    result.analysis.b.set(read_optional_duration(*node, "analysis.b", "--b"));
  }
  if (const auto* node = optional_node(table, "c")) {
    result.analysis.c.set(read_optional_duration(*node, "analysis.c", "--c"));
  }
}

void load_filters(const toml::table& table, ConfigurationOverrides& result) {
  constexpr std::array allowed{"min_size", "max_size",      "events",         "threads", "apis",
                               "modules",  "stack_modules", "allocation_ids", "statuses"};
  reject_unknown_keys(table, allowed, "filters");

  if (const auto* node = optional_node(table, "min_size")) {
    result.filters.min_size.set(read_optional_size(*node, "filters.min_size", "--min-size"));
  }
  if (const auto* node = optional_node(table, "max_size")) {
    result.filters.max_size.set(read_optional_size(*node, "filters.max_size", "--max-size"));
  }
  if (const auto* node = optional_node(table, "events")) {
    result.filters.events.set(read_enum_array<EventType>(*node, "filters.events", "--event"));
  }
  if (const auto* node = optional_node(table, "threads")) {
    result.filters.threads.set(read_unsigned_array(*node, "filters.threads", "--thread"));
  }
  if (const auto* node = optional_node(table, "apis")) {
    result.filters.apis.set(read_string_array(*node, "filters.apis", "--api"));
  }
  if (const auto* node = optional_node(table, "modules")) {
    result.filters.modules.set(read_string_array(*node, "filters.modules", "--module"));
  }
  if (const auto* node = optional_node(table, "stack_modules")) {
    result.filters.stack_modules.set(
        read_string_array(*node, "filters.stack_modules", "--stack-module"));
  }
  if (const auto* node = optional_node(table, "allocation_ids")) {
    result.filters.allocation_ids.set(
        read_unsigned_array(*node, "filters.allocation_ids", "--allocation-id"));
  }
  if (const auto* node = optional_node(table, "statuses")) {
    result.filters.statuses.set(
        read_enum_array<EventStatus>(*node, "filters.statuses", "--status"));
  }
}

void load_symbols(const toml::table& table, ConfigurationOverrides& result,
                  const std::filesystem::path& base_directory) {
  constexpr std::array allowed{"mode", "paths", "servers"};
  reject_unknown_keys(table, allowed, "symbols");

  if (const auto* node = optional_node(table, "mode")) {
    result.symbols.mode.set(read_enum<SymbolMode>(*node, "symbols.mode", "--symbols"));
  }
  if (const auto* node = optional_node(table, "paths")) {
    result.symbols.paths.set(
        read_path_array(*node, "symbols.paths", "--symbol-path", base_directory));
  }
  if (const auto* node = optional_node(table, "servers")) {
    result.symbols.servers.set(read_string_array(*node, "symbols.servers", "--symbol-server"));
  }
}

void load_patch(const toml::table& table, ConfigurationOverrides& result,
                const std::filesystem::path& base_directory) {
  constexpr std::array allowed{"input", "output", "method", "agent_name", "allow_break_signature",
                               "verify"};
  reject_unknown_keys(table, allowed, "patch");

  if (const auto* node = optional_node(table, "input")) {
    result.patch.input.set(read_optional_path(*node, "patch.input", "--input", base_directory));
  }
  if (const auto* node = optional_node(table, "output")) {
    result.patch.output.set(read_optional_path(*node, "patch.output", "--output", base_directory));
  }
  if (const auto* node = optional_node(table, "method")) {
    result.patch.method.set(read_enum<PatchMethod>(*node, "patch.method", "--patch-method"));
  }
  if (const auto* node = optional_node(table, "agent_name")) {
    result.patch.agent_name.set(read_string(*node, "patch.agent_name", "--agent-name"));
  }
  if (const auto* node = optional_node(table, "allow_break_signature")) {
    result.patch.allow_break_signature.set(
        read_boolean(*node, "patch.allow_break_signature", "--allow-break-signature"));
  }
  if (const auto* node = optional_node(table, "verify")) {
    result.patch.verify.set(read_boolean(*node, "patch.verify", "--verify"));
  }
}

void load_diagnostics(const toml::table& table, ConfigurationOverrides& result) {
  constexpr std::array allowed{"log_level", "color"};
  reject_unknown_keys(table, allowed, "diagnostics");

  if (const auto* node = optional_node(table, "log_level")) {
    result.diagnostics.log_level.set(
        read_enum<LogLevel>(*node, "diagnostics.log_level", "--log-level"));
  }
  if (const auto* node = optional_node(table, "color")) {
    result.diagnostics.color.set(read_enum<ColorMode>(*node, "diagnostics.color", "--color"));
  }
}

}  // namespace

std::filesystem::path normalize_path(std::string_view input,
                                     const std::filesystem::path& base_directory) {
  std::u8string utf8_input;
  utf8_input.reserve(input.size());
  for (const char character : input) {
    utf8_input.push_back(static_cast<char8_t>(static_cast<unsigned char>(character)));
  }
  auto path = std::filesystem::path{utf8_input};
  if (path.is_relative()) {
    path = base_directory / path;
  }
  return std::filesystem::absolute(path).lexically_normal();
}

std::string path_to_utf8(const std::filesystem::path& path) {
  const auto utf8 = path.generic_u8string();
  return {reinterpret_cast<const char*>(utf8.data()), utf8.size()};
}

ConfigurationOverrides load_toml_config(const std::filesystem::path& config_path) {
  const auto normalized_path = std::filesystem::absolute(config_path).lexically_normal();
  const auto base_directory = normalized_path.parent_path();
  const auto contents = read_config_file(normalized_path);

  toml::table root;
  try {
    root = toml::parse(contents, path_to_utf8(normalized_path));
  } catch (const toml::parse_error& error) {
    throw ConfigError{"cannot parse configuration file '" + path_to_utf8(normalized_path) +
                      "': " + std::string{error.description()}};
  }

  constexpr std::array root_keys{"schema_version", "operation", "target",     "injection",
                                 "capture",        "trace",     "analysis",   "filters",
                                 "symbols",        "patch",     "diagnostics"};
  reject_unknown_keys(root, root_keys, {});

  const toml::node* const schema_node = root.get("schema_version");
  if (schema_node == nullptr) {
    throw ConfigError{key_error("schema_version", {}, "required key is missing")};
  }
  const auto schema_version = read_integer<std::uint32_t>(
      *schema_node, "schema_version", {}, 0U, std::numeric_limits<std::uint32_t>::max());
  if (schema_version != kConfigSchemaVersion) {
    throw ConfigError{key_error("schema_version", {}, "unsupported schema version")};
  }

  ConfigurationOverrides result;
  result.schema_version.set(schema_version);
  if (const auto* node = root.get("operation")) {
    result.operation.set(read_enum<Operation>(*node, "operation", "subcommand"));
  }

  if (const auto* table = optional_table(root, "target")) {
    load_target(*table, result, base_directory);
  }
  if (const auto* table = optional_table(root, "injection")) {
    load_injection(*table, result, base_directory);
  }
  if (const auto* table = optional_table(root, "capture")) {
    load_capture(*table, result);
  }
  if (const auto* table = optional_table(root, "trace")) {
    load_trace(*table, result, base_directory);
  }
  if (const auto* table = optional_table(root, "analysis")) {
    load_analysis(*table, result, base_directory);
  }
  if (const auto* table = optional_table(root, "filters")) {
    load_filters(*table, result);
  }
  if (const auto* table = optional_table(root, "symbols")) {
    load_symbols(*table, result, base_directory);
  }
  if (const auto* table = optional_table(root, "patch")) {
    load_patch(*table, result, base_directory);
  }
  if (const auto* table = optional_table(root, "diagnostics")) {
    load_diagnostics(*table, result);
  }
  return result;
}

}  // namespace noleax::config
