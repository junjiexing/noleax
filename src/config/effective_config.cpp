#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"

namespace noleax::config {
namespace {

[[nodiscard]] std::string quote_toml(std::string_view value) {
  constexpr char kHexDigits[] = "0123456789ABCDEF";
  std::string result;
  result.reserve(value.size() + 2U);
  result.push_back('"');
  for (const char raw_character : value) {
    const auto character = static_cast<unsigned char>(raw_character);
    switch (character) {
      case '\b':
        result.append("\\b");
        break;
      case '\t':
        result.append("\\t");
        break;
      case '\n':
        result.append("\\n");
        break;
      case '\f':
        result.append("\\f");
        break;
      case '\r':
        result.append("\\r");
        break;
      case '"':
        result.append("\\\"");
        break;
      case '\\':
        result.append("\\\\");
        break;
      default:
        if (character < 0x20U || character == 0x7FU) {
          result.append("\\u00");
          result.push_back(kHexDigits[(character >> 4U) & 0x0FU]);
          result.push_back(kHexDigits[character & 0x0FU]);
        } else {
          result.push_back(static_cast<char>(character));
        }
        break;
    }
  }
  result.push_back('"');
  return result;
}

[[nodiscard]] std::string format_size(std::uint64_t bytes) {
  constexpr std::uint64_t kKiB = 1024U;
  constexpr std::uint64_t kMiB = 1024U * kKiB;
  constexpr std::uint64_t kGiB = 1024U * kMiB;
  if (bytes == 0U) {
    return "0B";
  }
  if (bytes % kGiB == 0U) {
    return std::to_string(bytes / kGiB) + "GiB";
  }
  if (bytes % kMiB == 0U) {
    return std::to_string(bytes / kMiB) + "MiB";
  }
  if (bytes % kKiB == 0U) {
    return std::to_string(bytes / kKiB) + "KiB";
  }
  return std::to_string(bytes) + "B";
}

[[nodiscard]] std::string format_duration(std::chrono::nanoseconds duration) {
  constexpr std::int64_t kNanosecondsPerMicrosecond = 1000;
  constexpr std::int64_t kNanosecondsPerMillisecond = 1000 * kNanosecondsPerMicrosecond;
  constexpr std::int64_t kNanosecondsPerSecond = 1000 * kNanosecondsPerMillisecond;
  constexpr std::int64_t kNanosecondsPerMinute = 60 * kNanosecondsPerSecond;
  constexpr std::int64_t kNanosecondsPerHour = 60 * kNanosecondsPerMinute;
  const auto nanoseconds = duration.count();

  if (nanoseconds != 0 && nanoseconds % kNanosecondsPerHour == 0) {
    return std::to_string(nanoseconds / kNanosecondsPerHour) + "h";
  }
  if (nanoseconds != 0 && nanoseconds % kNanosecondsPerMinute == 0) {
    return std::to_string(nanoseconds / kNanosecondsPerMinute) + "m";
  }
  if (nanoseconds != 0 && nanoseconds % kNanosecondsPerSecond == 0) {
    return std::to_string(nanoseconds / kNanosecondsPerSecond) + "s";
  }
  if (nanoseconds != 0 && nanoseconds % kNanosecondsPerMillisecond == 0) {
    return std::to_string(nanoseconds / kNanosecondsPerMillisecond) + "ms";
  }
  if (nanoseconds != 0 && nanoseconds % kNanosecondsPerMicrosecond == 0) {
    return std::to_string(nanoseconds / kNanosecondsPerMicrosecond) + "us";
  }
  return std::to_string(nanoseconds) + "ns";
}

[[nodiscard]] std::string format_path(const std::optional<std::filesystem::path>& path) {
  return quote_toml(path.has_value() ? path_to_utf8(*path) : std::string_view{});
}

[[nodiscard]] std::string format_paths(const std::vector<std::filesystem::path>& paths) {
  std::string result{"["};
  for (std::size_t index = 0; index < paths.size(); ++index) {
    if (index != 0U) {
      result.append(", ");
    }
    result.append(quote_toml(path_to_utf8(paths[index])));
  }
  result.push_back(']');
  return result;
}

[[nodiscard]] std::string format_strings(const std::vector<std::string>& values) {
  std::string result{"["};
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0U) {
      result.append(", ");
    }
    result.append(quote_toml(values[index]));
  }
  result.push_back(']');
  return result;
}

[[nodiscard]] std::string format_integers(const std::vector<std::uint64_t>& values) {
  std::string result{"["};
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0U) {
      result.append(", ");
    }
    result.append(std::to_string(values[index]));
  }
  result.push_back(']');
  return result;
}

template <typename Enum>
[[nodiscard]] std::string format_enums(const std::vector<Enum>& values) {
  std::string result{"["};
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0U) {
      result.append(", ");
    }
    result.append(quote_toml(enum_value_name(values[index])));
  }
  result.push_back(']');
  return result;
}

void append_setting(std::string& output, std::string_view key, const std::string& value,
                    ValueSource source) {
  output.append(key);
  output.append(" = ");
  output.append(value);
  output.append(" # source: ");
  output.append(value_source_name(source));
  output.push_back('\n');
}

void append_table(std::string& output, std::string_view name) {
  output.push_back('\n');
  output.push_back('[');
  output.append(name);
  output.append("]\n");
}

[[nodiscard]] std::string format_optional_size(const std::optional<std::uint64_t>& value) {
  return quote_toml(value.has_value() ? format_size(*value) : std::string{});
}

[[nodiscard]] std::string format_optional_duration(
    const std::optional<std::chrono::nanoseconds>& value) {
  return quote_toml(value.has_value() ? format_duration(*value) : std::string{});
}

[[nodiscard]] std::string format_window_bound(const WindowBound& bound) {
  if (bound.sequence.has_value()) {
    return "#" + std::to_string(*bound.sequence);
  }
  if (bound.time.has_value()) {
    return format_duration(*bound.time);
  }
  return {};
}

[[nodiscard]] std::string format_optional_window_bound(const std::optional<WindowBound>& value) {
  return quote_toml(value.has_value() ? format_window_bound(*value) : std::string{});
}

}  // namespace

std::string serialize_effective_config(const Configuration& configuration) {
  std::string output;
  output.reserve(4096U);

  append_setting(output, "schema_version", std::to_string(configuration.schema_version.value),
                 configuration.schema_version.source);
  append_setting(output, "operation",
                 quote_toml(configuration.operation.value.has_value()
                                ? enum_value_name(*configuration.operation.value)
                                : std::string_view{}),
                 configuration.operation.source);

  append_table(output, "target");
  append_setting(output, "path", format_path(configuration.target.path.value),
                 configuration.target.path.source);
  append_setting(output, "args", format_strings(configuration.target.args.value),
                 configuration.target.args.source);
  append_setting(output, "working_directory",
                 format_path(configuration.target.working_directory.value),
                 configuration.target.working_directory.source);
  append_setting(output, "pid", std::to_string(configuration.target.pid.value.value_or(0U)),
                 configuration.target.pid.source);

  append_table(output, "injection");
  append_setting(output, "method",
                 quote_toml(enum_value_name(configuration.injection.method.value)),
                 configuration.injection.method.source);
  append_setting(output, "agent_path", format_path(configuration.injection.agent_path.value),
                 configuration.injection.agent_path.source);
  append_setting(output, "timeout",
                 quote_toml(format_duration(configuration.injection.timeout.value)),
                 configuration.injection.timeout.source);
  append_setting(output, "unload_on_stop",
                 configuration.injection.unload_on_stop.value ? "true" : "false",
                 configuration.injection.unload_on_stop.source);

  append_table(output, "capture");
  append_setting(output, "hook_profile",
                 quote_toml(enum_value_name(configuration.capture.hook_profile.value)),
                 configuration.capture.hook_profile.source);
  append_setting(output, "max_stack_depth",
                 std::to_string(configuration.capture.max_stack_depth.value),
                 configuration.capture.max_stack_depth.source);
  append_setting(output, "min_size", quote_toml(format_size(configuration.capture.min_size.value)),
                 configuration.capture.min_size.source);
  append_setting(output, "duration", format_optional_duration(configuration.capture.duration.value),
                 configuration.capture.duration.source);
  append_setting(output, "live", configuration.capture.live.value ? "true" : "false",
                 configuration.capture.live.source);

  append_table(output, "trace");
  append_setting(output, "path", format_path(configuration.trace.path.value),
                 configuration.trace.path.source);
  append_setting(output, "buffer_size",
                 quote_toml(format_size(configuration.trace.buffer_size.value)),
                 configuration.trace.buffer_size.source);
  append_setting(output, "max_file_size",
                 quote_toml(format_size(configuration.trace.max_file_size.value)),
                 configuration.trace.max_file_size.source);
  append_setting(output, "max_files", std::to_string(configuration.trace.max_files.value),
                 configuration.trace.max_files.source);
  append_setting(output, "on_full", quote_toml(enum_value_name(configuration.trace.on_full.value)),
                 configuration.trace.on_full.source);
  append_setting(output, "flush_interval",
                 quote_toml(format_duration(configuration.trace.flush_interval.value)),
                 configuration.trace.flush_interval.source);
  append_setting(output, "compression",
                 quote_toml(enum_value_name(configuration.trace.compression.value)),
                 configuration.trace.compression.source);
  append_setting(output, "compression_level",
                 std::to_string(configuration.trace.compression_level.value),
                 configuration.trace.compression_level.source);

  append_table(output, "analysis");
  append_setting(output, "inputs", format_paths(configuration.analysis.inputs.value),
                 configuration.analysis.inputs.source);
  append_setting(output, "mode", quote_toml(enum_value_name(configuration.analysis.mode.value)),
                 configuration.analysis.mode.source);
  append_setting(output, "format", quote_toml(enum_value_name(configuration.analysis.format.value)),
                 configuration.analysis.format.source);
  append_setting(output, "output", format_path(configuration.analysis.output.value),
                 configuration.analysis.output.source);
  append_setting(output, "from", format_optional_window_bound(configuration.analysis.from.value),
                 configuration.analysis.from.source);
  append_setting(output, "to", format_optional_window_bound(configuration.analysis.to.value),
                 configuration.analysis.to.source);
  append_setting(output, "end", format_optional_window_bound(configuration.analysis.end.value),
                 configuration.analysis.end.source);
  append_setting(output, "group_by",
                 quote_toml(configuration.analysis.group_by.value.has_value()
                                ? enum_value_name(*configuration.analysis.group_by.value)
                                : std::string_view{}),
                 configuration.analysis.group_by.source);
  append_setting(output, "sort", quote_toml(enum_value_name(configuration.analysis.sort.value)),
                 configuration.analysis.sort.source);
  append_setting(output, "trim_agent_frames",
                 configuration.analysis.trim_agent_frames.value ? "true" : "false",
                 configuration.analysis.trim_agent_frames.source);

  append_table(output, "filters");
  append_setting(output, "min_size", format_optional_size(configuration.filters.min_size.value),
                 configuration.filters.min_size.source);
  append_setting(output, "max_size", format_optional_size(configuration.filters.max_size.value),
                 configuration.filters.max_size.source);
  append_setting(output, "events", format_enums(configuration.filters.events.value),
                 configuration.filters.events.source);
  append_setting(output, "threads", format_integers(configuration.filters.threads.value),
                 configuration.filters.threads.source);
  append_setting(output, "apis", format_strings(configuration.filters.apis.value),
                 configuration.filters.apis.source);
  append_setting(output, "modules", format_strings(configuration.filters.modules.value),
                 configuration.filters.modules.source);
  append_setting(output, "stack_modules", format_strings(configuration.filters.stack_modules.value),
                 configuration.filters.stack_modules.source);
  append_setting(output, "allocation_ids",
                 format_integers(configuration.filters.allocation_ids.value),
                 configuration.filters.allocation_ids.source);
  append_setting(output, "statuses", format_enums(configuration.filters.statuses.value),
                 configuration.filters.statuses.source);

  append_table(output, "symbols");
  append_setting(output, "mode", quote_toml(enum_value_name(configuration.symbols.mode.value)),
                 configuration.symbols.mode.source);
  append_setting(output, "paths", format_paths(configuration.symbols.paths.value),
                 configuration.symbols.paths.source);
  append_setting(output, "servers", format_strings(configuration.symbols.servers.value),
                 configuration.symbols.servers.source);

  append_table(output, "patch");
  append_setting(output, "input", format_path(configuration.patch.input.value),
                 configuration.patch.input.source);
  append_setting(output, "output", format_path(configuration.patch.output.value),
                 configuration.patch.output.source);
  append_setting(output, "method", quote_toml(enum_value_name(configuration.patch.method.value)),
                 configuration.patch.method.source);
  append_setting(output, "agent_name", quote_toml(configuration.patch.agent_name.value),
                 configuration.patch.agent_name.source);
  append_setting(output, "allow_break_signature",
                 configuration.patch.allow_break_signature.value ? "true" : "false",
                 configuration.patch.allow_break_signature.source);
  append_setting(output, "verify", configuration.patch.verify.value ? "true" : "false",
                 configuration.patch.verify.source);
  append_setting(output, "standalone", configuration.patch.standalone.value ? "true" : "false",
                 configuration.patch.standalone.source);

  append_table(output, "diagnostics");
  append_setting(output, "log_level",
                 quote_toml(enum_value_name(configuration.diagnostics.log_level.value)),
                 configuration.diagnostics.log_level.source);
  append_setting(output, "color",
                 quote_toml(enum_value_name(configuration.diagnostics.color.value)),
                 configuration.diagnostics.color.source);
  return output;
}

}  // namespace noleax::config
