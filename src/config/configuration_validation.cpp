#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"

namespace noleax::config {
namespace {

constexpr std::uint64_t kMinimumTraceBufferSize = 4U * 1024U;
constexpr std::uint64_t kMinimumTraceOverhead = 4U * 1024U;

[[noreturn]] void fail(std::string_view key, std::string_view detail) {
  std::string message{"configuration key '"};
  message.append(key);
  message.append("': ");
  message.append(detail);
  throw ConfigError{message};
}

template <typename T>
void require_default(const Setting<T>& setting, const Setting<T>& default_setting,
                     std::string_view key, Operation operation) {
  if (setting.value != default_setting.value) {
    std::string detail{"is not valid for operation '"};
    detail.append(enum_value_name(operation));
    detail.push_back('\'');
    fail(key, detail);
  }
}

void require_default_target(const Configuration& configuration, const Configuration& defaults,
                            Operation operation) {
  require_default(configuration.target.path, defaults.target.path, "target.path", operation);
  require_default(configuration.target.args, defaults.target.args, "target.args", operation);
  require_default(configuration.target.working_directory, defaults.target.working_directory,
                  "target.working_directory", operation);
  require_default(configuration.target.pid, defaults.target.pid, "target.pid", operation);
}

void require_default_injection(const Configuration& configuration, const Configuration& defaults,
                               Operation operation) {
  require_default(configuration.injection.method, defaults.injection.method, "injection.method",
                  operation);
  require_default(configuration.injection.agent_path, defaults.injection.agent_path,
                  "injection.agent_path", operation);
  require_default(configuration.injection.timeout, defaults.injection.timeout, "injection.timeout",
                  operation);
  require_default(configuration.injection.unload_on_stop, defaults.injection.unload_on_stop,
                  "injection.unload_on_stop", operation);
}

void require_default_capture(const Configuration& configuration, const Configuration& defaults,
                             Operation operation) {
  require_default(configuration.capture.hook_profile, defaults.capture.hook_profile,
                  "capture.hook_profile", operation);
  require_default(configuration.capture.max_stack_depth, defaults.capture.max_stack_depth,
                  "capture.max_stack_depth", operation);
  require_default(configuration.capture.min_size, defaults.capture.min_size, "capture.min_size",
                  operation);
  require_default(configuration.capture.duration, defaults.capture.duration, "capture.duration",
                  operation);
  require_default(configuration.capture.live, defaults.capture.live, "capture.live", operation);
}

void require_default_trace(const Configuration& configuration, const Configuration& defaults,
                           Operation operation) {
  require_default(configuration.trace.path, defaults.trace.path, "trace.path", operation);
  require_default(configuration.trace.buffer_size, defaults.trace.buffer_size, "trace.buffer_size",
                  operation);
  require_default(configuration.trace.max_file_size, defaults.trace.max_file_size,
                  "trace.max_file_size", operation);
  require_default(configuration.trace.max_files, defaults.trace.max_files, "trace.max_files",
                  operation);
  require_default(configuration.trace.on_full, defaults.trace.on_full, "trace.on_full", operation);
  require_default(configuration.trace.flush_interval, defaults.trace.flush_interval,
                  "trace.flush_interval", operation);
  require_default(configuration.trace.compression, defaults.trace.compression, "trace.compression",
                  operation);
  require_default(configuration.trace.compression_level, defaults.trace.compression_level,
                  "trace.compression_level", operation);
}

void require_default_analysis(const Configuration& configuration, const Configuration& defaults,
                              Operation operation) {
  require_default(configuration.analysis.inputs, defaults.analysis.inputs, "analysis.inputs",
                  operation);
  require_default(configuration.analysis.mode, defaults.analysis.mode, "analysis.mode", operation);
  require_default(configuration.analysis.format, defaults.analysis.format, "analysis.format",
                  operation);
  require_default(configuration.analysis.output, defaults.analysis.output, "analysis.output",
                  operation);
  require_default(configuration.analysis.from, defaults.analysis.from, "analysis.from", operation);
  require_default(configuration.analysis.to, defaults.analysis.to, "analysis.to", operation);
  require_default(configuration.analysis.end, defaults.analysis.end, "analysis.end", operation);
  require_default(configuration.analysis.group_by, defaults.analysis.group_by, "analysis.group_by",
                  operation);
  require_default(configuration.analysis.sort, defaults.analysis.sort, "analysis.sort", operation);
  require_default(configuration.analysis.trim_agent_frames, defaults.analysis.trim_agent_frames,
                  "analysis.trim_agent_frames", operation);
}

void require_default_filters(const Configuration& configuration, const Configuration& defaults,
                             Operation operation) {
  require_default(configuration.filters.min_size, defaults.filters.min_size, "filters.min_size",
                  operation);
  require_default(configuration.filters.max_size, defaults.filters.max_size, "filters.max_size",
                  operation);
  require_default(configuration.filters.events, defaults.filters.events, "filters.events",
                  operation);
  require_default(configuration.filters.threads, defaults.filters.threads, "filters.threads",
                  operation);
  require_default(configuration.filters.apis, defaults.filters.apis, "filters.apis", operation);
  require_default(configuration.filters.modules, defaults.filters.modules, "filters.modules",
                  operation);
  require_default(configuration.filters.stack_modules, defaults.filters.stack_modules,
                  "filters.stack_modules", operation);
  require_default(configuration.filters.allocation_ids, defaults.filters.allocation_ids,
                  "filters.allocation_ids", operation);
  require_default(configuration.filters.statuses, defaults.filters.statuses, "filters.statuses",
                  operation);
}

void require_default_symbols(const Configuration& configuration, const Configuration& defaults,
                             Operation operation) {
  require_default(configuration.symbols.mode, defaults.symbols.mode, "symbols.mode", operation);
  require_default(configuration.symbols.paths, defaults.symbols.paths, "symbols.paths", operation);
  require_default(configuration.symbols.servers, defaults.symbols.servers, "symbols.servers",
                  operation);
}

void require_default_patch(const Configuration& configuration, const Configuration& defaults,
                           Operation operation) {
  require_default(configuration.patch.input, defaults.patch.input, "patch.input", operation);
  require_default(configuration.patch.output, defaults.patch.output, "patch.output", operation);
  require_default(configuration.patch.method, defaults.patch.method, "patch.method", operation);
  require_default(configuration.patch.agent_name, defaults.patch.agent_name, "patch.agent_name",
                  operation);
  require_default(configuration.patch.allow_break_signature, defaults.patch.allow_break_signature,
                  "patch.allow_break_signature", operation);
  require_default(configuration.patch.verify, defaults.patch.verify, "patch.verify", operation);
  require_default(configuration.patch.standalone, defaults.patch.standalone, "patch.standalone",
                  operation);
}

void require_existing_path(const std::optional<std::filesystem::path>& path, std::string_view key) {
  if (!path.has_value()) {
    fail(key, "a path is required");
  }
  std::error_code error;
  const bool exists = std::filesystem::exists(*path, error);
  if (error || !exists) {
    fail(key, "path does not exist");
  }
}

void validate_optional_existing_path(const std::optional<std::filesystem::path>& path,
                                     std::string_view key) {
  if (path.has_value()) {
    require_existing_path(path, key);
  }
}

void validate_optional_directory(const std::optional<std::filesystem::path>& path,
                                 std::string_view key) {
  if (!path.has_value()) {
    return;
  }
  std::error_code error;
  if (!std::filesystem::is_directory(*path, error) || error) {
    fail(key, "path does not exist or is not a directory");
  }
}

void validate_output_parent(const std::optional<std::filesystem::path>& path,
                            std::string_view key) {
  if (!path.has_value()) {
    return;
  }

  auto ancestor = path->parent_path();
  std::error_code error;
  while (!ancestor.empty() && !std::filesystem::exists(ancestor, error)) {
    if (error) {
      fail(key, "cannot inspect the output directory");
    }
    const auto parent = ancestor.parent_path();
    if (parent == ancestor) {
      break;
    }
    ancestor = parent;
  }
  if (ancestor.empty() || error || !std::filesystem::is_directory(ancestor, error) || error) {
    fail(key, "parent directory does not exist or is not a directory");
  }
}

void validate_window_bound(const std::optional<WindowBound>& bound, std::string_view key) {
  if (bound.has_value() && bound->time.has_value() && bound->sequence.has_value()) {
    fail(key, "must be a duration or a #sequence, not both");
  }
}

// Orders only bounds of the same kind (time against time, sequence against sequence); different
// kinds have no defined order and pass.
[[nodiscard]] bool window_bounds_out_of_order(const WindowBound& lower, const WindowBound& upper) {
  if (lower.time.has_value() && upper.time.has_value() && *lower.time > *upper.time) {
    return true;
  }
  if (lower.sequence.has_value() && upper.sequence.has_value() &&
      *lower.sequence > *upper.sequence) {
    return true;
  }
  return false;
}

void validate_common_capture(const Configuration& configuration) {
  if (configuration.capture.max_stack_depth.value < 1U ||
      configuration.capture.max_stack_depth.value > 256U) {
    fail("capture.max_stack_depth", "must be between 1 and 256");
  }
  if (configuration.injection.timeout.value <= std::chrono::nanoseconds::zero()) {
    fail("injection.timeout", "must be greater than zero");
  }
  if (configuration.capture.duration.value.has_value() &&
      *configuration.capture.duration.value <= std::chrono::nanoseconds::zero()) {
    fail("capture.duration", "must be greater than zero when provided");
  }
  validate_optional_existing_path(configuration.injection.agent_path.value, "injection.agent_path");

  if (configuration.trace.buffer_size.value < kMinimumTraceBufferSize) {
    fail("trace.buffer_size", "must be at least 4 KiB");
  }
  if (configuration.trace.max_file_size.value <= configuration.trace.buffer_size.value ||
      configuration.trace.max_file_size.value - configuration.trace.buffer_size.value <
          kMinimumTraceOverhead) {
    fail("trace.max_file_size", "must fit the trace buffer plus file metadata");
  }
  if (configuration.trace.max_files.value < 1U) {
    fail("trace.max_files", "must be at least 1");
  }
  if (configuration.trace.on_full.value == TraceFullPolicy::kRotate &&
      configuration.trace.max_files.value < 2U) {
    fail("trace.max_files", "must be at least 2 when trace.on_full is rotate");
  }
  if (configuration.trace.flush_interval.value <= std::chrono::nanoseconds::zero()) {
    fail("trace.flush_interval", "must be greater than zero");
  }
  if (configuration.trace.compression.value != Compression::kZstd &&
      configuration.trace.compression_level.value != 0) {
    fail("trace.compression_level", "must be 0 for none and lz4 compression");
  }
  if (configuration.trace.compression.value == Compression::kZstd &&
      configuration.trace.compression_level.value != 0 &&
      configuration.trace.compression_level.value != 1) {
    fail("trace.compression_level", "V1 supports zstd level 1 or 0 for the codec default");
  }
  validate_output_parent(configuration.trace.path.value, "trace.path");
}

void validate_run(const Configuration& configuration, const Configuration& defaults) {
  require_existing_path(configuration.target.path.value, "target.path");
  require_default(configuration.target.pid, defaults.target.pid, "target.pid", Operation::kRun);
  validate_optional_directory(configuration.target.working_directory.value,
                              "target.working_directory");
  if (configuration.injection.method.value != InjectionMethod::kRemoteThread &&
      configuration.injection.method.value != InjectionMethod::kThreadHijack &&
      configuration.injection.method.value != InjectionMethod::kEntrypointCode &&
      configuration.injection.method.value != InjectionMethod::kStaticPePatch) {
    fail("injection.method", "is not supported by run");
  }
  require_default(configuration.injection.unload_on_stop, defaults.injection.unload_on_stop,
                  "injection.unload_on_stop", Operation::kRun);
  validate_common_capture(configuration);
  require_default_analysis(configuration, defaults, Operation::kRun);
  require_default_filters(configuration, defaults, Operation::kRun);
  require_default_symbols(configuration, defaults, Operation::kRun);
  require_default_patch(configuration, defaults, Operation::kRun);
}

void validate_attach(const Configuration& configuration, const Configuration& defaults) {
  require_default(configuration.target.path, defaults.target.path, "target.path",
                  Operation::kAttach);
  require_default(configuration.target.args, defaults.target.args, "target.args",
                  Operation::kAttach);
  require_default(configuration.target.working_directory, defaults.target.working_directory,
                  "target.working_directory", Operation::kAttach);
  if (!configuration.target.pid.value.has_value() || *configuration.target.pid.value == 0U) {
    fail("target.pid", "must be greater than zero for attach");
  }
  if (configuration.injection.method.value != InjectionMethod::kRemoteThread &&
      configuration.injection.method.value != InjectionMethod::kThreadHijack) {
    fail("injection.method", "attach supports remote-thread and thread-hijack");
  }
  validate_common_capture(configuration);
  require_default_analysis(configuration, defaults, Operation::kAttach);
  require_default_filters(configuration, defaults, Operation::kAttach);
  require_default_symbols(configuration, defaults, Operation::kAttach);
  require_default_patch(configuration, defaults, Operation::kAttach);
}

void validate_patch(const Configuration& configuration, const Configuration& defaults) {
  require_default_target(configuration, defaults, Operation::kPatch);
  require_default_injection(configuration, defaults, Operation::kPatch);
  require_default_capture(configuration, defaults, Operation::kPatch);
  require_default_trace(configuration, defaults, Operation::kPatch);
  require_default_analysis(configuration, defaults, Operation::kPatch);
  require_default_filters(configuration, defaults, Operation::kPatch);
  require_default_symbols(configuration, defaults, Operation::kPatch);

  require_existing_path(configuration.patch.input.value, "patch.input");
  if (!configuration.patch.output.value.has_value()) {
    fail("patch.output", "a path is required");
  }
  if (*configuration.patch.input.value == *configuration.patch.output.value) {
    fail("patch.output", "must be different from patch.input");
  }
  std::error_code error;
  if (std::filesystem::exists(*configuration.patch.output.value, error) || error) {
    fail("patch.output", "already exists or cannot be inspected");
  }
  validate_output_parent(configuration.patch.output.value, "patch.output");
  if (configuration.patch.agent_name.value.empty()) {
    fail("patch.agent_name", "must not be empty");
  }
}

void validate_analyze(const Configuration& configuration, const Configuration& defaults) {
  require_default_target(configuration, defaults, Operation::kAnalyze);
  require_default_injection(configuration, defaults, Operation::kAnalyze);
  require_default_capture(configuration, defaults, Operation::kAnalyze);
  require_default_trace(configuration, defaults, Operation::kAnalyze);
  require_default_patch(configuration, defaults, Operation::kAnalyze);

  if (configuration.analysis.inputs.value.empty()) {
    fail("analysis.inputs", "at least one trace path is required");
  }
  for (const auto& input : configuration.analysis.inputs.value) {
    require_existing_path(std::optional{input}, "analysis.inputs");
  }
  validate_output_parent(configuration.analysis.output.value, "analysis.output");
  const bool events_mode = configuration.analysis.mode.value == AnalysisMode::kEvents;
  if (events_mode && configuration.analysis.end.value.has_value()) {
    fail("analysis.end", "is only valid in leaks mode");
  }
  validate_window_bound(configuration.analysis.from.value, "analysis.from");
  validate_window_bound(configuration.analysis.to.value, "analysis.to");
  validate_window_bound(configuration.analysis.end.value, "analysis.end");
  if (configuration.analysis.from.value.has_value() &&
      configuration.analysis.to.value.has_value() &&
      window_bounds_out_of_order(*configuration.analysis.from.value,
                                 *configuration.analysis.to.value)) {
    fail("analysis.from", "must be less than or equal to analysis.to");
  }
  if (configuration.analysis.end.value.has_value() && configuration.analysis.to.value.has_value() &&
      window_bounds_out_of_order(*configuration.analysis.to.value,
                                 *configuration.analysis.end.value)) {
    fail("analysis.end", "must be greater than or equal to analysis.to");
  }
  if (configuration.analysis.end.value.has_value() &&
      !configuration.analysis.to.value.has_value() &&
      configuration.analysis.from.value.has_value() &&
      window_bounds_out_of_order(*configuration.analysis.from.value,
                                 *configuration.analysis.end.value)) {
    fail("analysis.end", "must be greater than or equal to analysis.from when --to is omitted");
  }
  const bool sort_specified = configuration.analysis.sort.source != ValueSource::kDefault;
  if (sort_specified && !configuration.analysis.group_by.value.has_value()) {
    fail("analysis.sort", "requires --group-by");
  }
  if (configuration.symbols.mode.value == SymbolMode::kOff &&
      (!configuration.symbols.paths.value.empty() ||
       !configuration.symbols.servers.value.empty())) {
    fail("symbols.mode", "off conflicts with configured symbols.paths or symbols.servers");
  }
  if (configuration.analysis.group_by.value.has_value() && sort_specified) {
    const AnalysisSort sort = configuration.analysis.sort.value;
    if (events_mode && sort == AnalysisSort::kBytes) {
      fail("analysis.sort", "bytes is only valid with --mode leaks");
    }
    if (!events_mode && (sort == AnalysisSort::kAllocBytes || sort == AnalysisSort::kFreeBytes ||
                         sort == AnalysisSort::kNetBytes)) {
      fail("analysis.sort",
           "alloc-bytes, free-bytes, and net-bytes are only valid with --mode events");
    }
  }
  if (configuration.filters.min_size.value.has_value() &&
      configuration.filters.max_size.value.has_value() &&
      *configuration.filters.min_size.value > *configuration.filters.max_size.value) {
    fail("filters.min_size", "must be less than or equal to filters.max_size");
  }
}

void validate_doctor(const Configuration& configuration, const Configuration& defaults) {
  validate_optional_existing_path(configuration.target.path.value, "target.path");
  require_default(configuration.target.args, defaults.target.args, "target.args",
                  Operation::kDoctor);
  require_default(configuration.target.working_directory, defaults.target.working_directory,
                  "target.working_directory", Operation::kDoctor);
  if (configuration.target.pid.value.has_value() && *configuration.target.pid.value == 0U) {
    fail("target.pid", "must be greater than zero when provided");
  }
  validate_optional_existing_path(configuration.injection.agent_path.value, "injection.agent_path");
  require_default(configuration.injection.timeout, defaults.injection.timeout, "injection.timeout",
                  Operation::kDoctor);
  require_default(configuration.injection.unload_on_stop, defaults.injection.unload_on_stop,
                  "injection.unload_on_stop", Operation::kDoctor);
  require_default_capture(configuration, defaults, Operation::kDoctor);
  require_default_trace(configuration, defaults, Operation::kDoctor);
  require_default_analysis(configuration, defaults, Operation::kDoctor);
  require_default_filters(configuration, defaults, Operation::kDoctor);
  require_default_symbols(configuration, defaults, Operation::kDoctor);
  require_default_patch(configuration, defaults, Operation::kDoctor);
}

}  // namespace

void validate_configuration(const Configuration& configuration) {
  if (configuration.schema_version.value != kConfigSchemaVersion) {
    fail("schema_version", "unsupported schema version");
  }
  if (!configuration.operation.value.has_value()) {
    fail("operation", "no operation was selected");
  }

  const auto defaults = make_default_configuration();
  switch (*configuration.operation.value) {
    case Operation::kRun:
      validate_run(configuration, defaults);
      break;
    case Operation::kAttach:
      validate_attach(configuration, defaults);
      break;
    case Operation::kPatch:
      validate_patch(configuration, defaults);
      break;
    case Operation::kAnalyze:
      validate_analyze(configuration, defaults);
      break;
    case Operation::kDoctor:
      validate_doctor(configuration, defaults);
      break;
  }
}

}  // namespace noleax::config
