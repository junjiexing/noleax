#include <algorithm>
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

constexpr std::uint64_t kMinimumTraceBufferSize = 4U * 1024U;
constexpr std::uint64_t kMinimumTraceOverhead = 4U * 1024U;
constexpr auto kMaximumMemorySnapshotInterval = std::chrono::hours{1};

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
  require_default(configuration.capture.memory_counters_interval,
                  defaults.capture.memory_counters_interval, "capture.memory_counters_interval",
                  operation);
  require_default(configuration.capture.memory_map_interval, defaults.capture.memory_map_interval,
                  "capture.memory_map_interval", operation);
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

void require_default_symbol_listing(const Configuration& configuration,
                                    const Configuration& defaults, Operation operation) {
  require_default(configuration.symbol_listing.input, defaults.symbol_listing.input,
                  "symbol_listing.input", operation);
  require_default(configuration.symbol_listing.format, defaults.symbol_listing.format,
                  "symbol_listing.format", operation);
  require_default(configuration.symbol_listing.output, defaults.symbol_listing.output,
                  "symbol_listing.output", operation);
  require_default(configuration.symbol_listing.name, defaults.symbol_listing.name,
                  "symbol_listing.name", operation);
  require_default(configuration.symbol_listing.match_case, defaults.symbol_listing.match_case,
                  "symbol_listing.match_case", operation);
  require_default(configuration.symbol_listing.kind, defaults.symbol_listing.kind,
                  "symbol_listing.kind", operation);
  require_default(configuration.symbol_listing.fields, defaults.symbol_listing.fields,
                  "symbol_listing.fields", operation);
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

void validate_custom_hook_role(const CustomHookRole& role, std::string_view key, bool required) {
  const std::uint32_t locators = (role.export_name.has_value() ? 1U : 0U) +
                                 (role.pdb_symbol.has_value() ? 1U : 0U) +
                                 (role.rva.has_value() ? 1U : 0U);
  if (locators > 1U) {
    fail(key, "accepts exactly one of an export name, a _pdb symbol, or an _rva");
  }
  if (required && locators == 0U) {
    fail(key, "is required");
  }
  if (role.export_name.has_value() && role.export_name->empty()) {
    fail(key, "export name must not be empty");
  }
  if (role.pdb_symbol.has_value() && role.pdb_symbol->empty()) {
    fail(key, "PDB symbol must not be empty");
  }
}

[[nodiscard]] std::string lowercase(std::string_view value) {
  std::string result;
  result.reserve(value.size());
  for (const char character : value) {
    result.push_back(character >= 'A' && character <= 'Z' ? static_cast<char>(character - 'A' + 'a')
                                                          : character);
  }
  return result;
}

void validate_custom_hooks(const Configuration& configuration) {
  const auto& hooks = configuration.custom_hooks.value;
  if (hooks.size() > kMaximumCustomHooks) {
    fail("custom_hooks", "declares too many hook points");
  }
  std::vector<std::string> seen_modules;
  seen_modules.reserve(hooks.size());
  for (const CustomHook& hook : hooks) {
    if (hook.module.empty() || hook.module.find('\0') != std::string::npos) {
      fail("custom_hooks.module", "must not be empty or contain NUL");
    }
    validate_custom_hook_role(hook.alloc, "custom_hooks.alloc", true);
    validate_custom_hook_role(hook.realloc, "custom_hooks.realloc", false);
    validate_custom_hook_role(hook.free, "custom_hooks.free", true);
    if (hook.size_arg > 7U || hook.ptr_arg > 7U) {
      fail("custom_hooks.size_arg", "argument slots must be between 0 and 7");
    }
    if ((hook.result_arg.has_value() && *hook.result_arg > 7U) ||
        (hook.count_arg.has_value() && *hook.count_arg > 7U) ||
        (hook.free_size_arg.has_value() && *hook.free_size_arg > 7U)) {
      fail("custom_hooks.result_arg", "argument slots must be between 0 and 7");
    }
    if ((hook.kind == CustomHookKind::kCalloc) != hook.count_arg.has_value()) {
      fail("custom_hooks.count_arg", "requires kind = \"calloc\" and vice versa");
    }
    if (hook.wait_module < std::chrono::nanoseconds::zero()) {
      fail("custom_hooks.wait_module", "must not be negative");
    }
    if ((hook.alloc.pdb_symbol.has_value() || hook.realloc.pdb_symbol.has_value() ||
         hook.free.pdb_symbol.has_value()) &&
        configuration.symbols.mode.value == SymbolMode::kOff) {
      fail("custom_hooks.alloc_pdb", "requires symbols.mode other than \"off\"");
    }
    const std::string lowered = lowercase(hook.module);
    if (std::find(seen_modules.begin(), seen_modules.end(), lowered) != seen_modules.end()) {
      fail("custom_hooks.module", "declares module '" + hook.module + "' more than once");
    }
    seen_modules.push_back(lowered);
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
  if (configuration.capture.memory_counters_interval.value < std::chrono::nanoseconds::zero() ||
      configuration.capture.memory_counters_interval.value > kMaximumMemorySnapshotInterval) {
    fail("capture.memory_counters_interval", "must be between 0s (disabled) and 1h");
  }
  if (configuration.capture.memory_map_interval.value < std::chrono::nanoseconds::zero() ||
      configuration.capture.memory_map_interval.value > kMaximumMemorySnapshotInterval) {
    fail("capture.memory_map_interval", "must be between 0s (disabled) and 1h");
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
      configuration.injection.method.value != InjectionMethod::kStaticPePatch &&
      configuration.injection.method.value != InjectionMethod::kLdPreload) {
    fail("injection.method", "is not supported by run");
  }
  require_default(configuration.injection.unload_on_stop, defaults.injection.unload_on_stop,
                  "injection.unload_on_stop", Operation::kRun);
  validate_common_capture(configuration);
  validate_custom_hooks(configuration);
  require_default_analysis(configuration, defaults, Operation::kRun);
  require_default_filters(configuration, defaults, Operation::kRun);
  if (configuration.custom_hooks.value.empty()) {
    require_default_symbols(configuration, defaults, Operation::kRun);
  }
  require_default_symbol_listing(configuration, defaults, Operation::kRun);
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
  validate_custom_hooks(configuration);
  require_default_analysis(configuration, defaults, Operation::kAttach);
  require_default_filters(configuration, defaults, Operation::kAttach);
  if (configuration.custom_hooks.value.empty()) {
    require_default_symbols(configuration, defaults, Operation::kAttach);
  }
  require_default_symbol_listing(configuration, defaults, Operation::kAttach);
  require_default_patch(configuration, defaults, Operation::kAttach);
}

void validate_patch(const Configuration& configuration, const Configuration& defaults) {
  require_default_target(configuration, defaults, Operation::kPatch);
  require_default_injection(configuration, defaults, Operation::kPatch);
  require_default_capture(configuration, defaults, Operation::kPatch);
  require_default_trace(configuration, defaults, Operation::kPatch);
  require_default_analysis(configuration, defaults, Operation::kPatch);
  require_default_filters(configuration, defaults, Operation::kPatch);
  if (configuration.custom_hooks.value.empty()) {
    require_default_symbols(configuration, defaults, Operation::kPatch);
  }
  require_default_symbol_listing(configuration, defaults, Operation::kPatch);
  validate_custom_hooks(configuration);

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
  require_default_symbol_listing(configuration, defaults, Operation::kAnalyze);
  require_default(configuration.custom_hooks, defaults.custom_hooks, "custom_hooks",
                  Operation::kAnalyze);

  if (configuration.analysis.inputs.value.empty()) {
    fail("analysis.inputs", "at least one trace path is required");
  }
  for (const auto& input : configuration.analysis.inputs.value) {
    require_existing_path(std::optional{input}, "analysis.inputs");
  }
  validate_output_parent(configuration.analysis.output.value, "analysis.output");
  const bool events_mode = configuration.analysis.mode.value == AnalysisMode::kEvents;
  if (configuration.analysis.mode.value != AnalysisMode::kOutstanding &&
      configuration.analysis.end.value.has_value()) {
    fail("analysis.end", "is only valid in leaks mode");
  }
  const bool memory_mode = configuration.analysis.mode.value == AnalysisMode::kMemory;
  if (memory_mode) {
    const auto reject_setting = [](ValueSource source, std::string_view key) {
      if (source != ValueSource::kDefault) {
        fail(key, "is not valid with --mode memory");
      }
    };
    if (configuration.analysis.from.value.has_value() &&
        configuration.analysis.from.value->sequence.has_value()) {
      fail("analysis.from", "a #sequence window is not valid with --mode memory");
    }
    if (configuration.analysis.to.value.has_value() &&
        configuration.analysis.to.value->sequence.has_value()) {
      fail("analysis.to", "a #sequence window is not valid with --mode memory");
    }
    reject_setting(configuration.analysis.group_by.source, "analysis.group_by");
    reject_setting(configuration.analysis.sort.source, "analysis.sort");
    reject_setting(configuration.analysis.trim_agent_frames.source, "analysis.trim_agent_frames");
    reject_setting(configuration.filters.min_size.source, "filters.min_size");
    reject_setting(configuration.filters.max_size.source, "filters.max_size");
    reject_setting(configuration.filters.events.source, "filters.events");
    reject_setting(configuration.filters.threads.source, "filters.threads");
    reject_setting(configuration.filters.apis.source, "filters.apis");
    reject_setting(configuration.filters.modules.source, "filters.modules");
    reject_setting(configuration.filters.stack_modules.source, "filters.stack_modules");
    reject_setting(configuration.filters.allocation_ids.source, "filters.allocation_ids");
    reject_setting(configuration.filters.statuses.source, "filters.statuses");
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
  require_default_symbol_listing(configuration, defaults, Operation::kDoctor);
  require_default_patch(configuration, defaults, Operation::kDoctor);
  require_default(configuration.custom_hooks, defaults.custom_hooks, "custom_hooks",
                  Operation::kDoctor);
}

void validate_symbols_listing(const Configuration& configuration, const Configuration& defaults) {
  require_default_target(configuration, defaults, Operation::kSymbols);
  require_default_injection(configuration, defaults, Operation::kSymbols);
  require_default_capture(configuration, defaults, Operation::kSymbols);
  require_default_trace(configuration, defaults, Operation::kSymbols);
  require_default_analysis(configuration, defaults, Operation::kSymbols);
  require_default_filters(configuration, defaults, Operation::kSymbols);
  require_default_patch(configuration, defaults, Operation::kSymbols);
  require_default(configuration.custom_hooks, defaults.custom_hooks, "custom_hooks",
                  Operation::kSymbols);

  require_existing_path(configuration.symbol_listing.input.value, "symbol_listing.input");
  if (configuration.symbol_listing.output.value.has_value() &&
      *configuration.symbol_listing.output.value == *configuration.symbol_listing.input.value) {
    fail("symbol_listing.output", "must be different from symbol_listing.input");
  }
  validate_output_parent(configuration.symbol_listing.output.value, "symbol_listing.output");
  if (configuration.symbol_listing.fields.source != ValueSource::kDefault &&
      configuration.symbol_listing.fields.value.empty()) {
    fail("symbol_listing.fields", "must not be empty when provided");
  }
  const auto& fields = configuration.symbol_listing.fields.value;
  for (std::size_t index = 0U; index < fields.size(); ++index) {
    for (std::size_t other = index + 1U; other < fields.size(); ++other) {
      if (fields[index] == fields[other]) {
        fail("symbol_listing.fields", "must not contain duplicates");
      }
    }
  }
  if (configuration.symbols.mode.value == SymbolMode::kOff) {
    fail("symbols.mode", "off is not valid for symbols; enumeration requires DbgHelp");
  }
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
    case Operation::kSymbols:
      validate_symbols_listing(configuration, defaults);
      break;
  }
}

}  // namespace noleax::config
