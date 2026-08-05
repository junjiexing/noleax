#include "noleax/config/configuration.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>

namespace noleax::config {
namespace {

template <typename T>
void apply_override(Setting<T>& setting, const SettingOverride<T>& override_value,
                    ValueSource source) {
  if (override_value.specified) {
    setting.value = override_value.value;
    setting.source = source;
  }
}

[[nodiscard]] std::string custom_hook_role_label(const CustomHook& hook,
                                                 const CustomHookRole& role) {
  if (role.export_name.has_value()) {
    return *role.export_name;
  }
  if (role.pdb_symbol.has_value()) {
    const std::size_t separator = role.pdb_symbol->find('!');
    return separator == std::string::npos ? *role.pdb_symbol
                                          : role.pdb_symbol->substr(separator + 1U);
  }
  std::string label = hook.module;
  label.append("+0x");
  std::array<char, 16> digits{};
  const auto converted = std::to_chars(digits.data(), digits.data() + digits.size(), *role.rva, 16);
  label.append(digits.data(), converted.ptr);
  return label;
}

}  // namespace

std::string custom_hook_label(const CustomHook& hook) {
  if (hook.alloc.declared()) {
    return custom_hook_role_label(hook, hook.alloc);
  }
  if (hook.free.declared()) {
    return custom_hook_role_label(hook, hook.free);
  }
  if (hook.realloc.declared()) {
    return custom_hook_role_label(hook, hook.realloc);
  }
  return hook.module;
}

std::string_view value_source_name(ValueSource source) noexcept {
  switch (source) {
    case ValueSource::kDefault:
      return "default";
    case ValueSource::kConfig:
      return "config";
    case ValueSource::kCommandLine:
      return "cli";
  }
  return "unknown";
}

WindowBound parse_window_bound(std::string_view input) {
  WindowBound bound;
  if (!input.empty() && input.front() == '#') {
    bound.sequence = parse_unsigned_integer(
        input.substr(1U), (std::numeric_limits<std::uint64_t>::max)(), "window bound");
    return bound;
  }
  bound.time = parse_duration(input);
  return bound;
}

Configuration make_default_configuration() {
  using namespace std::chrono_literals;

  Configuration configuration;
  configuration.schema_version.value = kConfigSchemaVersion;
  configuration.operation.value = std::nullopt;

  configuration.injection.method.value = InjectionMethod::kRemoteThread;
  configuration.injection.timeout.value = 10s;
  configuration.injection.unload_on_stop.value = false;

  configuration.capture.hook_profile.value = HookProfile::kWindowsNative;
  configuration.capture.max_stack_depth.value = 64U;
  configuration.capture.min_size.value = 0U;
  configuration.capture.live.value = false;

  configuration.trace.buffer_size.value = 16U * 1024U * 1024U;
  configuration.trace.max_file_size.value = 256U * 1024U * 1024U;
  configuration.trace.max_files.value = 1U;
  configuration.trace.on_full.value = TraceFullPolicy::kStop;
  configuration.trace.flush_interval.value = 250ms;
  configuration.trace.compression.value = Compression::kLz4;
  configuration.trace.compression_level.value = 0;

  configuration.analysis.mode.value = AnalysisMode::kEvents;
  configuration.analysis.format.value = OutputFormat::kConsole;
  configuration.analysis.sort.value = AnalysisSort::kAllocBytes;
  configuration.analysis.trim_agent_frames.value = true;

  configuration.symbols.mode.value = SymbolMode::kAuto;

  configuration.symbol_listing.format.value = OutputFormat::kConsole;
  configuration.symbol_listing.match_case.value = false;

  configuration.patch.method.value = PatchMethod::kEntrypointSection;
  configuration.patch.agent_name.value = "noleax-agent.dll";
  configuration.patch.allow_break_signature.value = false;
  configuration.patch.verify.value = true;
  configuration.patch.standalone.value = false;

  configuration.diagnostics.log_level.value = LogLevel::kInfo;
  configuration.diagnostics.color.value = ColorMode::kAuto;
  return configuration;
}

void apply_overrides(Configuration& configuration, const ConfigurationOverrides& overrides,
                     ValueSource source) {
  apply_override(configuration.schema_version, overrides.schema_version, source);
  if (overrides.operation.specified) {
    configuration.operation.value = overrides.operation.value;
    configuration.operation.source = source;
  }

  apply_override(configuration.target.path, overrides.target.path, source);
  apply_override(configuration.target.args, overrides.target.args, source);
  apply_override(configuration.target.working_directory, overrides.target.working_directory,
                 source);
  apply_override(configuration.target.pid, overrides.target.pid, source);

  apply_override(configuration.injection.method, overrides.injection.method, source);
  apply_override(configuration.injection.agent_path, overrides.injection.agent_path, source);
  apply_override(configuration.injection.timeout, overrides.injection.timeout, source);
  apply_override(configuration.injection.unload_on_stop, overrides.injection.unload_on_stop,
                 source);

  apply_override(configuration.capture.hook_profile, overrides.capture.hook_profile, source);
  apply_override(configuration.capture.max_stack_depth, overrides.capture.max_stack_depth, source);
  apply_override(configuration.capture.min_size, overrides.capture.min_size, source);
  apply_override(configuration.capture.duration, overrides.capture.duration, source);
  apply_override(configuration.capture.live, overrides.capture.live, source);

  apply_override(configuration.trace.path, overrides.trace.path, source);
  apply_override(configuration.trace.buffer_size, overrides.trace.buffer_size, source);
  apply_override(configuration.trace.max_file_size, overrides.trace.max_file_size, source);
  apply_override(configuration.trace.max_files, overrides.trace.max_files, source);
  apply_override(configuration.trace.on_full, overrides.trace.on_full, source);
  apply_override(configuration.trace.flush_interval, overrides.trace.flush_interval, source);
  apply_override(configuration.trace.compression, overrides.trace.compression, source);
  apply_override(configuration.trace.compression_level, overrides.trace.compression_level, source);

  apply_override(configuration.analysis.inputs, overrides.analysis.inputs, source);
  apply_override(configuration.analysis.mode, overrides.analysis.mode, source);
  apply_override(configuration.analysis.format, overrides.analysis.format, source);
  apply_override(configuration.analysis.output, overrides.analysis.output, source);
  apply_override(configuration.analysis.from, overrides.analysis.from, source);
  apply_override(configuration.analysis.to, overrides.analysis.to, source);
  apply_override(configuration.analysis.end, overrides.analysis.end, source);
  apply_override(configuration.analysis.group_by, overrides.analysis.group_by, source);
  apply_override(configuration.analysis.sort, overrides.analysis.sort, source);
  apply_override(configuration.analysis.trim_agent_frames, overrides.analysis.trim_agent_frames,
                 source);

  apply_override(configuration.filters.min_size, overrides.filters.min_size, source);
  apply_override(configuration.filters.max_size, overrides.filters.max_size, source);
  apply_override(configuration.filters.events, overrides.filters.events, source);
  apply_override(configuration.filters.threads, overrides.filters.threads, source);
  apply_override(configuration.filters.apis, overrides.filters.apis, source);
  apply_override(configuration.filters.modules, overrides.filters.modules, source);
  apply_override(configuration.filters.stack_modules, overrides.filters.stack_modules, source);
  apply_override(configuration.filters.allocation_ids, overrides.filters.allocation_ids, source);
  apply_override(configuration.filters.statuses, overrides.filters.statuses, source);

  apply_override(configuration.symbols.mode, overrides.symbols.mode, source);
  apply_override(configuration.symbols.paths, overrides.symbols.paths, source);
  apply_override(configuration.symbols.servers, overrides.symbols.servers, source);

  apply_override(configuration.symbol_listing.input, overrides.symbol_listing.input, source);
  apply_override(configuration.symbol_listing.format, overrides.symbol_listing.format, source);
  apply_override(configuration.symbol_listing.output, overrides.symbol_listing.output, source);
  apply_override(configuration.symbol_listing.name, overrides.symbol_listing.name, source);
  apply_override(configuration.symbol_listing.match_case, overrides.symbol_listing.match_case,
                 source);
  apply_override(configuration.symbol_listing.kind, overrides.symbol_listing.kind, source);
  apply_override(configuration.symbol_listing.fields, overrides.symbol_listing.fields, source);

  apply_override(configuration.patch.input, overrides.patch.input, source);
  apply_override(configuration.patch.output, overrides.patch.output, source);
  apply_override(configuration.patch.method, overrides.patch.method, source);
  apply_override(configuration.patch.agent_name, overrides.patch.agent_name, source);
  apply_override(configuration.patch.allow_break_signature, overrides.patch.allow_break_signature,
                 source);
  apply_override(configuration.patch.verify, overrides.patch.verify, source);
  apply_override(configuration.patch.standalone, overrides.patch.standalone, source);

  apply_override(configuration.diagnostics.log_level, overrides.diagnostics.log_level, source);
  apply_override(configuration.diagnostics.color, overrides.diagnostics.color, source);

  apply_override(configuration.custom_hooks, overrides.custom_hooks, source);
}

}  // namespace noleax::config
