#include "noleax/config/configuration.hpp"

#include <chrono>
#include <cstdint>
#include <optional>

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

}  // namespace

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

  configuration.trace.buffer_size.value = 16U * 1024U * 1024U;
  configuration.trace.max_file_size.value = 256U * 1024U * 1024U;
  configuration.trace.max_files.value = 1U;
  configuration.trace.on_full.value = TraceFullPolicy::kStop;
  configuration.trace.flush_interval.value = 250ms;
  configuration.trace.compression.value = Compression::kLz4;
  configuration.trace.compression_level.value = 0;

  configuration.analysis.mode.value = AnalysisMode::kEvents;
  configuration.analysis.format.value = OutputFormat::kConsole;

  configuration.symbols.mode.value = SymbolMode::kAuto;

  configuration.patch.method.value = PatchMethod::kEntrypointSection;
  configuration.patch.agent_name.value = "noleax-agent.dll";
  configuration.patch.allow_break_signature.value = false;
  configuration.patch.verify.value = true;

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
  apply_override(configuration.analysis.a, overrides.analysis.a, source);
  apply_override(configuration.analysis.b, overrides.analysis.b, source);
  apply_override(configuration.analysis.c, overrides.analysis.c, source);

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

  apply_override(configuration.patch.input, overrides.patch.input, source);
  apply_override(configuration.patch.output, overrides.patch.output, source);
  apply_override(configuration.patch.method, overrides.patch.method, source);
  apply_override(configuration.patch.agent_name, overrides.patch.agent_name, source);
  apply_override(configuration.patch.allow_break_signature, overrides.patch.allow_break_signature,
                 source);
  apply_override(configuration.patch.verify, overrides.patch.verify, source);

  apply_override(configuration.diagnostics.log_level, overrides.diagnostics.log_level, source);
  apply_override(configuration.diagnostics.color, overrides.diagnostics.color, source);
}

}  // namespace noleax::config
