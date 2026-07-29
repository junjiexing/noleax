#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "noleax/config/value_parser.hpp"

namespace noleax::config {

inline constexpr std::uint32_t kConfigSchemaVersion = 1;

enum class ValueSource : std::uint8_t {
  kDefault,
  kConfig,
  kCommandLine,
};

enum class Operation : std::uint8_t {
  kRun,
  kAttach,
  kPatch,
  kAnalyze,
  kDoctor,
};

enum class LogLevel : std::uint8_t {
  kTrace,
  kDebug,
  kInfo,
  kWarn,
  kError,
};

enum class ColorMode : std::uint8_t {
  kAuto,
  kAlways,
  kNever,
};

enum class InjectionMethod : std::uint8_t {
  kRemoteThread,
  kThreadHijack,
  kEntrypointCode,
};

enum class HookProfile : std::uint8_t {
  kWindowsNtHeap,
  kWindowsVirtualMemory,
  kWindowsNative,
};

enum class TraceFullPolicy : std::uint8_t {
  kStop,
  kRotate,
};

enum class Compression : std::uint8_t {
  kNone,
  kLz4,
  kZstd,
};

enum class AnalysisMode : std::uint8_t {
  kEvents,
  kOutstanding,
};

enum class OutputFormat : std::uint8_t {
  kConsole,
  kJson,
  kCsv,
};

enum class SymbolMode : std::uint8_t {
  kAuto,
};

enum class PatchMethod : std::uint8_t {
  kEntrypointSection,
};

enum class EventType : std::uint8_t {
  kHeapCreate,
  kHeapDestroy,
  kAlloc,
  kRealloc,
  kFree,
  kVmAlloc,
  kVmFree,
  kMap,
  kUnmap,
};

enum class EventStatus : std::uint8_t {
  kSuccess,
  kFailure,
  kUnmatched,
};

template <typename Enum>
struct EnumTraits;

template <>
struct EnumTraits<Operation> {
  inline static constexpr std::string_view kind = "operation";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"run"}, Operation::kRun},
      NamedEnumValue{std::string_view{"attach"}, Operation::kAttach},
      NamedEnumValue{std::string_view{"patch"}, Operation::kPatch},
      NamedEnumValue{std::string_view{"analyze"}, Operation::kAnalyze},
      NamedEnumValue{std::string_view{"doctor"}, Operation::kDoctor},
  };
};

template <>
struct EnumTraits<LogLevel> {
  inline static constexpr std::string_view kind = "log level";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"trace"}, LogLevel::kTrace},
      NamedEnumValue{std::string_view{"debug"}, LogLevel::kDebug},
      NamedEnumValue{std::string_view{"info"}, LogLevel::kInfo},
      NamedEnumValue{std::string_view{"warn"}, LogLevel::kWarn},
      NamedEnumValue{std::string_view{"error"}, LogLevel::kError},
  };
};

template <>
struct EnumTraits<ColorMode> {
  inline static constexpr std::string_view kind = "color mode";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"auto"}, ColorMode::kAuto},
      NamedEnumValue{std::string_view{"always"}, ColorMode::kAlways},
      NamedEnumValue{std::string_view{"never"}, ColorMode::kNever},
  };
};

template <>
struct EnumTraits<InjectionMethod> {
  inline static constexpr std::string_view kind = "injection method";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"remote-thread"}, InjectionMethod::kRemoteThread},
      NamedEnumValue{std::string_view{"thread-hijack"}, InjectionMethod::kThreadHijack},
      NamedEnumValue{std::string_view{"entrypoint-code"}, InjectionMethod::kEntrypointCode},
  };
};

template <>
struct EnumTraits<HookProfile> {
  inline static constexpr std::string_view kind = "hook profile";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"windows-nt-heap"}, HookProfile::kWindowsNtHeap},
      NamedEnumValue{std::string_view{"windows-virtual-memory"},
                     HookProfile::kWindowsVirtualMemory},
      NamedEnumValue{std::string_view{"windows-native"}, HookProfile::kWindowsNative},
  };
};

template <>
struct EnumTraits<TraceFullPolicy> {
  inline static constexpr std::string_view kind = "trace full policy";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"stop"}, TraceFullPolicy::kStop},
      NamedEnumValue{std::string_view{"rotate"}, TraceFullPolicy::kRotate},
  };
};

template <>
struct EnumTraits<Compression> {
  inline static constexpr std::string_view kind = "compression codec";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"none"}, Compression::kNone},
      NamedEnumValue{std::string_view{"lz4"}, Compression::kLz4},
      NamedEnumValue{std::string_view{"zstd"}, Compression::kZstd},
  };
};

template <>
struct EnumTraits<AnalysisMode> {
  inline static constexpr std::string_view kind = "analysis mode";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"events"}, AnalysisMode::kEvents},
      NamedEnumValue{std::string_view{"outstanding"}, AnalysisMode::kOutstanding},
  };
};

template <>
struct EnumTraits<OutputFormat> {
  inline static constexpr std::string_view kind = "output format";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"console"}, OutputFormat::kConsole},
      NamedEnumValue{std::string_view{"json"}, OutputFormat::kJson},
      NamedEnumValue{std::string_view{"csv"}, OutputFormat::kCsv},
  };
};

template <>
struct EnumTraits<SymbolMode> {
  inline static constexpr std::string_view kind = "symbol mode";
  inline static constexpr auto values =
      std::array{NamedEnumValue{std::string_view{"auto"}, SymbolMode::kAuto}};
};

template <>
struct EnumTraits<PatchMethod> {
  inline static constexpr std::string_view kind = "patch method";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"entrypoint-section"}, PatchMethod::kEntrypointSection}};
};

template <>
struct EnumTraits<EventType> {
  inline static constexpr std::string_view kind = "event type";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"heap_create"}, EventType::kHeapCreate},
      NamedEnumValue{std::string_view{"heap_destroy"}, EventType::kHeapDestroy},
      NamedEnumValue{std::string_view{"alloc"}, EventType::kAlloc},
      NamedEnumValue{std::string_view{"realloc"}, EventType::kRealloc},
      NamedEnumValue{std::string_view{"free"}, EventType::kFree},
      NamedEnumValue{std::string_view{"vm_alloc"}, EventType::kVmAlloc},
      NamedEnumValue{std::string_view{"vm_free"}, EventType::kVmFree},
      NamedEnumValue{std::string_view{"map"}, EventType::kMap},
      NamedEnumValue{std::string_view{"unmap"}, EventType::kUnmap},
  };
};

template <>
struct EnumTraits<EventStatus> {
  inline static constexpr std::string_view kind = "event status";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"success"}, EventStatus::kSuccess},
      NamedEnumValue{std::string_view{"failure"}, EventStatus::kFailure},
      NamedEnumValue{std::string_view{"unmatched"}, EventStatus::kUnmatched},
  };
};

template <typename Enum>
[[nodiscard]] Enum parse_enum_value(std::string_view input) {
  return parse_enum(input, EnumTraits<Enum>::values, EnumTraits<Enum>::kind);
}

template <typename Enum>
[[nodiscard]] std::string_view enum_value_name(Enum value) {
  return enum_name(value, EnumTraits<Enum>::values);
}

template <typename T>
struct Setting {
  T value{};
  ValueSource source{ValueSource::kDefault};
};

template <typename T>
struct SettingOverride {
  bool specified{false};
  T value{};

  void set(T new_value) {
    value = std::move(new_value);
    specified = true;
  }
};

struct TargetSettings {
  Setting<std::optional<std::filesystem::path>> path;
  Setting<std::vector<std::string>> args;
  Setting<std::optional<std::filesystem::path>> working_directory;
  Setting<std::optional<std::uint32_t>> pid;
};

struct InjectionSettings {
  Setting<InjectionMethod> method;
  Setting<std::optional<std::filesystem::path>> agent_path;
  Setting<std::chrono::nanoseconds> timeout;
  Setting<bool> unload_on_stop;
};

struct CaptureSettings {
  Setting<HookProfile> hook_profile;
  Setting<std::uint16_t> max_stack_depth;
  Setting<std::uint64_t> min_size;
  Setting<std::optional<std::chrono::nanoseconds>> duration;
};

struct TraceSettings {
  Setting<std::optional<std::filesystem::path>> path;
  Setting<std::uint64_t> buffer_size;
  Setting<std::uint64_t> max_file_size;
  Setting<std::uint32_t> max_files;
  Setting<TraceFullPolicy> on_full;
  Setting<std::chrono::nanoseconds> flush_interval;
  Setting<Compression> compression;
  Setting<std::int32_t> compression_level;
};

struct AnalysisSettings {
  Setting<std::vector<std::filesystem::path>> inputs;
  Setting<AnalysisMode> mode;
  Setting<OutputFormat> format;
  Setting<std::optional<std::filesystem::path>> output;
  Setting<std::optional<std::chrono::nanoseconds>> a;
  Setting<std::optional<std::chrono::nanoseconds>> b;
  Setting<std::optional<std::chrono::nanoseconds>> c;
};

struct FilterSettings {
  Setting<std::optional<std::uint64_t>> min_size;
  Setting<std::optional<std::uint64_t>> max_size;
  Setting<std::vector<EventType>> events;
  Setting<std::vector<std::uint64_t>> threads;
  Setting<std::vector<std::string>> apis;
  Setting<std::vector<std::string>> modules;
  Setting<std::vector<std::string>> stack_modules;
  Setting<std::vector<std::uint64_t>> allocation_ids;
  Setting<std::vector<EventStatus>> statuses;
};

struct SymbolSettings {
  Setting<SymbolMode> mode;
  Setting<std::vector<std::filesystem::path>> paths;
  Setting<std::vector<std::string>> servers;
};

struct PatchSettings {
  Setting<std::optional<std::filesystem::path>> input;
  Setting<std::optional<std::filesystem::path>> output;
  Setting<PatchMethod> method;
  Setting<std::string> agent_name;
  Setting<bool> allow_break_signature;
  Setting<bool> verify;
};

struct DiagnosticSettings {
  Setting<LogLevel> log_level;
  Setting<ColorMode> color;
};

struct Configuration {
  Setting<std::uint32_t> schema_version;
  Setting<std::optional<Operation>> operation;
  TargetSettings target;
  InjectionSettings injection;
  CaptureSettings capture;
  TraceSettings trace;
  AnalysisSettings analysis;
  FilterSettings filters;
  SymbolSettings symbols;
  PatchSettings patch;
  DiagnosticSettings diagnostics;
};

struct TargetOverrides {
  SettingOverride<std::optional<std::filesystem::path>> path;
  SettingOverride<std::vector<std::string>> args;
  SettingOverride<std::optional<std::filesystem::path>> working_directory;
  SettingOverride<std::optional<std::uint32_t>> pid;
};

struct InjectionOverrides {
  SettingOverride<InjectionMethod> method;
  SettingOverride<std::optional<std::filesystem::path>> agent_path;
  SettingOverride<std::chrono::nanoseconds> timeout;
  SettingOverride<bool> unload_on_stop;
};

struct CaptureOverrides {
  SettingOverride<HookProfile> hook_profile;
  SettingOverride<std::uint16_t> max_stack_depth;
  SettingOverride<std::uint64_t> min_size;
  SettingOverride<std::optional<std::chrono::nanoseconds>> duration;
};

struct TraceOverrides {
  SettingOverride<std::optional<std::filesystem::path>> path;
  SettingOverride<std::uint64_t> buffer_size;
  SettingOverride<std::uint64_t> max_file_size;
  SettingOverride<std::uint32_t> max_files;
  SettingOverride<TraceFullPolicy> on_full;
  SettingOverride<std::chrono::nanoseconds> flush_interval;
  SettingOverride<Compression> compression;
  SettingOverride<std::int32_t> compression_level;
};

struct AnalysisOverrides {
  SettingOverride<std::vector<std::filesystem::path>> inputs;
  SettingOverride<AnalysisMode> mode;
  SettingOverride<OutputFormat> format;
  SettingOverride<std::optional<std::filesystem::path>> output;
  SettingOverride<std::optional<std::chrono::nanoseconds>> a;
  SettingOverride<std::optional<std::chrono::nanoseconds>> b;
  SettingOverride<std::optional<std::chrono::nanoseconds>> c;
};

struct FilterOverrides {
  SettingOverride<std::optional<std::uint64_t>> min_size;
  SettingOverride<std::optional<std::uint64_t>> max_size;
  SettingOverride<std::vector<EventType>> events;
  SettingOverride<std::vector<std::uint64_t>> threads;
  SettingOverride<std::vector<std::string>> apis;
  SettingOverride<std::vector<std::string>> modules;
  SettingOverride<std::vector<std::string>> stack_modules;
  SettingOverride<std::vector<std::uint64_t>> allocation_ids;
  SettingOverride<std::vector<EventStatus>> statuses;
};

struct SymbolOverrides {
  SettingOverride<SymbolMode> mode;
  SettingOverride<std::vector<std::filesystem::path>> paths;
  SettingOverride<std::vector<std::string>> servers;
};

struct PatchOverrides {
  SettingOverride<std::optional<std::filesystem::path>> input;
  SettingOverride<std::optional<std::filesystem::path>> output;
  SettingOverride<PatchMethod> method;
  SettingOverride<std::string> agent_name;
  SettingOverride<bool> allow_break_signature;
  SettingOverride<bool> verify;
};

struct DiagnosticOverrides {
  SettingOverride<LogLevel> log_level;
  SettingOverride<ColorMode> color;
};

struct ConfigurationOverrides {
  SettingOverride<std::uint32_t> schema_version;
  SettingOverride<Operation> operation;
  TargetOverrides target;
  InjectionOverrides injection;
  CaptureOverrides capture;
  TraceOverrides trace;
  AnalysisOverrides analysis;
  FilterOverrides filters;
  SymbolOverrides symbols;
  PatchOverrides patch;
  DiagnosticOverrides diagnostics;
};

[[nodiscard]] std::string_view value_source_name(ValueSource source) noexcept;
[[nodiscard]] Configuration make_default_configuration();
void apply_overrides(Configuration& configuration, const ConfigurationOverrides& overrides,
                     ValueSource source);

}  // namespace noleax::config
