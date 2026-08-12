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

#include "noleax/analyzer/symbol_listing.hpp"
#include "noleax/config/value_parser.hpp"

namespace noleax::config {

inline constexpr std::uint32_t kConfigSchemaVersion = 1;

// A capture can declare at most this many custom hook points; the agent binds every point to
// one replacement thunk from a fixed pool (mirrors noleax::ipc::kMaximumCustomHooks).
inline constexpr std::size_t kMaximumCustomHooks = 32U;

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
  kSymbols,
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
  kStaticPePatch,
  kLdPreload,
  kPtrace,
};

enum class HookProfile : std::uint8_t {
  kWindowsNtHeap,
  kWindowsVirtualMemory,
  kWindowsNative,
  kLinuxGlibcHeap,
  kLinuxVirtualMemory,
  kLinuxNative,
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
  kMemory,
};

enum class AnalysisSort : std::uint8_t {
  kCalls,
  kAllocBytes,
  kFreeBytes,
  kNetBytes,
  kBytes,
};

enum class AnalysisGroupBy : std::uint8_t {
  kStack,
};

enum class OutputFormat : std::uint8_t {
  kConsole,
  kJson,
  kCsv,
};

enum class SymbolMode : std::uint8_t {
  kAuto,
  kOff,
  kRequired,
};

enum class PatchMethod : std::uint8_t {
  kEntrypointSection,
};

enum class CustomHookKind : std::uint8_t {
  kAlloc,
  kCalloc,
};

// One function role of a custom hook declaration. At most one locator is set; a role with no
// locator is undeclared (valid only for realloc). export_name is a dynamic-export symbol the
// agent resolves in the target, pdb_symbol a Windows PDB symbol the controller bakes to an
// RVA, symbol a Linux ELF symtab/dynsym symbol the controller resolves to an RVA, and rva a
// raw module-relative offset.
struct CustomHookRole {
  std::optional<std::string> export_name;
  std::optional<std::string> pdb_symbol;
  std::optional<std::string> symbol;
  std::optional<std::uint64_t> rva;

  [[nodiscard]] bool declared() const noexcept {
    return export_name.has_value() || pdb_symbol.has_value() || symbol.has_value() ||
           rva.has_value();
  }

  bool operator==(const CustomHookRole&) const = default;
};

// PE image identity recorded when PDB symbols are baked to RVAs ahead of time (`noleax patch`
// or the agent session configuration); the agent verifies it against the loaded module.
struct CustomHookImageIdentity {
  std::uint32_t timestamp{0U};
  std::uint32_t checksum{0U};
  std::uint32_t image_size{0U};

  bool operator==(const CustomHookImageIdentity&) const = default;
};

// One `[[custom_hooks]]` declaration: a module and its alloc/realloc/free function roles.
// Argument mapping comes in two shapes: the legacy shared slots (size_arg serves alloc and
// realloc, ptr_arg serves realloc and free, count_arg pairs with kind = "calloc") and the
// per-role slots (alloc_size_arg/alloc_count_arg/realloc_ptr_arg/realloc_size_arg/
// free_ptr_arg) for signatures whose roles disagree, such as a C++ member allocator with
// `this` in argument 0. The two shapes cannot be mixed in one declaration;
// resolve_custom_hook_arguments turns either into the per-role wire fields.
struct CustomHook {
  std::string module;
  CustomHookRole alloc;
  CustomHookRole realloc;
  CustomHookRole free;
  std::uint8_t size_arg{0U};
  std::uint8_t ptr_arg{0U};
  std::optional<std::uint8_t> result_arg;
  CustomHookKind kind{CustomHookKind::kAlloc};
  std::optional<std::uint8_t> count_arg;
  std::optional<std::uint8_t> free_size_arg;
  std::optional<std::uint8_t> alloc_size_arg;
  std::optional<std::uint8_t> alloc_count_arg;
  std::optional<std::uint8_t> realloc_ptr_arg;
  std::optional<std::uint8_t> realloc_size_arg;
  std::optional<std::uint8_t> free_ptr_arg;
  bool forced{false};
  std::chrono::nanoseconds wait_module{0};
  std::optional<CustomHookImageIdentity> image_identity;

  bool operator==(const CustomHook&) const = default;
};

// The per-role argument slots the wire protocol and the agents consume.
struct CustomHookRoleArguments {
  std::uint8_t alloc_size_arg{0U};
  std::optional<std::uint8_t> alloc_count_arg;
  std::uint8_t realloc_ptr_arg{0U};
  std::uint8_t realloc_size_arg{0U};
  std::uint8_t free_ptr_arg{0U};
};

// Resolves a declaration's argument mapping to the per-role slots. Any per-role field set
// selects the per-role shape (unset fields default to slot 0) and forbids the legacy fields;
// otherwise the legacy shared slots expand to every role they serve. Throws
// std::invalid_argument when legacy and per-role keys are mixed.
[[nodiscard]] CustomHookRoleArguments resolve_custom_hook_arguments(const CustomHook& hook);

// The label recorded in the trace's CustomHookDefinition record: the alloc role's symbol name,
// or "module+0x<rva>" when the alloc role is located by RVA.
[[nodiscard]] std::string custom_hook_label(const CustomHook& hook);

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
  kPreexisting,
};

// One analysis window endpoint: a duration relative to the trace start ("10s") or an event
// sequence ("#123456"). Exactly one component is set for values accepted from configuration;
// an empty bound is unbounded.
struct WindowBound {
  std::optional<std::chrono::nanoseconds> time;
  std::optional<std::uint64_t> sequence;

  bool operator==(const WindowBound&) const = default;
};

// Parses "#123" as a sequence endpoint and anything else as a duration endpoint.
[[nodiscard]] WindowBound parse_window_bound(std::string_view input);

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
      NamedEnumValue{std::string_view{"symbols"}, Operation::kSymbols},
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
      NamedEnumValue{std::string_view{"static-pe-patch"}, InjectionMethod::kStaticPePatch},
      NamedEnumValue{std::string_view{"ld-preload"}, InjectionMethod::kLdPreload},
      NamedEnumValue{std::string_view{"ptrace"}, InjectionMethod::kPtrace},
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
      NamedEnumValue{std::string_view{"linux-glibc-heap"}, HookProfile::kLinuxGlibcHeap},
      NamedEnumValue{std::string_view{"linux-virtual-memory"}, HookProfile::kLinuxVirtualMemory},
      NamedEnumValue{std::string_view{"linux-native"}, HookProfile::kLinuxNative},
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
      NamedEnumValue{std::string_view{"leaks"}, AnalysisMode::kOutstanding},
      NamedEnumValue{std::string_view{"memory"}, AnalysisMode::kMemory},
  };
};

template <>
struct EnumTraits<AnalysisSort> {
  inline static constexpr std::string_view kind = "analysis sort";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"calls"}, AnalysisSort::kCalls},
      NamedEnumValue{std::string_view{"alloc-bytes"}, AnalysisSort::kAllocBytes},
      NamedEnumValue{std::string_view{"free-bytes"}, AnalysisSort::kFreeBytes},
      NamedEnumValue{std::string_view{"net-bytes"}, AnalysisSort::kNetBytes},
      NamedEnumValue{std::string_view{"bytes"}, AnalysisSort::kBytes},
  };
};

template <>
struct EnumTraits<AnalysisGroupBy> {
  inline static constexpr std::string_view kind = "analysis grouping";
  inline static constexpr auto values =
      std::array{NamedEnumValue{std::string_view{"stack"}, AnalysisGroupBy::kStack}};
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
      std::array{NamedEnumValue{std::string_view{"auto"}, SymbolMode::kAuto},
                 NamedEnumValue{std::string_view{"off"}, SymbolMode::kOff},
                 NamedEnumValue{std::string_view{"required"}, SymbolMode::kRequired}};
};

template <>
struct EnumTraits<noleax::analyzer::SymbolKind> {
  inline static constexpr std::string_view kind = "symbol kind";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"function"}, noleax::analyzer::SymbolKind::kFunction},
      NamedEnumValue{std::string_view{"data"}, noleax::analyzer::SymbolKind::kData},
      NamedEnumValue{std::string_view{"public"}, noleax::analyzer::SymbolKind::kPublic},
      NamedEnumValue{std::string_view{"export"}, noleax::analyzer::SymbolKind::kExport},
      NamedEnumValue{std::string_view{"other"}, noleax::analyzer::SymbolKind::kOther},
  };
};

template <>
struct EnumTraits<noleax::analyzer::SymbolListingField> {
  inline static constexpr std::string_view kind = "symbol listing field";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"name"}, noleax::analyzer::SymbolListingField::kName},
      NamedEnumValue{std::string_view{"undecorated_name"},
                     noleax::analyzer::SymbolListingField::kUndecoratedName},
      NamedEnumValue{std::string_view{"rva"}, noleax::analyzer::SymbolListingField::kRva},
      NamedEnumValue{std::string_view{"va"}, noleax::analyzer::SymbolListingField::kVa},
      NamedEnumValue{std::string_view{"size"}, noleax::analyzer::SymbolListingField::kSize},
      NamedEnumValue{std::string_view{"kind"}, noleax::analyzer::SymbolListingField::kKind},
  };
};

template <>
struct EnumTraits<PatchMethod> {
  inline static constexpr std::string_view kind = "patch method";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"entrypoint-section"}, PatchMethod::kEntrypointSection}};
};

template <>
struct EnumTraits<CustomHookKind> {
  inline static constexpr std::string_view kind = "custom hook kind";
  inline static constexpr auto values = std::array{
      NamedEnumValue{std::string_view{"alloc"}, CustomHookKind::kAlloc},
      NamedEnumValue{std::string_view{"calloc"}, CustomHookKind::kCalloc},
  };
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
      NamedEnumValue{std::string_view{"preexisting"}, EventStatus::kPreexisting},
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
  Setting<bool> live;
  Setting<std::chrono::nanoseconds> memory_counters_interval;
  Setting<std::chrono::nanoseconds> memory_map_interval;
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
  Setting<std::optional<WindowBound>> from;
  Setting<std::optional<WindowBound>> to;
  Setting<std::optional<WindowBound>> end;
  Setting<std::optional<AnalysisGroupBy>> group_by;
  Setting<AnalysisSort> sort;
  Setting<bool> trim_agent_frames;
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

struct SymbolListingSettings {
  Setting<std::optional<std::filesystem::path>> input;
  Setting<OutputFormat> format;
  Setting<std::optional<std::filesystem::path>> output;
  Setting<std::vector<std::string>> name;
  Setting<bool> match_case;
  Setting<std::vector<noleax::analyzer::SymbolKind>> kind;
  Setting<std::vector<noleax::analyzer::SymbolListingField>> fields;
};

struct PatchSettings {
  Setting<std::optional<std::filesystem::path>> input;
  Setting<std::optional<std::filesystem::path>> output;
  Setting<PatchMethod> method;
  Setting<std::string> agent_name;
  Setting<bool> allow_break_signature;
  Setting<bool> verify;
  Setting<bool> standalone;
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
  SymbolListingSettings symbol_listing;
  PatchSettings patch;
  DiagnosticSettings diagnostics;
  Setting<std::vector<CustomHook>> custom_hooks;
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
  SettingOverride<bool> live;
  SettingOverride<std::chrono::nanoseconds> memory_counters_interval;
  SettingOverride<std::chrono::nanoseconds> memory_map_interval;
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
  SettingOverride<std::optional<WindowBound>> from;
  SettingOverride<std::optional<WindowBound>> to;
  SettingOverride<std::optional<WindowBound>> end;
  SettingOverride<std::optional<AnalysisGroupBy>> group_by;
  SettingOverride<AnalysisSort> sort;
  SettingOverride<bool> trim_agent_frames;
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

struct SymbolListingOverrides {
  SettingOverride<std::optional<std::filesystem::path>> input;
  SettingOverride<OutputFormat> format;
  SettingOverride<std::optional<std::filesystem::path>> output;
  SettingOverride<std::vector<std::string>> name;
  SettingOverride<bool> match_case;
  SettingOverride<std::vector<noleax::analyzer::SymbolKind>> kind;
  SettingOverride<std::vector<noleax::analyzer::SymbolListingField>> fields;
};

struct PatchOverrides {
  SettingOverride<std::optional<std::filesystem::path>> input;
  SettingOverride<std::optional<std::filesystem::path>> output;
  SettingOverride<PatchMethod> method;
  SettingOverride<std::string> agent_name;
  SettingOverride<bool> allow_break_signature;
  SettingOverride<bool> verify;
  SettingOverride<bool> standalone;
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
  SymbolListingOverrides symbol_listing;
  PatchOverrides patch;
  DiagnosticOverrides diagnostics;
  SettingOverride<std::vector<CustomHook>> custom_hooks;
};

[[nodiscard]] std::string_view value_source_name(ValueSource source) noexcept;
[[nodiscard]] Configuration make_default_configuration();
void apply_overrides(Configuration& configuration, const ConfigurationOverrides& overrides,
                     ValueSource source);

}  // namespace noleax::config
