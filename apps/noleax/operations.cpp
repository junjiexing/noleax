#include "operations.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include "noleax/analyzer/console.hpp"
#include "noleax/analyzer/csv.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/json.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/analyzer/stacks.hpp"
#include "noleax/analyzer/symbolizer.hpp"
#include "noleax/analyzer/trace_metadata.hpp"
#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "noleax/controller/windows/controller.hpp"
#include "noleax/controller/windows/diagnostics.hpp"
#include "noleax/controller/windows/pe_patch.hpp"
#endif

namespace noleax::app {
namespace {

using namespace std::chrono_literals;

[[noreturn]] void unsupported(std::string_view message) {
  throw ApplicationError{5, std::string{message}};
}

void ensure_output_directory(const std::filesystem::path& path) {
  const std::filesystem::path parent = path.parent_path();
  if (parent.empty()) {
    return;
  }
  std::error_code error;
  static_cast<void>(std::filesystem::create_directories(parent, error));
  if (error || !std::filesystem::is_directory(parent, error) || error) {
    throw ApplicationError{
        1, "cannot create output directory '" + noleax::config::path_to_utf8(parent) + "'"};
  }
}

[[nodiscard]] noleax::analyzer::AnalysisFilter make_filter(
    const noleax::config::Configuration& configuration) {
  noleax::analyzer::AnalysisFilterCriteria criteria;
  criteria.minimum_size = configuration.filters.min_size.value;
  criteria.maximum_size = configuration.filters.max_size.value;
  criteria.thread_ids = configuration.filters.threads.value;
  criteria.api_names = configuration.filters.apis.value;
  criteria.module_patterns = configuration.filters.modules.value;
  criteria.stack_module_patterns = configuration.filters.stack_modules.value;
  criteria.allocation_ids = configuration.filters.allocation_ids.value;

  criteria.operations.reserve(configuration.filters.events.value.size());
  for (const auto event : configuration.filters.events.value) {
    switch (event) {
      case noleax::config::EventType::kHeapCreate:
        criteria.operations.push_back(noleax::trace::EventOperation::kHeapCreate);
        break;
      case noleax::config::EventType::kHeapDestroy:
        criteria.operations.push_back(noleax::trace::EventOperation::kHeapDestroy);
        break;
      case noleax::config::EventType::kAlloc:
        criteria.operations.push_back(noleax::trace::EventOperation::kAllocate);
        break;
      case noleax::config::EventType::kRealloc:
        criteria.operations.push_back(noleax::trace::EventOperation::kReallocate);
        break;
      case noleax::config::EventType::kFree:
        criteria.operations.push_back(noleax::trace::EventOperation::kFree);
        break;
      case noleax::config::EventType::kVmAlloc:
        criteria.operations.push_back(noleax::trace::EventOperation::kVmAllocate);
        break;
      case noleax::config::EventType::kVmFree:
        criteria.operations.push_back(noleax::trace::EventOperation::kVmFree);
        break;
      case noleax::config::EventType::kMap:
        criteria.operations.push_back(noleax::trace::EventOperation::kMap);
        break;
      case noleax::config::EventType::kUnmap:
        criteria.operations.push_back(noleax::trace::EventOperation::kUnmap);
        break;
    }
  }

  criteria.statuses.reserve(configuration.filters.statuses.value.size());
  for (const auto status : configuration.filters.statuses.value) {
    switch (status) {
      case noleax::config::EventStatus::kSuccess:
        criteria.statuses.push_back(noleax::trace::EventStatus::kSuccess);
        break;
      case noleax::config::EventStatus::kFailure:
        criteria.statuses.push_back(noleax::trace::EventStatus::kFailure);
        break;
      case noleax::config::EventStatus::kUnmatched:
        criteria.statuses.push_back(noleax::trace::EventStatus::kUnmatched);
        break;
      case noleax::config::EventStatus::kPreexisting:
        criteria.statuses.push_back(noleax::trace::EventStatus::kPreexisting);
        break;
    }
  }
  return noleax::analyzer::AnalysisFilter{std::move(criteria)};
}

// Unset from/a endpoints map to the trace start so default output keeps showing 0ns.
[[nodiscard]] noleax::analyzer::WindowBound make_window_bound(
    const std::optional<noleax::config::WindowBound>& bound) {
  noleax::analyzer::WindowBound result;
  if (bound.has_value()) {
    result.time = bound->time;
    result.sequence = bound->sequence;
  } else {
    result.time = std::chrono::nanoseconds{0};
  }
  return result;
}

[[nodiscard]] std::optional<noleax::analyzer::WindowBound> make_optional_window_bound(
    const std::optional<noleax::config::WindowBound>& bound) {
  if (!bound.has_value()) {
    return std::nullopt;
  }
  return make_window_bound(bound);
}

[[nodiscard]] noleax::analyzer::SymbolizerOptions make_symbolizer_options(
    const noleax::config::Configuration& configuration) {
  noleax::analyzer::SymbolizerOptions options;
  switch (configuration.symbols.mode.value) {
    case noleax::config::SymbolMode::kAuto:
      options.mode = noleax::analyzer::SymbolResolutionMode::kAuto;
      break;
    case noleax::config::SymbolMode::kOff:
      options.mode = noleax::analyzer::SymbolResolutionMode::kOff;
      break;
    case noleax::config::SymbolMode::kRequired:
      options.mode = noleax::analyzer::SymbolResolutionMode::kRequired;
      break;
  }
  options.search_paths = configuration.symbols.paths.value;
  options.symbol_servers = configuration.symbols.servers.value;
  // DbgHelp convention: with no explicitly configured paths or servers, fall back to the
  // _NT_SYMBOL_PATH/_NT_ALT_SYMBOL_PATH environment variables.
  if (options.search_paths.empty() && options.symbol_servers.empty()) {
    options.raw_search_path = noleax::analyzer::symbol_search_path_from_environment();
  }
  return options;
}

[[nodiscard]] bool console_color_enabled(const noleax::config::Configuration& configuration,
                                         bool writing_stdout) noexcept {
  if (configuration.diagnostics.color.value == noleax::config::ColorMode::kAlways) {
    return true;
  }
  if (configuration.diagnostics.color.value == noleax::config::ColorMode::kNever ||
      !writing_stdout) {
    return false;
  }
#if defined(_WIN32)
  DWORD mode = 0U;
  return GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) != FALSE;
#else
  return false;
#endif
}

struct AnalysisResult {
  noleax::trace::CompletenessReport completeness = noleax::trace::CompletenessReport::from_mask(0U);
};

[[nodiscard]] AnalysisResult analyze_one(const noleax::config::Configuration& configuration,
                                         const std::filesystem::path& input_path,
                                         std::ostream& output, bool writing_stdout) {
  std::ifstream metadata_input{input_path, std::ios::binary};
  if (!metadata_input) {
    throw ApplicationError{
        1, "cannot open input trace '" + noleax::config::path_to_utf8(input_path) + "'"};
  }
  noleax::analyzer::TraceMetadata metadata{make_symbolizer_options(configuration)};
  metadata.set_trim_agent_frames(configuration.analysis.trim_agent_frames.value);
  try {
    static_cast<void>(metadata.scan(metadata_input));
  } catch (const std::exception& error) {
    throw ApplicationError{4, "cannot scan input trace '" +
                                  noleax::config::path_to_utf8(input_path) + "': " + error.what()};
  }
  metadata_input.close();

  std::ifstream input{input_path, std::ios::binary};
  if (!input) {
    throw ApplicationError{
        1, "cannot reopen input trace '" + noleax::config::path_to_utf8(input_path) + "'"};
  }
  const auto filter = make_filter(configuration);
  const noleax::analyzer::EventMetadataResolver filter_resolver =
      [&metadata](const noleax::trace::Event& event) { return metadata.metadata(event); };
  const noleax::analyzer::EventPresentationResolver presentation_resolver =
      [&metadata](const noleax::trace::Event& event) { return metadata.presentation(event); };

  try {
    const auto stacks_sort = [](noleax::config::AnalysisSort value) {
      switch (value) {
        case noleax::config::AnalysisSort::kCalls:
          return noleax::analyzer::StacksSort::kCalls;
        case noleax::config::AnalysisSort::kFreeBytes:
          return noleax::analyzer::StacksSort::kFreeBytes;
        case noleax::config::AnalysisSort::kNetBytes:
          return noleax::analyzer::StacksSort::kNetBytes;
        case noleax::config::AnalysisSort::kBytes:
          return noleax::analyzer::StacksSort::kBytes;
        case noleax::config::AnalysisSort::kAllocBytes:
          return noleax::analyzer::StacksSort::kAllocBytes;
      }
      return noleax::analyzer::StacksSort::kAllocBytes;
    };
    const bool group_by = configuration.analysis.group_by.value.has_value();
    if (configuration.analysis.mode.value == noleax::config::AnalysisMode::kEvents) {
      if (group_by) {
        noleax::analyzer::StacksWindow window;
        window.from = make_window_bound(configuration.analysis.from.value);
        window.to = make_optional_window_bound(configuration.analysis.to.value);
        const auto sort = stacks_sort(configuration.analysis.sort.value);
        noleax::analyzer::EventsStacksResult result;
        switch (configuration.analysis.format.value) {
          case noleax::config::OutputFormat::kConsole:
            result = noleax::analyzer::analyze_event_stacks_to_console(
                input, output, window, sort, filter, filter_resolver, presentation_resolver,
                {console_color_enabled(configuration, writing_stdout)});
            break;
          case noleax::config::OutputFormat::kJson:
            result = noleax::analyzer::analyze_event_stacks_to_json(
                input, output, window, sort, filter, filter_resolver, presentation_resolver);
            break;
          case noleax::config::OutputFormat::kCsv:
            result = noleax::analyzer::analyze_event_stacks_to_csv(
                input, output, window, sort, filter, filter_resolver, presentation_resolver);
            break;
        }
        return {result.trace.completeness};
      }
      noleax::analyzer::FilteredEventsWindow window;
      window.from = make_window_bound(configuration.analysis.from.value);
      window.to = make_optional_window_bound(configuration.analysis.to.value);
      noleax::analyzer::FilteredEventsResult result;
      switch (configuration.analysis.format.value) {
        case noleax::config::OutputFormat::kConsole:
          result = noleax::analyzer::analyze_events_to_console(
              input, output, filter, filter_resolver, presentation_resolver,
              {console_color_enabled(configuration, writing_stdout)}, {}, window);
          break;
        case noleax::config::OutputFormat::kJson:
          result = noleax::analyzer::analyze_events_to_json(input, output, filter, filter_resolver,
                                                            presentation_resolver, {}, window);
          break;
        case noleax::config::OutputFormat::kCsv:
          result = noleax::analyzer::analyze_events_to_csv(input, output, filter, filter_resolver,
                                                           presentation_resolver, {}, window);
          break;
      }
      return {result.trace.completeness};
    }

    noleax::analyzer::OutstandingWindow window;
    window.a = make_window_bound(configuration.analysis.from.value);
    window.b = make_optional_window_bound(configuration.analysis.to.value);
    window.c = make_optional_window_bound(configuration.analysis.end.value);
    if (group_by) {
      auto sort = stacks_sort(configuration.analysis.sort.value);
      if (configuration.analysis.sort.source == noleax::config::ValueSource::kDefault) {
        sort = noleax::analyzer::StacksSort::kBytes;
      }
      noleax::analyzer::LeaksStacksResult result;
      switch (configuration.analysis.format.value) {
        case noleax::config::OutputFormat::kConsole:
          result = noleax::analyzer::analyze_leak_stacks_to_console(
              input, output, window, sort, filter, filter_resolver, presentation_resolver,
              {console_color_enabled(configuration, writing_stdout)});
          break;
        case noleax::config::OutputFormat::kJson:
          result = noleax::analyzer::analyze_leak_stacks_to_json(
              input, output, window, sort, filter, filter_resolver, presentation_resolver);
          break;
        case noleax::config::OutputFormat::kCsv:
          result = noleax::analyzer::analyze_leak_stacks_to_csv(
              input, output, window, sort, filter, filter_resolver, presentation_resolver);
          break;
      }
      return {result.outstanding.trace.completeness};
    }
    noleax::analyzer::OutstandingResult result;
    switch (configuration.analysis.format.value) {
      case noleax::config::OutputFormat::kConsole:
        result = noleax::analyzer::analyze_outstanding_to_console(
            input, output, window, filter, filter_resolver, presentation_resolver,
            {console_color_enabled(configuration, writing_stdout)});
        break;
      case noleax::config::OutputFormat::kJson:
        result = noleax::analyzer::analyze_outstanding_to_json(
            input, output, window, filter, filter_resolver, presentation_resolver);
        break;
      case noleax::config::OutputFormat::kCsv:
        result = noleax::analyzer::analyze_outstanding_to_csv(
            input, output, window, filter, filter_resolver, presentation_resolver);
        break;
    }
    return {result.trace.completeness};
  } catch (const noleax::analyzer::OutstandingAnalysisError& error) {
    throw ApplicationError{1, "invalid outstanding analysis window for '" +
                                  noleax::config::path_to_utf8(input_path) + "': " + error.what()};
  } catch (const noleax::analyzer::StacksAnalysisError& error) {
    throw ApplicationError{1, "invalid stacks analysis window for '" +
                                  noleax::config::path_to_utf8(input_path) + "': " + error.what()};
  } catch (const noleax::analyzer::AnalysisFilterError& error) {
    throw ApplicationError{1, "invalid analysis filter: " + std::string{error.what()}};
  } catch (const std::exception& error) {
    throw ApplicationError{4, "cannot analyze input trace '" +
                                  noleax::config::path_to_utf8(input_path) + "': " + error.what()};
  }
}

[[nodiscard]] int execute_analyze(const noleax::config::Configuration& configuration) {
  if (configuration.analysis.inputs.value.size() != 1U) {
    unsupported("P6 analyze currently requires exactly one input trace");
  }
  if (configuration.analysis.output.value.has_value() &&
      *configuration.analysis.output.value == configuration.analysis.inputs.value.front()) {
    throw ApplicationError{1, "analysis output must be different from its input trace"};
  }

  std::ofstream output_file;
  std::ostream* output = &std::cout;
  if (configuration.analysis.output.value.has_value()) {
    ensure_output_directory(*configuration.analysis.output.value);
    output_file.open(*configuration.analysis.output.value, std::ios::binary | std::ios::trunc);
    if (!output_file) {
      throw ApplicationError{
          1, "cannot create analysis output '" +
                 noleax::config::path_to_utf8(*configuration.analysis.output.value) + "'"};
    }
    output = &output_file;
  }
  const auto result = analyze_one(configuration, configuration.analysis.inputs.value.front(),
                                  *output, output == &std::cout);
  output->flush();
  if (!*output) {
    throw ApplicationError{1, "cannot finish analysis output"};
  }
  return result.completeness.recommended_exit_code();
}

#if defined(_WIN32)

std::atomic<bool> stop_requested{false};

BOOL WINAPI console_control_handler(DWORD control_type) {
  if (control_type == CTRL_C_EVENT || control_type == CTRL_BREAK_EVENT ||
      control_type == CTRL_CLOSE_EVENT) {
    stop_requested.store(true, std::memory_order_relaxed);
    return TRUE;
  }
  return FALSE;
}

class ConsoleControlGuard final {
 public:
  ConsoleControlGuard() {
    stop_requested.store(false, std::memory_order_relaxed);
    if (SetConsoleCtrlHandler(console_control_handler, TRUE) == FALSE) {
      throw ApplicationError{1, "cannot install the console control handler"};
    }
    installed_ = true;
  }

  ~ConsoleControlGuard() {
    if (installed_) {
      static_cast<void>(SetConsoleCtrlHandler(console_control_handler, FALSE));
    }
  }

  ConsoleControlGuard(const ConsoleControlGuard&) = delete;
  ConsoleControlGuard& operator=(const ConsoleControlGuard&) = delete;

 private:
  bool installed_{false};
};

[[nodiscard]] std::filesystem::path executable_path() {
  std::wstring buffer(32'768U, L'\0');
  const DWORD length =
      GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0U || length == buffer.size()) {
    throw ApplicationError{1, "cannot determine the noleax executable path"};
  }
  buffer.resize(length);
  return std::filesystem::path{buffer};
}

[[nodiscard]] std::string timestamp_text() {
  SYSTEMTIME value{};
  GetSystemTime(&value);
  std::ostringstream output;
  output << std::setfill('0') << std::setw(4) << value.wYear << std::setw(2) << value.wMonth
         << std::setw(2) << value.wDay << '-' << std::setw(2) << value.wHour << std::setw(2)
         << value.wMinute << std::setw(2) << value.wSecond << '-' << std::setw(3)
         << value.wMilliseconds;
  return output.str();
}

[[nodiscard]] std::filesystem::path default_trace_path(
    const noleax::config::Configuration& configuration) {
  std::string prefix{"noleax"};
  if (configuration.target.path.value.has_value()) {
    prefix = noleax::config::path_to_utf8(configuration.target.path.value->stem());
  } else if (configuration.target.pid.value.has_value()) {
    prefix.append("-");
    prefix.append(std::to_string(*configuration.target.pid.value));
  }
  return std::filesystem::current_path() / (prefix + "-" + timestamp_text() + ".nlx");
}

[[nodiscard]] std::chrono::milliseconds capture_timeout(
    const noleax::config::Configuration& configuration) {
  const auto nanoseconds = configuration.injection.timeout.value;
  auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(nanoseconds);
  if (milliseconds < nanoseconds) {
    milliseconds += 1ms;
  }
  if (milliseconds.count() <= 0 ||
      milliseconds.count() > static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max())) {
    throw ApplicationError{1, "injection timeout does not fit the Windows bootstrap ABI"};
  }
  return milliseconds;
}

[[nodiscard]] noleax::ipc::HookProfile hook_profile(noleax::config::HookProfile profile) {
  switch (profile) {
    case noleax::config::HookProfile::kWindowsNtHeap:
      return noleax::ipc::HookProfile::kWindowsNtHeap;
    case noleax::config::HookProfile::kWindowsVirtualMemory:
      return noleax::ipc::HookProfile::kWindowsVirtualMemory;
    case noleax::config::HookProfile::kWindowsNative:
      return noleax::ipc::HookProfile::kWindowsNative;
  }
  unsupported("hook profile is not supported on Windows");
}

[[nodiscard]] noleax::ipc::CompressionCodec compression_codec(
    noleax::config::Compression compression) {
  switch (compression) {
    case noleax::config::Compression::kNone:
      return noleax::ipc::CompressionCodec::kNone;
    case noleax::config::Compression::kLz4:
      return noleax::ipc::CompressionCodec::kLz4;
    case noleax::config::Compression::kZstd:
      return noleax::ipc::CompressionCodec::kZstd;
  }
  unsupported("compression codec is not supported by the Windows agent");
}

[[nodiscard]] noleax::controller::windows::InjectionMethod injection_method(
    noleax::config::InjectionMethod method) {
  switch (method) {
    case noleax::config::InjectionMethod::kRemoteThread:
      return noleax::controller::windows::InjectionMethod::kRemoteThread;
    case noleax::config::InjectionMethod::kThreadHijack:
      return noleax::controller::windows::InjectionMethod::kThreadHijack;
    case noleax::config::InjectionMethod::kEntrypointCode:
      return noleax::controller::windows::InjectionMethod::kEntrypointCode;
    case noleax::config::InjectionMethod::kStaticPePatch:
      return noleax::controller::windows::InjectionMethod::kStaticPePatch;
  }
  unsupported("injection method is not supported by the Windows controller");
}

[[nodiscard]] noleax::controller::windows::CaptureOptions capture_options(
    const noleax::config::Configuration& configuration, const std::filesystem::path& trace_path) {
  noleax::controller::windows::CaptureOptions capture;
  capture.agent_path = configuration.injection.agent_path.value.value_or(
      executable_path().parent_path() / "noleax-agent.dll");
  capture.timeout = capture_timeout(configuration);
  capture.method = injection_method(configuration.injection.method.value);
  capture.start.hook_profile = hook_profile(configuration.capture.hook_profile.value);
  capture.start.compression = compression_codec(configuration.trace.compression.value);
  capture.start.maximum_stack_depth = configuration.capture.max_stack_depth.value;
  capture.start.minimum_capture_size = configuration.capture.min_size.value;
  capture.start.buffer_size = configuration.trace.buffer_size.value;
  capture.start.maximum_trace_size = configuration.trace.max_file_size.value;
  capture.start.flush_interval_ns =
      static_cast<std::uint64_t>(configuration.trace.flush_interval.value.count());
  capture.start.compression_level = configuration.trace.compression_level.value;
  capture.start.trace_path_utf8 = noleax::config::path_to_utf8(trace_path);
  capture.start.unload_on_stop = configuration.injection.unload_on_stop.value;
  return capture;
}

void validate_capture_support(const noleax::config::Configuration& configuration) {
  if (configuration.trace.on_full.value != noleax::config::TraceFullPolicy::kStop ||
      configuration.trace.max_files.value != 1U) {
    unsupported("P6 supports only --on-trace-full stop with --max-trace-files 1");
  }
  if (configuration.injection.unload_on_stop.value &&
      *configuration.operation.value != noleax::config::Operation::kAttach) {
    unsupported("--unload-on-stop is only supported for attach");
  }
}

[[nodiscard]] bool wait_until_stop(noleax::controller::windows::CaptureSession& session,
                                   const std::optional<std::chrono::nanoseconds>& duration) {
  const auto started = std::chrono::steady_clock::now();
  for (;;) {
    if (session.wait_for_target(0ms)) {
      return true;
    }
    if (stop_requested.load(std::memory_order_relaxed)) {
      return false;
    }
    if (duration.has_value() && std::chrono::steady_clock::now() - started >= *duration) {
      return false;
    }
    std::this_thread::sleep_for(25ms);
  }
}

[[nodiscard]] int finish_capture(noleax::controller::windows::CaptureSession& session,
                                 const std::filesystem::path& trace_path, bool target_exited) {
  noleax::ipc::CaptureStatus final;
  try {
    final = session.stop();
  } catch (const std::exception& error) {
    throw ApplicationError{target_exited ? 2 : 3,
                           std::string{"cannot finalize capture: "} + error.what()};
  }
  if (final.state != noleax::ipc::AgentState::kFinalized) {
    std::cout << "capture ended: trace=" << noleax::config::path_to_utf8(trace_path)
              << " pid=" << session.process_id();
    if (target_exited) {
      std::cout << " target_exit_code=" << session.target_exit_code();
    }
    std::cout << " note=target exited before the agent finalized the capture; trace trailer is "
                 "missing\n";
    return 2;
  }
  std::cout << "capture finalized: trace=" << noleax::config::path_to_utf8(trace_path)
            << " pid=" << session.process_id() << " observed=" << final.observed_calls
            << " written=" << final.written_events << " filtered=" << final.filtered_calls
            << " dropped=" << final.dropped_events << " bytes=" << final.bytes_written;
  if (target_exited) {
    std::cout << " target_exit_code=" << session.target_exit_code();
  } else {
    std::cout << " target_state=running";
  }
  std::cout << '\n';
  return final.dropped_events == 0U ? 0 : 2;
}

// ---- agent-capture mode (default): the controller passes a session TOML through the
// bootstrap parameters and the agent records autonomously; --live selects the pipe session.

[[nodiscard]] std::filesystem::path write_agent_session_config(
    const noleax::config::Configuration& configuration, const std::filesystem::path& trace_path) {
  static std::atomic<std::uint32_t> session_counter{0U};
  const std::uint32_t ordinal = session_counter.fetch_add(1U, std::memory_order_relaxed);
  std::ostringstream name;
  name << "noleax-" << std::hex << GetCurrentProcessId() << '-' << ordinal << ".toml";
  const auto config_path = std::filesystem::temp_directory_path() / name.str();

  std::ofstream output{config_path, std::ios::binary | std::ios::trunc};
  if (!output) {
    throw ApplicationError{1, "cannot create the agent session configuration '" +
                                  noleax::config::path_to_utf8(config_path) + "'"};
  }
  const auto trace_utf8 = std::filesystem::absolute(trace_path).generic_u8string();
  output << "schema_version = 1\n\n";
  if (configuration.target.pid.value.has_value()) {
    output << "[target]\npid = " << *configuration.target.pid.value << "\n\n";
  }
  output << "[capture]\n"
         << "hook_profile = \""
         << noleax::config::enum_value_name(configuration.capture.hook_profile.value) << "\"\n"
         << "max_stack_depth = " << configuration.capture.max_stack_depth.value << "\n"
         << "min_size = \"" << configuration.capture.min_size.value << "B\"\n";
  if (configuration.capture.duration.value.has_value()) {
    output << "duration = \"" << configuration.capture.duration.value->count() << "ns\"\n";
  }
  output << "\n[trace]\n"
         << "path = \"" << std::string{trace_utf8.begin(), trace_utf8.end()} << "\"\n"
         << "buffer_size = \"" << configuration.trace.buffer_size.value << "B\"\n"
         << "max_file_size = \"" << configuration.trace.max_file_size.value << "B\"\n"
         << "flush_interval = \"" << configuration.trace.flush_interval.value.count() << "ns\"\n"
         << "compression = \""
         << noleax::config::enum_value_name(configuration.trace.compression.value) << "\"\n"
         << "compression_level = " << configuration.trace.compression_level.value << "\n";
  if (!output) {
    throw ApplicationError{1, "cannot write the agent session configuration '" +
                                  noleax::config::path_to_utf8(config_path) + "'"};
  }
  return config_path;
}

void remove_quietly(const std::filesystem::path& path) noexcept {
  std::error_code error;
  static_cast<void>(std::filesystem::remove(path, error));
}

[[nodiscard]] int print_agent_capture_summary(const std::filesystem::path& trace_path,
                                              std::uint32_t pid, bool target_exited,
                                              const std::optional<std::uint32_t>& exit_code,
                                              bool interrupted) {
  if (interrupted) {
    std::cout << "capture detached: trace=" << noleax::config::path_to_utf8(trace_path)
              << " pid=" << pid
              << " note=controller stopped waiting; the agent continues until its duration or "
                 "the target exits\n";
    return 2;
  }
  std::ifstream input{trace_path, std::ios::binary};
  if (!input) {
    std::cout << "capture produced no trace: trace=" << noleax::config::path_to_utf8(trace_path)
              << " pid=" << pid << " note=the agent may have been disabled or failed to start\n";
    return 2;
  }
  const auto analyzed = noleax::analyzer::analyze_event_stream(input);
  std::cout << "capture finalized: trace=" << noleax::config::path_to_utf8(trace_path)
            << " pid=" << pid;
  if (analyzed.statistics.has_value()) {
    const auto& statistics = *analyzed.statistics;
    std::cout << " observed=" << statistics.observed_calls << " written="
              << statistics.observed_calls - statistics.filtered_before_queue -
                     statistics.dropped_events
              << " filtered=" << statistics.filtered_before_queue
              << " dropped=" << statistics.dropped_events
              << " bytes=" << statistics.written_stored_bytes;
  }
  if (target_exited && exit_code.has_value()) {
    std::cout << " target_exit_code=" << *exit_code;
  } else if (!target_exited) {
    std::cout << " target_state=running";
  }
  std::cout << '\n';
  return analyzed.completeness.recommended_exit_code();
}

[[nodiscard]] int execute_agent_capture(
    const noleax::config::Configuration& configuration, const std::filesystem::path& trace_path,
    const noleax::controller::windows::CaptureOptions& capture) {
  const auto agent_config = write_agent_session_config(configuration, trace_path);
  std::uint32_t pid = 0U;
  HANDLE target = nullptr;
  std::optional<noleax::controller::windows::SuspendedProcess> launched;
  noleax::controller::windows::AgentProcessHandle attached;
  try {
    if (*configuration.operation.value == noleax::config::Operation::kRun) {
      noleax::controller::windows::LaunchOptions launch;
      launch.executable = *configuration.target.path.value;
      launch.arguments = configuration.target.args.value;
      launch.working_directory =
          configuration.target.working_directory.value.value_or(launch.executable.parent_path());
      launched = noleax::controller::windows::launch_agent_capture(launch, capture, agent_config);
      pid = launched->process_id();
      target = static_cast<HANDLE>(launched->process_handle());
    } else {
      pid = *configuration.target.pid.value;
      attached = noleax::controller::windows::attach_agent_capture(pid, capture, agent_config);
      target = static_cast<HANDLE>(attached.get());
    }
  } catch (const std::exception& error) {
    remove_quietly(agent_config);
    throw ApplicationError{3, std::string{"capture injection failed: "} + error.what()};
  }

  const auto duration = configuration.capture.duration.value;
  const auto deadline = std::chrono::steady_clock::now() +
                        duration.value_or(std::chrono::nanoseconds::zero()) +
                        std::chrono::milliseconds{2'000};
  bool target_exited = false;
  bool interrupted = false;
  for (;;) {
    if (WaitForSingleObject(target, 25U) == WAIT_OBJECT_0) {
      target_exited = true;
      break;
    }
    if (stop_requested.load(std::memory_order_relaxed)) {
      interrupted = true;
      break;
    }
    if (duration.has_value() && std::chrono::steady_clock::now() >= deadline) {
      break;
    }
  }
  std::optional<std::uint32_t> exit_code;
  if (target_exited) {
    DWORD code = 0U;
    if (GetExitCodeProcess(target, &code) != FALSE) {
      exit_code = code;
    }
  }
  remove_quietly(agent_config);
  return print_agent_capture_summary(trace_path, pid, target_exited, exit_code, interrupted);
}

[[nodiscard]] int execute_capture(const noleax::config::Configuration& configuration) {
  validate_capture_support(configuration);
  const std::filesystem::path trace_path =
      configuration.trace.path.value.value_or(default_trace_path(configuration));
  ensure_output_directory(trace_path);
  const auto capture = capture_options(configuration, trace_path);
  ConsoleControlGuard controls;
  try {
    if (*configuration.operation.value == noleax::config::Operation::kRun &&
        capture.method == noleax::controller::windows::InjectionMethod::kStaticPePatch &&
        !noleax::controller::windows::read_static_patch_info(*configuration.target.path.value)
             .has_value()) {
      throw ApplicationError{
          1,
          "the target is not a noleax-patched executable; create one with 'noleax patch' "
          "before using --inject-method static-pe-patch"};
    }
    if (!configuration.capture.live.value) {
      return execute_agent_capture(configuration, trace_path, capture);
    }
    if (*configuration.operation.value == noleax::config::Operation::kRun) {
      noleax::controller::windows::LaunchOptions launch;
      launch.executable = *configuration.target.path.value;
      launch.arguments = configuration.target.args.value;
      launch.working_directory =
          configuration.target.working_directory.value.value_or(launch.executable.parent_path());
      auto session = noleax::controller::windows::CaptureSession::launch(launch, capture);
      const bool target_exited = wait_until_stop(session, configuration.capture.duration.value);
      return finish_capture(session, trace_path, target_exited);
    }

    auto session = noleax::controller::windows::CaptureSession::attach(
        *configuration.target.pid.value, capture);
    const bool target_exited = wait_until_stop(session, configuration.capture.duration.value);
    return finish_capture(session, trace_path, target_exited);
  } catch (const ApplicationError&) {
    throw;
  } catch (const std::exception& error) {
    throw ApplicationError{3, std::string{"capture failed: "} + error.what()};
  }
}

[[nodiscard]] int execute_doctor(const noleax::config::Configuration& configuration) {
  noleax::controller::windows::DoctorOptions options;
  options.agent_path = configuration.injection.agent_path.value;
  options.target_path = configuration.target.path.value;
  options.process_id = configuration.target.pid.value;
  options.injection_method = noleax::config::enum_value_name(configuration.injection.method.value);
  const auto report = noleax::controller::windows::run_doctor(options);
  noleax::controller::windows::write_doctor_report(std::cout, report);
  if (report.has_error_category(noleax::controller::windows::DiagnosticCategory::kPermission)) {
    return 3;
  }
  if (report.has_error_category(noleax::controller::windows::DiagnosticCategory::kUnsupported)) {
    return 5;
  }
  return report.has_errors() ? 1 : 0;
}

#else

[[nodiscard]] int execute_capture(const noleax::config::Configuration&) {
  unsupported("run and attach are not implemented on this platform");
}

[[nodiscard]] int execute_doctor(const noleax::config::Configuration&) {
  unsupported("doctor is not implemented on this platform");
}

#endif

#if defined(_WIN32)

[[nodiscard]] int execute_patch(const noleax::config::Configuration& configuration) {
  noleax::controller::windows::PePatchOptions options;
  options.input = *configuration.patch.input.value;
  options.output = *configuration.patch.output.value;
  options.agent_name = configuration.patch.agent_name.value;
  options.allow_break_signature = configuration.patch.allow_break_signature.value;
  options.verify = configuration.patch.verify.value;
  options.standalone = configuration.patch.standalone.value;
  try {
    const auto result = noleax::controller::windows::patch_pe_image(options);
    std::cout << "patched: input=" << noleax::config::path_to_utf8(options.input)
              << " output=" << noleax::config::path_to_utf8(options.output);
    std::cout << std::hex << std::showbase << " entry=" << result.entry_rva
              << " patch_rva=" << result.patch_rva << " section_rva=" << result.section_rva
              << std::dec << std::noshowbase << " bytes=" << result.output_size;
    if (result.signature_removed) {
      std::cout << " signature=removed";
    }
    if (options.standalone) {
      std::cout << " standalone=1";
    }
    std::cout << '\n';
    return 0;
  } catch (const noleax::controller::windows::PePatchException& error) {
    switch (error.code()) {
      case noleax::controller::windows::PePatchError::kNotX64:
      case noleax::controller::windows::PePatchError::kNotExecutable:
      case noleax::controller::windows::PePatchError::kManaged:
      case noleax::controller::windows::PePatchError::kPacked:
      case noleax::controller::windows::PePatchError::kSigned:
        throw ApplicationError{5, std::string{"cannot patch: "} + error.what()};
      default:
        throw ApplicationError{1, std::string{"cannot patch: "} + error.what()};
    }
  }
}

#else

[[nodiscard]] int execute_patch(const noleax::config::Configuration&) {
  unsupported("patch is not implemented on this platform");
}

#endif

}  // namespace

ApplicationError::ApplicationError(int exit_code, const std::string& message)
    : std::runtime_error{message}, exit_code_{exit_code} {
  if (exit_code_ < 1 || exit_code_ > 5) {
    throw std::invalid_argument{"application error exit code must be between 1 and 5"};
  }
}

int ApplicationError::exit_code() const noexcept { return exit_code_; }

int execute_operation(const noleax::config::Configuration& configuration) {
  switch (*configuration.operation.value) {
    case noleax::config::Operation::kRun:
    case noleax::config::Operation::kAttach:
      return execute_capture(configuration);
    case noleax::config::Operation::kAnalyze:
      return execute_analyze(configuration);
    case noleax::config::Operation::kDoctor:
      return execute_doctor(configuration);
    case noleax::config::Operation::kPatch:
      return execute_patch(configuration);
  }
  unsupported("operation is not supported");
}

}  // namespace noleax::app
