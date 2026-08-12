#include "operations.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
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

#if !defined(_WIN32)
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <ctime>
#endif

#include "noleax/analyzer/console.hpp"
#include "noleax/analyzer/csv.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/json.hpp"
#include "noleax/analyzer/memory.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/analyzer/stacks.hpp"
#include "noleax/analyzer/symbol_listing.hpp"
#include "noleax/analyzer/symbolizer.hpp"
#include "noleax/analyzer/trace_metadata.hpp"
#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"
#include "noleax/config/hook_profile_ipc.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "noleax/controller/windows/controller.hpp"
#include "noleax/controller/windows/diagnostics.hpp"
#include "noleax/controller/windows/pe_patch.hpp"
#else
#include "elf_image.hpp"
#include "noleax/controller/linux/controller.hpp"
#include "noleax/controller/linux/diagnostics.hpp"
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

// ---- custom hook symbol resolution (controller side: PDB locators become baked RVAs) ----

#if defined(_WIN32)

[[noreturn]] void custom_hook_resolution_error(std::string_view message) {
  throw ApplicationError{3, std::string{message}};
}

[[nodiscard]] std::wstring widen_utf8(std::string_view value, std::string_view what) {
  if (value.empty() || value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
    custom_hook_resolution_error("custom hook " + std::string{what} + " is empty or too long");
  }
  const int input_size = static_cast<int>(value.size());
  const int output_size =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_size, nullptr, 0);
  if (output_size <= 0) {
    custom_hook_resolution_error("custom hook " + std::string{what} + " is not valid UTF-8");
  }
  std::wstring wide(static_cast<std::size_t>(output_size), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_size, wide.data(),
                          output_size) != output_size) {
    custom_hook_resolution_error("custom hook " + std::string{what} + " conversion failed");
  }
  return wide;
}

[[nodiscard]] bool has_pdb_locator(const noleax::config::CustomHookRole& role) noexcept {
  return role.pdb_symbol.has_value();
}

[[nodiscard]] bool needs_pdb_resolution(const noleax::config::CustomHook& hook) noexcept {
  return has_pdb_locator(hook.alloc) || has_pdb_locator(hook.realloc) || has_pdb_locator(hook.free);
}

struct PeImageInfo {
  std::uint32_t timestamp{0U};
  std::uint32_t checksum{0U};
  std::uint32_t image_size{0U};
  std::uint64_t image_base{0U};
  bool x64{false};
};

[[noreturn]] void pe_image_error(int exit_code, const std::string& message) {
  throw ApplicationError{exit_code, message};
}

// Reads the PE identity fields and the optional-header image base. Both PE32 and PE32+ are
// accepted; `x64` lets callers that can only handle 64-bit images (custom hook resolution)
// reject 32-bit ones.
[[nodiscard]] PeImageInfo read_pe_image_info(const std::filesystem::path& path, int exit_code) {
  std::ifstream input{path, std::ios::binary};
  if (!input) {
    pe_image_error(exit_code,
                   "cannot open module image '" + noleax::config::path_to_utf8(path) + "'");
  }
  IMAGE_DOS_HEADER dos{};
  input.read(reinterpret_cast<char*>(&dos), sizeof(dos));
  if (!input || dos.e_magic != IMAGE_DOS_SIGNATURE) {
    pe_image_error(exit_code,
                   "module image '" + noleax::config::path_to_utf8(path) + "' is not a PE file");
  }
  input.seekg(static_cast<std::streamoff>(dos.e_lfanew), std::ios::beg);
  IMAGE_NT_HEADERS64 nt{};
  input.read(reinterpret_cast<char*>(&nt), sizeof(nt));
  if (!input || nt.Signature != IMAGE_NT_SIGNATURE ||
      (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
       nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
    pe_image_error(exit_code,
                   "module image '" + noleax::config::path_to_utf8(path) + "' is not a PE file");
  }
  // CheckSum and SizeOfImage share their offsets between the PE32 and PE32+ optional header
  // layouts; only ImageBase differs (32-bit at optional-header offset 0x1C for PE32, 64-bit at
  // offset 0x18 for PE32+).
  PeImageInfo info{nt.FileHeader.TimeDateStamp, nt.OptionalHeader.CheckSum,
                   nt.OptionalHeader.SizeOfImage, 0U,
                   nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC};
  if (info.x64) {
    info.image_base = nt.OptionalHeader.ImageBase;
  } else {
    std::uint32_t image_base = 0U;
    const auto* optional_header = reinterpret_cast<const unsigned char*>(&nt.OptionalHeader);
    std::memcpy(&image_base, optional_header + 0x1CU, sizeof(image_base));
    info.image_base = image_base;
  }
  return info;
}

[[nodiscard]] std::filesystem::path locate_custom_hook_module(
    const noleax::config::Configuration& configuration, const noleax::config::CustomHook& hook) {
  const std::string& module = hook.module;
  if (module.find_first_of("/\\") != std::string::npos || module.find(':') != std::string::npos) {
    return noleax::config::normalize_path(module, std::filesystem::current_path());
  }
  const std::wstring wide_name = widen_utf8(module, "module name");
  if (*configuration.operation.value == noleax::config::Operation::kAttach) {
    const auto remote = noleax::controller::windows::find_remote_module_path(
        *configuration.target.pid.value, wide_name);
    if (!remote.has_value()) {
      custom_hook_resolution_error("custom hook module '" + module + "' is not loaded in process " +
                                   std::to_string(*configuration.target.pid.value));
    }
    return *remote;
  }
  const std::filesystem::path base_directory =
      *configuration.operation.value == noleax::config::Operation::kPatch
          ? configuration.patch.input.value->parent_path()
          : configuration.target.path.value->parent_path();
  std::filesystem::path sibling = base_directory / wide_name;
  std::error_code error;
  if (std::filesystem::is_regular_file(sibling, error) && !error) {
    return sibling;
  }
  std::wstring buffer(MAX_PATH, L'\0');
  const DWORD length = SearchPathW(nullptr, wide_name.c_str(), nullptr,
                                   static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
  if (length != 0U && length < buffer.size()) {
    buffer.resize(length);
    return std::filesystem::path{buffer};
  }
  custom_hook_resolution_error("cannot locate custom hook module '" + module +
                               "' beside the target executable or on the search path");
}

void resolve_custom_hook_pdb_role(noleax::analyzer::OfflineSymbolizer& symbolizer,
                                  noleax::trace::ModuleId module_id, const std::string& module_name,
                                  const char* role_name, const std::string& pdb_symbol,
                                  std::uint64_t& rva_out) {
  const auto rva = symbolizer.resolve_symbol(module_id, pdb_symbol);
  if (!rva.has_value()) {
    custom_hook_resolution_error("custom hook " + std::string{role_name} + " PDB symbol '" +
                                 pdb_symbol + "' was not found in module '" + module_name +
                                 "' (missing PDB, no such public symbol, or the function has no "
                                 "standalone code)");
  }
  rva_out = *rva;
}

[[nodiscard]] noleax::ipc::CustomHookSpec resolve_custom_hook(
    const noleax::config::Configuration& configuration, const noleax::config::CustomHook& hook) {
  noleax::ipc::CustomHookSpec spec;
  spec.module = hook.module;
  spec.size_arg = hook.size_arg;
  spec.ptr_arg = hook.ptr_arg;
  spec.result_arg = hook.result_arg;
  spec.count_arg = hook.count_arg;
  spec.free_size_arg = hook.free_size_arg;
  spec.calloc = hook.kind == noleax::config::CustomHookKind::kCalloc;
  spec.forced = hook.forced;
  // Round up so a sub-millisecond wait still polls once (the wait itself is 100 ms-granular).
  spec.wait_module_ms =
      static_cast<std::uint64_t>((hook.wait_module.count() + 999'999) / 1'000'000);
  spec.label = noleax::config::custom_hook_label(hook);

  const auto map_role = [](const noleax::config::CustomHookRole& role) {
    noleax::ipc::CustomHookRoleSpec mapped;
    if (role.export_name.has_value()) {
      mapped.locator = noleax::ipc::CustomHookLocator::kExport;
      mapped.export_name = *role.export_name;
    } else if (role.rva.has_value()) {
      mapped.locator = noleax::ipc::CustomHookLocator::kRva;
      mapped.rva = *role.rva;
    }
    return mapped;
  };
  spec.alloc = map_role(hook.alloc);
  spec.realloc = map_role(hook.realloc);
  spec.free = map_role(hook.free);

  if (!needs_pdb_resolution(hook)) {
    return spec;
  }
  const std::filesystem::path module_path = locate_custom_hook_module(configuration, hook);
  const PeImageInfo image = read_pe_image_info(module_path, 3);
  if (!image.x64) {
    custom_hook_resolution_error("module image '" + noleax::config::path_to_utf8(module_path) +
                                 "' is not an x64 PE file");
  }
  noleax::analyzer::OfflineSymbolizer symbolizer{make_symbolizer_options(configuration)};
  noleax::analyzer::SymbolModule symbol_module;
  symbol_module.module_id = noleax::trace::ModuleId{1U};
  symbol_module.image_size = image.image_size;
  symbol_module.image_path = module_path;
  const noleax::analyzer::SymbolModuleResult registered = symbolizer.register_module(symbol_module);
  if (registered.status != noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded) {
    custom_hook_resolution_error(
        "cannot resolve PDB symbols for custom hook module '" + hook.module +
        "': " + std::string{noleax::analyzer::symbol_module_status_name(registered.status)});
  }
  if (hook.alloc.pdb_symbol.has_value()) {
    spec.alloc.locator = noleax::ipc::CustomHookLocator::kRva;
    resolve_custom_hook_pdb_role(symbolizer, symbol_module.module_id, hook.module, "alloc",
                                 *hook.alloc.pdb_symbol, spec.alloc.rva);
  }
  if (hook.realloc.pdb_symbol.has_value()) {
    spec.realloc.locator = noleax::ipc::CustomHookLocator::kRva;
    resolve_custom_hook_pdb_role(symbolizer, symbol_module.module_id, hook.module, "realloc",
                                 *hook.realloc.pdb_symbol, spec.realloc.rva);
  }
  if (hook.free.pdb_symbol.has_value()) {
    spec.free.locator = noleax::ipc::CustomHookLocator::kRva;
    resolve_custom_hook_pdb_role(symbolizer, symbol_module.module_id, hook.module, "free",
                                 *hook.free.pdb_symbol, spec.free.rva);
  }
  symbolizer.unregister_module(symbol_module.module_id);
  if (registered.image_identity.has_value()) {
    spec.image_identity = noleax::ipc::CustomHookImageIdentity{
        registered.image_identity->timestamp, registered.image_identity->checksum,
        registered.image_identity->image_size};
  }
  return spec;
}

[[nodiscard]] std::vector<noleax::ipc::CustomHookSpec> resolve_custom_hooks(
    const noleax::config::Configuration& configuration) {
  std::vector<noleax::ipc::CustomHookSpec> specs;
  specs.reserve(configuration.custom_hooks.value.size());
  for (const auto& hook : configuration.custom_hooks.value) {
    specs.push_back(resolve_custom_hook(configuration, hook));
  }
  return specs;
}

[[nodiscard]] std::string toml_escaped(std::string_view value) {
  std::string result;
  result.reserve(value.size() + 2U);
  result.push_back('"');
  for (const char character : value) {
    if (character == '"' || character == '\\') {
      result.push_back('\\');
    }
    result.push_back(character);
  }
  result.push_back('"');
  return result;
}

void write_custom_hook_toml(std::ostream& output, const noleax::ipc::CustomHookSpec& hook) {
  output << "\n[[custom_hooks]]\nmodule = " << toml_escaped(hook.module) << "\n";
  const auto write_role = [&output](const char* name, const noleax::ipc::CustomHookRoleSpec& role) {
    if (role.locator == noleax::ipc::CustomHookLocator::kExport) {
      output << name << " = " << toml_escaped(role.export_name) << "\n";
    } else if (role.locator == noleax::ipc::CustomHookLocator::kRva) {
      output << name << "_rva = \"0x" << std::hex << role.rva << std::dec << "\"\n";
    }
  };
  write_role("alloc", hook.alloc);
  write_role("realloc", hook.realloc);
  write_role("free", hook.free);
  if (hook.size_arg != 0U) {
    output << "size_arg = " << static_cast<std::uint32_t>(hook.size_arg) << "\n";
  }
  if (hook.ptr_arg != 0U) {
    output << "ptr_arg = " << static_cast<std::uint32_t>(hook.ptr_arg) << "\n";
  }
  if (hook.result_arg.has_value()) {
    output << "result_arg = " << static_cast<std::uint32_t>(*hook.result_arg) << "\n";
  }
  if (hook.calloc) {
    output << "kind = \"calloc\"\n";
  }
  if (hook.count_arg.has_value()) {
    output << "count_arg = " << static_cast<std::uint32_t>(*hook.count_arg) << "\n";
  }
  if (hook.free_size_arg.has_value()) {
    output << "free_size_arg = " << static_cast<std::uint32_t>(*hook.free_size_arg) << "\n";
  }
  if (hook.forced) {
    output << "forced = true\n";
  }
  if (hook.wait_module_ms != 0U) {
    output << "wait_module = \"" << hook.wait_module_ms << "ms\"\n";
  }
  if (hook.image_identity.has_value()) {
    output << "image_timestamp = 0x" << std::hex << hook.image_identity->timestamp << "\n"
           << "image_checksum = 0x" << hook.image_identity->checksum << std::dec << "\n"
           << "image_size = " << hook.image_identity->image_size << "\n";
  }
}

#endif

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
  if (configuration.analysis.mode.value == noleax::config::AnalysisMode::kMemory) {
    // Memory snapshots carry no stacks, so the TraceMetadata scan is unnecessary.
    std::ifstream input{input_path, std::ios::binary};
    if (!input) {
      throw ApplicationError{
          1, "cannot open input trace '" + noleax::config::path_to_utf8(input_path) + "'"};
    }
    noleax::analyzer::MemoryWindow window;
    window.from = make_window_bound(configuration.analysis.from.value);
    window.to = make_optional_window_bound(configuration.analysis.to.value);
    try {
      noleax::analyzer::MemoryAnalysisResult result;
      switch (configuration.analysis.format.value) {
        case noleax::config::OutputFormat::kConsole:
          result = noleax::analyzer::analyze_memory_to_console(
              input, output, window, {console_color_enabled(configuration, writing_stdout)});
          break;
        case noleax::config::OutputFormat::kJson:
          result = noleax::analyzer::analyze_memory_to_json(input, output, window);
          break;
        case noleax::config::OutputFormat::kCsv:
          result = noleax::analyzer::analyze_memory_to_csv(input, output, window);
          break;
      }
      return {result.trace.completeness};
    } catch (const std::exception& error) {
      throw ApplicationError{4, "cannot analyze input trace '" +
                                    noleax::config::path_to_utf8(input_path) +
                                    "': " + error.what()};
    }
  }

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

// Capture-wide capability gate shared by both platforms: trace rotation is not
// implemented anywhere, and unload-on-stop only makes sense for attach.
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
  const auto mapped = noleax::config::windows_ipc_hook_profile(profile);
  if (!mapped.has_value()) {
    unsupported("hook profile is not supported on Windows");
  }
  return *mapped;
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
    case noleax::config::InjectionMethod::kLdPreload:
    case noleax::config::InjectionMethod::kPtrace:
      break;
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
  capture.start.memory_counters_interval_ns =
      static_cast<std::uint64_t>(configuration.capture.memory_counters_interval.value.count());
  capture.start.memory_map_interval_ns =
      static_cast<std::uint64_t>(configuration.capture.memory_map_interval.value.count());
  capture.start.compression_level = configuration.trace.compression_level.value;
  capture.start.trace_path_utf8 = noleax::config::path_to_utf8(trace_path);
  capture.start.unload_on_stop = configuration.injection.unload_on_stop.value;
  capture.start.custom_hooks = resolve_custom_hooks(configuration);
  return capture;
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
    const noleax::config::Configuration& configuration, const std::filesystem::path& trace_path,
    const std::vector<noleax::ipc::CustomHookSpec>& custom_hooks) {
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
  output << "memory_counters_interval = \""
         << configuration.capture.memory_counters_interval.value.count() << "ns\"\n"
         << "memory_map_interval = \"" << configuration.capture.memory_map_interval.value.count()
         << "ns\"\n";
  output << "\n[trace]\n"
         << "path = \"" << std::string{trace_utf8.begin(), trace_utf8.end()} << "\"\n"
         << "buffer_size = \"" << configuration.trace.buffer_size.value << "B\"\n"
         << "max_file_size = \"" << configuration.trace.max_file_size.value << "B\"\n"
         << "flush_interval = \"" << configuration.trace.flush_interval.value.count() << "ns\"\n"
         << "compression = \""
         << noleax::config::enum_value_name(configuration.trace.compression.value) << "\"\n"
         << "compression_level = " << configuration.trace.compression_level.value << "\n";
  for (const auto& hook : custom_hooks) {
    write_custom_hook_toml(output, hook);
  }
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
  const auto agent_config =
      write_agent_session_config(configuration, trace_path, capture.start.custom_hooks);
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

std::atomic<bool> stop_requested{false};

void sigint_handler(int /*signal*/) { stop_requested.store(true, std::memory_order_relaxed); }

class InterruptHandlerGuard final {
 public:
  InterruptHandlerGuard() {
    stop_requested.store(false, std::memory_order_relaxed);
    struct sigaction action {};
    action.sa_handler = sigint_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;  // no SA_RESTART: the wait loop polls, EINTR is fine
    if (::sigaction(SIGINT, &action, &previous_) != 0) {
      throw ApplicationError{1, "cannot install the SIGINT handler"};
    }
    installed_ = true;
  }

  ~InterruptHandlerGuard() {
    if (installed_) {
      static_cast<void>(::sigaction(SIGINT, &previous_, nullptr));
    }
  }

  InterruptHandlerGuard(const InterruptHandlerGuard&) = delete;
  InterruptHandlerGuard& operator=(const InterruptHandlerGuard&) = delete;

 private:
  struct sigaction previous_ {};
  bool installed_{false};
};

[[nodiscard]] std::filesystem::path executable_path() {
  std::array<char, 4096U> buffer{};
  const ssize_t length = ::readlink("/proc/self/exe", buffer.data(), buffer.size() - 1U);
  if (length <= 0) {
    throw ApplicationError{1, "cannot determine the noleax executable path"};
  }
  return std::filesystem::path{std::string{buffer.data(), static_cast<std::size_t>(length)}};
}

[[nodiscard]] std::string timestamp_text() {
  const std::time_t now = std::time(nullptr);
  std::tm broken_down{};
  static_cast<void>(::localtime_r(&now, &broken_down));
  std::ostringstream output;
  output << std::setfill('0') << std::setw(4) << broken_down.tm_year + 1900 << std::setw(2)
         << broken_down.tm_mon + 1 << std::setw(2) << broken_down.tm_mday << '-' << std::setw(2)
         << broken_down.tm_hour << std::setw(2) << broken_down.tm_min << std::setw(2)
         << broken_down.tm_sec;
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

[[nodiscard]] noleax::ipc::HookProfile linux_hook_profile(noleax::config::HookProfile profile) {
  const auto mapped = noleax::config::linux_ipc_hook_profile(profile);
  if (!mapped.has_value()) {
    throw ApplicationError{5, "hook profile '" +
                                  std::string{noleax::config::enum_value_name(profile)} +
                                  "' is not supported on Linux"};
  }
  return *mapped;
}

[[nodiscard]] noleax::ipc::CompressionCodec linux_compression_codec(
    noleax::config::Compression compression) {
  switch (compression) {
    case noleax::config::Compression::kNone:
      return noleax::ipc::CompressionCodec::kNone;
    case noleax::config::Compression::kLz4:
      return noleax::ipc::CompressionCodec::kLz4;
    case noleax::config::Compression::kZstd:
      return noleax::ipc::CompressionCodec::kZstd;
  }
  throw ApplicationError{5, "compression codec is not supported by the Linux agent"};
}

// ---- custom hook symbol resolution (controller side: *_sym ELF locators become RVAs) ----

[[noreturn]] void custom_hook_resolution_error(std::string_view message) {
  throw ApplicationError{3, std::string{message}};
}

[[nodiscard]] bool needs_symbol_resolution(const noleax::config::CustomHook& hook) noexcept {
  return hook.alloc.symbol.has_value() || hook.realloc.symbol.has_value() ||
         hook.free.symbol.has_value();
}

// Finds an already-loaded module in the attach target by exact maps basename, anchored at
// the file-offset-0 mapping (mirrors the Windows remote module search).
[[nodiscard]] std::filesystem::path find_attach_module_path(std::uint32_t pid,
                                                            const std::string& module) {
  const std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
  std::ifstream input{maps_path};
  if (!input) {
    custom_hook_resolution_error("cannot read " + maps_path + " to locate custom hook module '" +
                                 module + "'");
  }
  std::string line;
  while (std::getline(input, line)) {
    unsigned long long start = 0U;
    unsigned long long end = 0U;
    unsigned long long offset = 0U;
    int consumed = 0;
    if (std::sscanf(line.c_str(), "%llx-%llx %*4s %llx %*s %*u%n", &start, &end, &offset,
                    &consumed) != 3 ||
        offset != 0U) {
      continue;
    }
    const std::string_view rest = std::string_view{line}.substr(static_cast<std::size_t>(consumed));
    const std::size_t first = rest.find_first_not_of(' ');
    if (first == std::string_view::npos) {
      continue;
    }
    const std::string_view path = rest.substr(first);
    const std::size_t slash = path.rfind('/');
    if (path.substr(slash == std::string_view::npos ? 0U : slash + 1U) == module) {
      return std::filesystem::path{std::string{path}};
    }
  }
  custom_hook_resolution_error("custom hook module '" + module + "' is not loaded in process " +
                               std::to_string(pid));
}

// Locates the on-disk image of a custom hook module: an absolute or relative path is used
// as given (relative to the working directory); a bare name is found beside the target
// executable for run, or among the attach target's loaded modules.
[[nodiscard]] std::filesystem::path locate_custom_hook_module(
    const noleax::config::Configuration& configuration, const noleax::config::CustomHook& hook) {
  const std::string& module = hook.module;
  if (module.find('/') != std::string::npos) {
    return noleax::config::normalize_path(module, std::filesystem::current_path());
  }
  if (*configuration.operation.value == noleax::config::Operation::kAttach) {
    return find_attach_module_path(*configuration.target.pid.value, module);
  }
  std::error_code error;
  const std::filesystem::path sibling = configuration.target.path.value->parent_path() / module;
  if (std::filesystem::is_regular_file(sibling, error) && !error) {
    return sibling;
  }
  custom_hook_resolution_error("cannot locate custom hook module '" + module +
                               "' beside the target executable");
}

[[nodiscard]] noleax::ipc::CustomHookSpec resolve_custom_hook(
    const noleax::config::Configuration& configuration, const noleax::config::CustomHook& hook) {
  noleax::ipc::CustomHookSpec spec;
  spec.module = hook.module;
  spec.size_arg = hook.size_arg;
  spec.ptr_arg = hook.ptr_arg;
  spec.result_arg = hook.result_arg;
  spec.count_arg = hook.count_arg;
  spec.free_size_arg = hook.free_size_arg;
  spec.calloc = hook.kind == noleax::config::CustomHookKind::kCalloc;
  spec.forced = hook.forced;
  // Round up so a sub-millisecond wait still polls once.
  spec.wait_module_ms =
      static_cast<std::uint64_t>((hook.wait_module.count() + 999'999) / 1'000'000);
  spec.label = noleax::config::custom_hook_label(hook);

  const auto map_role = [](const noleax::config::CustomHookRole& role) {
    noleax::ipc::CustomHookRoleSpec mapped;
    if (role.export_name.has_value()) {
      mapped.locator = noleax::ipc::CustomHookLocator::kExport;
      mapped.export_name = *role.export_name;
    } else if (role.rva.has_value()) {
      mapped.locator = noleax::ipc::CustomHookLocator::kRva;
      mapped.rva = *role.rva;
    }
    return mapped;
  };
  spec.alloc = map_role(hook.alloc);
  spec.realloc = map_role(hook.realloc);
  spec.free = map_role(hook.free);

  if (!needs_symbol_resolution(hook)) {
    return spec;
  }
  const std::filesystem::path module_path = locate_custom_hook_module(configuration, hook);
  std::optional<noleax::analyzer::elf::ElfImage> image;
  try {
    image.emplace(module_path);
  } catch (const noleax::analyzer::elf::ElfImageError& error) {
    custom_hook_resolution_error("cannot read custom hook module image '" +
                                 noleax::config::path_to_utf8(module_path) + "': " + error.what());
  }
  const auto resolve_role = [&hook, &image](const noleax::config::CustomHookRole& role,
                                            const char* role_name,
                                            noleax::ipc::CustomHookRoleSpec& target) {
    if (!role.symbol.has_value()) {
      return;
    }
    const std::optional<noleax::analyzer::elf::ElfSymbol> symbol = image->find_symbol(*role.symbol);
    if (!symbol.has_value()) {
      custom_hook_resolution_error("custom hook " + std::string{role_name} + " symbol '" +
                                   *role.symbol + "' was not found in module '" + hook.module +
                                   "' (no such ELF symtab/dynsym symbol)");
    }
    if (symbol->value < image->minimum_load_vaddr()) {
      custom_hook_resolution_error("custom hook " + std::string{role_name} + " symbol '" +
                                   *role.symbol + "' in module '" + hook.module +
                                   "' is not a loadable address");
    }
    target.locator = noleax::ipc::CustomHookLocator::kRva;
    target.rva = symbol->value - image->minimum_load_vaddr();
  };
  resolve_role(hook.alloc, "alloc", spec.alloc);
  resolve_role(hook.realloc, "realloc", spec.realloc);
  resolve_role(hook.free, "free", spec.free);
  return spec;
}

[[nodiscard]] std::vector<noleax::ipc::CustomHookSpec> resolve_custom_hooks(
    const noleax::config::Configuration& configuration) {
  std::vector<noleax::ipc::CustomHookSpec> specs;
  specs.reserve(configuration.custom_hooks.value.size());
  for (const auto& hook : configuration.custom_hooks.value) {
    specs.push_back(resolve_custom_hook(configuration, hook));
  }
  return specs;
}

[[nodiscard]] noleax::controller::linux::CaptureOptions linux_capture_options(
    const noleax::config::Configuration& configuration, const std::filesystem::path& trace_path) {
  noleax::controller::linux::CaptureOptions capture;
  capture.agent_path = configuration.injection.agent_path.value.value_or(
      executable_path().parent_path() / "noleax-agent.so");
  const auto nanoseconds = configuration.injection.timeout.value;
  auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(nanoseconds);
  if (milliseconds < nanoseconds) {
    milliseconds += 1ms;
  }
  capture.timeout = milliseconds;
  capture.start.capture_kind = *configuration.operation.value == noleax::config::Operation::kAttach
                                   ? noleax::ipc::CaptureKind::kAttach
                                   : noleax::ipc::CaptureKind::kLaunch;
  capture.start.hook_profile = linux_hook_profile(configuration.capture.hook_profile.value);
  capture.start.compression = linux_compression_codec(configuration.trace.compression.value);
  capture.start.maximum_stack_depth = configuration.capture.max_stack_depth.value;
  capture.start.minimum_capture_size = configuration.capture.min_size.value;
  capture.start.buffer_size = configuration.trace.buffer_size.value;
  capture.start.maximum_trace_size = configuration.trace.max_file_size.value;
  capture.start.flush_interval_ns =
      static_cast<std::uint64_t>(configuration.trace.flush_interval.value.count());
  capture.start.memory_counters_interval_ns =
      static_cast<std::uint64_t>(configuration.capture.memory_counters_interval.value.count());
  capture.start.memory_map_interval_ns =
      static_cast<std::uint64_t>(configuration.capture.memory_map_interval.value.count());
  capture.start.compression_level = configuration.trace.compression_level.value;
  const auto trace_utf8 = std::filesystem::absolute(trace_path).generic_u8string();
  capture.start.trace_path_utf8 = std::string{trace_utf8.begin(), trace_utf8.end()};
  capture.start.unload_on_stop = configuration.injection.unload_on_stop.value;
  capture.start.custom_hooks = resolve_custom_hooks(configuration);
  return capture;
}

[[nodiscard]] int print_capture_summary(const std::filesystem::path& trace_path, std::uint32_t pid,
                                        bool target_exited,
                                        std::optional<std::uint32_t> target_exit_code,
                                        bool detached) {
  if (detached) {
    std::cout << "capture detached: trace=" << noleax::config::path_to_utf8(trace_path)
              << " pid=" << pid
              << " note=controller stopped waiting; the agent continues until the target "
                 "exits\n";
    return 2;
  }
  std::ifstream input{trace_path, std::ios::binary};
  if (!input) {
    std::cout << "capture produced no trace: trace=" << noleax::config::path_to_utf8(trace_path)
              << " pid=" << pid << " note=the agent may have failed to start\n";
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
  if (target_exited && target_exit_code.has_value()) {
    std::cout << " target_exit_code=" << *target_exit_code;
  } else if (!target_exited) {
    std::cout << " target_state=running";
  }
  std::cout << '\n';
  return analyzed.completeness.recommended_exit_code();
}

[[nodiscard]] int execute_capture(const noleax::config::Configuration& configuration) {
  validate_capture_support(configuration);
  const auto operation = *configuration.operation.value;
  const bool is_attach = operation == noleax::config::Operation::kAttach;
  const auto method = configuration.injection.method.value;
  const bool method_is_default =
      configuration.injection.method.source == noleax::config::ValueSource::kDefault;
  if (!is_attach && method != noleax::config::InjectionMethod::kLdPreload) {
    throw ApplicationError{5, "injection method '" +
                                  std::string{noleax::config::enum_value_name(method)} +
                                  "' is not supported on Linux; use ld-preload"};
  }
  // Attach has no env channel, so ld-preload cannot apply; a default-valued method
  // upgrades to ptrace automatically, an explicit one is a user error.
  if (is_attach && method == noleax::config::InjectionMethod::kLdPreload && !method_is_default) {
    throw ApplicationError{5, "ld-preload cannot attach to a running process; use ptrace"};
  }
  if (is_attach && method != noleax::config::InjectionMethod::kLdPreload &&
      method != noleax::config::InjectionMethod::kPtrace) {
    throw ApplicationError{5, "injection method '" +
                                  std::string{noleax::config::enum_value_name(method)} +
                                  "' is not supported for attach on Linux; use ptrace"};
  }

  const std::filesystem::path trace_path =
      configuration.trace.path.value.value_or(default_trace_path(configuration));
  ensure_output_directory(trace_path);
  const auto capture = linux_capture_options(configuration, trace_path);
  InterruptHandlerGuard interrupts;
  try {
    std::optional<noleax::controller::linux::CaptureSession> session;
    if (is_attach) {
      session.emplace(noleax::controller::linux::CaptureSession::attach(
          *configuration.target.pid.value, capture));
    } else {
      noleax::controller::linux::LaunchOptions launch;
      launch.executable = *configuration.target.path.value;
      launch.arguments = configuration.target.args.value;
      launch.working_directory =
          configuration.target.working_directory.value.value_or(launch.executable.parent_path());
      session.emplace(noleax::controller::linux::CaptureSession::launch(launch, capture));
    }

    // Wait for the target exit, the capture duration, or Ctrl+C (detach), whichever
    // comes first. On duration the controller drives the stop/finalize handshake; the
    // target then keeps running with hooks reverted.
    bool target_exited = false;
    bool detached = false;
    const auto deadline =
        configuration.capture.duration.value.has_value()
            ? std::chrono::steady_clock::now() + *configuration.capture.duration.value
            : std::chrono::steady_clock::time_point::max();
    for (;;) {
      if (session->wait_for_target(50ms)) {
        target_exited = true;
        break;
      }
      if (stop_requested.load(std::memory_order_relaxed)) {
        detached = true;
        break;
      }
      if (std::chrono::steady_clock::now() >= deadline) {
        static_cast<void>(session->stop());
        break;
      }
    }

    return print_capture_summary(trace_path, session->process_id(), target_exited,
                                 target_exited && !is_attach
                                     ? std::optional<std::uint32_t>{session->target_exit_code()}
                                     : std::nullopt,
                                 detached);
  } catch (const ApplicationError&) {
    throw;
  } catch (const std::exception& error) {
    throw ApplicationError{3, std::string{"capture failed: "} + error.what()};
  }
}

[[nodiscard]] int execute_doctor(const noleax::config::Configuration& configuration) {
  noleax::controller::linux::DoctorOptions options;
  options.agent_path = configuration.injection.agent_path.value;
  options.target_path = configuration.target.path.value;
  options.process_id = configuration.target.pid.value;
  options.injection_method =
      std::string{noleax::config::enum_value_name(configuration.injection.method.value)};
  const auto report = noleax::controller::linux::run_doctor(options);
  noleax::controller::linux::write_doctor_report(std::cout, report);
  if (report.has_error_category(noleax::controller::linux::DiagnosticCategory::kPermission)) {
    return 3;
  }
  if (report.has_error_category(noleax::controller::linux::DiagnosticCategory::kUnsupported)) {
    return 5;
  }
  return report.has_errors() ? 1 : 0;
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
    // Standalone baking contract: PDB symbols are resolved against the module image now, and
    // the resolved configuration (RVAs plus the image identity) is written beside the output.
    const std::vector<noleax::ipc::CustomHookSpec> custom_hooks =
        resolve_custom_hooks(configuration);
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
    if (!custom_hooks.empty()) {
      const auto agent_config_path = options.output.parent_path() / "noleax-agent.toml";
      std::ofstream output{agent_config_path, std::ios::binary | std::ios::trunc};
      if (!output) {
        throw ApplicationError{1, "cannot create the baked agent configuration '" +
                                      noleax::config::path_to_utf8(agent_config_path) + "'"};
      }
      output << "schema_version = 1\n";
      for (const auto& hook : custom_hooks) {
        write_custom_hook_toml(output, hook);
      }
      if (!output) {
        throw ApplicationError{1, "cannot write the baked agent configuration '" +
                                      noleax::config::path_to_utf8(agent_config_path) + "'"};
      }
      std::cout << " agent_config=noleax-agent.toml";
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

#if defined(_WIN32)

[[nodiscard]] int execute_symbols(const noleax::config::Configuration& configuration) {
  const std::filesystem::path& input = *configuration.symbol_listing.input.value;
  const PeImageInfo image = read_pe_image_info(input, 1);

  // Registering with base address 0 makes DbgHelp report RVAs directly (mirrors the custom
  // hook resolution path above). Unlike trace analysis, the listing enables the export-symbol
  // fallback so modules without a usable PDB still enumerate their exports.
  auto symbolizer_options = make_symbolizer_options(configuration);
  symbolizer_options.allow_export_symbols = true;
  noleax::analyzer::OfflineSymbolizer symbolizer{symbolizer_options};
  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{1U};
  module.image_size = image.image_size;
  module.image_path = input;
  const noleax::analyzer::SymbolModuleResult registered = symbolizer.register_module(module);
  switch (registered.status) {
    case noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded:
    case noleax::analyzer::SymbolModuleStatus::kExportsOnly:
    case noleax::analyzer::SymbolModuleStatus::kNoSymbols:
      break;
    case noleax::analyzer::SymbolModuleStatus::kUnsupportedPlatform:
      throw ApplicationError{5, "symbols is not supported on this platform"};
    case noleax::analyzer::SymbolModuleStatus::kImageNotFound:
    case noleax::analyzer::SymbolModuleStatus::kImageIdentityMismatch:
    case noleax::analyzer::SymbolModuleStatus::kPdbNotFound:
    case noleax::analyzer::SymbolModuleStatus::kPdbIdentityMismatch:
    case noleax::analyzer::SymbolModuleStatus::kDebugIdentityMismatch:
    case noleax::analyzer::SymbolModuleStatus::kLoadFailed:
      throw ApplicationError{
          1, "cannot load symbols for '" + noleax::config::path_to_utf8(input) + "': " +
                 std::string{noleax::analyzer::symbol_module_status_name(registered.status)}};
  }

  noleax::analyzer::SymbolListing listing;
  listing.module_path = noleax::config::path_to_utf8(input);
  listing.status = std::string{noleax::analyzer::symbol_module_status_name(registered.status)};
  listing.image_size = image.image_size;
  listing.image_base = image.image_base;
  listing.timestamp = image.timestamp;
  listing.checksum = image.checksum;
  listing.name_filters = configuration.symbol_listing.name.value;
  listing.match_case = configuration.symbol_listing.match_case.value;
  listing.kind_filters = configuration.symbol_listing.kind.value;

  const bool exports_only = registered.status == noleax::analyzer::SymbolModuleStatus::kExportsOnly;
  const auto enumerated = symbolizer.enumerate_symbols(module.module_id);
  listing.total = enumerated.size();
  for (const auto& symbol : enumerated) {
    const auto kind = noleax::analyzer::symbol_kind_from_tag(symbol.tag, exports_only);
    if (!listing.name_filters.empty()) {
      const bool matched =
          std::any_of(listing.name_filters.begin(), listing.name_filters.end(),
                      [&](const std::string& pattern) {
                        return noleax::analyzer::detail::wildcard_match(pattern, symbol.name,
                                                                        listing.match_case) ||
                               noleax::analyzer::detail::wildcard_match(
                                   pattern, symbol.undecorated_name, listing.match_case);
                      });
      if (!matched) {
        continue;
      }
    }
    if (!listing.kind_filters.empty() &&
        std::find(listing.kind_filters.begin(), listing.kind_filters.end(), kind) ==
            listing.kind_filters.end()) {
      continue;
    }
    noleax::analyzer::SymbolListingEntry entry;
    entry.name = symbol.name;
    entry.undecorated_name = symbol.undecorated_name;
    entry.rva = symbol.rva;
    entry.va = image.image_base + symbol.rva;
    entry.size = symbol.size;
    entry.kind = kind;
    listing.entries.push_back(std::move(entry));
  }
  symbolizer.unregister_module(module.module_id);

  std::ofstream output_file;
  std::ostream* output = &std::cout;
  if (configuration.symbol_listing.output.value.has_value()) {
    ensure_output_directory(*configuration.symbol_listing.output.value);
    output_file.open(*configuration.symbol_listing.output.value,
                     std::ios::binary | std::ios::trunc);
    if (!output_file) {
      throw ApplicationError{
          1, "cannot create symbols output '" +
                 noleax::config::path_to_utf8(*configuration.symbol_listing.output.value) + "'"};
    }
    output = &output_file;
  }
  const auto& fields = configuration.symbol_listing.fields.value;
  switch (configuration.symbol_listing.format.value) {
    case noleax::config::OutputFormat::kConsole:
      noleax::analyzer::write_symbol_listing_console(*output, listing, fields);
      break;
    case noleax::config::OutputFormat::kJson:
      noleax::analyzer::write_symbol_listing_json(*output, listing, fields);
      break;
    case noleax::config::OutputFormat::kCsv:
      noleax::analyzer::write_symbol_listing_csv(*output, listing, fields);
      break;
  }
  output->flush();
  if (!*output) {
    throw ApplicationError{1, "cannot finish symbols output"};
  }
  return 0;
}

#else

// ELF module images have no PE timestamp/checksum identity; the listing carries zeros
// there. image_base is 0 (RVAs are the file-relative link vaddrs minus the PT_LOAD bias,
// which the symbolizer backend applies).
[[nodiscard]] int execute_symbols(const noleax::config::Configuration& configuration) {
  const std::filesystem::path& input = *configuration.symbol_listing.input.value;
  std::error_code size_error;
  const auto image_size = static_cast<std::uint64_t>(std::filesystem::file_size(input, size_error));
  if (size_error) {
    throw ApplicationError{1, "cannot read the ELF image '" + noleax::config::path_to_utf8(input) +
                                  "': " + size_error.message()};
  }

  auto symbolizer_options = make_symbolizer_options(configuration);
  symbolizer_options.allow_export_symbols = true;
  noleax::analyzer::OfflineSymbolizer symbolizer{symbolizer_options};
  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{1U};
  module.image_size = image_size;
  module.image_path = input;
  const noleax::analyzer::SymbolModuleResult registered = symbolizer.register_module(module);
  switch (registered.status) {
    case noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded:
    case noleax::analyzer::SymbolModuleStatus::kExportsOnly:
    case noleax::analyzer::SymbolModuleStatus::kNoSymbols:
      break;
    case noleax::analyzer::SymbolModuleStatus::kUnsupportedPlatform:
      throw ApplicationError{5, "symbols is not supported on this platform"};
    case noleax::analyzer::SymbolModuleStatus::kImageNotFound:
    case noleax::analyzer::SymbolModuleStatus::kImageIdentityMismatch:
    case noleax::analyzer::SymbolModuleStatus::kPdbNotFound:
    case noleax::analyzer::SymbolModuleStatus::kPdbIdentityMismatch:
    case noleax::analyzer::SymbolModuleStatus::kDebugIdentityMismatch:
    case noleax::analyzer::SymbolModuleStatus::kLoadFailed:
      throw ApplicationError{
          1, "cannot load symbols for '" + noleax::config::path_to_utf8(input) + "': " +
                 std::string{noleax::analyzer::symbol_module_status_name(registered.status)}};
  }

  noleax::analyzer::SymbolListing listing;
  listing.module_path = noleax::config::path_to_utf8(input);
  listing.status = std::string{noleax::analyzer::symbol_module_status_name(registered.status)};
  listing.image_size = image_size;
  listing.image_base = 0U;
  listing.timestamp = 0U;
  listing.checksum = 0U;
  listing.name_filters = configuration.symbol_listing.name.value;
  listing.match_case = configuration.symbol_listing.match_case.value;
  listing.kind_filters = configuration.symbol_listing.kind.value;

  const bool exports_only = registered.status == noleax::analyzer::SymbolModuleStatus::kExportsOnly;
  const auto enumerated = symbolizer.enumerate_symbols(module.module_id);
  listing.total = enumerated.size();
  for (const auto& symbol : enumerated) {
    const auto kind = noleax::analyzer::symbol_kind_from_tag(symbol.tag, exports_only);
    if (!listing.name_filters.empty()) {
      const bool matched =
          std::any_of(listing.name_filters.begin(), listing.name_filters.end(),
                      [&](const std::string& pattern) {
                        return noleax::analyzer::detail::wildcard_match(pattern, symbol.name,
                                                                        listing.match_case) ||
                               noleax::analyzer::detail::wildcard_match(
                                   pattern, symbol.undecorated_name, listing.match_case);
                      });
      if (!matched) {
        continue;
      }
    }
    if (!listing.kind_filters.empty() &&
        std::find(listing.kind_filters.begin(), listing.kind_filters.end(), kind) ==
            listing.kind_filters.end()) {
      continue;
    }
    noleax::analyzer::SymbolListingEntry entry;
    entry.name = symbol.name;
    entry.undecorated_name = symbol.undecorated_name;
    entry.rva = symbol.rva;
    entry.va = symbol.rva;
    entry.size = symbol.size;
    entry.kind = kind;
    listing.entries.push_back(std::move(entry));
  }
  symbolizer.unregister_module(module.module_id);

  std::ofstream output_file;
  std::ostream* output = &std::cout;
  if (configuration.symbol_listing.output.value.has_value()) {
    ensure_output_directory(*configuration.symbol_listing.output.value);
    output_file.open(*configuration.symbol_listing.output.value,
                     std::ios::binary | std::ios::trunc);
    if (!output_file) {
      throw ApplicationError{
          1, "cannot create symbols output '" +
                 noleax::config::path_to_utf8(*configuration.symbol_listing.output.value) + "'"};
    }
    output = &output_file;
  }
  const auto& fields = configuration.symbol_listing.fields.value;
  switch (configuration.symbol_listing.format.value) {
    case noleax::config::OutputFormat::kConsole:
      noleax::analyzer::write_symbol_listing_console(*output, listing, fields);
      break;
    case noleax::config::OutputFormat::kJson:
      noleax::analyzer::write_symbol_listing_json(*output, listing, fields);
      break;
    case noleax::config::OutputFormat::kCsv:
      noleax::analyzer::write_symbol_listing_csv(*output, listing, fields);
      break;
  }
  output->flush();
  if (!*output) {
    throw ApplicationError{1, "cannot finish symbols output"};
  }
  return 0;
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
    case noleax::config::Operation::kSymbols:
      return execute_symbols(configuration);
  }
  unsupported("operation is not supported");
}

}  // namespace noleax::app
