#include "noleax/analyzer/symbolizer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "noleax/analyzer/presentation.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"
#include "utf8.hpp"

#ifdef _WIN32
#define NOMINMAX
// DbgHelp requires the Windows base types to be declared first.
// clang-format off
#include <windows.h>
#include <dbghelp.h>
// clang-format on
#endif

namespace noleax::analyzer {
namespace {

[[nodiscard]] bool is_zero_guid(const PdbIdentity& identity) noexcept {
  return std::all_of(identity.guid.begin(), identity.guid.end(),
                     [](std::byte value) { return value == std::byte{0}; });
}

[[nodiscard]] std::wstring absolute_path(const std::filesystem::path& path) {
  std::error_code error;
  const auto absolute = std::filesystem::absolute(path, error);
  return (error ? path : absolute).wstring();
}

[[nodiscard]] std::wstring widen_symbol_text(std::string_view value) {
  if (!detail::is_valid_utf8(value)) {
    throw SymbolizerError{"symbol server is not valid UTF-8"};
  }
  if (value.empty()) {
    return {};
  }
#ifdef _WIN32
  const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                           static_cast<int>(value.size()), nullptr, 0);
  if (required <= 0) {
    throw SymbolizerError{"cannot convert UTF-8 symbol text to UTF-16"};
  }
  std::wstring result(static_cast<std::size_t>(required), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), result.data(), required) != required) {
    throw SymbolizerError{"cannot convert UTF-8 symbol text to UTF-16"};
  }
  return result;
#else
  // Symbolization is Windows-only; elsewhere the built path is never consumed, so a
  // byte-wise widening keeps this function well-defined without a full UTF-8 decoder.
  std::wstring result;
  result.reserve(value.size());
  for (const char character : value) {
    result.push_back(static_cast<wchar_t>(static_cast<unsigned char>(character)));
  }
  return result;
#endif
}

[[nodiscard]] bool has_srv_prefix(std::string_view value) noexcept {
  constexpr std::string_view prefix{"srv*"};
  return value.size() >= prefix.size() &&
         std::equal(prefix.begin(), prefix.end(), value.begin(), [](char expected, char actual) {
           const char lowered =
               actual >= 'A' && actual <= 'Z' ? static_cast<char>(actual - 'A' + 'a') : actual;
           return expected == lowered;
         });
}

#ifdef _WIN32
[[nodiscard]] std::wstring environment_value(const wchar_t* name) {
  const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
  if (required == 0U) {
    return {};
  }
  std::wstring result(required, L'\0');
  const DWORD length = GetEnvironmentVariableW(name, result.data(), required);
  result.resize(length);
  return result;
}
#else
[[nodiscard]] std::wstring environment_value(const char* name) {
  if (const char* value = std::getenv(name); value != nullptr) {
    return widen_symbol_text(value);
  }
  return {};
}
#endif

#ifdef _WIN32

[[nodiscard]] std::mutex& dbghelp_mutex() {
  static std::mutex value;
  return value;
}

class DbgHelpOptionsGuard {
 public:
  DbgHelpOptionsGuard() : previous_{SymGetOptions()} {
    constexpr DWORD options = SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS |
                              SYMOPT_EXACT_SYMBOLS | SYMOPT_NO_PROMPTS | SYMOPT_SECURE;
    static_cast<void>(SymSetOptions(options));
  }

  ~DbgHelpOptionsGuard() {
    // DbgHelp documents SYMOPT_SECURE as process-sticky once enabled.
    static_cast<void>(SymSetOptions(previous_ | SYMOPT_SECURE));
  }

  DbgHelpOptionsGuard(const DbgHelpOptionsGuard&) = delete;
  DbgHelpOptionsGuard& operator=(const DbgHelpOptionsGuard&) = delete;

 private:
  DWORD previous_;
};

[[nodiscard]] std::string wide_to_utf8(std::wstring_view value) {
  if (value.empty()) {
    return {};
  }
  const int required =
      WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (required <= 0) {
    throw SymbolizerError{"cannot convert UTF-16 symbol text to UTF-8"};
  }
  std::string result(static_cast<std::size_t>(required), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), result.data(), required, nullptr,
                          nullptr) != required) {
    throw SymbolizerError{"cannot convert UTF-16 symbol text to UTF-8"};
  }
  return result;
}

[[nodiscard]] PdbIdentity pdb_identity(const GUID& guid, std::uint32_t age) noexcept {
  PdbIdentity result;
  static_assert(sizeof(guid) == result.guid.size());
  std::memcpy(result.guid.data(), &guid, result.guid.size());
  result.age = age;
  return result;
}

[[nodiscard]] SymbolModuleStatus status_from_symbol_type(SYM_TYPE type) noexcept {
  switch (type) {
    case SymPdb:
    case SymDia:
    case SymCv:
    case SymCoff:
      return SymbolModuleStatus::kSymbolsLoaded;
    case SymExport:
      return SymbolModuleStatus::kExportsOnly;
    case SymNone:
    case SymDeferred:
    case SymSym:
    case SymVirtual:
    case NumSymTypes:
      return SymbolModuleStatus::kNoSymbols;
  }
  return SymbolModuleStatus::kNoSymbols;
}

#endif

}  // namespace

std::wstring build_symbol_search_path(const SymbolizerOptions& options) {
  if (options.search_paths.empty() && options.symbol_servers.empty()) {
    return options.raw_search_path;
  }
  std::wstring result;
  const auto append = [&result](const std::wstring& value) {
    if (value.find(L';') != std::wstring::npos) {
      throw SymbolizerError{"symbol path entries must not contain semicolons"};
    }
    if (!result.empty()) {
      result.push_back(L';');
    }
    result.append(value);
  };
  for (const auto& path : options.search_paths) {
    append(absolute_path(path));
  }
  for (const auto& server : options.symbol_servers) {
    if (server.empty()) {
      throw SymbolizerError{"symbol server must not be empty"};
    }
    append(has_srv_prefix(server) ? widen_symbol_text(server)
                                  : L"srv*" + widen_symbol_text(server));
  }
  return result;
}

std::wstring symbol_search_path_from_environment() {
#ifdef _WIN32
  std::wstring result = environment_value(L"_NT_SYMBOL_PATH");
  const std::wstring alternate = environment_value(L"_NT_ALT_SYMBOL_PATH");
#else
  std::wstring result = environment_value("_NT_SYMBOL_PATH");
  const std::wstring alternate = environment_value("_NT_ALT_SYMBOL_PATH");
#endif
  if (!alternate.empty()) {
    if (!result.empty()) {
      result.push_back(L';');
    }
    result.append(alternate);
  }
  return result;
}

class OfflineSymbolizer::Impl {
 public:
  explicit Impl(const SymbolizerOptions& options) : options_{options} {
#ifdef _WIN32
    search_path_ = build_symbol_search_path(options_);
    process_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (process_ == nullptr) {
      throw SymbolizerError{"cannot create the DbgHelp session handle"};
    }
    std::scoped_lock lock{dbghelp_mutex()};
    DbgHelpOptionsGuard options_guard;
    if (SymInitializeW(process_, search_path_.c_str(), FALSE) == FALSE) {
      const DWORD error = GetLastError();
      CloseHandle(process_);
      process_ = nullptr;
      throw SymbolizerError{"cannot initialize DbgHelp (error " + std::to_string(error) + ")"};
    }
#else
    static_cast<void>(options_);
#endif
  }

  ~Impl() {
#ifdef _WIN32
    if (process_ != nullptr) {
      std::scoped_lock lock{dbghelp_mutex()};
      DbgHelpOptionsGuard options_guard;
      static_cast<void>(SymCleanup(process_));
      CloseHandle(process_);
    }
#endif
  }

  [[nodiscard]] SymbolModuleResult register_module(const SymbolModule& module) {
    validate_module(module);
    std::unique_lock modules_lock{modules_mutex_};
    if (modules_.contains(module.module_id)) {
      throw SymbolizerError{"module ID is already registered"};
    }

    Entry entry;
    entry.module = module;
    entry.module_name = module_name(entry.module.image_path);
#ifdef _WIN32
    register_windows_module(entry);
#else
    entry.result.status = SymbolModuleStatus::kUnsupportedPlatform;
#endif
    const auto result = entry.result;
    modules_.emplace(entry.module.module_id, std::move(entry));
    return result;
  }

  void unregister_module(noleax::trace::ModuleId module_id) {
    std::unique_lock modules_lock{modules_mutex_};
    auto item = modules_.find(module_id);
    if (item == modules_.end()) {
      throw SymbolizerError{"module ID is not registered"};
    }
#ifdef _WIN32
    if (item->second.dbghelp_loaded) {
      std::scoped_lock lock{dbghelp_mutex()};
      DbgHelpOptionsGuard options_guard;
      if (SymUnloadModule64(process_, item->second.dbghelp_base) == FALSE) {
        throw SymbolizerError{"cannot unload the DbgHelp module"};
      }
    }
#endif
    modules_.erase(item);
  }

  [[nodiscard]] SymbolModuleResult module_result(noleax::trace::ModuleId module_id) const {
    std::shared_lock modules_lock{modules_mutex_};
    return find_module(module_id).result;
  }

  [[nodiscard]] ResolvedStackFrame resolve_frame(noleax::trace::ModuleId module_id,
                                                 noleax::trace::Address absolute_address) const {
    std::shared_lock modules_lock{modules_mutex_};
    const Entry& entry = find_module(module_id);
    if (absolute_address < entry.module.base_address ||
        absolute_address - entry.module.base_address >= entry.module.image_size) {
      throw SymbolizerError{"frame address is outside the registered module range"};
    }

    ResolvedStackFrame frame;
    frame.absolute_address = absolute_address;
    frame.module_name = entry.module_name;
    frame.module_offset = absolute_address - entry.module.base_address;
#ifdef _WIN32
    if (entry.dbghelp_loaded) {
      resolve_windows_symbol(entry, frame);
    }
#endif
    return frame;
  }

 private:
  struct Entry {
    SymbolModule module;
    SymbolModuleResult result;
    std::string module_name;
#ifdef _WIN32
    DWORD64 dbghelp_base{0};
    bool dbghelp_loaded{false};
#endif
  };

  static void validate_module(const SymbolModule& module) {
    if (!module.module_id.is_valid()) {
      throw SymbolizerError{"module ID must not be zero"};
    }
    if (module.image_size == 0U || module.image_size > std::numeric_limits<std::uint32_t>::max()) {
      throw SymbolizerError{"module image size must fit a nonzero PE image size"};
    }
    if (module.image_path.empty()) {
      throw SymbolizerError{"module image path must not be empty"};
    }
    if (module.base_address >
        std::numeric_limits<noleax::trace::Address>::max() - module.image_size) {
      throw SymbolizerError{"module address range overflows"};
    }
    if (module.expected_pdb_identity.has_value() &&
        (is_zero_guid(*module.expected_pdb_identity) || module.expected_pdb_identity->age == 0U)) {
      throw SymbolizerError{"expected PDB identity requires a nonzero GUID and age"};
    }
  }

  [[nodiscard]] static std::string module_name(const std::filesystem::path& path) {
#ifdef _WIN32
    return wide_to_utf8(path.filename().wstring());
#else
    const auto value = path.filename().u8string();
    return {reinterpret_cast<const char*>(value.data()), value.size()};
#endif
  }

  [[nodiscard]] const Entry& find_module(noleax::trace::ModuleId module_id) const {
    const auto item = modules_.find(module_id);
    if (item == modules_.end()) {
      throw SymbolizerError{"module ID is not registered"};
    }
    return item->second;
  }

#ifdef _WIN32
  [[nodiscard]] DWORD64 allocate_dbghelp_base(std::uint64_t image_size) {
    constexpr std::uint64_t alignment = 0x10000U;
    if (image_size > std::numeric_limits<std::uint64_t>::max() - (alignment - 1U)) {
      throw SymbolizerError{"module image size cannot be aligned"};
    }
    const std::uint64_t aligned = (image_size + alignment - 1U) & ~(alignment - 1U);
    if (next_dbghelp_base_ > std::numeric_limits<std::uint64_t>::max() - aligned - alignment) {
      throw SymbolizerError{"DbgHelp synthetic address space is exhausted"};
    }
    const DWORD64 result = next_dbghelp_base_;
    next_dbghelp_base_ += aligned + alignment;
    return result;
  }

  void register_windows_module(Entry& entry) {
    std::error_code filesystem_error;
    if (!std::filesystem::is_regular_file(entry.module.image_path, filesystem_error)) {
      entry.result.status = SymbolModuleStatus::kImageNotFound;
      entry.result.system_error = filesystem_error
                                      ? static_cast<std::uint32_t>(filesystem_error.value())
                                      : static_cast<std::uint32_t>(ERROR_FILE_NOT_FOUND);
      return;
    }

    const DWORD64 requested_base = allocate_dbghelp_base(entry.module.image_size);
    const std::wstring image_path = absolute_path(entry.module.image_path);
    std::scoped_lock lock{dbghelp_mutex()};
    DbgHelpOptionsGuard options_guard;
    const DWORD64 loaded_base =
        SymLoadModuleExW(process_, nullptr, image_path.c_str(), nullptr, requested_base,
                         static_cast<DWORD>(entry.module.image_size), nullptr, 0U);
    if (loaded_base == 0U) {
      entry.result.status = SymbolModuleStatus::kLoadFailed;
      entry.result.system_error = GetLastError();
      return;
    }
    entry.dbghelp_base = loaded_base;
    entry.dbghelp_loaded = true;

    IMAGEHLP_MODULEW64 information{};
    information.SizeOfStruct = sizeof(information);
    if (SymGetModuleInfoW64(process_, loaded_base, &information) == FALSE) {
      entry.result.status = SymbolModuleStatus::kLoadFailed;
      entry.result.system_error = GetLastError();
      unload_after_identity_failure(entry);
      return;
    }

    entry.result.image_identity =
        PeImageIdentity{information.TimeDateStamp, information.CheckSum, information.ImageSize};
    const SymbolModuleStatus loaded_status = status_from_symbol_type(information.SymType);
    const bool loaded_pdb = information.SymType == SymPdb || information.SymType == SymDia;
    const PdbIdentity actual_pdb = pdb_identity(information.PdbSig70, information.PdbAge);
    if (loaded_pdb && !is_zero_guid(actual_pdb) && actual_pdb.age != 0U) {
      entry.result.pdb_identity = actual_pdb;
    }

    if (information.ImageSize != entry.module.image_size || information.DbgUnmatched != FALSE ||
        (entry.module.expected_image_identity.has_value() &&
         *entry.module.expected_image_identity != *entry.result.image_identity)) {
      entry.result.status = SymbolModuleStatus::kImageIdentityMismatch;
      unload_after_identity_failure(entry);
      return;
    }
    if (information.PdbUnmatched != FALSE) {
      entry.result.status = SymbolModuleStatus::kPdbIdentityMismatch;
      unload_after_identity_failure(entry);
      return;
    }
    if (entry.module.expected_pdb_identity.has_value()) {
      if (!loaded_pdb || !entry.result.pdb_identity.has_value()) {
        entry.result.status = SymbolModuleStatus::kPdbNotFound;
        return;
      }
      if (*entry.module.expected_pdb_identity != *entry.result.pdb_identity) {
        entry.result.status = SymbolModuleStatus::kPdbIdentityMismatch;
        unload_after_identity_failure(entry);
        return;
      }
    }
    entry.result.status = loaded_status;
  }

  void unload_after_identity_failure(Entry& entry) const noexcept {
    static_cast<void>(SymUnloadModule64(process_, entry.dbghelp_base));
    entry.dbghelp_loaded = false;
    entry.dbghelp_base = 0U;
  }

  void resolve_windows_symbol(const Entry& entry, ResolvedStackFrame& frame) const {
    constexpr std::size_t maximum_name_length = 4096U;
    alignas(SYMBOL_INFOW)
        std::array<std::byte, sizeof(SYMBOL_INFOW) + maximum_name_length * sizeof(wchar_t)>
            storage{};
    auto* symbol = reinterpret_cast<SYMBOL_INFOW*>(storage.data());
    symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol->MaxNameLen = static_cast<ULONG>(maximum_name_length);
    DWORD64 displacement = 0U;
    const DWORD64 address = entry.dbghelp_base + *frame.module_offset;

    std::scoped_lock lock{dbghelp_mutex()};
    DbgHelpOptionsGuard options_guard;
    if (SymFromAddrW(process_, address, &displacement, symbol) == FALSE) {
      return;
    }
    frame.symbol_name =
        wide_to_utf8(std::wstring_view{symbol->Name, static_cast<std::size_t>(symbol->NameLen)});
    frame.symbol_offset = displacement;
  }
#endif

  SymbolizerOptions options_;
  mutable std::shared_mutex modules_mutex_;
  std::map<noleax::trace::ModuleId, Entry> modules_;
#ifdef _WIN32
  std::wstring search_path_;
  HANDLE process_{nullptr};
  DWORD64 next_dbghelp_base_{0x0000010000000000ULL};
#endif
};

std::string_view symbol_module_status_name(SymbolModuleStatus status) noexcept {
  switch (status) {
    case SymbolModuleStatus::kSymbolsLoaded:
      return "symbols_loaded";
    case SymbolModuleStatus::kExportsOnly:
      return "exports_only";
    case SymbolModuleStatus::kNoSymbols:
      return "no_symbols";
    case SymbolModuleStatus::kImageNotFound:
      return "image_not_found";
    case SymbolModuleStatus::kImageIdentityMismatch:
      return "image_identity_mismatch";
    case SymbolModuleStatus::kPdbNotFound:
      return "pdb_not_found";
    case SymbolModuleStatus::kPdbIdentityMismatch:
      return "pdb_identity_mismatch";
    case SymbolModuleStatus::kLoadFailed:
      return "load_failed";
    case SymbolModuleStatus::kUnsupportedPlatform:
      return "unsupported_platform";
  }
  return "unknown";
}

OfflineSymbolizer::OfflineSymbolizer(const SymbolizerOptions& options)
    : impl_{std::make_unique<Impl>(options)} {}

OfflineSymbolizer::~OfflineSymbolizer() = default;

SymbolModuleResult OfflineSymbolizer::register_module(const SymbolModule& module) {
  return impl_->register_module(module);
}

void OfflineSymbolizer::unregister_module(noleax::trace::ModuleId module_id) {
  impl_->unregister_module(module_id);
}

SymbolModuleResult OfflineSymbolizer::module_result(noleax::trace::ModuleId module_id) const {
  return impl_->module_result(module_id);
}

ResolvedStackFrame OfflineSymbolizer::resolve_frame(noleax::trace::ModuleId module_id,
                                                    noleax::trace::Address absolute_address) const {
  return impl_->resolve_frame(module_id, absolute_address);
}

}  // namespace noleax::analyzer
