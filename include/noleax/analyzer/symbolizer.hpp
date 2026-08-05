#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "noleax/analyzer/presentation.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/module.hpp"

namespace noleax::analyzer {

using PeImageIdentity = noleax::trace::PeImageIdentity;
using PdbIdentity = noleax::trace::PdbIdentity;

struct SymbolModule {
  noleax::trace::ModuleId module_id;
  noleax::trace::Address base_address{0};
  std::uint64_t image_size{0};
  std::filesystem::path image_path;
  std::optional<PeImageIdentity> expected_image_identity;
  std::optional<PdbIdentity> expected_pdb_identity;
};

enum class SymbolModuleStatus : std::uint8_t {
  kSymbolsLoaded,
  kExportsOnly,
  kNoSymbols,
  kImageNotFound,
  kImageIdentityMismatch,
  kPdbNotFound,
  kPdbIdentityMismatch,
  kLoadFailed,
  kUnsupportedPlatform,
};

[[nodiscard]] std::string_view symbol_module_status_name(SymbolModuleStatus status) noexcept;

struct SymbolModuleResult {
  SymbolModuleStatus status{SymbolModuleStatus::kLoadFailed};
  std::optional<PeImageIdentity> image_identity;
  std::optional<PdbIdentity> pdb_identity;
  std::uint32_t system_error{0};

  bool operator==(const SymbolModuleResult&) const = default;
};

enum class SymbolResolutionMode : std::uint8_t {
  // Resolve when possible, silently fall back to module+offset otherwise.
  kAuto,
  // Never touch DbgHelp: no image probing, no symbol downloads, always module+offset.
  kOff,
  // Like kAuto, but TraceMetadata rejects modules whose symbols cannot be resolved.
  kRequired,
};

struct SymbolizerOptions {
  SymbolResolutionMode mode{SymbolResolutionMode::kAuto};
  std::vector<std::filesystem::path> search_paths;
  std::vector<std::string> symbol_servers;
  // Verbatim DbgHelp search path used only when search_paths and symbol_servers are both
  // empty (the CLI fills this from _NT_SYMBOL_PATH/_NT_ALT_SYMBOL_PATH).
  std::wstring raw_search_path;
};

// Joins search paths and symbol servers into a DbgHelp search path. Servers get an "srv*"
// prefix unless they already carry one (case-insensitive), so "srv*cache*server" can select
// the download cache. Returns raw_search_path verbatim when both lists are empty.
[[nodiscard]] std::wstring build_symbol_search_path(const SymbolizerOptions& options);

// DbgHelp-style search path from _NT_SYMBOL_PATH and _NT_ALT_SYMBOL_PATH joined with ';'.
// Empty when neither variable is set.
[[nodiscard]] std::wstring symbol_search_path_from_environment();

class SymbolizerError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class OfflineSymbolizer {
 public:
  explicit OfflineSymbolizer(const SymbolizerOptions& options = {});
  ~OfflineSymbolizer();

  OfflineSymbolizer(const OfflineSymbolizer&) = delete;
  OfflineSymbolizer& operator=(const OfflineSymbolizer&) = delete;
  OfflineSymbolizer(OfflineSymbolizer&&) = delete;
  OfflineSymbolizer& operator=(OfflineSymbolizer&&) = delete;

  [[nodiscard]] SymbolModuleResult register_module(const SymbolModule& module);
  void unregister_module(noleax::trace::ModuleId module_id);
  [[nodiscard]] SymbolModuleResult module_result(noleax::trace::ModuleId module_id) const;
  [[nodiscard]] ResolvedStackFrame resolve_frame(noleax::trace::ModuleId module_id,
                                                 noleax::trace::Address absolute_address) const;
  // Resolves an export or PDB symbol name to its RVA inside a registered module. Returns
  // nullopt when the module has no usable symbols loaded, the name is not found, or the hit
  // lies outside the module (for example a same-named symbol from another module).
  [[nodiscard]] std::optional<std::uint64_t> resolve_symbol(noleax::trace::ModuleId module_id,
                                                            std::string_view symbol_name) const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace noleax::analyzer
