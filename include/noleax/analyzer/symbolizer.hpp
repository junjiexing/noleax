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

struct SymbolizerOptions {
  std::vector<std::filesystem::path> search_paths;
  std::vector<std::string> symbol_servers;
};

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

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace noleax::analyzer
