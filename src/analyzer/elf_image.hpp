#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace noleax::analyzer::elf {

// Which on-disk symbol table a symbol was parsed from. The full .symtab is preferred for
// lookups; .dynsym (the export-equivalent table) is only a fallback.
enum class SymbolTable : std::uint8_t {
  kSymtab,
  kDynsym,
};

// One parsed ELF64 symbol table entry.
struct ElfSymbol {
  std::string name;
  // Link-time virtual address (st_value).
  std::uint64_t value{0};
  // st_size; zero when the symbol carries no size.
  std::uint64_t size{0};
  // st_shndx; SHN_UNDEF (0) marks an undefined (imported) symbol.
  std::uint32_t section_index{0};
  // STT_* symbol type.
  std::uint8_t type{0};
  // STB_* symbol binding.
  std::uint8_t binding{0};
  SymbolTable table{SymbolTable::kSymtab};
};

// Raised for unreadable, truncated, malformed, or unsupported (non-ELF64, big-endian, or
// non-x86-64) images. `system_error` carries errno when the failure came from a syscall.
class ElfImageError final : public std::runtime_error {
 public:
  explicit ElfImageError(const std::string& message, std::uint32_t system_error = 0U)
      : std::runtime_error{message}, system_error_{system_error} {}

  [[nodiscard]] std::uint32_t system_error() const noexcept { return system_error_; }

 private:
  std::uint32_t system_error_;
};

// Read-only ELF64 (little-endian, x86-64) image. The header, program headers, symbol tables,
// and build ID are parsed once at construction; lookups run entirely against the in-memory
// tables. Instances are immutable and safe to query from multiple threads.
class ElfImage {
 public:
  // Throws ElfImageError when the file cannot be read or is not a supported ELF64 image.
  explicit ElfImage(const std::filesystem::path& path);

  // Lowest p_vaddr over the PT_LOAD segments: the link-time base bias subtracted from a
  // link-time vaddr to get the offset relative to the module's recorded load base.
  [[nodiscard]] std::uint64_t minimum_load_vaddr() const noexcept { return minimum_load_vaddr_; }

  // Every parsed symbol (including undefined ones) from the requested table, in file order.
  [[nodiscard]] const std::vector<ElfSymbol>& symbols(SymbolTable table) const noexcept {
    return table == SymbolTable::kSymtab ? symtab_ : dynsym_;
  }

  // True when the table holds at least one defined function symbol (STT_FUNC/STT_GNU_IFUNC).
  [[nodiscard]] bool has_function_symbols(SymbolTable table) const noexcept {
    return table == SymbolTable::kSymtab ? !symtab_functions_.empty()
                                         : !dynsym_functions_.empty();
  }

  // .note.gnu.build-id descriptor bytes; empty when the image carries no build ID.
  [[nodiscard]] const std::vector<std::byte>& build_id() const noexcept { return build_id_; }

  // Best function candidate for `vaddr` (a link-time virtual address): the defined
  // STT_FUNC/STT_GNU_IFUNC symbol with st_value <= vaddr < st_value + st_size, or the nearest
  // function symbol below `vaddr` when sizes are zero. .dynsym is consulted only when .symtab
  // has no candidate below the address.
  [[nodiscard]] std::optional<ElfSymbol> find_function(std::uint64_t vaddr) const;

  // Exact raw-name lookup of a defined symbol, .symtab first, then .dynsym.
  [[nodiscard]] std::optional<ElfSymbol> find_symbol(std::string_view name) const;

 private:
  std::uint64_t minimum_load_vaddr_{0};
  std::vector<ElfSymbol> symtab_;
  std::vector<ElfSymbol> dynsym_;
  // Indices into symtab_/dynsym_ of the defined function symbols, sorted by value.
  std::vector<std::size_t> symtab_functions_;
  std::vector<std::size_t> dynsym_functions_;
  std::vector<std::byte> build_id_;
};

// True when a symbol is defined in the image and worth listing: skips undefined, unnamed,
// file, and section records.
[[nodiscard]] bool is_displayable(const ElfSymbol& symbol) noexcept;

// DbgHelp-compatible listing tag so the shared symbol_kind_from_tag mapping needs no ELF
// knowledge: functions map to SymTagFunction (5), data to SymTagData (7), everything else to
// SymTagPublicSymbol (10).
[[nodiscard]] std::uint32_t listing_tag(const ElfSymbol& symbol) noexcept;

// C++ demangling via abi::__cxa_demangle; returns `name` unchanged when it is not a valid
// mangled name (C symbols, demangle failures).
[[nodiscard]] std::string demangle(std::string_view name);

}  // namespace noleax::analyzer::elf
