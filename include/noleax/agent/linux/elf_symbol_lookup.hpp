#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>

namespace noleax::agent::linux {

// Finds `symbol_name` in the module file at `module_path`: .symtab first, then .dynsym.
// When the file has no usable .symtab, falls back to its .gnu_debuglink companion,
// searched in: the image's directory, its .debug/ subdirectory, and
// /usr/lib/debug/<image absolute path>/. A companion is used only after identity
// verification (GNU CRC32 from the debuglink section — zlib/IEEE polynomial, NOT CRC32C —
// plus Build ID equality when both files carry one). Returns the link-time st_value.
// Streaming with early exit: symbol tables and string tables are never loaded whole, so
// multi-GB debug companions with millions of symbols stay scannable. Every failure
// (truncated file, malformed section, missing candidate, identity mismatch) yields
// nullopt; the function never throws.
[[nodiscard]] std::optional<std::uint64_t> find_elf_symbol_vaddr(
    const std::filesystem::path& module_path, std::string_view symbol_name);

}  // namespace noleax::agent::linux
