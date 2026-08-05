#pragma once

#include <array>
#include <cstdint>
#include <iosfwd>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace noleax::analyzer {

inline constexpr std::uint32_t kSymbolsJsonSchemaVersion = 1U;

class SymbolListingError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Symbol category reported by `noleax symbols`; the kind filter values reuse these names.
enum class SymbolKind : std::uint8_t {
  kFunction,
  kData,
  kPublic,
  kExport,
  kOther,
};

[[nodiscard]] std::string_view symbol_kind_name(SymbolKind kind) noexcept;

// Maps a raw DbgHelp SymTagEnum value (SYMBOL_INFOW.Tag) to a listing kind. Symbols from an
// exports-only module are all reported as kExport regardless of their tag.
[[nodiscard]] SymbolKind symbol_kind_from_tag(std::uint32_t tag, bool exports_only) noexcept;

// One selectable output column / JSON object key.
enum class SymbolListingField : std::uint8_t {
  kName,
  kUndecoratedName,
  kRva,
  kVa,
  kSize,
  kKind,
};

[[nodiscard]] std::string_view symbol_listing_field_name(SymbolListingField field) noexcept;

// Every field in its fixed default order; an empty field selection means all of them.
inline constexpr std::array kAllSymbolListingFields{
    SymbolListingField::kName, SymbolListingField::kUndecoratedName,
    SymbolListingField::kRva,  SymbolListingField::kVa,
    SymbolListingField::kSize, SymbolListingField::kKind};

// Parses a comma-separated field list ("name,rva"), preserving the requested order; empty,
// unknown, and duplicate fields are rejected.
[[nodiscard]] std::vector<SymbolListingField> parse_symbol_listing_fields(std::string_view csv);

namespace detail {

// Iterative glob match supporting '*' and '?'; case folding is ASCII-only.
[[nodiscard]] inline bool wildcard_match(std::string_view pattern, std::string_view text,
                                         bool case_sensitive) noexcept {
  const auto normalize = [case_sensitive](char value) noexcept {
    if (!case_sensitive && value >= 'A' && value <= 'Z') {
      return static_cast<char>(value + ('a' - 'A'));
    }
    return value;
  };

  std::size_t pattern_index = 0U;
  std::size_t text_index = 0U;
  std::size_t star_index = std::string_view::npos;
  std::size_t retry_text_index = 0U;
  while (text_index < text.size()) {
    if (pattern_index < pattern.size() &&
        (pattern[pattern_index] == '?' ||
         normalize(pattern[pattern_index]) == normalize(text[text_index]))) {
      ++pattern_index;
      ++text_index;
      continue;
    }
    if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
      star_index = pattern_index;
      ++pattern_index;
      retry_text_index = text_index;
      continue;
    }
    if (star_index == std::string_view::npos) {
      return false;
    }
    pattern_index = star_index + 1U;
    text_index = ++retry_text_index;
  }
  while (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
    ++pattern_index;
  }
  return pattern_index == pattern.size();
}

}  // namespace detail

struct SymbolListingEntry {
  std::string name;
  std::string undecorated_name;
  std::uint64_t rva{0};
  std::uint64_t va{0};
  std::uint64_t size{0};
  SymbolKind kind{SymbolKind::kOther};
};

// The full listing document: module identity, the active filters echoed back, and the filtered
// entries. `total` counts the enumerated symbols before filtering; `entries` is the matched set.
struct SymbolListing {
  std::string module_path;
  std::string status;
  std::uint64_t image_size{0};
  std::uint64_t image_base{0};
  std::uint32_t timestamp{0};
  std::uint32_t checksum{0};
  std::vector<std::string> name_filters;
  bool match_case{false};
  std::vector<SymbolKind> kind_filters;
  std::uint64_t total{0};
  std::vector<SymbolListingEntry> entries;
};

// Writes the listing in the console, JSON (schema noleax.symbols v1), or CSV format. An empty
// `fields` selection writes every field in the fixed default order.
void write_symbol_listing_console(std::ostream& output, const SymbolListing& listing,
                                  const std::vector<SymbolListingField>& fields);
void write_symbol_listing_json(std::ostream& output, const SymbolListing& listing,
                               const std::vector<SymbolListingField>& fields);
void write_symbol_listing_csv(std::ostream& output, const SymbolListing& listing,
                              const std::vector<SymbolListingField>& fields);

}  // namespace noleax::analyzer
