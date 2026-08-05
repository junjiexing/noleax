#include "noleax/analyzer/symbol_listing.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "utf8.hpp"

namespace noleax::analyzer {
namespace {

// Raw SymTagEnum values (see dbghelp.h): kept numeric so this translation unit does not depend
// on the Windows-only DbgHelp headers.
constexpr std::uint32_t kSymTagFunction = 5U;
constexpr std::uint32_t kSymTagData = 7U;
constexpr std::uint32_t kSymTagPublicSymbol = 10U;

class JsonEmitter {
 public:
  explicit JsonEmitter(std::ostream& output) : output_{output} {}

  void raw(std::string_view value) {
    output_.write(value.data(), static_cast<std::streamsize>(value.size()));
  }

  void string(std::string_view value) {
    if (!detail::is_valid_utf8(value)) {
      throw SymbolListingError{"JSON string is not valid UTF-8"};
    }
    raw("\"");
    for (const char byte_char : value) {
      const auto byte = static_cast<unsigned char>(byte_char);
      switch (byte) {
        case '"':
          raw("\\\"");
          break;
        case '\\':
          raw("\\\\");
          break;
        case '\b':
          raw("\\b");
          break;
        case '\f':
          raw("\\f");
          break;
        case '\n':
          raw("\\n");
          break;
        case '\r':
          raw("\\r");
          break;
        case '\t':
          raw("\\t");
          break;
        default:
          if (byte < 0x20U) {
            constexpr std::string_view digits{"0123456789abcdef"};
            const std::array escaped{'\\', 'u', '0', '0', digits[byte >> 4U], digits[byte & 0x0fU]};
            output_.write(escaped.data(), static_cast<std::streamsize>(escaped.size()));
          } else {
            output_.put(static_cast<char>(byte));
          }
          break;
      }
    }
    raw("\"");
  }

  void unsigned_number(std::uint64_t value) {
    std::array<char, 32> buffer{};
    const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    if (result.ec != std::errc{}) {
      throw SymbolListingError{"cannot format an unsigned JSON integer"};
    }
    output_.write(buffer.data(), result.ptr - buffer.data());
  }

  void boolean(bool value) { raw(value ? "true" : "false"); }

 private:
  std::ostream& output_;
};

class CsvEmitter {
 public:
  explicit CsvEmitter(std::ostream& output) : output_{output} {}

  void row(const std::vector<std::string>& fields) {
    for (const auto& field : fields) {
      if (!detail::is_valid_utf8(field)) {
        throw SymbolListingError{"CSV field is not valid UTF-8"};
      }
    }
    bool first = true;
    for (const auto& field : fields) {
      if (!first) {
        output_.put(',');
      }
      first = false;
      write_field(field);
    }
    output_.write("\r\n", 2);
  }

 private:
  void write_field(std::string_view value) {
    if (value.find_first_of(",\"\r\n") == std::string_view::npos) {
      output_.write(value.data(), static_cast<std::streamsize>(value.size()));
      return;
    }
    output_.put('"');
    for (const char character : value) {
      if (character == '"') {
        output_.write("\"\"", 2);
      } else {
        output_.put(character);
      }
    }
    output_.put('"');
  }

  std::ostream& output_;
};

[[nodiscard]] std::string decimal(std::uint64_t value) {
  std::array<char, 32> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  if (result.ec != std::errc{}) {
    throw SymbolListingError{"cannot format a decimal integer"};
  }
  return {buffer.data(), result.ptr};
}

[[nodiscard]] std::string hex_value(std::uint64_t value) {
  std::array<char, 16> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
  if (result.ec != std::errc{}) {
    throw SymbolListingError{"cannot format a hexadecimal value"};
  }
  std::string output{"0x"};
  output.append(buffer.data(), result.ptr);
  return output;
}

[[nodiscard]] std::vector<SymbolListingField> effective_fields(
    const std::vector<SymbolListingField>& fields) {
  if (!fields.empty()) {
    return fields;
  }
  return {kAllSymbolListingFields.begin(), kAllSymbolListingFields.end()};
}

[[nodiscard]] std::string entry_field_value(const SymbolListingEntry& entry,
                                            SymbolListingField field) {
  switch (field) {
    case SymbolListingField::kName:
      return entry.name;
    case SymbolListingField::kUndecoratedName:
      return entry.undecorated_name;
    case SymbolListingField::kRva:
      return hex_value(entry.rva);
    case SymbolListingField::kVa:
      return hex_value(entry.va);
    case SymbolListingField::kSize:
      return decimal(entry.size);
    case SymbolListingField::kKind:
      return std::string{symbol_kind_name(entry.kind)};
  }
  return {};
}

void write_entry_field_json(JsonEmitter& json, const SymbolListingEntry& entry,
                            SymbolListingField field, bool first) {
  if (!first) {
    json.raw(",");
  }
  switch (field) {
    case SymbolListingField::kName:
      json.raw("\"name\":");
      json.string(entry.name);
      break;
    case SymbolListingField::kUndecoratedName:
      json.raw("\"undecorated_name\":");
      json.string(entry.undecorated_name);
      break;
    case SymbolListingField::kRva:
      json.raw("\"rva\":");
      json.string(hex_value(entry.rva));
      break;
    case SymbolListingField::kVa:
      json.raw("\"va\":");
      json.string(hex_value(entry.va));
      break;
    case SymbolListingField::kSize:
      json.raw("\"size\":");
      json.unsigned_number(entry.size);
      break;
    case SymbolListingField::kKind:
      json.raw("\"kind\":");
      json.string(symbol_kind_name(entry.kind));
      break;
  }
}

[[nodiscard]] std::string joined(const std::vector<std::string>& values,
                                 std::string_view separator) {
  std::string result;
  for (std::size_t index = 0U; index < values.size(); ++index) {
    if (index != 0U) {
      result.append(separator);
    }
    result.append(values[index]);
  }
  return result;
}

[[nodiscard]] std::string joined_kinds(const std::vector<SymbolKind>& kinds) {
  std::string result;
  for (std::size_t index = 0U; index < kinds.size(); ++index) {
    if (index != 0U) {
      result.push_back(',');
    }
    result.append(symbol_kind_name(kinds[index]));
  }
  return result;
}

}  // namespace

std::string_view symbol_kind_name(SymbolKind kind) noexcept {
  switch (kind) {
    case SymbolKind::kFunction:
      return "function";
    case SymbolKind::kData:
      return "data";
    case SymbolKind::kPublic:
      return "public";
    case SymbolKind::kExport:
      return "export";
    case SymbolKind::kOther:
      return "other";
  }
  return "unknown";
}

SymbolKind symbol_kind_from_tag(std::uint32_t tag, bool exports_only) noexcept {
  if (exports_only) {
    return SymbolKind::kExport;
  }
  if (tag == kSymTagFunction) {
    return SymbolKind::kFunction;
  }
  if (tag == kSymTagData) {
    return SymbolKind::kData;
  }
  if (tag == kSymTagPublicSymbol) {
    return SymbolKind::kPublic;
  }
  return SymbolKind::kOther;
}

std::string_view symbol_listing_field_name(SymbolListingField field) noexcept {
  switch (field) {
    case SymbolListingField::kName:
      return "name";
    case SymbolListingField::kUndecoratedName:
      return "undecorated_name";
    case SymbolListingField::kRva:
      return "rva";
    case SymbolListingField::kVa:
      return "va";
    case SymbolListingField::kSize:
      return "size";
    case SymbolListingField::kKind:
      return "kind";
  }
  return "unknown";
}

std::vector<SymbolListingField> parse_symbol_listing_fields(std::string_view csv) {
  std::vector<SymbolListingField> fields;
  std::size_t offset = 0U;
  while (offset <= csv.size()) {
    const std::size_t comma = csv.find(',', offset);
    const std::string_view token =
        csv.substr(offset, comma == std::string_view::npos ? comma : comma - offset);
    offset = comma == std::string_view::npos ? csv.size() + 1U : comma + 1U;

    SymbolListingField field = SymbolListingField::kName;
    bool known = false;
    for (const SymbolListingField candidate : kAllSymbolListingFields) {
      if (symbol_listing_field_name(candidate) == token) {
        field = candidate;
        known = true;
        break;
      }
    }
    if (!known) {
      throw SymbolListingError{"unknown symbol listing field '" + std::string{token} + "'"};
    }
    if (std::find(fields.begin(), fields.end(), field) != fields.end()) {
      throw SymbolListingError{"duplicate symbol listing field '" + std::string{token} + "'"};
    }
    fields.push_back(field);
  }
  return fields;
}

void write_symbol_listing_console(std::ostream& output, const SymbolListing& listing,
                                  const std::vector<SymbolListingField>& fields) {
  const auto selected = effective_fields(fields);
  output << "noleax symbols\n";
  output << "module: " << listing.module_path << " (image-size=" << listing.image_size
         << " base=" << hex_value(listing.image_base) << ")\n";
  output << "symbols: " << listing.status << "\n";
  output << "filters: ";
  if (listing.name_filters.empty() && listing.kind_filters.empty()) {
    output << "none";
  } else {
    bool wrote_part = false;
    if (!listing.name_filters.empty()) {
      output << "name=" << joined(listing.name_filters, ",")
             << (listing.match_case ? " (case-sensitive)" : " (ignore-case)");
      wrote_part = true;
    }
    if (!listing.kind_filters.empty()) {
      if (wrote_part) {
        output << "; ";
      }
      output << "kind=" << joined_kinds(listing.kind_filters);
    }
  }
  output << "\n";
  std::vector<std::string> field_names;
  field_names.reserve(selected.size());
  for (const SymbolListingField field : selected) {
    field_names.emplace_back(symbol_listing_field_name(field));
  }
  output << "fields: " << joined(field_names, ", ") << "\n";
  output << "total: " << listing.total << "  matched: " << listing.entries.size() << "\n";

  std::vector<std::vector<std::string>> rows;
  rows.reserve(listing.entries.size());
  std::vector<std::size_t> widths(selected.size(), 0U);
  for (std::size_t column = 0U; column < selected.size(); ++column) {
    widths[column] = field_names[column].size();
  }
  for (const SymbolListingEntry& entry : listing.entries) {
    std::vector<std::string> row;
    row.reserve(selected.size());
    for (std::size_t column = 0U; column < selected.size(); ++column) {
      row.push_back(entry_field_value(entry, selected[column]));
      widths[column] = (std::max)(widths[column], row.back().size());
    }
    rows.push_back(std::move(row));
  }

  const auto write_row = [&output, &widths](const std::vector<std::string>& row) {
    for (std::size_t column = 0U; column < row.size(); ++column) {
      if (column != 0U) {
        output << "  ";
      }
      output << row[column];
      if (column + 1U < row.size()) {
        const std::size_t padding = widths[column] - row[column].size();
        for (std::size_t count = 0U; count < padding; ++count) {
          output.put(' ');
        }
      }
    }
    output.put('\n');
  };
  write_row(field_names);
  for (const auto& row : rows) {
    write_row(row);
  }
}

void write_symbol_listing_json(std::ostream& output, const SymbolListing& listing,
                               const std::vector<SymbolListingField>& fields) {
  const auto selected = effective_fields(fields);
  JsonEmitter json{output};
  json.raw("{\"schema\":\"noleax.symbols\",\"schema_version\":");
  json.unsigned_number(kSymbolsJsonSchemaVersion);
  json.raw(",\"module\":{\"path\":");
  json.string(listing.module_path);
  json.raw(",\"status\":");
  json.string(listing.status);
  json.raw(",\"image_size\":");
  json.unsigned_number(listing.image_size);
  json.raw(",\"image_base\":");
  json.string(hex_value(listing.image_base));
  json.raw(",\"timestamp\":");
  json.string(hex_value(listing.timestamp));
  json.raw(",\"checksum\":");
  json.string(hex_value(listing.checksum));
  json.raw("},\"filters\":{\"names\":[");
  for (std::size_t index = 0U; index < listing.name_filters.size(); ++index) {
    if (index != 0U) {
      json.raw(",");
    }
    json.string(listing.name_filters[index]);
  }
  json.raw("],\"match_case\":");
  json.boolean(listing.match_case);
  json.raw(",\"kinds\":[");
  for (std::size_t index = 0U; index < listing.kind_filters.size(); ++index) {
    if (index != 0U) {
      json.raw(",");
    }
    json.string(symbol_kind_name(listing.kind_filters[index]));
  }
  json.raw("]},\"fields\":[");
  for (std::size_t index = 0U; index < selected.size(); ++index) {
    if (index != 0U) {
      json.raw(",");
    }
    json.string(symbol_listing_field_name(selected[index]));
  }
  json.raw("],\"summary\":{\"total\":");
  json.unsigned_number(listing.total);
  json.raw(",\"matched\":");
  json.unsigned_number(listing.entries.size());
  json.raw("},\"symbols\":[");
  for (std::size_t index = 0U; index < listing.entries.size(); ++index) {
    if (index != 0U) {
      json.raw(",");
    }
    json.raw("{");
    for (std::size_t column = 0U; column < selected.size(); ++column) {
      write_entry_field_json(json, listing.entries[index], selected[column], column == 0U);
    }
    json.raw("}");
  }
  json.raw("]}\n");
}

void write_symbol_listing_csv(std::ostream& output, const SymbolListing& listing,
                              const std::vector<SymbolListingField>& fields) {
  const auto selected = effective_fields(fields);
  CsvEmitter csv{output};
  std::vector<std::string> header;
  header.reserve(selected.size());
  for (const SymbolListingField field : selected) {
    header.emplace_back(symbol_listing_field_name(field));
  }
  csv.row(header);
  for (const SymbolListingEntry& entry : listing.entries) {
    std::vector<std::string> row;
    row.reserve(selected.size());
    for (const SymbolListingField field : selected) {
      row.push_back(entry_field_value(entry, field));
    }
    csv.row(row);
  }
}

}  // namespace noleax::analyzer
