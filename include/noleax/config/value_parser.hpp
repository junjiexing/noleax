#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace noleax::config {

class ValueParseError final : public std::invalid_argument {
 public:
  ValueParseError(std::string_view value_kind, std::string_view input, std::string_view detail);
};

[[nodiscard]] std::uint64_t parse_byte_size(std::string_view input);
[[nodiscard]] std::chrono::nanoseconds parse_duration(std::string_view input);
// Parses a nonzero 32-bit RVA: hexadecimal with a 0x prefix or decimal.
[[nodiscard]] std::uint32_t parse_rva(std::string_view input);
[[nodiscard]] std::uint64_t parse_unsigned_integer(std::string_view input, std::uint64_t maximum,
                                                   std::string_view value_kind);
[[nodiscard]] std::int64_t parse_signed_integer(std::string_view input, std::int64_t minimum,
                                                std::int64_t maximum, std::string_view value_kind);
[[nodiscard]] bool parse_boolean(std::string_view input);

template <typename Enum>
struct NamedEnumValue {
  std::string_view name;
  Enum value;
};

template <typename Enum, std::size_t Size>
[[nodiscard]] Enum parse_enum(std::string_view input,
                              const std::array<NamedEnumValue<Enum>, Size>& values,
                              std::string_view value_kind) {
  for (const auto& candidate : values) {
    if (candidate.name == input) {
      return candidate.value;
    }
  }

  std::string detail{"expected one of: "};
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0U) {
      detail.append(", ");
    }
    detail.append(values[index].name);
  }
  throw ValueParseError{value_kind, input, detail};
}

template <typename Enum, std::size_t Size>
[[nodiscard]] std::string_view enum_name(Enum value,
                                         const std::array<NamedEnumValue<Enum>, Size>& values) {
  for (const auto& candidate : values) {
    if (candidate.value == value) {
      return candidate.name;
    }
  }
  throw std::logic_error{"enum value has no serialized name"};
}

}  // namespace noleax::config
