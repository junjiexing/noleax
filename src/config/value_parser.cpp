#include "noleax/config/value_parser.hpp"

#include <charconv>
#include <limits>
#include <string>
#include <system_error>

namespace noleax::config {
namespace {

[[nodiscard]] std::string make_error_message(std::string_view value_kind, std::string_view input,
                                             std::string_view detail) {
  std::string message{"invalid "};
  message.append(value_kind);
  message.append(" '");
  message.append(input);
  message.append("': ");
  message.append(detail);
  return message;
}

struct NumberAndUnit {
  std::string_view number;
  std::string_view unit;
};

[[nodiscard]] NumberAndUnit split_number_and_unit(std::string_view input,
                                                  std::string_view value_kind) {
  std::size_t unit_offset = 0;
  while (unit_offset < input.size() && input[unit_offset] >= '0' && input[unit_offset] <= '9') {
    ++unit_offset;
  }

  if (unit_offset == 0U || unit_offset == input.size()) {
    throw ValueParseError{value_kind, input, "expected an unsigned integer followed by a unit"};
  }
  return {input.substr(0, unit_offset), input.substr(unit_offset)};
}

[[nodiscard]] std::uint64_t checked_multiply(std::uint64_t value, std::uint64_t multiplier,
                                             std::uint64_t maximum, std::string_view input,
                                             std::string_view value_kind) {
  if (multiplier != 0U && value > maximum / multiplier) {
    throw ValueParseError{value_kind, input, "value is out of range"};
  }
  return value * multiplier;
}

}  // namespace

ValueParseError::ValueParseError(std::string_view value_kind, std::string_view input,
                                 std::string_view detail)
    : std::invalid_argument{make_error_message(value_kind, input, detail)} {}

std::uint64_t parse_unsigned_integer(std::string_view input, std::uint64_t maximum,
                                     std::string_view value_kind) {
  if (input.empty()) {
    throw ValueParseError{value_kind, input, "expected an unsigned decimal integer"};
  }

  std::uint64_t value = 0;
  const char* const begin = input.data();
  const char* const end = begin + input.size();
  const auto result = std::from_chars(begin, end, value, 10);
  if (result.ec == std::errc::result_out_of_range || value > maximum) {
    throw ValueParseError{value_kind, input, "value is out of range"};
  }
  if (result.ec != std::errc{} || result.ptr != end) {
    throw ValueParseError{value_kind, input, "expected an unsigned decimal integer"};
  }
  return value;
}

std::uint64_t parse_byte_size(std::string_view input) {
  const auto parts = split_number_and_unit(input, "size");
  const auto value =
      parse_unsigned_integer(parts.number, std::numeric_limits<std::uint64_t>::max(), "size");

  std::uint64_t multiplier = 0;
  if (parts.unit == "B") {
    multiplier = 1U;
  } else if (parts.unit == "KiB") {
    multiplier = 1024U;
  } else if (parts.unit == "MiB") {
    multiplier = 1024U * 1024U;
  } else if (parts.unit == "GiB") {
    multiplier = 1024U * 1024U * 1024U;
  } else {
    throw ValueParseError{"size", input, "supported units are B, KiB, MiB, and GiB"};
  }

  return checked_multiply(value, multiplier, std::numeric_limits<std::uint64_t>::max(), input,
                          "size");
}

std::chrono::nanoseconds parse_duration(std::string_view input) {
  const auto parts = split_number_and_unit(input, "duration");
  const auto value =
      parse_unsigned_integer(parts.number, std::numeric_limits<std::uint64_t>::max(), "duration");

  std::uint64_t multiplier = 0;
  if (parts.unit == "ns") {
    multiplier = 1U;
  } else if (parts.unit == "us") {
    multiplier = 1000U;
  } else if (parts.unit == "ms") {
    multiplier = 1000U * 1000U;
  } else if (parts.unit == "s") {
    multiplier = 1000U * 1000U * 1000U;
  } else if (parts.unit == "m") {
    multiplier = 60ULL * 1000U * 1000U * 1000U;
  } else if (parts.unit == "h") {
    multiplier = 60ULL * 60U * 1000U * 1000U * 1000U;
  } else {
    throw ValueParseError{"duration", input, "supported units are ns, us, ms, s, m, and h"};
  }

  constexpr auto kMaximumNanoseconds =
      static_cast<std::uint64_t>(std::numeric_limits<std::chrono::nanoseconds::rep>::max());
  const auto nanoseconds =
      checked_multiply(value, multiplier, kMaximumNanoseconds, input, "duration");
  return std::chrono::nanoseconds{static_cast<std::chrono::nanoseconds::rep>(nanoseconds)};
}

bool parse_boolean(std::string_view input) {
  if (input == "true") {
    return true;
  }
  if (input == "false") {
    return false;
  }
  throw ValueParseError{"boolean", input, "expected true or false"};
}

}  // namespace noleax::config
