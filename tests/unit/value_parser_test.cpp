#include "noleax/config/value_parser.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string_view>

namespace {

using noleax::config::ValueParseError;

enum class TestMode : std::uint8_t {
  kFirst,
  kSecond,
};

constexpr std::array kTestModes{
    noleax::config::NamedEnumValue{std::string_view{"first"}, TestMode::kFirst},
    noleax::config::NamedEnumValue{std::string_view{"second"}, TestMode::kSecond},
};

}  // namespace

TEST_CASE("byte sizes use binary units and check overflow", "[config][value-parser]") {
  CHECK(noleax::config::parse_byte_size("0B") == 0U);
  CHECK(noleax::config::parse_byte_size("1KiB") == 1024U);
  CHECK(noleax::config::parse_byte_size("2MiB") == 2U * 1024U * 1024U);
  CHECK(noleax::config::parse_byte_size("3GiB") == 3ULL * 1024U * 1024U * 1024U);
  CHECK(noleax::config::parse_byte_size("18446744073709551615B") ==
        std::numeric_limits<std::uint64_t>::max());

  constexpr std::array invalidSizes{"",
                                    "1",
                                    "-1B",
                                    "1KB",
                                    "1MiB ",
                                    " 1MiB",
                                    "1.5MiB",
                                    "1mib",
                                    "+1B",
                                    "17179869184GiB",
                                    "18446744073709551616B"};
  for (const std::string_view value : invalidSizes) {
    CAPTURE(value);
    CHECK_THROWS_AS(noleax::config::parse_byte_size(value), ValueParseError);
  }
}

TEST_CASE("durations convert to nanoseconds and check representation limits",
          "[config][value-parser]") {
  using namespace std::chrono_literals;

  CHECK(noleax::config::parse_duration("1ns") == 1ns);
  CHECK(noleax::config::parse_duration("2us") == 2us);
  CHECK(noleax::config::parse_duration("3ms") == 3ms);
  CHECK(noleax::config::parse_duration("4s") == 4s);
  CHECK(noleax::config::parse_duration("5m") == 5min);
  CHECK(noleax::config::parse_duration("6h") == 6h);
  CHECK(noleax::config::parse_duration("9223372036854775807ns").count() ==
        std::numeric_limits<std::chrono::nanoseconds::rep>::max());

  constexpr std::array invalidDurations{
      "", "1", "-1s", "1MS", "1.0s", "1 s", "1d", "+1s", "9223372036854775808ns", "2562048h"};
  for (const std::string_view value : invalidDurations) {
    CAPTURE(value);
    CHECK_THROWS_AS(noleax::config::parse_duration(value), ValueParseError);
  }
}

TEST_CASE("unsigned decimal parser rejects partial and overflowing values",
          "[config][value-parser]") {
  CHECK(noleax::config::parse_unsigned_integer("0", 10U, "test integer") == 0U);
  CHECK(noleax::config::parse_unsigned_integer("10", 10U, "test integer") == 10U);

  constexpr std::array invalidIntegers{"", "11", "-1", "+1", "1.0", "1x", " 1", "1 "};
  for (const std::string_view value : invalidIntegers) {
    CAPTURE(value);
    CHECK_THROWS_AS(noleax::config::parse_unsigned_integer(value, 10U, "test integer"),
                    ValueParseError);
  }
}

TEST_CASE("booleans and enum names use exact lowercase spelling", "[config][value-parser]") {
  CHECK(noleax::config::parse_boolean("true"));
  CHECK_FALSE(noleax::config::parse_boolean("false"));
  CHECK_THROWS_AS(noleax::config::parse_boolean("TRUE"), ValueParseError);
  CHECK_THROWS_AS(noleax::config::parse_boolean("1"), ValueParseError);

  CHECK(noleax::config::parse_enum("first", kTestModes, "test mode") == TestMode::kFirst);
  CHECK(noleax::config::parse_enum("second", kTestModes, "test mode") == TestMode::kSecond);
  CHECK(noleax::config::enum_name(TestMode::kSecond, kTestModes) == "second");
  CHECK_THROWS_AS(noleax::config::parse_enum("First", kTestModes, "test mode"), ValueParseError);
}
