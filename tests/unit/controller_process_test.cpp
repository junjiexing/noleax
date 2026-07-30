#include <catch2/catch_test_macros.hpp>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: shellapi.h requires Windows base declarations.
#include <windows.h>
#include <shellapi.h>
// clang-format on

#include <array>
#include <string>
#include <string_view>

#include "noleax/controller/windows/process.hpp"

namespace {

void check_command_line_round_trip(std::wstring_view argument) {
  const std::wstring command_line =
      L"dummy.exe " + noleax::controller::windows::quote_windows_argument(argument);
  int argument_count = 0;
  wchar_t** arguments = CommandLineToArgvW(command_line.c_str(), &argument_count);
  REQUIRE(arguments != nullptr);
  CHECK(argument_count == 2);
  if (argument_count == 2) {
    CHECK(std::wstring_view{arguments[1]} == argument);
  }
  static_cast<void>(LocalFree(arguments));
}

}  // namespace

TEST_CASE("Windows command line quoting follows CommandLineToArgvW rules",
          "[controller][windows][process]") {
  using noleax::controller::windows::quote_windows_argument;
  CHECK(quote_windows_argument(L"plain") == L"plain");
  CHECK(quote_windows_argument(L"") == L"\"\"");
  CHECK(quote_windows_argument(L"two words") == L"\"two words\"");
  for (const std::wstring_view argument :
       std::array{std::wstring_view{}, std::wstring_view{L"plain"}, std::wstring_view{L"two words"},
                  std::wstring_view{L"a\\\"b"}, std::wstring_view{L"trailing \\"},
                  std::wstring_view{L"\\\\\" quoted"}}) {
    check_command_line_round_trip(argument);
  }
}

TEST_CASE("Windows UTF conversions reject malformed input", "[controller][windows][process]") {
  using noleax::controller::windows::utf8_to_wide;
  using noleax::controller::windows::wide_to_utf8;
  const std::string utf8 = "noleax-\xe6\xb5\x8b\xe8\xaf\x95";
  CHECK(wide_to_utf8(utf8_to_wide(utf8)) == utf8);
  CHECK_THROWS_AS(utf8_to_wide(std::string{"\xff", 1U}), noleax::controller::windows::ProcessError);
}
