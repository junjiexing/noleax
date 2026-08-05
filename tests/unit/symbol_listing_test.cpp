#include "noleax/analyzer/symbol_listing.hpp"

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace {

[[nodiscard]] noleax::analyzer::SymbolListing sample_listing() {
  noleax::analyzer::SymbolListing listing;
  listing.module_path = "C:/modules/foo.dll";
  listing.status = "symbols_loaded";
  listing.image_size = 123456U;
  listing.image_base = 0x180000000ULL;
  listing.timestamp = 0x5f8a1b2cU;
  listing.checksum = 0x1f2a3U;
  listing.name_filters = {"*alloc*"};
  listing.match_case = false;
  listing.kind_filters = {noleax::analyzer::SymbolKind::kFunction};
  listing.total = 1234U;

  noleax::analyzer::SymbolListingEntry function;
  function.name = "?alloc@foo@@YAPEAX_K@Z";
  function.undecorated_name = "foo::alloc";
  function.rva = 0x1a210U;
  function.va = 0x18001a210ULL;
  function.size = 128U;
  function.kind = noleax::analyzer::SymbolKind::kFunction;

  noleax::analyzer::SymbolListingEntry data;
  data.name = "g_counter";
  data.undecorated_name = "foo::g_counter";
  data.rva = 0x4d000U;
  data.va = 0x18004d000ULL;
  data.size = 4U;
  data.kind = noleax::analyzer::SymbolKind::kData;

  listing.entries = {function, data};
  return listing;
}

[[nodiscard]] noleax::analyzer::SymbolListing empty_listing() {
  noleax::analyzer::SymbolListing listing;
  listing.module_path = "C:/modules/empty.dll";
  listing.status = "no_symbols";
  listing.image_size = 4096U;
  listing.image_base = 0x400000ULL;
  return listing;
}

}  // namespace

TEST_CASE("wildcard match supports star question and case folding", "[analyzer][symbols]") {
  using noleax::analyzer::detail::wildcard_match;

  CHECK(wildcard_match("my_free*", "my_free", false));
  CHECK(wildcard_match("my_free*", "my_free_size", false));
  CHECK_FALSE(wildcard_match("my_free*", "my_malloc", false));
  CHECK(wildcard_match("MY_FREE", "my_free", false));
  CHECK_FALSE(wildcard_match("MY_FREE", "my_free", true));
  CHECK(wildcard_match("My_Free", "my_FREE", true) == false);
  CHECK(wildcard_match("a?c", "abc", true));
  CHECK_FALSE(wildcard_match("a?c", "ac", true));
  CHECK(wildcard_match("", "", false));
  CHECK_FALSE(wildcard_match("", "a", false));
  CHECK_FALSE(wildcard_match("a", "", false));
  CHECK(wildcard_match("*", "anything", true));
  CHECK(wildcard_match("**a**", "xxaxx", true));
  CHECK(wildcard_match("a*", "a", true));
  CHECK(wildcard_match("*a", "ba", true));
  CHECK(wildcard_match("foo::*", "foo::alloc", true));
  CHECK(wildcard_match("?lloc", "alloc", true));
  CHECK_FALSE(wildcard_match("alloc", "alloca", true));
  CHECK(wildcard_match("*~", "wave~", true));
}

TEST_CASE("symbol listing field parsing preserves order and rejects bad input",
          "[analyzer][symbols]") {
  using noleax::analyzer::parse_symbol_listing_fields;
  using noleax::analyzer::SymbolListingField;

  CHECK(parse_symbol_listing_fields("name,rva,kind") == std::vector{SymbolListingField::kName,
                                                                    SymbolListingField::kRva,
                                                                    SymbolListingField::kKind});
  CHECK(parse_symbol_listing_fields("kind,name") ==
        std::vector{SymbolListingField::kKind, SymbolListingField::kName});
  CHECK(parse_symbol_listing_fields("size") == std::vector{SymbolListingField::kSize});

  CHECK_THROWS_AS(parse_symbol_listing_fields(""), noleax::analyzer::SymbolListingError);
  CHECK_THROWS_AS(parse_symbol_listing_fields("bogus"), noleax::analyzer::SymbolListingError);
  CHECK_THROWS_AS(parse_symbol_listing_fields("name,name"), noleax::analyzer::SymbolListingError);
  CHECK_THROWS_AS(parse_symbol_listing_fields("name,"), noleax::analyzer::SymbolListingError);
  CHECK_THROWS_AS(parse_symbol_listing_fields(",name"), noleax::analyzer::SymbolListingError);
  CHECK_THROWS_AS(parse_symbol_listing_fields("name,,rva"), noleax::analyzer::SymbolListingError);
}

TEST_CASE("symbol kind and field names are stable", "[analyzer][symbols]") {
  using noleax::analyzer::SymbolKind;
  using noleax::analyzer::SymbolListingField;

  CHECK(noleax::analyzer::symbol_kind_name(SymbolKind::kFunction) == "function");
  CHECK(noleax::analyzer::symbol_kind_name(SymbolKind::kData) == "data");
  CHECK(noleax::analyzer::symbol_kind_name(SymbolKind::kPublic) == "public");
  CHECK(noleax::analyzer::symbol_kind_name(SymbolKind::kExport) == "export");
  CHECK(noleax::analyzer::symbol_kind_name(SymbolKind::kOther) == "other");

  CHECK(noleax::analyzer::symbol_listing_field_name(SymbolListingField::kName) == "name");
  CHECK(noleax::analyzer::symbol_listing_field_name(SymbolListingField::kUndecoratedName) ==
        "undecorated_name");
  CHECK(noleax::analyzer::symbol_listing_field_name(SymbolListingField::kRva) == "rva");
  CHECK(noleax::analyzer::symbol_listing_field_name(SymbolListingField::kVa) == "va");
  CHECK(noleax::analyzer::symbol_listing_field_name(SymbolListingField::kSize) == "size");
  CHECK(noleax::analyzer::symbol_listing_field_name(SymbolListingField::kKind) == "kind");
}

TEST_CASE("symbol kind maps DbgHelp tags and the exports-only override", "[analyzer][symbols]") {
  using noleax::analyzer::symbol_kind_from_tag;
  using noleax::analyzer::SymbolKind;

  // Raw SymTagEnum values: SymTagFunction = 5, SymTagData = 7, SymTagPublicSymbol = 10.
  CHECK(symbol_kind_from_tag(5U, false) == SymbolKind::kFunction);
  CHECK(symbol_kind_from_tag(7U, false) == SymbolKind::kData);
  CHECK(symbol_kind_from_tag(10U, false) == SymbolKind::kPublic);
  CHECK(symbol_kind_from_tag(0U, false) == SymbolKind::kOther);
  CHECK(symbol_kind_from_tag(42U, false) == SymbolKind::kOther);
  CHECK(symbol_kind_from_tag(5U, true) == SymbolKind::kExport);
  CHECK(symbol_kind_from_tag(7U, true) == SymbolKind::kExport);
  CHECK(symbol_kind_from_tag(10U, true) == SymbolKind::kExport);
}

TEST_CASE("console symbol listing golden output", "[analyzer][symbols]") {
  std::ostringstream output;
  noleax::analyzer::write_symbol_listing_console(output, sample_listing(), {});
  CHECK(output.str() == R"(noleax symbols
module: C:/modules/foo.dll (image-size=123456 base=0x180000000)
symbols: symbols_loaded
filters: name=*alloc* (ignore-case); kind=function
fields: name, undecorated_name, rva, va, size, kind
total: 1234  matched: 2
name                    undecorated_name  rva      va           size  kind
?alloc@foo@@YAPEAX_K@Z  foo::alloc        0x1a210  0x18001a210  128   function
g_counter               foo::g_counter    0x4d000  0x18004d000  4     data
)");
}

TEST_CASE("console symbol listing honors the field selection", "[analyzer][symbols]") {
  std::ostringstream output;
  noleax::analyzer::write_symbol_listing_console(
      output, sample_listing(),
      {noleax::analyzer::SymbolListingField::kName, noleax::analyzer::SymbolListingField::kKind});
  CHECK(output.str() == R"(noleax symbols
module: C:/modules/foo.dll (image-size=123456 base=0x180000000)
symbols: symbols_loaded
filters: name=*alloc* (ignore-case); kind=function
fields: name, kind
total: 1234  matched: 2
name                    kind
?alloc@foo@@YAPEAX_K@Z  function
g_counter               data
)");
}

TEST_CASE("console symbol listing golden output for an empty match set", "[analyzer][symbols]") {
  std::ostringstream output;
  noleax::analyzer::write_symbol_listing_console(output, empty_listing(), {});
  CHECK(output.str() == R"(noleax symbols
module: C:/modules/empty.dll (image-size=4096 base=0x400000)
symbols: no_symbols
filters: none
fields: name, undecorated_name, rva, va, size, kind
total: 0  matched: 0
name  undecorated_name  rva  va  size  kind
)");
}

TEST_CASE("JSON symbol listing golden output", "[analyzer][symbols]") {
  std::ostringstream output;
  noleax::analyzer::write_symbol_listing_json(output, sample_listing(), {});
  CHECK(
      output.str() ==
      R"({"schema":"noleax.symbols","schema_version":1,"module":{"path":"C:/modules/foo.dll","status":"symbols_loaded","image_size":123456,"image_base":"0x180000000","timestamp":"0x5f8a1b2c","checksum":"0x1f2a3"},"filters":{"names":["*alloc*"],"match_case":false,"kinds":["function"]},"fields":["name","undecorated_name","rva","va","size","kind"],"summary":{"total":1234,"matched":2},"symbols":[{"name":"?alloc@foo@@YAPEAX_K@Z","undecorated_name":"foo::alloc","rva":"0x1a210","va":"0x18001a210","size":128,"kind":"function"},{"name":"g_counter","undecorated_name":"foo::g_counter","rva":"0x4d000","va":"0x18004d000","size":4,"kind":"data"}]}
)");
}

TEST_CASE("JSON symbol listing honors the field selection", "[analyzer][symbols]") {
  std::ostringstream output;
  noleax::analyzer::write_symbol_listing_json(
      output, sample_listing(),
      {noleax::analyzer::SymbolListingField::kName, noleax::analyzer::SymbolListingField::kRva});
  CHECK(
      output.str() ==
      R"({"schema":"noleax.symbols","schema_version":1,"module":{"path":"C:/modules/foo.dll","status":"symbols_loaded","image_size":123456,"image_base":"0x180000000","timestamp":"0x5f8a1b2c","checksum":"0x1f2a3"},"filters":{"names":["*alloc*"],"match_case":false,"kinds":["function"]},"fields":["name","rva"],"summary":{"total":1234,"matched":2},"symbols":[{"name":"?alloc@foo@@YAPEAX_K@Z","rva":"0x1a210"},{"name":"g_counter","rva":"0x4d000"}]}
)");
}

TEST_CASE("JSON symbol listing escapes strings and rejects invalid UTF-8", "[analyzer][symbols]") {
  auto listing = empty_listing();
  noleax::analyzer::SymbolListingEntry escaped;
  escaped.name = "quo\"te\\back\tslash";
  escaped.undecorated_name = "quo\"te\\back\tslash";
  escaped.kind = noleax::analyzer::SymbolKind::kOther;
  listing.entries = {escaped};
  listing.total = 1U;

  std::ostringstream output;
  noleax::analyzer::write_symbol_listing_json(output, listing,
                                              {noleax::analyzer::SymbolListingField::kName});
  // Note: the raw string is bound outside CHECK because the MSVC preprocessor mislexes raw
  // strings containing quoted text and escaped quotes when stringizing macro arguments.
  const std::string expected_name = R"json("name":"quo\"te\\back\tslash")json";
  CHECK(output.str().find(expected_name) != std::string::npos);

  auto invalid = empty_listing();
  noleax::analyzer::SymbolListingEntry bad;
  bad.name = "bad\xff";
  invalid.entries = {bad};
  invalid.total = 1U;
  CHECK_THROWS_AS(noleax::analyzer::write_symbol_listing_json(
                      output, invalid, {noleax::analyzer::SymbolListingField::kName}),
                  noleax::analyzer::SymbolListingError);
}

TEST_CASE("CSV symbol listing golden output", "[analyzer][symbols]") {
  std::ostringstream output;
  noleax::analyzer::write_symbol_listing_csv(output, sample_listing(), {});
  CHECK(output.str() ==
        "name,undecorated_name,rva,va,size,kind\r\n"
        "?alloc@foo@@YAPEAX_K@Z,foo::alloc,0x1a210,0x18001a210,128,function\r\n"
        "g_counter,foo::g_counter,0x4d000,0x18004d000,4,data\r\n");
}

TEST_CASE("CSV symbol listing honors the field selection and quotes fields",
          "[analyzer][symbols]") {
  auto listing = sample_listing();
  noleax::analyzer::SymbolListingEntry tricky;
  tricky.name = "quo\"te,comma";
  tricky.rva = 0x10U;
  tricky.kind = noleax::analyzer::SymbolKind::kPublic;
  listing.entries.push_back(tricky);

  std::ostringstream output;
  noleax::analyzer::write_symbol_listing_csv(
      output, listing,
      {noleax::analyzer::SymbolListingField::kName, noleax::analyzer::SymbolListingField::kRva});
  CHECK(output.str() ==
        "name,rva\r\n"
        "?alloc@foo@@YAPEAX_K@Z,0x1a210\r\n"
        "g_counter,0x4d000\r\n"
        "\"quo\"\"te,comma\",0x10\r\n");
}

TEST_CASE("CSV symbol listing rejects invalid UTF-8", "[analyzer][symbols]") {
  auto listing = empty_listing();
  noleax::analyzer::SymbolListingEntry bad;
  bad.name = "bad\x80";
  listing.entries = {bad};
  listing.total = 1U;

  std::ostringstream output;
  CHECK_THROWS_AS(noleax::analyzer::write_symbol_listing_csv(output, listing, {}),
                  noleax::analyzer::SymbolListingError);
}
