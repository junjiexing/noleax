#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"
#include "noleax/config/value_parser.hpp"

namespace {

class TemporaryDirectory {
 public:
  TemporaryDirectory() {
    static std::atomic<std::uint64_t> sequence{0};
    const auto suffix =
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "-" +
        std::to_string(sequence.fetch_add(1));
    path_ = std::filesystem::temp_directory_path() / ("noleax-custom-hook-test-" + suffix);
    if (!std::filesystem::create_directory(path_)) {
      throw std::runtime_error{"cannot create test directory"};
    }
  }

  TemporaryDirectory(const TemporaryDirectory&) = delete;
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

  ~TemporaryDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

void write_file(const std::filesystem::path& path, std::string_view contents = {}) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  if (!output) {
    throw std::runtime_error{"cannot create test file"};
  }
  output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

[[nodiscard]] noleax::config::Configuration run_configuration(const std::filesystem::path& target) {
  auto configuration = noleax::config::make_default_configuration();
  configuration.operation.value = noleax::config::Operation::kRun;
  configuration.target.path.value = target;
  return configuration;
}

[[nodiscard]] noleax::config::CustomHook export_hook() {
  noleax::config::CustomHook hook;
  hook.module = "myalloc.dll";
  hook.alloc.export_name = "my_malloc";
  hook.free.export_name = "my_free";
  return hook;
}

[[nodiscard]] std::string load_error(const TemporaryDirectory& temporary,
                                     std::string_view document) {
  const auto config_path = temporary.path() / "noleax.toml";
  write_file(config_path, document);
  try {
    static_cast<void>(noleax::config::load_toml_config(config_path));
  } catch (const noleax::config::ConfigError& error) {
    return error.what();
  }
  return {};
}

}  // namespace

TEST_CASE("TOML custom_hooks parse locators, argument mapping, and defaults",
          "[config][toml][custom-hook]") {
  using namespace std::chrono_literals;
  TemporaryDirectory temporary;
  const auto config_path = temporary.path() / "noleax.toml";
  write_file(config_path, R"toml(schema_version = 1

[[custom_hooks]]
module = "myalloc.dll"
alloc = "my_malloc"
realloc = "my_realloc"
free = "my_free"
size_arg = 1
ptr_arg = 2
forced = true
wait_module = "10s"

[[custom_hooks]]
module = "jealloc.dll"
alloc_pdb = "jealloc!je_malloc"
free_rva = "0x1a210"
result_arg = 0
kind = "calloc"
count_arg = 0
free_size_arg = 1
image_timestamp = 0x65a1b2c3
image_checksum = 0x1a2b
image_size = 198656
)toml");

  const auto overrides = noleax::config::load_toml_config(config_path);
  REQUIRE(overrides.custom_hooks.specified);
  REQUIRE(overrides.custom_hooks.value.size() == 2U);

  const auto& first = overrides.custom_hooks.value.at(0U);
  CHECK(first.module == "myalloc.dll");
  CHECK(first.alloc.export_name == "my_malloc");
  CHECK(first.realloc.export_name == "my_realloc");
  CHECK(first.free.export_name == "my_free");
  CHECK(first.size_arg == 1U);
  CHECK(first.ptr_arg == 2U);
  CHECK(first.forced);
  CHECK(first.wait_module == 10s);
  CHECK_FALSE(first.result_arg.has_value());
  CHECK(first.kind == noleax::config::CustomHookKind::kAlloc);
  CHECK_FALSE(first.image_identity.has_value());

  const auto& second = overrides.custom_hooks.value.at(1U);
  CHECK(second.module == "jealloc.dll");
  CHECK(second.alloc.pdb_symbol == "jealloc!je_malloc");
  CHECK(second.free.rva == 0x1a210U);
  CHECK(second.result_arg == 0U);
  CHECK(second.kind == noleax::config::CustomHookKind::kCalloc);
  CHECK(second.count_arg == 0U);
  CHECK(second.free_size_arg == 1U);
  REQUIRE(second.image_identity.has_value());
  CHECK(second.image_identity->timestamp == 0x65a1b2c3U);
  CHECK(second.image_identity->checksum == 0x1a2bU);
  CHECK(second.image_identity->image_size == 198656U);
}

TEST_CASE("TOML custom_hooks accept RVA as integer or string and reject malformed shapes",
          "[config][toml][custom-hook]") {
  TemporaryDirectory temporary;
  const auto config_path = temporary.path() / "noleax.toml";
  write_file(config_path, R"toml(schema_version = 1

[[custom_hooks]]
module = "myalloc.dll"
alloc_rva = 0x12340
free_rva = "0x1a210"
)toml");
  const auto overrides = noleax::config::load_toml_config(config_path);
  REQUIRE(overrides.custom_hooks.value.size() == 1U);
  CHECK(overrides.custom_hooks.value.at(0U).alloc.rva == 0x12340U);
  CHECK(overrides.custom_hooks.value.at(0U).free.rva == 0x1a210U);

  CHECK(load_error(temporary, "schema_version = 1\ncustom_hooks = 42\n")
            .find("expected an array of tables") != std::string::npos);
  CHECK(load_error(temporary, "schema_version = 1\n\n[[custom_hooks]]\nunknown_key = 1\n")
            .find("unknown key") != std::string::npos);
  CHECK(load_error(temporary, "schema_version = 1\n\n[[custom_hooks]]\nalloc_rva = \"0xzz\"\n")
            .find("RVA") != std::string::npos);
  CHECK(load_error(temporary, "schema_version = 1\n\n[[custom_hooks]]\nimage_timestamp = 1\n")
            .find("image_checksum") != std::string::npos);
}

TEST_CASE("custom hook validation enforces roles, locators, slots, and module uniqueness",
          "[config][custom-hook]") {
  TemporaryDirectory temporary;
  const auto target = temporary.path() / "target.exe";
  write_file(target);
  auto configuration = run_configuration(target);

  // alloc and free are required.
  configuration.custom_hooks.value.clear();
  noleax::config::CustomHook hook;
  hook.module = "myalloc.dll";
  configuration.custom_hooks.value = {hook};
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);

  // One locator per role.
  hook.alloc.export_name = "a";
  hook.alloc.rva = 0x1000U;
  hook.free.export_name = "f";
  configuration.custom_hooks.value = {hook};
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);

  // Valid baseline.
  hook = export_hook();
  configuration.custom_hooks.value = {hook};
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));

  // Argument slots are bounded.
  hook.size_arg = 8U;
  configuration.custom_hooks.value = {hook};
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);

  // calloc requires count_arg and vice versa.
  hook = export_hook();
  hook.kind = noleax::config::CustomHookKind::kCalloc;
  configuration.custom_hooks.value = {hook};
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
  hook.count_arg = 1U;
  configuration.custom_hooks.value = {hook};
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
  hook.kind = noleax::config::CustomHookKind::kAlloc;
  configuration.custom_hooks.value = {hook};
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);

  // Duplicate modules are rejected case-insensitively.
  configuration.custom_hooks.value = {export_hook(), export_hook()};
  configuration.custom_hooks.value.at(1U).module = "MYALLOC.dll";
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);

  // Too many hook points are rejected.
  configuration.custom_hooks.value.assign(noleax::config::kMaximumCustomHooks + 1U, export_hook());
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);

  // PDB locators are rejected when symbols are disabled.
  hook = export_hook();
  hook.alloc.export_name.reset();
  hook.alloc.pdb_symbol = "myalloc!internal_alloc";
  configuration.custom_hooks.value = {hook};
  configuration.symbols.mode.value = noleax::config::SymbolMode::kOff;
  CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                  noleax::config::ConfigError);
}

TEST_CASE("custom hooks are rejected for analyze and doctor operations", "[config][custom-hook]") {
  for (const auto operation :
       {noleax::config::Operation::kAnalyze, noleax::config::Operation::kDoctor}) {
    auto configuration = noleax::config::make_default_configuration();
    configuration.operation.value = operation;
    if (operation == noleax::config::Operation::kAnalyze) {
      configuration.analysis.inputs.value = {std::filesystem::current_path() / "x.nlx"};
    }
    configuration.custom_hooks.value = {export_hook()};
    CHECK_THROWS_AS(noleax::config::validate_configuration(configuration),
                    noleax::config::ConfigError);
  }

  // Symbols settings become available once custom hooks are declared.
  TemporaryDirectory temporary;
  const auto target = temporary.path() / "target.exe";
  write_file(target);
  auto configuration = run_configuration(target);
  configuration.custom_hooks.value = {export_hook()};
  configuration.symbols.paths.value = {std::filesystem::current_path()};
  CHECK_NOTHROW(noleax::config::validate_configuration(configuration));
}

TEST_CASE("effective TOML serializes and round-trips custom hooks", "[config][toml][custom-hook]") {
  using namespace std::chrono_literals;
  TemporaryDirectory temporary;
  auto configuration = noleax::config::make_default_configuration();
  configuration.operation.value = noleax::config::Operation::kDoctor;

  noleax::config::CustomHook hook;
  hook.module = "myalloc.dll";
  hook.alloc.pdb_symbol = "myalloc!internal_alloc";
  hook.free.rva = 0x1a210U;
  hook.size_arg = 1U;
  hook.result_arg = 0U;
  hook.forced = true;
  hook.wait_module = 10s;
  hook.image_identity = noleax::config::CustomHookImageIdentity{0x65a1b2c3U, 0x1a2bU, 198656U};
  configuration.custom_hooks.value = {hook};
  configuration.custom_hooks.source = noleax::config::ValueSource::kCommandLine;

  const auto serialized = noleax::config::serialize_effective_config(configuration);
  CHECK(serialized.find("[[custom_hooks]] # source: cli") != std::string::npos);
  CHECK(serialized.find("module = \"myalloc.dll\"") != std::string::npos);
  CHECK(serialized.find("alloc_pdb = \"myalloc!internal_alloc\"") != std::string::npos);
  CHECK(serialized.find("free_rva = \"0x1a210\"") != std::string::npos);
  CHECK(serialized.find("wait_module = \"10s\"") != std::string::npos);

  const auto path = temporary.path() / "effective.toml";
  write_file(path, serialized);
  const auto overrides = noleax::config::load_toml_config(path);
  REQUIRE(overrides.custom_hooks.specified);
  REQUIRE(overrides.custom_hooks.value.size() == 1U);
  CHECK(overrides.custom_hooks.value.at(0U) == hook);
}

TEST_CASE("custom hook label prefers the alloc symbol and falls back to module+RVA",
          "[config][custom-hook]") {
  auto hook = export_hook();
  CHECK(noleax::config::custom_hook_label(hook) == "my_malloc");

  hook.alloc.export_name.reset();
  hook.alloc.pdb_symbol = "myalloc!internal_alloc";
  CHECK(noleax::config::custom_hook_label(hook) == "internal_alloc");

  hook.alloc.pdb_symbol.reset();
  hook.alloc.rva = 0x12340U;
  CHECK(noleax::config::custom_hook_label(hook) == "myalloc.dll+0x12340");
}

TEST_CASE("parse_rva accepts hexadecimal and decimal and rejects invalid input",
          "[config][custom-hook]") {
  CHECK(noleax::config::parse_rva("0x12340") == 0x12340U);
  CHECK(noleax::config::parse_rva("0X1A") == 0x1AU);
  CHECK(noleax::config::parse_rva("4660") == 0x1234U);
  CHECK_THROWS_AS(noleax::config::parse_rva("0"), noleax::config::ValueParseError);
  CHECK_THROWS_AS(noleax::config::parse_rva("0x"), noleax::config::ValueParseError);
  CHECK_THROWS_AS(noleax::config::parse_rva("0xzz"), noleax::config::ValueParseError);
  CHECK_THROWS_AS(noleax::config::parse_rva("0x100000000"), noleax::config::ValueParseError);
  CHECK_THROWS_AS(noleax::config::parse_rva(""), noleax::config::ValueParseError);
}
