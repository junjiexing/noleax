#include "noleax/analyzer/symbolizer.hpp"

#include <array>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "noleax/analyzer/presentation.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace {

#ifdef _WIN32

class LoadedImage {
 public:
  explicit LoadedImage(const std::filesystem::path& path) : module_{LoadLibraryW(path.c_str())} {
    if (module_ == nullptr) {
      throw std::runtime_error{"cannot load symbolizer test image"};
    }
    const auto* base = reinterpret_cast<const std::byte*>(module_);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
      throw std::runtime_error{"symbolizer test image has an invalid DOS header"};
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.SizeOfImage == 0U) {
      throw std::runtime_error{"symbolizer test image has an invalid NT header"};
    }
    base_ = reinterpret_cast<std::uintptr_t>(module_);
    size_ = nt->OptionalHeader.SizeOfImage;
  }

  ~LoadedImage() {
    if (module_ != nullptr) {
      FreeLibrary(module_);
    }
  }

  LoadedImage(const LoadedImage&) = delete;
  LoadedImage& operator=(const LoadedImage&) = delete;

  [[nodiscard]] std::uint32_t size() const noexcept { return size_; }

  [[nodiscard]] std::uint64_t exported_offset(const char* name) const {
    const FARPROC address = GetProcAddress(module_, name);
    if (address == nullptr) {
      throw std::runtime_error{"symbolizer test export is unavailable"};
    }
    return reinterpret_cast<std::uintptr_t>(address) - base_;
  }

 private:
  HMODULE module_{nullptr};
  std::uintptr_t base_{0U};
  std::uint32_t size_{0U};
};

[[nodiscard]] std::filesystem::path fixture_path() {
  return std::filesystem::path{NOLEAX_SYMBOL_FIXTURE_PATH};
}

[[nodiscard]] std::filesystem::path system_module_path() {
  std::array<wchar_t, MAX_PATH> buffer{};
  const UINT length = GetSystemDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
  if (length == 0U || length >= buffer.size()) {
    throw std::runtime_error{"cannot locate the Windows system directory"};
  }
  return std::filesystem::path{std::wstring_view{buffer.data(), length}} / L"kernel32.dll";
}

[[nodiscard]] noleax::analyzer::SymbolModule fixture_module(std::uint64_t module_id,
                                                            std::uint64_t trace_base,
                                                            std::uint32_t image_size) {
  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{module_id};
  module.base_address = trace_base;
  module.image_size = image_size;
  module.image_path = fixture_path();
  return module;
}

class EnvironmentVariableGuard {
 public:
  explicit EnvironmentVariableGuard(const wchar_t* name) : name_{name} {
    const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required != 0U) {
      std::wstring value(required, L'\0');
      const DWORD length = GetEnvironmentVariableW(name, value.data(), required);
      value.resize(length);
      saved_ = std::move(value);
    }
  }

  ~EnvironmentVariableGuard() {
    SetEnvironmentVariableW(name_.c_str(), saved_.has_value() ? saved_->c_str() : nullptr);
  }

  EnvironmentVariableGuard(const EnvironmentVariableGuard&) = delete;
  EnvironmentVariableGuard& operator=(const EnvironmentVariableGuard&) = delete;

 private:
  std::wstring name_;
  std::optional<std::wstring> saved_;
};

#endif

}  // namespace

TEST_CASE("symbol module status names are stable", "[analyzer][symbolizer]") {
  using Status = noleax::analyzer::SymbolModuleStatus;
  constexpr std::array cases{
      std::pair{Status::kSymbolsLoaded, std::string_view{"symbols_loaded"}},
      std::pair{Status::kExportsOnly, std::string_view{"exports_only"}},
      std::pair{Status::kNoSymbols, std::string_view{"no_symbols"}},
      std::pair{Status::kImageNotFound, std::string_view{"image_not_found"}},
      std::pair{Status::kImageIdentityMismatch, std::string_view{"image_identity_mismatch"}},
      std::pair{Status::kPdbNotFound, std::string_view{"pdb_not_found"}},
      std::pair{Status::kPdbIdentityMismatch, std::string_view{"pdb_identity_mismatch"}},
      std::pair{Status::kLoadFailed, std::string_view{"load_failed"}},
      std::pair{Status::kUnsupportedPlatform, std::string_view{"unsupported_platform"}},
  };
  for (const auto& [status, name] : cases) {
    CHECK(noleax::analyzer::symbol_module_status_name(status) == name);
  }
}

#ifdef _WIN32

TEST_CASE("offline symbolizer resolves a matching PDB and serializes concurrent DbgHelp calls",
          "[analyzer][symbolizer]") {
  constexpr std::uint64_t trace_base = 0x00007ff600000000ULL;
  const LoadedImage image{fixture_path()};
  const std::uint64_t function_offset = image.exported_offset("noleax_symbolizer_fixture_target");

  noleax::analyzer::SymbolizerOptions options;
  options.search_paths.push_back(fixture_path().parent_path());

  noleax::analyzer::SymbolModuleResult discovered;
  {
    noleax::analyzer::OfflineSymbolizer symbolizer{options};
    const auto module = fixture_module(1U, trace_base, image.size());
    discovered = symbolizer.register_module(module);
    CAPTURE(noleax::analyzer::symbol_module_status_name(discovered.status));
    CAPTURE(discovered.system_error);
    REQUIRE(discovered.status == noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded);
    REQUIRE(discovered.image_identity.has_value());
    REQUIRE(discovered.pdb_identity.has_value());
    CHECK(symbolizer.module_result(module.module_id) == discovered);

    const auto frame = symbolizer.resolve_frame(module.module_id, trace_base + function_offset);
    CHECK(frame.absolute_address == trace_base + function_offset);
    CHECK(frame.module_name == fixture_path().filename().string());
    CHECK(frame.module_offset == function_offset);
    REQUIRE(frame.symbol_name.has_value());
    CHECK(frame.symbol_name->find("noleax_symbolizer_fixture_target") != std::string::npos);

    std::atomic<bool> concurrent_success{true};
    std::vector<std::thread> workers;
    workers.reserve(4U);
    for (std::size_t index = 0U; index < 4U; ++index) {
      workers.emplace_back([&] {
        try {
          for (std::size_t iteration = 0U; iteration < 25U; ++iteration) {
            const auto resolved =
                symbolizer.resolve_frame(module.module_id, trace_base + function_offset);
            if (!resolved.symbol_name.has_value()) {
              concurrent_success = false;
            }
          }
        } catch (...) {
          concurrent_success = false;
        }
      });
    }
    for (auto& worker : workers) {
      worker.join();
    }
    CHECK(concurrent_success);
  }

  SECTION("recorded identities match") {
    auto module = fixture_module(2U, trace_base, image.size());
    module.expected_image_identity = discovered.image_identity;
    module.expected_pdb_identity = discovered.pdb_identity;
    noleax::analyzer::OfflineSymbolizer symbolizer{options};
    const auto result = symbolizer.register_module(module);
    CAPTURE(noleax::analyzer::symbol_module_status_name(result.status));
    CHECK(result.status == noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded);
  }

  SECTION("PDB identity mismatch disables symbol use") {
    auto module = fixture_module(3U, trace_base, image.size());
    module.expected_pdb_identity = discovered.pdb_identity;
    module.expected_pdb_identity->guid[0] ^= std::byte{1U};
    noleax::analyzer::OfflineSymbolizer symbolizer{options};
    const auto result = symbolizer.register_module(module);
    CHECK(result.status == noleax::analyzer::SymbolModuleStatus::kPdbIdentityMismatch);
    const auto frame = symbolizer.resolve_frame(module.module_id, trace_base + function_offset);
    CHECK(frame.module_offset == function_offset);
    CHECK_FALSE(frame.symbol_name.has_value());
  }

  SECTION("image identity mismatch disables symbol use") {
    auto module = fixture_module(4U, trace_base, image.size());
    module.expected_image_identity = discovered.image_identity;
    ++module.expected_image_identity->timestamp;
    noleax::analyzer::OfflineSymbolizer symbolizer{options};
    const auto result = symbolizer.register_module(module);
    CHECK(result.status == noleax::analyzer::SymbolModuleStatus::kImageIdentityMismatch);
    const auto frame = symbolizer.resolve_frame(module.module_id, trace_base + function_offset);
    CHECK_FALSE(frame.symbol_name.has_value());
  }
}

TEST_CASE("offline symbolizer reports a missing PDB without implicit symbol server access",
          "[analyzer][symbolizer]") {
  constexpr std::uint64_t trace_base = 0x00007ff700000000ULL;
  const auto path = system_module_path();
  const LoadedImage image{path};

  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{10U};
  module.base_address = trace_base;
  module.image_size = image.size();
  module.image_path = path;
  noleax::analyzer::PdbIdentity expected;
  expected.guid[0] = std::byte{1U};
  expected.age = 1U;
  module.expected_pdb_identity = expected;

  noleax::analyzer::OfflineSymbolizer symbolizer;
  const auto result = symbolizer.register_module(module);
  CAPTURE(noleax::analyzer::symbol_module_status_name(result.status));
  CHECK(result.status == noleax::analyzer::SymbolModuleStatus::kPdbNotFound);

  const auto frame = symbolizer.resolve_frame(module.module_id, trace_base + 0x1000U);
  CHECK(frame.module_name == "kernel32.dll");
  CHECK(frame.module_offset == 0x1000U);
}

TEST_CASE("offline symbolizer validates modules and preserves fallback information",
          "[analyzer][symbolizer]") {
  constexpr std::uint64_t trace_base = 0x00007ff800000000ULL;
  noleax::analyzer::OfflineSymbolizer symbolizer;
  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{20U};
  module.base_address = trace_base;
  module.image_size = 4096U;
  module.image_path = fixture_path().parent_path() / L"missing-image.dll";

  const auto result = symbolizer.register_module(module);
  CHECK(result.status == noleax::analyzer::SymbolModuleStatus::kImageNotFound);
  const auto frame = symbolizer.resolve_frame(module.module_id, trace_base + 16U);
  CHECK(frame.module_name == "missing-image.dll");
  CHECK(frame.module_offset == 16U);
  CHECK_FALSE(frame.symbol_name.has_value());

  CHECK_THROWS_AS(symbolizer.register_module(module), noleax::analyzer::SymbolizerError);
  CHECK_THROWS_AS(symbolizer.resolve_frame(module.module_id, trace_base + module.image_size),
                  noleax::analyzer::SymbolizerError);
  symbolizer.unregister_module(module.module_id);
  CHECK_THROWS_AS(symbolizer.module_result(module.module_id), noleax::analyzer::SymbolizerError);

  SECTION("invalid module fields") {
    auto invalid = module;
    invalid.module_id = {};
    CHECK_THROWS_AS(symbolizer.register_module(invalid), noleax::analyzer::SymbolizerError);
    invalid = module;
    invalid.image_size = 0U;
    CHECK_THROWS_AS(symbolizer.register_module(invalid), noleax::analyzer::SymbolizerError);
    invalid = module;
    invalid.base_address = std::numeric_limits<std::uint64_t>::max() - 10U;
    CHECK_THROWS_AS(symbolizer.register_module(invalid), noleax::analyzer::SymbolizerError);
  }

  SECTION("invalid symbol paths") {
    noleax::analyzer::SymbolizerOptions options;
    options.search_paths.emplace_back(L"invalid;path");
    CHECK_THROWS_AS(noleax::analyzer::OfflineSymbolizer{options},
                    noleax::analyzer::SymbolizerError);
    options.search_paths.clear();
    options.symbol_servers.emplace_back();
    CHECK_THROWS_AS(noleax::analyzer::OfflineSymbolizer{options},
                    noleax::analyzer::SymbolizerError);
  }
}

TEST_CASE("symbol search path joins paths wraps servers and honors the raw fallback",
          "[analyzer][symbolizer]") {
  using noleax::analyzer::SymbolizerOptions;

  SymbolizerOptions fallback;
  fallback.raw_search_path = L"C:\\symcache;srv*https://symbols.example";
  CHECK(noleax::analyzer::build_symbol_search_path(fallback) == fallback.raw_search_path);

  const auto absolute = std::filesystem::absolute(std::filesystem::path{L"symbols"});
  SymbolizerOptions paths;
  paths.raw_search_path = L"ignored";
  paths.search_paths.emplace_back(L"symbols");
  CHECK(noleax::analyzer::build_symbol_search_path(paths) == absolute.wstring());

  SymbolizerOptions servers;
  servers.symbol_servers = {"https://one.example/symbols",
                            "srv*C:\\cache*https://two.example/symbols",
                            "SRV*D:\\cache*https://three.example/symbols"};
  CHECK(noleax::analyzer::build_symbol_search_path(servers) ==
        L"srv*https://one.example/symbols;srv*C:\\cache*https://two.example/symbols;"
        L"SRV*D:\\cache*https://three.example/symbols");

  SymbolizerOptions mixed;
  mixed.search_paths.emplace_back(L"symbols");
  mixed.symbol_servers = {"https://one.example"};
  CHECK(noleax::analyzer::build_symbol_search_path(mixed) ==
        absolute.wstring() + L";srv*https://one.example");

  SymbolizerOptions invalid_path;
  invalid_path.search_paths.emplace_back(L"invalid;path");
  CHECK_THROWS_AS(noleax::analyzer::build_symbol_search_path(invalid_path),
                  noleax::analyzer::SymbolizerError);

  SymbolizerOptions invalid_server;
  invalid_server.symbol_servers = {"https://one.example;symbols"};
  CHECK_THROWS_AS(noleax::analyzer::build_symbol_search_path(invalid_server),
                  noleax::analyzer::SymbolizerError);

  SymbolizerOptions empty_server;
  empty_server.symbol_servers = {""};
  CHECK_THROWS_AS(noleax::analyzer::build_symbol_search_path(empty_server),
                  noleax::analyzer::SymbolizerError);
}

TEST_CASE("symbol search path from environment joins the NT symbol variables",
          "[analyzer][symbolizer]") {
  const EnvironmentVariableGuard primary{L"_NT_SYMBOL_PATH"};
  const EnvironmentVariableGuard alternate{L"_NT_ALT_SYMBOL_PATH"};

  SetEnvironmentVariableW(L"_NT_SYMBOL_PATH", L"C:\\symcache;srv*https://symbols.example");
  SetEnvironmentVariableW(L"_NT_ALT_SYMBOL_PATH", nullptr);
  CHECK(noleax::analyzer::symbol_search_path_from_environment() ==
        L"C:\\symcache;srv*https://symbols.example");

  SetEnvironmentVariableW(L"_NT_ALT_SYMBOL_PATH", L"D:\\alt");
  CHECK(noleax::analyzer::symbol_search_path_from_environment() ==
        L"C:\\symcache;srv*https://symbols.example;D:\\alt");

  SetEnvironmentVariableW(L"_NT_SYMBOL_PATH", nullptr);
  CHECK(noleax::analyzer::symbol_search_path_from_environment() == L"D:\\alt");

  SetEnvironmentVariableW(L"_NT_ALT_SYMBOL_PATH", nullptr);
  CHECK(noleax::analyzer::symbol_search_path_from_environment().empty());
}

TEST_CASE("offline symbolizer falls back to the raw search path", "[analyzer][symbolizer]") {
  constexpr std::uint64_t trace_base = 0x00007ff900000000ULL;
  const LoadedImage image{fixture_path()};
  const std::uint64_t function_offset = image.exported_offset("noleax_symbolizer_fixture_target");

  noleax::analyzer::SymbolizerOptions options;
  options.raw_search_path = fixture_path().parent_path().wstring();
  noleax::analyzer::OfflineSymbolizer symbolizer{options};
  const auto module = fixture_module(30U, trace_base, image.size());
  const auto result = symbolizer.register_module(module);
  CAPTURE(noleax::analyzer::symbol_module_status_name(result.status));
  REQUIRE(result.status == noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded);
  const auto frame = symbolizer.resolve_frame(module.module_id, trace_base + function_offset);
  CHECK(frame.symbol_name.has_value());
}

#else

TEST_CASE("offline symbolizer reports unsupported non-Windows platforms",
          "[analyzer][symbolizer]") {
  noleax::analyzer::OfflineSymbolizer symbolizer;
  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{1U};
  module.image_size = 4096U;
  module.image_path = "module";
  CHECK(symbolizer.register_module(module).status ==
        noleax::analyzer::SymbolModuleStatus::kUnsupportedPlatform);
}

#endif
