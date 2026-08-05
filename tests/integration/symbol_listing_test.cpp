#include "noleax/controller/windows/process.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "support/csv_table.hpp"
#include "support/json_dom.hpp"
#include "support/json_schema.hpp"

namespace {

class Handle final {
 public:
  explicit Handle(HANDLE value = nullptr) noexcept : value_{value} {}
  ~Handle() {
    if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
      static_cast<void>(CloseHandle(value_));
    }
  }

  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : value_{std::exchange(other.value_, nullptr)} {}
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
        static_cast<void>(CloseHandle(value_));
      }
      value_ = std::exchange(other.value_, nullptr);
    }
    return *this;
  }
  [[nodiscard]] HANDLE get() const noexcept { return value_; }
  [[nodiscard]] bool valid() const noexcept {
    return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
  }

 private:
  HANDLE value_{nullptr};
};

struct ChildResult {
  std::uint32_t exit_code{0U};
  std::string log;
};

[[nodiscard]] std::string read_file(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  if (!input) {
    throw std::runtime_error{"cannot read test output"};
  }
  std::ostringstream output;
  output << input.rdbuf();
  return output.str();
}

void write_file(const std::filesystem::path& path, std::string_view contents) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  if (!output) {
    throw std::runtime_error{"cannot create test input"};
  }
  output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  if (!output) {
    throw std::runtime_error{"cannot write test input"};
  }
}

[[nodiscard]] std::wstring command_line(const std::filesystem::path& executable,
                                        const std::vector<std::string>& arguments) {
  std::wstring result = noleax::controller::windows::quote_windows_argument(executable.native());
  for (const auto& argument : arguments) {
    result.push_back(L' ');
    result.append(noleax::controller::windows::quote_windows_argument(
        noleax::controller::windows::utf8_to_wide(argument)));
  }
  return result;
}

[[nodiscard]] ChildResult run_child(const std::filesystem::path& executable,
                                    const std::vector<std::string>& arguments,
                                    const std::filesystem::path& log_path) {
  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;
  Handle log{CreateFileW(log_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr)};
  if (!log.valid()) {
    throw std::runtime_error{"cannot create child log"};
  }
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = log.get();
  startup.hStdError = log.get();

  std::wstring text = command_line(executable, arguments);
  std::vector<wchar_t> mutable_text{text.begin(), text.end()};
  mutable_text.push_back(L'\0');
  PROCESS_INFORMATION process{};
  if (CreateProcessW(executable.c_str(), mutable_text.data(), nullptr, nullptr, TRUE,
                     CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &startup,
                     &process) == FALSE) {
    throw std::runtime_error{"cannot start noleax child process"};
  }
  Handle process_handle{process.hProcess};
  Handle thread_handle{process.hThread};
  const DWORD wait = WaitForSingleObject(process_handle.get(), 60'000U);
  if (wait != WAIT_OBJECT_0) {
    static_cast<void>(TerminateProcess(process_handle.get(), 99U));
    throw std::runtime_error{"noleax child process timed out"};
  }
  DWORD exit_code = 0U;
  if (GetExitCodeProcess(process_handle.get(), &exit_code) == FALSE) {
    throw std::runtime_error{"cannot query noleax child exit code"};
  }
  log = Handle{};
  return {exit_code, read_file(log_path)};
}

[[nodiscard]] std::string utf8_path(const std::filesystem::path& path) {
  return noleax::controller::windows::wide_to_utf8(path.native());
}

[[nodiscard]] std::filesystem::path system_module_path() {
  std::array<wchar_t, MAX_PATH> buffer{};
  const UINT length = GetSystemDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
  if (length == 0U || length >= buffer.size()) {
    throw std::runtime_error{"cannot locate the Windows system directory"};
  }
  return std::filesystem::path{std::wstring_view{buffer.data(), length}} / L"kernel32.dll";
}

[[nodiscard]] bool contains(const ChildResult& result, std::string_view needle) {
  return result.log.find(needle) != std::string::npos;
}

void require_contains(const ChildResult& result, std::string_view needle, const char* scenario) {
  if (!contains(result, needle)) {
    throw std::runtime_error{std::string{scenario} + " is missing '" + std::string{needle} +
                             "': " + result.log};
  }
}

void require_not_contains(const ChildResult& result, std::string_view needle,
                          const char* scenario) {
  if (contains(result, needle)) {
    throw std::runtime_error{std::string{scenario} + " unexpectedly contains '" +
                             std::string{needle} + "': " + result.log};
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  try {
    if (argc != 5) {
      std::cerr << "usage: symbol_listing_test NOLEAX FIXTURE_DLL SCHEMA_JSON OUTPUT_DIR\n";
      return 2;
    }
    const std::filesystem::path noleax = std::filesystem::absolute(argv[1]);
    const std::filesystem::path fixture = std::filesystem::absolute(argv[2]);
    const std::filesystem::path schema_path = std::filesystem::absolute(argv[3]);
    const std::filesystem::path output_directory = std::filesystem::absolute(argv[4]);
    static_cast<void>(std::filesystem::create_directories(output_directory));
    const auto log = output_directory / "symbols.log";

    // Console defaults: the PDB-backed fixture lists exported and PDB-only symbols alike.
    const ChildResult console = run_child(noleax, {"symbols", utf8_path(fixture)}, log);
    if (console.exit_code != 0U) {
      throw std::runtime_error{"console symbols listing failed: " + console.log};
    }
    require_contains(console, "noleax symbols", "console");
    require_contains(console, "symbols: symbols_loaded", "console");
    require_contains(console, "filters: none", "console");
    require_contains(console, "total:", "console");
    require_contains(console, "matched:", "console");
    require_contains(console, "my_malloc", "console");
    require_contains(console, "my_internal_alloc", "console");

    // Name globbing keeps only matching rows and echoes the filter.
    const ChildResult names =
        run_child(noleax, {"symbols", "--name", "my_free*", utf8_path(fixture)}, log);
    if (names.exit_code != 0U) {
      throw std::runtime_error{"name-filtered listing failed: " + names.log};
    }
    require_contains(names, "name=my_free* (ignore-case)", "names");
    require_contains(names, "my_free ", "names");
    require_contains(names, "my_free_size", "names");
    require_contains(names, "my_free_internal", "names");
    require_not_contains(names, "my_malloc", "names");

    // Kind filtering and case sensitivity.
    const ChildResult kinds = run_child(
        noleax, {"symbols", "--name", "my_malloc", "--kind", "function", utf8_path(fixture)}, log);
    if (kinds.exit_code != 0U) {
      throw std::runtime_error{"kind-filtered listing failed: " + kinds.log};
    }
    require_contains(kinds, "kind=function", "kinds");
    require_contains(kinds, "my_malloc", "kinds");
    require_contains(kinds, "function", "kinds");

    const ChildResult wrong_kind = run_child(
        noleax, {"symbols", "--name", "my_malloc", "--kind", "data", utf8_path(fixture)}, log);
    if (wrong_kind.exit_code != 0U) {
      throw std::runtime_error{"wrong-kind listing failed: " + wrong_kind.log};
    }
    require_contains(wrong_kind, "matched: 0", "kinds");

    const ChildResult match_case = run_child(
        noleax, {"symbols", "--name", "MY_MALLOC", "--match-case", utf8_path(fixture)}, log);
    if (match_case.exit_code != 0U) {
      throw std::runtime_error{"match-case listing failed: " + match_case.log};
    }
    require_contains(match_case, "name=MY_MALLOC (case-sensitive)", "kinds");
    require_contains(match_case, "matched: 0", "kinds");

    const ChildResult ignore_case =
        run_child(noleax, {"symbols", "--name", "MY_MALLOC", utf8_path(fixture)}, log);
    if (ignore_case.exit_code != 0U) {
      throw std::runtime_error{"ignore-case listing failed: " + ignore_case.log};
    }
    require_contains(ignore_case, "my_malloc ", "kinds");
    require_not_contains(ignore_case, "matched: 0", "kinds");

    // JSON output validates against the published schema and exposes the listing fields.
    const auto json_path = output_directory / "symbols.json";
    const ChildResult json = run_child(
        noleax,
        {"symbols", "--format", "json", "--output", utf8_path(json_path), utf8_path(fixture)}, log);
    if (json.exit_code != 0U) {
      throw std::runtime_error{"JSON symbols listing failed: " + json.log};
    }
    const auto document = noleax::testing::parse_json(read_file(json_path));
    noleax::testing::validate_json_schema(document,
                                          noleax::testing::parse_json(read_file(schema_path)));
    if (document.at("schema").scalar() != "noleax.symbols" ||
        document.at("schema_version").unsigned_value() != 1U ||
        document.at("module").at("status").scalar() != "symbols_loaded" ||
        document.at("fields").array_items().size() != 6U) {
      throw std::runtime_error{"JSON symbols listing header does not match the contract"};
    }
    const auto& summary = document.at("summary");
    if (summary.at("total").unsigned_value() < summary.at("matched").unsigned_value() ||
        summary.at("matched").unsigned_value() != document.at("symbols").array_items().size()) {
      throw std::runtime_error{"JSON symbols listing summary is inconsistent"};
    }
    bool found_internal = false;
    for (const auto& symbol : document.at("symbols").array_items()) {
      if (symbol.at("name").scalar() == "my_internal_alloc") {
        found_internal = true;
        if (symbol.at("kind").scalar() != "function" ||
            symbol.at("rva").scalar().find("0x") != 0U ||
            symbol.at("va").scalar().find("0x") != 0U || symbol.at("size").unsigned_value() == 0U) {
          throw std::runtime_error{"JSON symbol entry fields are malformed"};
        }
      }
    }
    if (!found_internal) {
      throw std::runtime_error{"JSON symbols listing omitted the PDB-only symbol"};
    }

    // CSV honors the field selection: exactly two columns per row.
    const auto csv_path = output_directory / "symbols.csv";
    const ChildResult csv = run_child(noleax,
                                      {"symbols", "--format", "csv", "--fields", "name,rva",
                                       "--output", utf8_path(csv_path), utf8_path(fixture)},
                                      log);
    if (csv.exit_code != 0U) {
      throw std::runtime_error{"CSV symbols listing failed: " + csv.log};
    }
    const auto table = noleax::testing::parse_csv(read_file(csv_path));
    if (table.header != std::vector<std::string>{"name", "rva"} || table.rows.empty()) {
      throw std::runtime_error{"CSV symbols listing does not have the selected two columns"};
    }
    bool found_export_row = false;
    for (std::size_t row = 0U; row < table.rows.size(); ++row) {
      if (table.at(row, "name") == "my_malloc" && table.at(row, "rva").find("0x") == 0U) {
        found_export_row = true;
      }
    }
    if (!found_export_row) {
      throw std::runtime_error{"CSV symbols listing omitted my_malloc with its RVA"};
    }

    // Exports-only fallback: a system DLL has no locally resolvable PDB, and an empty explicit
    // symbol path keeps environment fallbacks out of the search. (Copying the fixture DLL
    // without its PDB is not enough: DbgHelp still finds the PDB at its recorded build path.)
    const std::filesystem::path kernel32 = system_module_path();
    const auto empty_symbols = output_directory / "empty-symbols";
    static_cast<void>(std::filesystem::create_directories(empty_symbols));
    const ChildResult exports = run_child(
        noleax, {"symbols", "--symbol-path", utf8_path(empty_symbols), utf8_path(kernel32)}, log);
    if (exports.exit_code != 0U) {
      throw std::runtime_error{"exports-only listing failed: " + exports.log};
    }
    require_contains(exports, "symbols: exports_only", "exports");
    require_contains(exports, "HeapAlloc", "exports");
    require_not_contains(exports, "my_internal_alloc", "exports");

    const auto exports_csv_path = output_directory / "symbols-exports.csv";
    const ChildResult exports_csv =
        run_child(noleax,
                  {"symbols", "--format", "csv", "--fields", "name,kind", "--name", "HeapAlloc",
                   "--symbol-path", utf8_path(empty_symbols), "--output",
                   utf8_path(exports_csv_path), utf8_path(kernel32)},
                  log);
    if (exports_csv.exit_code != 0U) {
      throw std::runtime_error{"exports-only CSV listing failed: " + exports_csv.log};
    }
    const auto exports_table = noleax::testing::parse_csv(read_file(exports_csv_path));
    if (exports_table.rows.empty()) {
      throw std::runtime_error{"exports-only CSV listing has no HeapAlloc row"};
    }
    for (std::size_t row = 0U; row < exports_table.rows.size(); ++row) {
      if (exports_table.at(row, "kind") != "export") {
        throw std::runtime_error{"exports-only symbol is not classified as export"};
      }
    }

    // Error paths: missing input, duplicate fields, and a non-PE input all fail with 1.
    const ChildResult missing =
        run_child(noleax, {"symbols", utf8_path(output_directory / "missing.dll")}, log);
    if (missing.exit_code != 1U || !contains(missing, "symbol_listing.input")) {
      throw std::runtime_error{"a missing input file did not produce exit code 1: " + missing.log};
    }
    const ChildResult duplicate_fields =
        run_child(noleax, {"symbols", "--fields", "name,name", utf8_path(fixture)}, log);
    if (duplicate_fields.exit_code != 1U || !contains(duplicate_fields, "symbol_listing.fields")) {
      throw std::runtime_error{"duplicate fields did not produce exit code 1: " +
                               duplicate_fields.log};
    }
    const auto not_a_pe = output_directory / "not-a-pe.txt";
    write_file(not_a_pe, "not a PE file");
    const ChildResult invalid_image = run_child(noleax, {"symbols", utf8_path(not_a_pe)}, log);
    if (invalid_image.exit_code != 1U || !contains(invalid_image, "is not a PE file")) {
      throw std::runtime_error{"a non-PE input did not produce exit code 1: " + invalid_image.log};
    }

    std::cout << "status=ok console=1 names=1 kinds=1 json=1 csv=1 exports=1 errors=1\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "status=error message=" << error.what() << '\n';
    return 1;
  }
}
