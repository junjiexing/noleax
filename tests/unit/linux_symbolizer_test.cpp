// _GNU_SOURCE. The g++ driver predefines it; the guard covers a bare cc1plus invocation and
// keeps dl_iterate_phdr/dladdr1 visible.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include "elf_image.hpp"
#include "noleax/analyzer/presentation.hpp"
#include "noleax/analyzer/symbolizer.hpp"
#include "noleax/analyzer/trace_metadata.hpp"
#include "noleax/trace/identifiers.hpp"
#include "support/synthetic_trace.hpp"

namespace {

namespace probe {

// Exported into .symtab of the test binary; noinline so taking its address below yields the
// canonical out-of-line function.
#if defined(__GNUC__)
__attribute__((noinline))
#endif
std::int32_t
linux_symbolizer_probe(std::int32_t value) {
  return value + 42;
}

}  // namespace probe

[[nodiscard]] std::uint64_t address_of(void* address) noexcept {
  return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(address));
}

// The module layout the Linux agent records for a trace: load bias plus the span of the
// PT_LOAD segments relative to the link-time vaddrs (see agent/linux/module_tracker.cpp).
struct ModuleLayout {
  std::uint64_t bias{0};
  std::uint64_t minimum_vaddr{0};
  std::uint64_t span{0};
  bool found{false};
};

struct LayoutRequest {
  bool match_main_executable{false};
  std::uint64_t match_bias{0};
  ModuleLayout layout;
};

int layout_callback(dl_phdr_info* info, std::size_t /*size*/, void* data) {
  auto& request = *static_cast<LayoutRequest*>(data);
  const bool is_main_executable = info->dlpi_name == nullptr || info->dlpi_name[0] == '\0';
  if (request.match_main_executable != is_main_executable) {
    return 0;
  }
  if (!request.match_main_executable &&
      static_cast<std::uint64_t>(info->dlpi_addr) != request.match_bias) {
    return 0;
  }
  std::uint64_t lowest = UINT64_MAX;
  std::uint64_t highest = 0;
  for (int index = 0; index < info->dlpi_phnum; ++index) {
    const Elf64_Phdr& segment = info->dlpi_phdr[index];
    if (segment.p_type != PT_LOAD) {
      continue;
    }
    lowest = std::min(lowest, static_cast<std::uint64_t>(segment.p_vaddr));
    highest = std::max(highest, static_cast<std::uint64_t>(segment.p_vaddr) +
                                    static_cast<std::uint64_t>(segment.p_memsz));
  }
  if (lowest == UINT64_MAX || highest <= lowest) {
    return 0;
  }
  request.layout.bias = static_cast<std::uint64_t>(info->dlpi_addr);
  request.layout.minimum_vaddr = lowest;
  request.layout.span = highest - lowest;
  request.layout.found = true;
  return 1;
}

[[nodiscard]] ModuleLayout main_executable_layout() {
  LayoutRequest request;
  request.match_main_executable = true;
  dl_iterate_phdr(&layout_callback, &request);
  return request.layout;
}

[[nodiscard]] ModuleLayout layout_for_address(void* address) {
  Dl_info info{};
  link_map* map = nullptr;
  if (dladdr1(address, &info, reinterpret_cast<void**>(&map), RTLD_DL_LINKMAP) == 0 ||
      map == nullptr) {
    return {};
  }
  LayoutRequest request;
  request.match_bias = static_cast<std::uint64_t>(map->l_addr);
  dl_iterate_phdr(&layout_callback, &request);
  return request.layout;
}

[[nodiscard]] noleax::analyzer::SymbolModule make_module(std::uint64_t module_id,
                                                         const ModuleLayout& layout,
                                                         std::filesystem::path path) {
  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{module_id};
  module.base_address = layout.bias + layout.minimum_vaddr;
  module.image_size = layout.span;
  module.image_path = std::move(path);
  return module;
}

// A unique scratch file under the temporary directory, removed on destruction.
class ScratchFile {
 public:
  explicit ScratchFile(std::string_view name)
      : path_{std::filesystem::temp_directory_path() /
              ("noleax-linux-symbolizer-" + std::string{name} + "-" +
               std::to_string(static_cast<unsigned long long>(::getpid())))} {}

  ~ScratchFile() {
    std::error_code error;
    std::filesystem::remove(path_, error);
  }

  ScratchFile(const ScratchFile&) = delete;
  ScratchFile& operator=(const ScratchFile&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

// Writes a well-formed ELF64 header with a single PT_LOAD segment and no section headers, so
// the image parses cleanly but carries no symbol tables at all.
void write_minimal_elf(const std::filesystem::path& path, std::uint16_t machine) {
  Elf64_Ehdr header{};
  header.e_ident[EI_MAG0] = ELFMAG0;
  header.e_ident[EI_MAG1] = ELFMAG1;
  header.e_ident[EI_MAG2] = ELFMAG2;
  header.e_ident[EI_MAG3] = ELFMAG3;
  header.e_ident[EI_CLASS] = ELFCLASS64;
  header.e_ident[EI_DATA] = ELFDATA2LSB;
  header.e_ident[EI_VERSION] = EV_CURRENT;
  header.e_type = ET_DYN;
  header.e_machine = machine;
  header.e_version = EV_CURRENT;
  header.e_phoff = sizeof(Elf64_Ehdr);
  header.e_ehsize = sizeof(Elf64_Ehdr);
  header.e_phentsize = sizeof(Elf64_Phdr);
  header.e_phnum = 1;
  header.e_shentsize = sizeof(Elf64_Shdr);
  Elf64_Phdr segment{};
  segment.p_type = PT_LOAD;
  segment.p_flags = PF_R | PF_X;
  segment.p_offset = 0;
  segment.p_vaddr = 0x1000;
  segment.p_filesz = sizeof(header) + sizeof(segment);
  segment.p_memsz = segment.p_filesz;
  segment.p_align = 0x1000;
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  output.write(reinterpret_cast<const char*>(&header), sizeof(header));
  output.write(reinterpret_cast<const char*>(&segment), sizeof(segment));
  if (!output) {
    throw std::runtime_error{"cannot write the scratch ELF image"};
  }
}

[[nodiscard]] noleax::analyzer::SymbolModule scratch_module(std::uint64_t module_id,
                                                            const std::filesystem::path& path) {
  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{module_id};
  module.base_address = 0x00007f0000000000ULL;
  module.image_size = 0x4000;
  module.image_path = path;
  return module;
}

}  // namespace

TEST_CASE("linux ELF image parses the test binary", "[analyzer][symbolizer][linux]") {
  const ModuleLayout layout = main_executable_layout();
  REQUIRE(layout.found);
  const auto exe_path = std::filesystem::read_symlink("/proc/self/exe");

  const noleax::analyzer::elf::ElfImage image{exe_path};
  CHECK(image.minimum_load_vaddr() == layout.minimum_vaddr);
  CHECK(!image.build_id().empty());
  CHECK(image.has_function_symbols(noleax::analyzer::elf::SymbolTable::kSymtab));

  using noleax::analyzer::elf::demangle;
  CHECK(demangle("_Z3foov") == "foo()");
  CHECK(demangle("plain_c_symbol") == "plain_c_symbol");
  CHECK(demangle("").empty());
}

TEST_CASE("linux symbolizer resolves frames in the test binary", "[analyzer][symbolizer][linux]") {
  const ModuleLayout layout = main_executable_layout();
  REQUIRE(layout.found);
  const auto exe_path = std::filesystem::read_symlink("/proc/self/exe");
  const std::uint64_t probe_address =
      address_of(reinterpret_cast<void*>(&probe::linux_symbolizer_probe));

  noleax::analyzer::OfflineSymbolizer symbolizer;
  const auto module = make_module(7U, layout, exe_path);
  const noleax::analyzer::SymbolModuleResult registered = symbolizer.register_module(module);
  CAPTURE(noleax::analyzer::symbol_module_status_name(registered.status));
  CAPTURE(registered.system_error);
  REQUIRE(registered.status == noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded);
  CHECK(symbolizer.module_result(module.module_id) == registered);

  const auto frame = symbolizer.resolve_frame(module.module_id, probe_address);
  CHECK(frame.absolute_address == probe_address);
  CHECK(frame.module_name == exe_path.filename().string());
  REQUIRE(frame.module_offset.has_value());
  CHECK(*frame.module_offset == probe_address - module.base_address);
  REQUIRE(frame.symbol_name.has_value());
  CHECK(frame.symbol_name->find("linux_symbolizer_probe") != std::string::npos);
  REQUIRE(frame.symbol_offset.has_value());
  CHECK(*frame.symbol_offset == 0U);

  const auto middle = symbolizer.resolve_frame(module.module_id, probe_address + 1U);
  REQUIRE(middle.symbol_name.has_value());
  CHECK(*middle.symbol_name == *frame.symbol_name);
  REQUIRE(middle.symbol_offset.has_value());
  CHECK(*middle.symbol_offset == 1U);

  const auto symbols = symbolizer.enumerate_symbols(module.module_id);
  const auto probe_symbol = std::find_if(symbols.begin(), symbols.end(), [](const auto& symbol) {
    return symbol.undecorated_name.find("linux_symbolizer_probe") != std::string::npos;
  });
  REQUIRE(probe_symbol != symbols.end());
  CHECK(probe_symbol->rva == probe_address - module.base_address);
  CHECK(probe_symbol->tag == 5U);
  CHECK(probe_symbol->size > 0U);

  const auto rva = symbolizer.resolve_symbol(module.module_id, probe_symbol->name);
  REQUIRE(rva.has_value());
  CHECK(*rva == probe_symbol->rva);
  CHECK(!symbolizer.resolve_symbol(module.module_id, "noleax_no_such_symbol").has_value());

  std::atomic<bool> concurrent_success{true};
  std::vector<std::thread> workers;
  workers.reserve(4U);
  for (std::size_t index = 0; index < 4U; ++index) {
    workers.emplace_back([&] {
      try {
        for (std::size_t iteration = 0; iteration < 25U; ++iteration) {
          const auto resolved = symbolizer.resolve_frame(module.module_id, probe_address);
          if (!resolved.symbol_name.has_value() || *resolved.symbol_offset != 0U) {
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
  CHECK(concurrent_success.load());

  symbolizer.unregister_module(module.module_id);
}

TEST_CASE("linux symbolizer resolves frames in the agent image", "[analyzer][symbolizer][linux]") {
  const std::filesystem::path agent_path{NOLEAX_TEST_AGENT_PATH};
  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{11U};
  module.base_address = 0x00007f0000000000ULL;
  module.image_size = std::filesystem::file_size(agent_path);
  module.image_path = agent_path;

  noleax::analyzer::OfflineSymbolizer symbolizer;
  const noleax::analyzer::SymbolModuleResult registered = symbolizer.register_module(module);
  CAPTURE(noleax::analyzer::symbol_module_status_name(registered.status));
  REQUIRE(registered.status == noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded);

  const auto symbols = symbolizer.enumerate_symbols(module.module_id);
  const auto export_symbol = std::find_if(symbols.begin(), symbols.end(), [](const auto& symbol) {
    return symbol.name == "noleax_agent_abi_version";
  });
  REQUIRE(export_symbol != symbols.end());
  CHECK(export_symbol->undecorated_name == "noleax_agent_abi_version");
  CHECK(export_symbol->tag == 5U);

  const auto rva = symbolizer.resolve_symbol(module.module_id, "noleax_agent_abi_version");
  REQUIRE(rva.has_value());
  CHECK(*rva == export_symbol->rva);

  const auto frame = symbolizer.resolve_frame(module.module_id, module.base_address + *rva);
  REQUIRE(frame.symbol_name.has_value());
  CHECK(*frame.symbol_name == "noleax_agent_abi_version");
  REQUIRE(frame.symbol_offset.has_value());
  CHECK(*frame.symbol_offset == 0U);
}

TEST_CASE("linux symbolizer falls back to dynsym for stripped system images",
          "[analyzer][symbolizer][linux]") {
  void* const libc = ::dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
  REQUIRE(libc != nullptr);
  void* const malloc_address = ::dlsym(libc, "malloc");
  REQUIRE(malloc_address != nullptr);

  Dl_info info{};
  REQUIRE(::dladdr(malloc_address, &info) != 0);
  const ModuleLayout layout = layout_for_address(malloc_address);
  REQUIRE(layout.found);

  noleax::analyzer::OfflineSymbolizer symbolizer;
  const auto module = make_module(13U, layout, info.dli_fname);
  const noleax::analyzer::SymbolModuleResult registered = symbolizer.register_module(module);
  CAPTURE(noleax::analyzer::symbol_module_status_name(registered.status));
  // glibc ships libc.so.6 without .symtab, leaving only the export-equivalent .dynsym.
  REQUIRE(registered.status == noleax::analyzer::SymbolModuleStatus::kExportsOnly);

  const auto frame = symbolizer.resolve_frame(module.module_id, address_of(malloc_address));
  REQUIRE(frame.module_offset.has_value());
  REQUIRE(frame.symbol_name.has_value());
  CHECK(frame.symbol_name->find("malloc") != std::string::npos);
  REQUIRE(frame.symbol_offset.has_value());
  CHECK(*frame.symbol_offset == 0U);

  const auto symbols = symbolizer.enumerate_symbols(module.module_id);
  CHECK(std::any_of(symbols.begin(), symbols.end(),
                    [](const auto& symbol) { return symbol.name == "malloc"; }));

  const auto rva = symbolizer.resolve_symbol(module.module_id, "malloc");
  REQUIRE(rva.has_value());
  CHECK(module.base_address + *rva == address_of(malloc_address));
}

TEST_CASE("linux symbolizer reports images without any function symbols",
          "[analyzer][symbolizer][linux]") {
  const ScratchFile scratch{"no-symbols.so"};
  write_minimal_elf(scratch.path(), EM_X86_64);

  noleax::analyzer::OfflineSymbolizer symbolizer;
  const auto module = scratch_module(17U, scratch.path());
  const noleax::analyzer::SymbolModuleResult registered = symbolizer.register_module(module);
  CHECK(registered.status == noleax::analyzer::SymbolModuleStatus::kNoSymbols);

  const auto frame = symbolizer.resolve_frame(module.module_id, module.base_address + 0x40U);
  CHECK(frame.module_offset == 0x40U);
  CHECK(!frame.symbol_name.has_value());
  CHECK(!frame.symbol_offset.has_value());
  CHECK(symbolizer.enumerate_symbols(module.module_id).empty());
  CHECK(!symbolizer.resolve_symbol(module.module_id, "anything").has_value());
}

TEST_CASE("linux symbolizer rejects unsupported or corrupt images",
          "[analyzer][symbolizer][linux]") {
  noleax::analyzer::OfflineSymbolizer symbolizer;

  const ScratchFile missing{"missing.so"};
  const auto missing_result = symbolizer.register_module(scratch_module(19U, missing.path()));
  CHECK(missing_result.status == noleax::analyzer::SymbolModuleStatus::kImageNotFound);
  CHECK(missing_result.system_error != 0U);

  const ScratchFile wrong_machine{"wrong-machine.so"};
  write_minimal_elf(wrong_machine.path(), EM_AARCH64);
  const auto machine_result = symbolizer.register_module(scratch_module(23U, wrong_machine.path()));
  CHECK(machine_result.status == noleax::analyzer::SymbolModuleStatus::kLoadFailed);

  const ScratchFile garbage{"garbage.so"};
  {
    std::ofstream output{garbage.path(), std::ios::binary | std::ios::trunc};
    output << "this is not an ELF image at all";
  }
  const auto garbage_result = symbolizer.register_module(scratch_module(29U, garbage.path()));
  CHECK(garbage_result.status == noleax::analyzer::SymbolModuleStatus::kLoadFailed);
}

TEST_CASE("linux symbolizer honors the off resolution mode", "[analyzer][symbolizer][linux]") {
  const ModuleLayout layout = main_executable_layout();
  REQUIRE(layout.found);
  const auto exe_path = std::filesystem::read_symlink("/proc/self/exe");
  const std::uint64_t probe_address =
      address_of(reinterpret_cast<void*>(&probe::linux_symbolizer_probe));

  noleax::analyzer::SymbolizerOptions options;
  options.mode = noleax::analyzer::SymbolResolutionMode::kOff;
  noleax::analyzer::OfflineSymbolizer symbolizer{options};
  const auto module = make_module(31U, layout, exe_path);
  const noleax::analyzer::SymbolModuleResult registered = symbolizer.register_module(module);
  CHECK(registered.status == noleax::analyzer::SymbolModuleStatus::kNoSymbols);

  const auto frame = symbolizer.resolve_frame(module.module_id, probe_address);
  CHECK(frame.module_name == exe_path.filename().string());
  REQUIRE(frame.module_offset.has_value());
  CHECK(*frame.module_offset == probe_address - module.base_address);
  CHECK(!frame.symbol_name.has_value());
  CHECK(symbolizer.enumerate_symbols(module.module_id).empty());
  CHECK(!symbolizer.resolve_symbol(module.module_id, "malloc").has_value());
}

TEST_CASE("linux symbolizer rejects frames outside the registered image",
          "[analyzer][symbolizer][linux]") {
  const ModuleLayout layout = main_executable_layout();
  REQUIRE(layout.found);
  const auto exe_path = std::filesystem::read_symlink("/proc/self/exe");

  noleax::analyzer::OfflineSymbolizer symbolizer;
  const auto module = make_module(37U, layout, exe_path);
  REQUIRE(symbolizer.register_module(module).status ==
          noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded);
  CHECK_THROWS_AS(
      symbolizer.resolve_frame(module.module_id, module.base_address + module.image_size),
      noleax::analyzer::SymbolizerError);
  CHECK_THROWS_AS(symbolizer.resolve_frame(module.module_id, module.base_address - 1U),
                  noleax::analyzer::SymbolizerError);
}

// ---- .gnu_debuglink split-debug fixtures (objcopy-generated, see tests/CMakeLists) ----

namespace {

constexpr std::uint64_t kDebuglinkBase = 0x100000000ULL;

[[nodiscard]] std::filesystem::path debuglink_case_dir(std::string_view name) {
  return std::filesystem::path{NOLEAX_DEBUGLINK_DIR} / name;
}

[[nodiscard]] noleax::analyzer::SymbolModule debuglink_module(std::uint64_t module_id,
                                                              std::string_view case_name) {
  noleax::analyzer::SymbolModule module;
  module.module_id = noleax::trace::ModuleId{module_id};
  module.base_address = kDebuglinkBase;
  module.image_size = 0x100000U;
  module.image_path = debuglink_case_dir(case_name) / "libnoleax-debuglink-fixture.so";
  return module;
}

// Resolves the hidden fixture function (present only in the companion's .symtab) and
// checks the round trip through frame resolution.
void check_internal_symbol_resolves(const noleax::analyzer::OfflineSymbolizer& symbolizer,
                                    noleax::trace::ModuleId module_id) {
  const auto rva = symbolizer.resolve_symbol(module_id, "_Z18debuglink_internali");
  REQUIRE(rva.has_value());
  const auto frame = symbolizer.resolve_frame(module_id, kDebuglinkBase + *rva + 1U);
  REQUIRE(frame.symbol_name.has_value());
  CHECK(*frame.symbol_name == "debuglink_internal(int)");
}

}  // namespace

TEST_CASE("linux split debug symbols are found next to the runtime image",
          "[analyzer][symbolizer][linux][debuglink]") {
  const auto stripped = debuglink_case_dir("plain") / "libnoleax-debuglink-fixture.so";
  const noleax::analyzer::elf::ElfImage image{stripped};
  REQUIRE(image.debuglink_name().has_value());
  CHECK(*image.debuglink_name() == "libnoleax-debuglink-fixture.so.debug");
  REQUIRE(image.debuglink_crc32().has_value());
  // objcopy stored the companion's real GNU CRC32; our verifier must reproduce it.
  CHECK(noleax::analyzer::elf::gnu_crc32_of_file(debuglink_case_dir("plain") /
                                                 "libnoleax-debuglink-fixture.so.debug") ==
        image.debuglink_crc32());
  CHECK_FALSE(image.build_id().empty());

  noleax::analyzer::OfflineSymbolizer symbolizer;
  const auto module = debuglink_module(41U, "plain");
  REQUIRE(symbolizer.register_module(module).status ==
          noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded);
  check_internal_symbol_resolves(symbolizer, module.module_id);
}

TEST_CASE("linux split debug symbols are found in the .debug subdirectory",
          "[analyzer][symbolizer][linux][debuglink]") {
  noleax::analyzer::OfflineSymbolizer symbolizer;
  const auto module = debuglink_module(43U, "subdir");
  REQUIRE(symbolizer.register_module(module).status ==
          noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded);
  check_internal_symbol_resolves(symbolizer, module.module_id);
}

TEST_CASE("linux split debug symbols are found through the symbol path",
          "[analyzer][symbolizer][linux][debuglink]") {
  noleax::analyzer::SymbolizerOptions options;
  options.search_paths.push_back(debuglink_case_dir("store"));
  noleax::analyzer::OfflineSymbolizer symbolizer{options};
  const auto module = debuglink_module(45U, "spath");
  REQUIRE(symbolizer.register_module(module).status ==
          noleax::analyzer::SymbolModuleStatus::kSymbolsLoaded);
  check_internal_symbol_resolves(symbolizer, module.module_id);
}

TEST_CASE("linux split debug candidate with a corrupted CRC32 is rejected",
          "[analyzer][symbolizer][linux][debuglink]") {
  noleax::analyzer::OfflineSymbolizer symbolizer;
  const auto module = debuglink_module(47U, "badcrc");
  CHECK(symbolizer.register_module(module).status ==
        noleax::analyzer::SymbolModuleStatus::kDebugIdentityMismatch);
  // The mismatch must not be used, but the runtime image's .dynsym still applies.
  CHECK(symbolizer.resolve_symbol(module.module_id, "_Z18debuglink_exportedi").has_value());
  CHECK(!symbolizer.resolve_symbol(module.module_id, "_Z18debuglink_internali").has_value());
}

TEST_CASE("linux split debug candidate with a foreign Build ID is rejected",
          "[analyzer][symbolizer][linux][debuglink]") {
  noleax::analyzer::OfflineSymbolizer symbolizer;
  const auto module = debuglink_module(49U, "badid");
  CHECK(symbolizer.register_module(module).status ==
        noleax::analyzer::SymbolModuleStatus::kDebugIdentityMismatch);
  CHECK(!symbolizer.resolve_symbol(module.module_id, "_Z18debuglink_internali").has_value());
}

TEST_CASE("linux symbolizer falls back to dynsym when the split debug file is missing",
          "[analyzer][symbolizer][linux][debuglink]") {
  noleax::analyzer::OfflineSymbolizer symbolizer;
  const auto module = debuglink_module(51U, "missing");
  CHECK(symbolizer.register_module(module).status ==
        noleax::analyzer::SymbolModuleStatus::kExportsOnly);
  CHECK(symbolizer.resolve_symbol(module.module_id, "_Z18debuglink_exportedi").has_value());
  CHECK(!symbolizer.resolve_symbol(module.module_id, "_Z18debuglink_internali").has_value());
}

TEST_CASE("required symbol mode rejects a split-debug identity mismatch",
          "[analyzer][symbolizer][linux][debuglink]") {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kLinux;
  header.architecture = noleax::trace::Architecture::kX64;
  header.monotonic_frequency = 1'000'000'000U;

  noleax::trace::ModuleLoad module;
  module.module_id = noleax::trace::ModuleId{53U};
  module.base_address = kDebuglinkBase;
  module.image_size = 0x100000U;
  const auto image_path =
      (debuglink_case_dir("badcrc") / "libnoleax-debuglink-fixture.so").u8string();
  module.image_path = {reinterpret_cast<const char*>(image_path.data()), image_path.size()};

  const std::string bytes = noleax::testing::SyntheticTraceBuilder{header, {true, false}}
                                .add_module(module)
                                .finish_normally()
                                .build();
  std::istringstream input{bytes, std::ios::binary};
  noleax::analyzer::SymbolizerOptions options;
  options.mode = noleax::analyzer::SymbolResolutionMode::kRequired;
  noleax::analyzer::TraceMetadata metadata{options};
  CHECK_THROWS_AS(metadata.scan(input), noleax::analyzer::TraceAnalysisError);
}
