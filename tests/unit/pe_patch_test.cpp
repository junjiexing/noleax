#include "noleax/controller/windows/pe_patch.hpp"

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

// Internal stub layout shared with the patcher (repo-root relative path).
#include "../../src/controller/windows/static_pe_patch_layout.hpp"

namespace {

namespace pepatch = noleax::controller::windows::pepatch;
using noleax::controller::windows::PePatchError;
using noleax::controller::windows::PePatchException;
using noleax::controller::windows::PePatchOptions;

std::filesystem::path make_temp_dir() {
  const auto base =
      std::filesystem::temp_directory_path() / std::filesystem::path{"noleax-pe-patch-unit"};
  std::error_code error;
  static_cast<void>(std::filesystem::remove_all(base, error));
  std::filesystem::create_directories(base);
  return base;
}

std::vector<std::byte> read_all(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  const std::string text{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
  std::vector<std::byte> data(text.size());
  if (!text.empty()) {
    std::memcpy(data.data(), text.data(), text.size());
  }
  return data;
}

void write_all(const std::filesystem::path& path, const std::vector<std::byte>& data) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  output.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
}

template <typename Value>
void poke(std::vector<std::byte>& data, std::uint64_t offset, const Value& value) {
  std::memcpy(data.data() + offset, &value, sizeof(value));
}

struct LayoutInfo {
  std::uint32_t pe_offset{0U};
  std::uint16_t optional_size{0U};
  std::uint32_t optional_offset{0U};
  std::uint16_t number_of_sections{0U};
  std::uint32_t section_table_offset{0U};
  std::uint32_t raw_end{0U};
};

LayoutInfo layout_of(const std::vector<std::byte>& data) {
  LayoutInfo info;
  std::memcpy(&info.pe_offset, data.data() + 0x3CU, sizeof(info.pe_offset));
  const std::uint64_t coff = info.pe_offset + 4ULL;
  std::memcpy(&info.number_of_sections, data.data() + coff + 2U, sizeof(info.number_of_sections));
  std::memcpy(&info.optional_size, data.data() + coff + 16U, sizeof(info.optional_size));
  info.optional_offset = static_cast<std::uint32_t>(coff + 20U);
  info.section_table_offset = info.optional_offset + info.optional_size;
  info.raw_end = static_cast<std::uint32_t>(data.size());
  return info;
}

PePatchOptions options_for(const std::filesystem::path& input,
                           const std::filesystem::path& output) {
  PePatchOptions options;
  options.input = input;
  options.output = output;
  return options;
}

}  // namespace

TEST_CASE("static patch stub hashes match the reference values", "[controller][pe-patch]") {
  CHECK(pepatch::kKernelbaseHash == 0x351A452U);
  CHECK(pepatch::kNtdllHash == 0xCEF6E822U);
  CHECK(pepatch::kLoadLibraryHash == 0xEC0E4EA4U);
  CHECK(pepatch::kGetProcAddressHash == 0x7C0DFCAAU);
  CHECK(pepatch::kSleepHash == 0xDB2D49B0U);
  CHECK(pepatch::kVirtualProtectHash == 0x7946C61BU);
  CHECK(pepatch::kNtFlushInstructionCacheHash == 0x534C0AB8U);
}

TEST_CASE("static patch stub layout is self-consistent", "[controller][pe-patch]") {
  CHECK(pepatch::kStaticStub.size() <= pepatch::kParamsOffset);
  CHECK(pepatch::kStaticStub[pepatch::kFixupSectionRvaOffset - 3U] == std::byte{0x48});
  CHECK(pepatch::kStaticStub[pepatch::kFixupSectionRvaOffset - 2U] == std::byte{0x81});
  CHECK(pepatch::kStaticStub[pepatch::kFixupSectionRvaOffset - 1U] == std::byte{0xEB});
  CHECK(pepatch::kStaticStub[pepatch::kFixupEntryRvaOffset - 2U] == std::byte{0x48});
  CHECK(pepatch::kStaticStub[pepatch::kFixupEntryRvaOffset - 1U] == std::byte{0x05});
  CHECK(pepatch::kParamsOffset + sizeof(noleax::agent::windows::BootstrapParameters) ==
        pepatch::kMarkerOffset);
  CHECK(pepatch::kContentSize >= pepatch::kScratchOffset + 0x118U);
  // The stub's params.version comparison must match the current bootstrap ABI.
  CHECK(pepatch::kStaticStub[pepatch::kVersionCmpOffset - 8U] == std::byte{0x41});
  CHECK(pepatch::kStaticStub[pepatch::kVersionCmpOffset - 7U] == std::byte{0x83});
  CHECK(static_cast<std::uint8_t>(pepatch::kStaticStub[pepatch::kVersionCmpOffset]) ==
        noleax::agent::windows::kBootstrapVersion);
}

TEST_CASE("patch produces a verifiable image and patch info", "[controller][pe-patch]") {
  const auto directory = make_temp_dir();
  const auto input = directory / "target.exe";
  const auto output = directory / "target-patched.exe";
  write_all(input, read_all(NOLEAX_TEST_CONTROLLER_TARGET_PATH));

  const auto result = noleax::controller::windows::patch_pe_image(options_for(input, output));
  CHECK(result.entry_rva != 0U);
  CHECK((result.patch_rva == result.entry_rva || result.patch_rva == result.entry_rva + 4U));
  CHECK(result.section_rva > result.entry_rva);
  CHECK_FALSE(result.signature_removed);

  const auto info = noleax::controller::windows::read_static_patch_info(output);
  REQUIRE(info.has_value());
  CHECK(info->entry_rva == result.entry_rva);
  CHECK(info->section_rva == result.section_rva);
  CHECK(info->params_rva ==
        result.section_rva + static_cast<std::uint32_t>(pepatch::kParamsOffset));

  CHECK_FALSE(noleax::controller::windows::read_static_patch_info(input).has_value());

  const auto second = directory / "target-patched-2.exe";
  try {
    static_cast<void>(noleax::controller::windows::patch_pe_image(options_for(output, second)));
    FAIL("re-patching a patched image must be rejected");
  } catch (const PePatchException& error) {
    CHECK(error.code() == PePatchError::kMalformed);
  }
}

TEST_CASE("standalone patch bakes the magic parameters while plain patch zeroes them",
          "[controller][pe-patch]") {
  const auto directory = make_temp_dir();
  const auto input = directory / "target.exe";
  write_all(input, read_all(NOLEAX_TEST_CONTROLLER_TARGET_PATH));

  const auto read_params = [](const std::filesystem::path& image_path) {
    const auto data = read_all(image_path);
    const LayoutInfo layout = layout_of(data);
    noleax::agent::windows::BootstrapParameters parameters;
    bool found = false;
    for (std::uint16_t index = 0U; index < layout.number_of_sections && !found; ++index) {
      const std::uint64_t entry = layout.section_table_offset + index * 40ULL;
      char name[9]{};
      std::memcpy(name, data.data() + entry, 8U);
      if (std::string_view{name} != ".nlxboot") {
        continue;
      }
      std::uint32_t raw_offset = 0U;
      std::memcpy(&raw_offset, data.data() + entry + 20U, sizeof(raw_offset));
      REQUIRE(raw_offset + pepatch::kParamsOffset + sizeof(parameters) <= data.size());
      std::memcpy(&parameters, data.data() + raw_offset + pepatch::kParamsOffset,
                  sizeof(parameters));
      found = true;
    }
    REQUIRE(found);
    return parameters;
  };

  auto plain_options = options_for(input, directory / "plain-patched.exe");
  static_cast<void>(noleax::controller::windows::patch_pe_image(plain_options));
  const auto plain = read_params(directory / "plain-patched.exe");
  CHECK(plain.session_token != noleax::agent::windows::kStandaloneMagic);
  CHECK(plain.pipe_name.front() == L'\0');

  auto standalone_options = options_for(input, directory / "standalone-patched.exe");
  standalone_options.standalone = true;
  static_cast<void>(noleax::controller::windows::patch_pe_image(standalone_options));
  const auto standalone = read_params(directory / "standalone-patched.exe");
  CHECK(standalone.structure_size == sizeof(standalone));
  CHECK(standalone.version == noleax::agent::windows::kBootstrapVersion);
  CHECK(standalone.session_token == noleax::agent::windows::kStandaloneMagic);
  CHECK(standalone.pipe_name.front() != L'\0');
}

TEST_CASE("patch rejects unsupported and malformed inputs", "[controller][pe-patch]") {
  const auto directory = make_temp_dir();
  const auto source = read_all(NOLEAX_TEST_CONTROLLER_TARGET_PATH);
  const LayoutInfo layout = layout_of(source);

  const auto expect_rejection = [&](const std::vector<std::byte>& mutated, PePatchError expected,
                                    const std::string& name) {
    const auto input = directory / (name + ".exe");
    write_all(input, mutated);
    try {
      static_cast<void>(noleax::controller::windows::patch_pe_image(
          options_for(input, directory / (name + "-out.exe"))));
      FAIL("expected a PePatchException for " + name);
    } catch (const PePatchException& error) {
      CHECK(error.code() == expected);
    }
  };

  SECTION("DLL flag is rejected") {
    auto mutated = source;
    std::uint16_t characteristics = 0U;
    std::memcpy(&characteristics, mutated.data() + layout.pe_offset + 4U + 18U,
                sizeof(characteristics));
    characteristics |= 0x2000U;
    poke(mutated, layout.pe_offset + 4U + 18U, characteristics);
    expect_rejection(mutated, PePatchError::kNotExecutable, "dll-flag");
  }

  SECTION("managed CLR directory is rejected") {
    auto mutated = source;
    poke<std::uint32_t>(mutated, layout.optional_offset + 112U + 14U * 8U, 0x2000U);
    poke<std::uint32_t>(mutated, layout.optional_offset + 116U + 14U * 8U, 0x48U);
    expect_rejection(mutated, PePatchError::kManaged, "managed");
  }

  SECTION("non-x64 machine is rejected") {
    auto mutated = source;
    poke<std::uint16_t>(mutated, layout.pe_offset + 4U, 0x14CU);  // I386
    expect_rejection(mutated, PePatchError::kNotX64, "i386");
  }

  SECTION("EFI subsystem is rejected") {
    auto mutated = source;
    poke<std::uint16_t>(mutated, layout.optional_offset + 68U, 10U);
    expect_rejection(mutated, PePatchError::kNotExecutable, "efi");
  }

  SECTION("UPX section names are rejected") {
    auto mutated = source;
    std::memcpy(mutated.data() + layout.section_table_offset, "UPX1\0\0\0\0", 8U);
    expect_rejection(mutated, PePatchError::kPacked, "upx");
  }

  SECTION("bad PE signature is rejected") {
    auto mutated = source;
    poke<std::uint32_t>(mutated, layout.pe_offset, 0U);
    expect_rejection(mutated, PePatchError::kNotPe, "bad-sig");
  }

  SECTION("entry point beyond the entry section raw data is rejected") {
    auto mutated = source;
    std::uint32_t entry_rva = 0U;
    std::memcpy(&entry_rva, mutated.data() + layout.optional_offset + 16U, sizeof(entry_rva));
    for (std::uint16_t index = 0U; index < layout.number_of_sections; ++index) {
      const std::uint64_t entry = layout.section_table_offset + index * 40ULL;
      std::uint32_t virtual_size = 0U;
      std::uint32_t virtual_address = 0U;
      std::uint32_t raw_size = 0U;
      std::memcpy(&virtual_size, mutated.data() + entry + 8U, sizeof(virtual_size));
      std::memcpy(&virtual_address, mutated.data() + entry + 12U, sizeof(virtual_address));
      std::memcpy(&raw_size, mutated.data() + entry + 16U, sizeof(raw_size));
      const std::uint64_t begin = virtual_address;
      const std::uint64_t size = (std::max)(static_cast<std::uint64_t>(virtual_size),
                                            static_cast<std::uint64_t>(raw_size));
      if (entry_rva < begin || entry_rva >= begin + size) {
        continue;
      }
      // Shrink the raw data so the entry RVA exists only virtually: still inside
      // max(virtual_size, raw_size), but past the raw bytes the patcher would touch.
      constexpr std::uint32_t shrunk = 0x200U;
      poke(mutated, entry + 16U, shrunk);
      poke(mutated, entry + 8U, (std::max)(virtual_size, shrunk + 0x200U));
      poke(mutated, layout.optional_offset + 16U, virtual_address + shrunk + 0x40U);
      expect_rejection(mutated, PePatchError::kMalformed, "virtual-tail-entry");
      const auto input = directory / "virtual-tail-info.exe";
      write_all(input, mutated);
      CHECK_FALSE(noleax::controller::windows::read_static_patch_info(input).has_value());
      return;
    }
    FAIL("test executable did not contain its entry point in a section");
  }

  SECTION("truncated image is rejected") {
    auto mutated = source;
    mutated.resize(layout.pe_offset + 0x40U);  // inside the optional header
    expect_rejection(mutated, PePatchError::kTruncated, "truncated");
  }

  SECTION("entry point outside sections is rejected") {
    auto mutated = source;
    poke<std::uint32_t>(mutated, layout.optional_offset + 16U, 0x7FFF'0000U);
    expect_rejection(mutated, PePatchError::kMalformed, "entry-outside");
  }

  SECTION("signature requires the explicit opt-in") {
    auto mutated = source;
    const std::uint64_t cert_offset = mutated.size();
    const std::array<std::byte, 16U> certificate{};
    mutated.insert(mutated.end(), certificate.begin(), certificate.end());
    poke<std::uint32_t>(mutated, layout.optional_offset + 112U + 4U * 8U,
                        static_cast<std::uint32_t>(cert_offset));
    poke<std::uint32_t>(mutated, layout.optional_offset + 116U + 4U * 8U,
                        static_cast<std::uint32_t>(certificate.size()));

    const auto input = directory / "signed.exe";
    write_all(input, mutated);
    try {
      static_cast<void>(noleax::controller::windows::patch_pe_image(
          options_for(input, directory / "signed-out.exe")));
      FAIL("expected the signed image to be rejected");
    } catch (const PePatchException& error) {
      CHECK(error.code() == PePatchError::kSigned);
    }

    auto options = options_for(input, directory / "signed-out.exe");
    options.allow_break_signature = true;
    const auto result = noleax::controller::windows::patch_pe_image(options);
    CHECK(result.signature_removed);
    CHECK(noleax::controller::windows::read_static_patch_info(directory / "signed-out.exe")
              .has_value());
  }

  SECTION("unexpected overlay is rejected") {
    auto mutated = source;
    mutated.push_back(std::byte{0xAA});
    expect_rejection(mutated, PePatchError::kOverlay, "overlay");
  }

  SECTION("existing output is rejected") {
    const auto input = directory / "plain.exe";
    const auto output = directory / "plain-out.exe";
    write_all(input, source);
    write_all(output, source);
    try {
      static_cast<void>(noleax::controller::windows::patch_pe_image(options_for(input, output)));
      FAIL("expected the existing output to be rejected");
    } catch (const PePatchException& error) {
      CHECK(error.code() == PePatchError::kOutputExists);
    }
  }

  SECTION("legacy temporary-name collisions are preserved") {
    const auto input = directory / "temporary-collision.exe";
    const auto output = directory / "temporary-collision-out.exe";
    const auto legacy_temporary = directory / "temporary-collision-out.exe.nlx-tmp";
    const std::vector<std::byte> sentinel{std::byte{0x4e}, std::byte{0x4c}, std::byte{0x58}};
    write_all(input, source);
    write_all(legacy_temporary, sentinel);

    static_cast<void>(noleax::controller::windows::patch_pe_image(options_for(input, output)));

    CHECK(read_all(legacy_temporary) == sentinel);
    CHECK(noleax::controller::windows::read_static_patch_info(output).has_value());
  }

  SECTION("agent name must be a bare file name") {
    const auto input = directory / "agent-name.exe";
    write_all(input, source);
    auto options = options_for(input, directory / "agent-name-out.exe");
    options.agent_name = "C:/evil/agent.dll";
    try {
      static_cast<void>(noleax::controller::windows::patch_pe_image(options));
      FAIL("expected the qualified agent name to be rejected");
    } catch (const PePatchException& error) {
      CHECK(error.code() == PePatchError::kMalformed);
    }
  }
}
