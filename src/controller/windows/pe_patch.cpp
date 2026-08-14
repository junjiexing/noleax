#include "noleax/controller/windows/pe_patch.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "static_pe_patch_layout.hpp"

namespace noleax::controller::windows {
namespace {

constexpr std::uint64_t kMaxImageSize = 512ULL * 1024ULL * 1024ULL;
constexpr std::uint16_t kMachineAmd64 = 0x8664U;
constexpr std::uint16_t kPe32PlusMagic = 0x20BU;
constexpr std::uint16_t kImageFileExecutableImage = 0x0002U;
constexpr std::uint16_t kImageFileDll = 0x2000U;
constexpr std::uint16_t kSubsystemNative = 1U;
constexpr std::uint16_t kSubsystemEfiApplication = 10U;
constexpr std::uint16_t kSubsystemEfiRom = 13U;
constexpr std::size_t kDirectorySecurity = 4U;
constexpr std::size_t kDirectoryClr = 14U;
constexpr std::uint32_t kScnCntCode = 0x0000'0020U;
constexpr std::uint32_t kScnCntInitializedData = 0x0000'0040U;
constexpr std::uint32_t kScnMemExecute = 0x2000'0000U;
constexpr std::uint32_t kScnMemRead = 0x4000'0000U;
constexpr std::uint32_t kScnMemWrite = 0x8000'0000U;
constexpr std::size_t kMaxSections = 96U;
constexpr std::size_t kSectionHeaderSize = 40U;
constexpr char kBootstrapSectionName[] = ".nlxboot";

[[noreturn]] void reject(PePatchError code, const std::string& message) {
  throw PePatchException{code, message};
}

class TemporaryPatchFile final {
 public:
  explicit TemporaryPatchFile(const std::filesystem::path& output) {
    static std::atomic<std::uint64_t> ordinal{0U};
    for (std::uint32_t attempt = 0U; attempt < 128U; ++attempt) {
      const std::uint64_t suffix = ordinal.fetch_add(1U, std::memory_order_relaxed);
      path_ = output.parent_path() /
              (output.filename().native() + L".nlx-tmp-" +
               std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(suffix));
      handle_ = CreateFileW(path_.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_TEMPORARY, nullptr);
      if (handle_ != INVALID_HANDLE_VALUE) {
        return;
      }
      const DWORD error = GetLastError();
      if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
        reject(PePatchError::kIo,
               "cannot create the temporary patch output (Windows error " +
                   std::to_string(error) + ")");
      }
    }
    reject(PePatchError::kIo, "cannot allocate a unique temporary patch output name");
  }

  ~TemporaryPatchFile() {
    close();
    if (remove_on_destroy_) {
      std::error_code error;
      static_cast<void>(std::filesystem::remove(path_, error));
    }
  }

  TemporaryPatchFile(const TemporaryPatchFile&) = delete;
  TemporaryPatchFile& operator=(const TemporaryPatchFile&) = delete;

  void write(std::span<const std::byte> data) {
    std::size_t offset = 0U;
    while (offset < data.size()) {
      const DWORD requested = static_cast<DWORD>((std::min)(
          data.size() - offset, static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
      DWORD written = 0U;
      if (WriteFile(handle_, data.data() + offset, requested, &written, nullptr) == FALSE ||
          written == 0U) {
        reject(PePatchError::kIo, "cannot write the temporary patch output");
      }
      offset += written;
    }
    if (FlushFileBuffers(handle_) == FALSE) {
      reject(PePatchError::kIo, "cannot flush the temporary patch output");
    }
    close();
  }

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

  void release() noexcept { remove_on_destroy_ = false; }

 private:
  void close() noexcept {
    if (handle_ != INVALID_HANDLE_VALUE) {
      static_cast<void>(CloseHandle(handle_));
      handle_ = INVALID_HANDLE_VALUE;
    }
  }

  std::filesystem::path path_;
  HANDLE handle_{INVALID_HANDLE_VALUE};
  bool remove_on_destroy_{true};
};

template <typename Value>
[[nodiscard]] Value read_at(const std::vector<std::byte>& data, std::uint64_t offset,
                            const char* subject) {
  if (offset > data.size() || sizeof(Value) > data.size() - offset) {
    reject(PePatchError::kTruncated, std::string{"image ends inside "} + subject);
  }
  Value value{};
  std::memcpy(&value, data.data() + offset, sizeof(Value));
  return value;
}

template <typename Value>
void write_at(std::vector<std::byte>& data, std::uint64_t offset, const Value& value) {
  std::memcpy(data.data() + offset, &value, sizeof(Value));
}

[[nodiscard]] std::vector<std::byte> read_file(const std::filesystem::path& path,
                                               const char* subject) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error || size > kMaxImageSize) {
    reject(PePatchError::kIo, std::string{"cannot inspect "} + subject + " file size");
  }
  std::ifstream input{path, std::ios::binary};
  if (!input) {
    reject(PePatchError::kIo, std::string{"cannot open "} + subject);
  }
  std::vector<std::byte> data(static_cast<std::size_t>(size));
  if (size != 0U &&
      !input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size))) {
    reject(PePatchError::kIo, std::string{"cannot read "} + subject);
  }
  return data;
}

struct Directory {
  std::uint32_t rva{0U};
  std::uint32_t size{0U};
};

struct Section {
  std::array<char, 8U> name{};
  std::uint32_t virtual_size{0U};
  std::uint32_t virtual_address{0U};
  std::uint32_t raw_size{0U};
  std::uint32_t raw_offset{0U};
  std::uint32_t characteristics{0U};

  [[nodiscard]] std::string_view name_view() const {
    const auto length =
        static_cast<std::size_t>(std::find(name.begin(), name.end(), '\0') - name.begin());
    return std::string_view{name.data(), length};
  }
};

struct PeImage {
  std::uint32_t pe_offset{0U};
  std::uint16_t machine{0U};
  std::uint16_t number_of_sections{0U};
  std::uint16_t characteristics{0U};
  std::uint32_t entry_rva{0U};
  std::uint32_t section_alignment{0U};
  std::uint32_t file_alignment{0U};
  std::uint32_t size_of_image{0U};
  std::uint32_t size_of_headers{0U};
  std::uint32_t checksum{0U};
  std::uint16_t subsystem{0U};
  std::array<Directory, 16U> directories{};
  std::vector<Section> sections;
  std::uint32_t section_table_offset{0U};
};

[[nodiscard]] PeImage parse_pe(const std::vector<std::byte>& data) {
  if (read_at<std::uint16_t>(data, 0U, "the DOS header") != 0x5A4DU) {  // "MZ"
    reject(PePatchError::kNotPe, "missing the MZ signature");
  }
  PeImage image;
  image.pe_offset = read_at<std::uint32_t>(data, 0x3CU, "the PE header offset");
  if (image.pe_offset < 0x40U || image.pe_offset > data.size()) {
    reject(PePatchError::kMalformed, "the PE header offset is out of bounds");
  }
  if (read_at<std::uint32_t>(data, image.pe_offset, "the PE signature") != 0x0000'4550U) {
    reject(PePatchError::kNotPe, "missing the PE signature");
  }
  const std::uint64_t coff = image.pe_offset + 4ULL;
  image.machine = read_at<std::uint16_t>(data, coff, "the COFF header");
  image.number_of_sections = read_at<std::uint16_t>(data, coff + 2U, "the COFF header");
  if (image.number_of_sections == 0U || image.number_of_sections > kMaxSections) {
    reject(PePatchError::kMalformed, "the section count is implausible");
  }
  const std::uint16_t optional_size = read_at<std::uint16_t>(data, coff + 16U, "the COFF header");
  if (optional_size < 0xF0U) {
    reject(PePatchError::kNotPe, "the optional header is not PE32+");
  }
  image.characteristics = read_at<std::uint16_t>(data, coff + 18U, "the COFF header");
  const std::uint64_t optional = coff + 20U;
  if (optional + optional_size > data.size()) {
    reject(PePatchError::kTruncated, "image ends inside the optional header");
  }
  if (read_at<std::uint16_t>(data, optional, "the optional header") != kPe32PlusMagic) {
    reject(PePatchError::kNotX64, "the image is not a PE32+ binary");
  }
  image.entry_rva = read_at<std::uint32_t>(data, optional + 16U, "the entry point");
  image.section_alignment = read_at<std::uint32_t>(data, optional + 32U, "SectionAlignment");
  image.file_alignment = read_at<std::uint32_t>(data, optional + 36U, "FileAlignment");
  image.size_of_image = read_at<std::uint32_t>(data, optional + 56U, "SizeOfImage");
  image.size_of_headers = read_at<std::uint32_t>(data, optional + 60U, "SizeOfHeaders");
  image.checksum = read_at<std::uint32_t>(data, optional + 64U, "CheckSum");
  image.subsystem = read_at<std::uint16_t>(data, optional + 68U, "Subsystem");
  const std::uint32_t directory_count =
      read_at<std::uint32_t>(data, optional + 108U, "NumberOfRvaAndSizes");
  if (directory_count < 15U) {
    reject(PePatchError::kMalformed, "the image has too few data directories");
  }
  for (std::size_t index = 0U; index < image.directories.size(); ++index) {
    image.directories[index].rva =
        read_at<std::uint32_t>(data, optional + 112U + index * 8U, "a data directory");
    image.directories[index].size =
        read_at<std::uint32_t>(data, optional + 116U + index * 8U, "a data directory");
  }
  image.section_table_offset =
      static_cast<std::uint32_t>(optional + static_cast<std::uint64_t>(optional_size));
  for (std::uint16_t index = 0U; index < image.number_of_sections; ++index) {
    const std::uint64_t offset = static_cast<std::uint64_t>(image.section_table_offset) +
                                 static_cast<std::uint64_t>(index) * kSectionHeaderSize;
    Section section;
    if (offset + kSectionHeaderSize > data.size()) {
      reject(PePatchError::kTruncated, "image ends inside a section header");
    }
    std::memcpy(section.name.data(), data.data() + offset, section.name.size());
    section.virtual_size = read_at<std::uint32_t>(data, offset + 8U, "a section header");
    section.virtual_address = read_at<std::uint32_t>(data, offset + 12U, "a section header");
    section.raw_size = read_at<std::uint32_t>(data, offset + 16U, "a section header");
    section.raw_offset = read_at<std::uint32_t>(data, offset + 20U, "a section header");
    section.characteristics = read_at<std::uint32_t>(data, offset + 36U, "a section header");
    if (section.raw_size != 0U &&
        (section.raw_offset > data.size() || section.raw_size > data.size() - section.raw_offset)) {
      reject(PePatchError::kMalformed, "a section's raw data exceeds the image");
    }
    image.sections.push_back(section);
  }
  return image;
}

[[nodiscard]] std::uint32_t align_up(std::uint64_t value, std::uint32_t alignment,
                                     const char* subject) {
  if (alignment == 0U || (alignment & (alignment - 1U)) != 0U) {
    reject(PePatchError::kMalformed, std::string{subject} + " is not a power of two");
  }
  const std::uint64_t aligned = (value + alignment - 1U) & ~std::uint64_t{alignment - 1U};
  if (aligned > std::numeric_limits<std::uint32_t>::max()) {
    reject(PePatchError::kMalformed, std::string{subject} + " overflows 32 bits");
  }
  return static_cast<std::uint32_t>(aligned);
}

[[nodiscard]] const Section& entry_section(const PeImage& image) {
  for (const Section& section : image.sections) {
    const std::uint64_t begin = section.virtual_address;
    const std::uint64_t size = (std::max)(static_cast<std::uint64_t>(section.virtual_size),
                                          static_cast<std::uint64_t>(section.raw_size));
    if (image.entry_rva >= begin && image.entry_rva < begin + size) {
      return section;
    }
  }
  reject(PePatchError::kMalformed, "the entry point is not inside any section");
}

// The entry probe reads 4 bytes (endbr64 check) and the patch writes kEntryPatchSize
// bytes at up to 4 bytes past the entry: both must stay inside the section's raw data.
[[nodiscard]] bool entry_has_raw_room(const Section& entry, std::uint64_t entry_rva) {
  const std::uint64_t entry_offset = entry_rva - entry.virtual_address;
  return entry_offset <= entry.raw_size &&
         4U + pepatch::kEntryPatchSize <= entry.raw_size - entry_offset;
}

void validate_patchable(const PeImage& image, std::uint64_t file_size, bool allow_break_signature) {
  if (image.machine != kMachineAmd64) {
    reject(PePatchError::kNotX64, "only native x64 (AMD64) images are supported");
  }
  if ((image.characteristics & kImageFileExecutableImage) == 0U) {
    reject(PePatchError::kNotPe, "the image is not an executable");
  }
  if ((image.characteristics & kImageFileDll) != 0U) {
    reject(PePatchError::kNotExecutable, "only executables are supported, not DLLs");
  }
  if (image.subsystem == kSubsystemNative ||
      (image.subsystem >= kSubsystemEfiApplication && image.subsystem <= kSubsystemEfiRom)) {
    reject(PePatchError::kNotExecutable, "drivers and EFI images are not supported");
  }
  if (image.directories[kDirectoryClr].rva != 0U) {
    reject(PePatchError::kManaged, "managed (.NET) images are not supported");
  }
  for (const Section& section : image.sections) {
    const std::string_view name = section.name_view();
    if (name == "UPX0" || name == "UPX1" || name == "UPX2") {
      reject(PePatchError::kPacked, "UPX-packed images are not supported");
    }
    if (name == kBootstrapSectionName) {
      reject(PePatchError::kMalformed, "the image already contains a noleax bootstrap section");
    }
  }
  const Section& entry = entry_section(image);
  if (entry.raw_size == 0U) {
    reject(PePatchError::kPacked, "the entry section has no raw data (packed image?)");
  }
  if (!entry_has_raw_room(entry, image.entry_rva)) {
    reject(PePatchError::kMalformed, "the entry point is outside the entry section's raw data");
  }
  if ((entry.characteristics & kScnMemExecute) == 0U) {
    reject(PePatchError::kMalformed, "the entry section is not executable");
  }

  std::uint64_t raw_end = image.size_of_headers;
  for (const Section& section : image.sections) {
    raw_end =
        (std::max)(raw_end, static_cast<std::uint64_t>(section.raw_offset) + section.raw_size);
  }
  const Directory& certificate = image.directories[kDirectorySecurity];
  const bool has_overlay = raw_end < file_size;
  if (certificate.rva != 0U || certificate.size != 0U) {
    if (!allow_break_signature) {
      reject(PePatchError::kSigned,
             "the image is Authenticode-signed; pass --allow-break-signature to patch anyway");
    }
    if (static_cast<std::uint64_t>(certificate.rva) != raw_end ||
        static_cast<std::uint64_t>(certificate.rva) + certificate.size != file_size) {
      reject(PePatchError::kOverlay,
             "the signature is not the only overlay; refusing to guess its layout");
    }
  } else if (has_overlay) {
    reject(PePatchError::kOverlay, "the image has data appended after its sections");
  }

  const std::uint64_t headers_end =
      static_cast<std::uint64_t>(image.section_table_offset) +
      static_cast<std::uint64_t>(image.number_of_sections) * kSectionHeaderSize +
      kSectionHeaderSize;
  std::uint64_t first_raw = file_size;
  for (const Section& section : image.sections) {
    if (section.raw_size != 0U) {
      first_raw = (std::min)(first_raw, static_cast<std::uint64_t>(section.raw_offset));
    }
  }
  if (headers_end > first_raw || headers_end > image.size_of_headers) {
    reject(PePatchError::kNoHeaderSpace, "no room for one more section header");
  }
  if (image.section_alignment < 0x1000U || image.file_alignment < 0x200U ||
      image.file_alignment > image.section_alignment) {
    reject(PePatchError::kMalformed, "implausible alignment values");
  }
}

[[nodiscard]] std::wstring validate_agent_name(const std::string& agent_name) {
  if (agent_name.empty() || agent_name.size() > (pepatch::kAgentNameCapacity / 2U) - 1U ||
      agent_name.find_first_of("\\/:*?\"<>|") != std::string::npos) {
    reject(PePatchError::kMalformed,
           "patch.agent_name must be a bare file name of at most 63 characters");
  }
  std::wstring wide;
  wide.reserve(agent_name.size());
  for (const char character : agent_name) {
    if (static_cast<unsigned char>(character) < 0x20U ||
        static_cast<unsigned char>(character) > 0x7EU) {
      reject(PePatchError::kMalformed, "patch.agent_name must be printable ASCII");
    }
    wide.push_back(static_cast<wchar_t>(character));
  }
  return wide;
}

struct EntryPatchPlan {
  std::uint32_t patch_rva{0U};
  std::uint32_t patch_raw_offset{0U};
  std::array<std::byte, pepatch::kEntryPatchSize> original_bytes{};
  std::int32_t jump_offset{0};
};

// Computes the on-disk direct jump written at the entry point. The first
// instruction is kept intact when it is endbr64; the direct rel32 branch
// needs no CFG target and stays valid under ASLR.
[[nodiscard]] EntryPatchPlan plan_entry_patch(const PeImage& image,
                                              const std::vector<std::byte>& data,
                                              std::uint32_t section_rva) {
  const Section& entry = entry_section(image);
  const std::uint64_t entry_raw =
      static_cast<std::uint64_t>(entry.raw_offset) + (image.entry_rva - entry.virtual_address);
  EntryPatchPlan plan;
  std::uint32_t first_bytes = 0U;
  std::memcpy(&first_bytes, data.data() + entry_raw, sizeof(first_bytes));
  const std::uint32_t patch_offset =
      first_bytes == 0xFA1E0FF3U ? 4U : 0U;  // endbr64 stays in place
  plan.patch_rva = image.entry_rva + patch_offset;
  plan.patch_raw_offset = static_cast<std::uint32_t>(entry_raw + patch_offset);
  std::memcpy(plan.original_bytes.data(), data.data() + plan.patch_raw_offset,
              plan.original_bytes.size());
  const std::int64_t distance = static_cast<std::int64_t>(section_rva) -
                                static_cast<std::int64_t>(plan.patch_rva) -
                                static_cast<std::int64_t>(pepatch::kEntryPatchSize);
  if (distance < std::numeric_limits<std::int32_t>::min() ||
      distance > std::numeric_limits<std::int32_t>::max()) {
    reject(PePatchError::kMalformed, "the bootstrap section is out of direct-jump range");
  }
  plan.jump_offset = static_cast<std::int32_t>(distance);
  return plan;
}

[[nodiscard]] std::vector<std::byte> build_section_content(
    std::uint32_t section_rva, std::uint32_t entry_rva, std::uint32_t patch_rva,
    const std::array<std::byte, pepatch::kEntryPatchSize>& original_bytes,
    const std::wstring& agent_name, bool standalone) {
  std::vector<std::byte> content(pepatch::kContentSize, std::byte{0U});
  std::memcpy(content.data(), pepatch::kStaticStub.data(), pepatch::kStaticStub.size());
  if (standalone) {
    // Bake standalone capture activation into the parameter area: the stub loads the
    // agent, and the agent recognizes the magic token and records without a controller.
    noleax::agent::windows::BootstrapParameters parameters;
    parameters.session_token = noleax::agent::windows::kStandaloneMagic;
    constexpr wchar_t kStandaloneSentinel[] = L"standalone";
    std::memcpy(parameters.pipe_name.data(), kStandaloneSentinel, sizeof(kStandaloneSentinel));
    parameters.connect_timeout_ms = 0U;
    parameters.controller_process_id = 0U;
    std::memcpy(content.data() + pepatch::kParamsOffset, &parameters, sizeof(parameters));
  }
  write_at<std::uint32_t>(content, pepatch::kFixupSectionRvaOffset, section_rva);
  write_at<std::uint32_t>(content, pepatch::kFixupEntryRvaOffset, entry_rva);
  std::memcpy(content.data() + pepatch::kMarkerOffset, pepatch::kMarker, pepatch::kMarkerSize);
  std::memcpy(content.data() + pepatch::kAgentNameOffset, agent_name.c_str(),
              (agent_name.size() + 1U) * sizeof(wchar_t));
  std::memcpy(content.data() + pepatch::kBootstrapSymbolOffset, pepatch::kBootstrapSymbol,
              sizeof(pepatch::kBootstrapSymbol));
  std::memcpy(content.data() + pepatch::kReadySymbolOffset, pepatch::kReadySymbol,
              sizeof(pepatch::kReadySymbol));
  write_at<std::uint32_t>(content, pepatch::kHashKernelbaseOffset, pepatch::kKernelbaseHash);
  write_at<std::uint32_t>(content, pepatch::kHashLoadLibraryOffset, pepatch::kLoadLibraryHash);
  write_at<std::uint32_t>(content, pepatch::kHashGetProcAddressOffset,
                          pepatch::kGetProcAddressHash);
  write_at<std::uint32_t>(content, pepatch::kHashSleepOffset, pepatch::kSleepHash);
  write_at<std::uint32_t>(content, pepatch::kHashNtdllOffset, pepatch::kNtdllHash);
  write_at<std::uint32_t>(content, pepatch::kHashVirtualProtectOffset,
                          pepatch::kVirtualProtectHash);
  write_at<std::uint32_t>(content, pepatch::kHashNtFlushOffset,
                          pepatch::kNtFlushInstructionCacheHash);
  std::memcpy(content.data() + pepatch::kOriginalBytesOffset, original_bytes.data(),
              original_bytes.size());
  write_at<std::uint64_t>(content, pepatch::kPatchRvaOffset, patch_rva);
  return content;
}

[[nodiscard]] std::uint64_t entry_raw_offset(const PeImage& image, const Section& entry) {
  return static_cast<std::uint64_t>(entry.raw_offset) + (image.entry_rva - entry.virtual_address);
}

void verify_patched_image(const std::filesystem::path& path, const PePatchResult& expected,
                          const EntryPatchPlan& plan) {
  const std::vector<std::byte> data = read_file(path, "the patched output");
  const PeImage image = parse_pe(data);
  if (image.entry_rva != expected.entry_rva || image.number_of_sections == 0U) {
    reject(PePatchError::kMalformed, "the patched output changed the entry point RVA");
  }
  const Section& section = image.sections.back();
  if (section.name_view() != kBootstrapSectionName ||
      section.virtual_address != expected.section_rva ||
      (section.characteristics & kScnMemExecute) == 0U ||
      (section.characteristics & kScnMemWrite) == 0U) {
    reject(PePatchError::kMalformed, "the patched output is missing its bootstrap section");
  }
  std::array<char, pepatch::kMarkerSize> marker{};
  std::memcpy(marker.data(), data.data() + section.raw_offset + pepatch::kMarkerOffset,
              marker.size());
  if (std::memcmp(marker.data(), pepatch::kMarker, pepatch::kMarkerSize) != 0) {
    reject(PePatchError::kMalformed, "the patched output is missing its marker");
  }
  if (read_at<std::uint32_t>(data, section.raw_offset + pepatch::kFixupSectionRvaOffset,
                             "a stub fixup") != expected.section_rva ||
      read_at<std::uint32_t>(data, section.raw_offset + pepatch::kFixupEntryRvaOffset,
                             "a stub fixup") != expected.entry_rva ||
      read_at<std::uint64_t>(data, section.raw_offset + pepatch::kPatchRvaOffset,
                             "the patch RVA") != expected.patch_rva) {
    reject(PePatchError::kMalformed, "the patched output has inconsistent stub fixups");
  }
  std::array<std::byte, pepatch::kEntryPatchSize> saved{};
  std::memcpy(saved.data(), data.data() + section.raw_offset + pepatch::kOriginalBytesOffset,
              saved.size());
  if (saved != plan.original_bytes) {
    reject(PePatchError::kMalformed, "the patched output lost the original entry bytes");
  }
  if (data[plan.patch_raw_offset] != std::byte{0xE9}) {
    reject(PePatchError::kMalformed, "the patched output is missing the entry jump");
  }
  std::int32_t jump_offset = 0;
  std::memcpy(&jump_offset, data.data() + plan.patch_raw_offset + 1U, sizeof(jump_offset));
  if (jump_offset != plan.jump_offset) {
    reject(PePatchError::kMalformed, "the patched entry jump offset is inconsistent");
  }
}

}  // namespace

PePatchException::PePatchException(PePatchError code, const std::string& message)
    : std::runtime_error{message}, code_{code} {}

PePatchError PePatchException::code() const noexcept { return code_; }

PePatchResult patch_pe_image(const PePatchOptions& options) {
  if (options.input.empty() || options.output.empty()) {
    reject(PePatchError::kMalformed, "patch input and output paths are required");
  }
  std::error_code exists_error;
  if (std::filesystem::exists(options.output, exists_error) || exists_error) {
    reject(PePatchError::kOutputExists, "the patch output already exists");
  }
  std::vector<std::byte> data = read_file(options.input, "the patch input");
  const PeImage image = parse_pe(data);
  validate_patchable(image, data.size(), options.allow_break_signature);
  const std::wstring agent_name = validate_agent_name(options.agent_name);

  PePatchResult result;
  result.entry_rva = image.entry_rva;

  std::uint32_t highest_va = image.size_of_headers;
  for (const Section& section : image.sections) {
    const std::uint64_t end = static_cast<std::uint64_t>(section.virtual_address) +
                              (std::max)(static_cast<std::uint64_t>(section.virtual_size),
                                         static_cast<std::uint64_t>(section.raw_size));
    highest_va = (std::max)(highest_va, align_up(end, image.section_alignment, "SizeOfImage"));
  }
  result.section_rva = highest_va;
  result.signature_removed = image.directories[kDirectorySecurity].rva != 0U;

  // The entry RVA stays untouched: only the first bytes after a possible
  // endbr64 become a direct jump to the bootstrap section. That keeps the
  // loader's CFG check and IBT landing on the original entry valid and is
  // relocation-safe under ASLR.
  const EntryPatchPlan plan = plan_entry_patch(image, data, result.section_rva);
  result.patch_rva = plan.patch_rva;

  // Strip the certificate overlay when allowed; anything else was rejected.
  const std::uint64_t raw_end =
      result.signature_removed
          ? static_cast<std::uint64_t>(image.directories[kDirectorySecurity].rva)
          : static_cast<std::uint64_t>(data.size());
  data.resize(static_cast<std::size_t>(raw_end));

  const std::uint32_t new_raw_offset = align_up(data.size(), image.file_alignment, "the raw size");
  const std::uint32_t new_raw_size =
      align_up(pepatch::kContentSize, image.file_alignment, "the raw size");
  const std::vector<std::byte> content =
      build_section_content(result.section_rva, result.entry_rva, result.patch_rva,
                            plan.original_bytes, agent_name, options.standalone);

  Section bootstrap;
  std::memcpy(bootstrap.name.data(), kBootstrapSectionName, sizeof(kBootstrapSectionName) - 1U);
  bootstrap.virtual_size = static_cast<std::uint32_t>(pepatch::kContentSize);
  bootstrap.virtual_address = result.section_rva;
  bootstrap.raw_size = new_raw_size;
  bootstrap.raw_offset = new_raw_offset;
  bootstrap.characteristics =
      kScnCntCode | kScnCntInitializedData | kScnMemExecute | kScnMemRead | kScnMemWrite;

  data.resize(new_raw_offset, std::byte{0U});
  const std::uint64_t optional = image.pe_offset + 4ULL + 20ULL;
  write_at<std::uint16_t>(data, image.pe_offset + 4ULL + 2U,
                          static_cast<std::uint16_t>(image.number_of_sections + 1U));
  write_at<std::uint32_t>(
      data, optional + 56U,
      align_up(static_cast<std::uint64_t>(result.section_rva) + pepatch::kContentSize,
               image.section_alignment, "SizeOfImage"));
  write_at<std::uint32_t>(data, optional + 64U, 0U);  // CheckSum: recomputed as not applicable
  write_at<std::uint32_t>(data, optional + 112U + kDirectorySecurity * 8U, 0U);
  write_at<std::uint32_t>(data, optional + 116U + kDirectorySecurity * 8U, 0U);

  // On-disk entry jump: E9 <rel32> to the bootstrap section.
  data[plan.patch_raw_offset] = std::byte{0xE9};
  std::memcpy(data.data() + plan.patch_raw_offset + 1U, &plan.jump_offset,
              sizeof(plan.jump_offset));

  const std::uint64_t new_header_offset =
      static_cast<std::uint64_t>(image.section_table_offset) +
      static_cast<std::uint64_t>(image.number_of_sections) * kSectionHeaderSize;
  write_at<std::uint32_t>(data, new_header_offset + 8U, bootstrap.virtual_size);
  write_at<std::uint32_t>(data, new_header_offset + 12U, bootstrap.virtual_address);
  write_at<std::uint32_t>(data, new_header_offset + 16U, bootstrap.raw_size);
  write_at<std::uint32_t>(data, new_header_offset + 20U, bootstrap.raw_offset);
  write_at<std::uint32_t>(data, new_header_offset + 36U, bootstrap.characteristics);
  std::memcpy(data.data() + new_header_offset, bootstrap.name.data(), bootstrap.name.size());

  data.resize(static_cast<std::size_t>(new_raw_offset) + new_raw_size, std::byte{0U});
  std::memcpy(data.data() + new_raw_offset, content.data(), content.size());
  result.output_size = data.size();

  TemporaryPatchFile temporary{options.output};
  temporary.write(data);
  if (options.verify) {
    verify_patched_image(temporary.path(), result, plan);
  }
  std::filesystem::rename(temporary.path(), options.output);
  temporary.release();
  return result;
}

std::optional<StaticPatchInfo> read_static_patch_info(const std::filesystem::path& image_path) {
  std::vector<std::byte> data;
  try {
    data = read_file(image_path, "the target image");
    const PeImage image = parse_pe(data);
    for (const Section& section : image.sections) {
      if (section.name_view() != kBootstrapSectionName) {
        continue;
      }
      if (section.raw_size < pepatch::kContentSize) {
        return std::nullopt;
      }
      std::array<char, pepatch::kMarkerSize> marker{};
      std::memcpy(marker.data(), data.data() + section.raw_offset + pepatch::kMarkerOffset,
                  marker.size());
      if (std::memcmp(marker.data(), pepatch::kMarker, pepatch::kMarkerSize) != 0) {
        return std::nullopt;
      }
      // The entry must carry our direct jump into the bootstrap section.
      const Section& entry = entry_section(image);
      if (!entry_has_raw_room(entry, image.entry_rva)) {
        return std::nullopt;
      }
      const std::uint64_t entry_raw = entry_raw_offset(image, entry);
      std::uint32_t first_bytes = 0U;
      std::memcpy(&first_bytes, data.data() + entry_raw, sizeof(first_bytes));
      const std::uint32_t patch_offset = first_bytes == 0xFA1E0FF3U ? 4U : 0U;
      const std::uint64_t patch_raw = entry_raw + patch_offset;
      if (data[patch_raw] != std::byte{0xE9}) {
        return std::nullopt;
      }
      std::int32_t jump_offset = 0;
      std::memcpy(&jump_offset, data.data() + patch_raw + 1U, sizeof(jump_offset));
      const std::int64_t target = static_cast<std::int64_t>(image.entry_rva) +
                                  static_cast<std::int64_t>(patch_offset) +
                                  static_cast<std::int64_t>(pepatch::kEntryPatchSize) +
                                  static_cast<std::int64_t>(jump_offset);
      if (target != static_cast<std::int64_t>(section.virtual_address)) {
        return std::nullopt;
      }
      return StaticPatchInfo{
          image.entry_rva, section.virtual_address,
          section.virtual_address + static_cast<std::uint32_t>(pepatch::kParamsOffset)};
    }
    return std::nullopt;
  } catch (const PePatchException&) {
    return std::nullopt;
  }
}

}  // namespace noleax::controller::windows
