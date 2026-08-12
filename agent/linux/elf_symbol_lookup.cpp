// Agent-side ELF symbol lookup (docs/CUSTOM_HOOKS.md): resolves a `_sym` custom hook role to
// the symbol's link-time st_value by scanning the module's on-disk image. Self-contained and
// streaming (the agent must not link the analyzer, and real debug companions reach multiple
// GB with millions of symbols): fixed-size headers are read once, symbol tables stream in
// bounded chunks, and names resolve through a sliding window over the linked string table.
// Every read is bounds-checked against the file size and every malformed shape degrades to
// "not found" — a corrupt or hostile image must never take the target down at install time.

#include "noleax/agent/linux/elf_symbol_lookup.hpp"

#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace noleax::agent::linux {
namespace {

// Defensive caps for install-time inputs (mirrors the custom_symbol_hooks.cpp ELF reader):
// enough for every real image, small enough that a hostile file cannot force huge reads.
inline constexpr std::uint64_t kMaximumSectionCount = 65'536U;
inline constexpr std::uint64_t kMaximumSectionNamesSize = 1U << 20U;
inline constexpr std::uint64_t kMaximumSymbolEntrySize = 4U << 10U;
inline constexpr std::uint64_t kMaximumNoteSectionSize = 1U << 20U;
inline constexpr std::uint64_t kMaximumDebugLinkSize = 1U << 10U;
inline constexpr std::size_t kMaximumSymbolNameSize = 4U << 10U;
inline constexpr std::size_t kSymbolChunkBytes = 128U << 10U;
inline constexpr std::size_t kStringWindowBytes = 256U << 10U;
inline constexpr std::size_t kCrcChunkBytes = 1U << 20U;
inline constexpr std::string_view kDebugLinkSectionName = ".gnu_debuglink";

// Positional reader over an open image file. Only bounded spans are read; the whole file is
// never pulled into memory.
class FileReader {
 public:
  FileReader() = default;
  ~FileReader() {
    if (fd_ >= 0) {
      static_cast<void>(::close(fd_));
    }
  }

  FileReader(const FileReader&) = delete;
  FileReader& operator=(const FileReader&) = delete;

  FileReader(FileReader&& other) noexcept : fd_{other.fd_}, size_{other.size_} {
    other.fd_ = -1;
    other.size_ = 0U;
  }
  FileReader& operator=(FileReader&& other) noexcept {
    if (this != &other) {
      if (fd_ >= 0) {
        static_cast<void>(::close(fd_));
      }
      fd_ = other.fd_;
      size_ = other.size_;
      other.fd_ = -1;
      other.size_ = 0U;
    }
    return *this;
  }

  [[nodiscard]] bool open(const std::filesystem::path& path) noexcept {
    fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) {
      return false;
    }
    struct stat status {};
    if (::fstat(fd_, &status) != 0 || status.st_size < 0) {
      static_cast<void>(::close(fd_));
      fd_ = -1;
      return false;
    }
    size_ = static_cast<std::uint64_t>(status.st_size);
    return true;
  }

  [[nodiscard]] std::uint64_t size() const noexcept { return size_; }

  [[nodiscard]] bool span_inside(std::uint64_t offset, std::uint64_t count) const noexcept {
    return count <= size_ && offset <= size_ - count;
  }

  // Reads exactly count bytes at offset; false on a short or failed read.
  [[nodiscard]] bool read_at(std::uint64_t offset, void* buffer, std::size_t count) const noexcept {
    if (!span_inside(offset, static_cast<std::uint64_t>(count))) {
      return false;
    }
    auto* output = static_cast<std::byte*>(buffer);
    std::size_t done = 0U;
    while (done < count) {
      const ssize_t chunk =
          ::pread(fd_, output + done, count - done, static_cast<off_t>(offset + done));
      if (chunk < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      if (chunk == 0) {
        return false;
      }
      done += static_cast<std::size_t>(chunk);
    }
    return true;
  }

  template <typename T>
  [[nodiscard]] bool read_struct(std::uint64_t offset, T& value) const noexcept {
    return read_at(offset, &value, sizeof(T));
  }

 private:
  int fd_{-1};
  std::uint64_t size_{0U};
};

// zlib/IEEE CRC32 (reflected polynomial, NOT the CRC32C Castagnoli polynomial), table-driven.
[[nodiscard]] constexpr std::array<std::uint32_t, 256U> make_crc32_table() noexcept {
  std::array<std::uint32_t, 256U> table{};
  for (std::uint32_t value = 0U; value < table.size(); ++value) {
    std::uint32_t crc = value;
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc >> 1U) ^ ((crc & 1U) != 0U ? 0xEDB88320U : 0U);
    }
    table[value] = crc;
  }
  return table;
}

inline constexpr std::array<std::uint32_t, 256U> kCrc32Table = make_crc32_table();

// The GNU debuglink CRC is the standard zlib CRC-32 of the whole companion file.
[[nodiscard]] std::optional<std::uint32_t> crc32_of_file(const FileReader& file) noexcept {
  std::uint32_t crc = 0xFFFFFFFFU;
  std::vector<char> buffer(kCrcChunkBytes);
  std::uint64_t offset = 0U;
  while (offset < file.size()) {
    const std::size_t chunk = static_cast<std::size_t>(
        (std::min)(file.size() - offset, static_cast<std::uint64_t>(buffer.size())));
    if (!file.read_at(offset, buffer.data(), chunk)) {
      return std::nullopt;
    }
    for (std::size_t index = 0U; index < chunk; ++index) {
      crc = kCrc32Table[(crc ^ static_cast<unsigned char>(buffer[index])) & 0xFFU] ^ (crc >> 8U);
    }
    offset += chunk;
  }
  return crc ^ 0xFFFFFFFFU;
}

// One symbol table (.symtab or .dynsym) with its linked string table, all spans validated
// against the file size.
struct SymbolTableSpan {
  std::uint64_t offset{0U};
  std::uint64_t size{0U};
  std::uint64_t entry_size{0U};
  std::uint64_t strings_offset{0U};
  std::uint64_t strings_size{0U};
};

// The .gnu_debuglink payload: a NUL-terminated companion basename plus its 4-byte-aligned
// GNU CRC32.
struct DebugLink {
  std::string name;
  std::uint32_t crc32{0U};
};

struct ParsedElf {
  FileReader file;
  std::vector<Elf64_Shdr> sections;
  std::vector<char> section_names;  // empty when the shstrtab is unusable
  std::optional<SymbolTableSpan> symtab;
  std::optional<SymbolTableSpan> dynsym;
  std::optional<DebugLink> debuglink;
  std::vector<std::byte> build_id;
};

[[nodiscard]] bool valid_section_span(const FileReader& file, const Elf64_Shdr& section,
                                      std::uint64_t maximum_size) noexcept {
  return section.sh_size != 0U && section.sh_size <= maximum_size &&
         file.span_inside(section.sh_offset, section.sh_size);
}

[[nodiscard]] std::optional<SymbolTableSpan> symbol_table_span(
    const FileReader& file, const std::vector<Elf64_Shdr>& sections,
    const Elf64_Shdr& table) noexcept {
  if (table.sh_size == 0U || table.sh_entsize < sizeof(Elf64_Sym) ||
      table.sh_entsize > kMaximumSymbolEntrySize || table.sh_link >= sections.size() ||
      !file.span_inside(table.sh_offset, table.sh_size)) {
    return std::nullopt;
  }
  const Elf64_Shdr& strings = sections[table.sh_link];
  if (strings.sh_type != SHT_STRTAB || !file.span_inside(strings.sh_offset, strings.sh_size)) {
    return std::nullopt;
  }
  SymbolTableSpan span;
  span.offset = table.sh_offset;
  span.size = table.sh_size;
  span.entry_size = table.sh_entsize;
  span.strings_offset = strings.sh_offset;
  span.strings_size = strings.sh_size;
  return span;
}

// Scans one SHT_NOTE section for the GNU build ID note (name "GNU", type NT_GNU_BUILD_ID).
void note_build_id(const FileReader& file, const Elf64_Shdr& section,
                   std::vector<std::byte>& build_id) noexcept {
  if (!build_id.empty() || !valid_section_span(file, section, kMaximumNoteSectionSize)) {
    return;
  }
  std::vector<std::byte> bytes(static_cast<std::size_t>(section.sh_size));
  if (!file.read_at(section.sh_offset, bytes.data(), bytes.size())) {
    return;
  }
  std::size_t cursor = 0U;
  while (cursor <= bytes.size() && bytes.size() - cursor >= sizeof(Elf64_Nhdr)) {
    Elf64_Nhdr header{};
    std::memcpy(&header, bytes.data() + cursor, sizeof(header));
    cursor += sizeof(Elf64_Nhdr);
    const std::size_t name_size = header.n_namesz;
    const std::size_t descriptor_size = header.n_descsz;
    if (name_size > bytes.size() - cursor) {
      return;
    }
    const bool gnu_name = name_size == 4U && std::memcmp(bytes.data() + cursor, "GNU", 3U) == 0;
    cursor = (cursor + name_size + 3U) & ~std::size_t{3U};
    if (cursor > bytes.size() || descriptor_size > bytes.size() - cursor) {
      return;
    }
    if (gnu_name && header.n_type == NT_GNU_BUILD_ID) {
      build_id.assign(bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
                      bytes.begin() + static_cast<std::ptrdiff_t>(cursor + descriptor_size));
      return;
    }
    cursor = (cursor + descriptor_size + 3U) & ~std::size_t{3U};
  }
}

[[nodiscard]] std::string_view section_name(const std::vector<char>& names,
                                            const Elf64_Shdr& section) noexcept {
  if (section.sh_name >= names.size()) {
    return {};
  }
  const char* const begin = names.data() + section.sh_name;
  const std::size_t remaining = names.size() - section.sh_name;
  const void* const terminator = std::memchr(begin, '\0', remaining);
  if (terminator == nullptr) {
    return {};
  }
  return {begin, static_cast<std::size_t>(static_cast<const char*>(terminator) - begin)};
}

[[nodiscard]] std::optional<DebugLink> parse_debug_link(const FileReader& file,
                                                        const Elf64_Shdr& section) noexcept {
  if (!valid_section_span(file, section, kMaximumDebugLinkSize)) {
    return std::nullopt;
  }
  std::array<char, kMaximumDebugLinkSize> bytes{};
  if (!file.read_at(section.sh_offset, bytes.data(), static_cast<std::size_t>(section.sh_size))) {
    return std::nullopt;
  }
  const std::size_t size = static_cast<std::size_t>(section.sh_size);
  const void* const terminator = std::memchr(bytes.data(), '\0', size);
  if (terminator == nullptr) {
    return std::nullopt;
  }
  const std::size_t name_size =
      static_cast<std::size_t>(static_cast<const char*>(terminator) - bytes.data());
  const std::string_view name{bytes.data(), name_size};
  // A bare basename only: separators and dot names would escape the search directories.
  if (name.empty() || name == "." || name == ".." ||
      name.find_first_of("/\\") != std::string_view::npos) {
    return std::nullopt;
  }
  const std::size_t crc_offset = (name_size + 1U + 3U) & ~std::size_t{3U};
  if (crc_offset > size || size - crc_offset < sizeof(std::uint32_t)) {
    return std::nullopt;
  }
  std::uint32_t crc32 = 0U;
  std::memcpy(&crc32, bytes.data() + crc_offset, sizeof(crc32));
  return DebugLink{std::string{name}, crc32};
}

// Parses the ELF64 header and section table of the image at `path`. Extended section
// numbering (real counts in section header 0) is supported; anything truncated, oversized,
// or inconsistent yields nullopt.
[[nodiscard]] std::optional<ParsedElf> parse_elf(const std::filesystem::path& path) noexcept {
  ParsedElf parsed;
  if (!parsed.file.open(path)) {
    return std::nullopt;
  }
  Elf64_Ehdr header{};
  if (!parsed.file.read_struct(0U, header) || std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
      header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
      header.e_ident[EI_VERSION] != EV_CURRENT || header.e_version != EV_CURRENT ||
      header.e_machine != EM_X86_64 || (header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
      header.e_shoff == 0U || header.e_shentsize != sizeof(Elf64_Shdr)) {
    return std::nullopt;
  }

  std::uint64_t section_count = header.e_shnum;
  std::uint64_t names_index = header.e_shstrndx;
  if (header.e_shnum == 0U || header.e_shstrndx == SHN_XINDEX) {
    // Extended numbering: the real counts live in section header 0.
    Elf64_Shdr first{};
    if (!parsed.file.read_struct(header.e_shoff, first)) {
      return std::nullopt;
    }
    if (header.e_shnum == 0U) {
      section_count = first.sh_size;
    }
    if (header.e_shstrndx == SHN_XINDEX) {
      names_index = first.sh_link;
    }
  }
  if (section_count == 0U || section_count > kMaximumSectionCount ||
      !parsed.file.span_inside(header.e_shoff, section_count * sizeof(Elf64_Shdr))) {
    return std::nullopt;
  }
  parsed.sections.resize(static_cast<std::size_t>(section_count));
  if (!parsed.file.read_at(header.e_shoff, parsed.sections.data(),
                           parsed.sections.size() * sizeof(Elf64_Shdr))) {
    return std::nullopt;
  }

  if (names_index < parsed.sections.size() &&
      valid_section_span(parsed.file, parsed.sections[names_index], kMaximumSectionNamesSize) &&
      parsed.sections[names_index].sh_type == SHT_STRTAB) {
    parsed.section_names.resize(static_cast<std::size_t>(parsed.sections[names_index].sh_size));
    if (!parsed.file.read_at(parsed.sections[names_index].sh_offset, parsed.section_names.data(),
                             parsed.section_names.size())) {
      parsed.section_names.clear();
    }
  }

  for (const Elf64_Shdr& section : parsed.sections) {
    if (section.sh_type == SHT_SYMTAB && !parsed.symtab.has_value()) {
      parsed.symtab = symbol_table_span(parsed.file, parsed.sections, section);
    } else if (section.sh_type == SHT_DYNSYM && !parsed.dynsym.has_value()) {
      parsed.dynsym = symbol_table_span(parsed.file, parsed.sections, section);
    } else if (section.sh_type == SHT_NOTE) {
      note_build_id(parsed.file, section, parsed.build_id);
    } else if (!parsed.debuglink.has_value() &&
               section_name(parsed.section_names, section) == kDebugLinkSectionName) {
      parsed.debuglink = parse_debug_link(parsed.file, section);
    }
  }
  return parsed;
}

// Answers "is the name at `name_offset` exactly `wanted`" through a sliding window over the
// string table: sequential scans hit the window, so a table of millions of names costs one
// bounded read per window instead of one per name (and never a whole-table allocation).
class StringTableMatcher {
 public:
  StringTableMatcher(const FileReader& file, std::uint64_t offset, std::uint64_t size,
                     std::string_view wanted) noexcept
      : file_{&file}, offset_{offset}, size_{size}, wanted_{wanted} {
    window_.resize(kStringWindowBytes);
  }

  [[nodiscard]] bool matches(std::uint32_t name_offset) noexcept {
    const std::uint64_t needed = wanted_.size() + 1U;
    if (name_offset >= size_ || size_ - name_offset < needed) {
      return false;
    }
    if (name_offset < window_start_ || name_offset + needed > window_start_ + window_valid_) {
      window_start_ = name_offset;
      window_valid_ = static_cast<std::size_t>(
          (std::min)(size_ - name_offset, static_cast<std::uint64_t>(window_.size())));
      if (!file_->read_at(offset_ + name_offset, window_.data(), window_valid_)) {
        window_valid_ = 0U;
        return false;
      }
    }
    const char* const at = window_.data() + (name_offset - window_start_);
    return std::memcmp(at, wanted_.data(), wanted_.size()) == 0 && at[wanted_.size()] == '\0';
  }

 private:
  const FileReader* file_;
  std::uint64_t offset_;
  std::uint64_t size_;
  std::string_view wanted_;
  std::vector<char> window_;
  std::uint64_t window_start_{0U};
  std::size_t window_valid_{0U};
};

// Streams one symbol table in bounded chunks and returns the link-time st_value of the first
// defined exact-name match.
[[nodiscard]] std::optional<std::uint64_t> scan_symbol_table(const FileReader& file,
                                                             const SymbolTableSpan& span,
                                                             std::string_view wanted) {
  StringTableMatcher matcher{file, span.strings_offset, span.strings_size, wanted};
  const std::uint64_t count = span.size / span.entry_size;
  const std::uint64_t entries_per_chunk = (std::max)(
      std::uint64_t{1U}, static_cast<std::uint64_t>(kSymbolChunkBytes) / span.entry_size);
  std::vector<std::byte> chunk(static_cast<std::size_t>(entries_per_chunk * span.entry_size));
  for (std::uint64_t base = 0U; base < count; base += entries_per_chunk) {
    const std::uint64_t entries = (std::min)(count - base, entries_per_chunk);
    const std::size_t bytes = static_cast<std::size_t>(entries * span.entry_size);
    if (!file.read_at(span.offset + base * span.entry_size, chunk.data(), bytes)) {
      return std::nullopt;
    }
    for (std::uint64_t index = 0U; index < entries; ++index) {
      Elf64_Sym symbol{};
      std::memcpy(&symbol, chunk.data() + static_cast<std::size_t>(index * span.entry_size),
                  sizeof(symbol));
      // Undefined imports and nameless entries can never be the hook target.
      if (symbol.st_shndx == SHN_UNDEF || symbol.st_name == 0U) {
        continue;
      }
      if (matcher.matches(symbol.st_name)) {
        return symbol.st_value;
      }
    }
  }
  return std::nullopt;
}

[[nodiscard]] std::optional<std::uint64_t> find_symbol_in(const ParsedElf& parsed,
                                                          std::string_view wanted) {
  if (parsed.symtab.has_value()) {
    if (std::optional<std::uint64_t> value =
            scan_symbol_table(parsed.file, *parsed.symtab, wanted)) {
      return value;
    }
  }
  if (parsed.dynsym.has_value()) {
    return scan_symbol_table(parsed.file, *parsed.dynsym, wanted);
  }
  return std::nullopt;
}

// The companion candidates of a .gnu_debuglink basename, in gdb's search order: beside the
// image, in its .debug/ subdirectory, and under /usr/lib/debug at the image's absolute path.
[[nodiscard]] std::vector<std::filesystem::path> debuglink_candidates(
    const std::filesystem::path& module_path, const std::string& name) noexcept {
  std::vector<std::filesystem::path> candidates;
  std::error_code error;
  const std::filesystem::path absolute = std::filesystem::absolute(module_path, error);
  if (error) {
    return candidates;
  }
  const std::filesystem::path directory = absolute.parent_path();
  candidates.push_back(directory / name);
  candidates.push_back(directory / ".debug" / name);
  const std::filesystem::path relative = absolute.relative_path();
  if (!relative.empty()) {
    candidates.push_back(std::filesystem::path{"/usr/lib/debug"} / relative.parent_path() / name);
  }
  return candidates;
}

// A companion is trusted only when its Build ID matches the image's (whenever both carry
// one) and its whole-file GNU CRC32 matches the debuglink's stored value.
[[nodiscard]] bool companion_identity_matches(const ParsedElf& image, ParsedElf& companion,
                                              std::uint32_t expected_crc32) noexcept {
  if (!image.build_id.empty() && !companion.build_id.empty() &&
      image.build_id != companion.build_id) {
    return false;
  }
  const std::optional<std::uint32_t> crc32 = crc32_of_file(companion.file);
  return crc32.has_value() && *crc32 == expected_crc32;
}

[[nodiscard]] std::optional<std::uint64_t> find_elf_symbol_vaddr_impl(
    const std::filesystem::path& module_path, std::string_view symbol_name) {
  if (symbol_name.empty() || symbol_name.size() > kMaximumSymbolNameSize) {
    return std::nullopt;
  }
  std::optional<ParsedElf> image = parse_elf(module_path);
  if (!image.has_value()) {
    return std::nullopt;
  }
  if (std::optional<std::uint64_t> value = find_symbol_in(*image, symbol_name)) {
    return value;
  }
  // The image's own tables had their say; the debuglink companion is only consulted when
  // the image has no usable .symtab at all (the stripped-binary case).
  if (image->symtab.has_value() || !image->debuglink.has_value()) {
    return std::nullopt;
  }
  for (const std::filesystem::path& candidate :
       debuglink_candidates(module_path, image->debuglink->name)) {
    std::optional<ParsedElf> companion = parse_elf(candidate);
    if (!companion.has_value()) {
      continue;
    }
    if (!companion_identity_matches(*image, *companion, image->debuglink->crc32)) {
      continue;
    }
    if (std::optional<std::uint64_t> value = find_symbol_in(*companion, symbol_name)) {
      return value;
    }
  }
  return std::nullopt;
}

}  // namespace

std::optional<std::uint64_t> find_elf_symbol_vaddr(const std::filesystem::path& module_path,
                                                   std::string_view symbol_name) {
  try {
    return find_elf_symbol_vaddr_impl(module_path, symbol_name);
  } catch (...) {
    // Install-time robustness: a hostile or racing image degrades to "not found", never to
    // an exception escaping into the bootstrap.
    return std::nullopt;
  }
}

}  // namespace noleax::agent::linux
