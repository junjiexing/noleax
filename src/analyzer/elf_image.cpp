#include "elf_image.hpp"

#include <cxxabi.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace noleax::analyzer::elf {
namespace {

// Symbol kind tags mirroring the DbgHelp SymTagEnum values consumed by symbol_kind_from_tag;
// kept numeric here so the listing code stays backend-agnostic.
constexpr std::uint32_t kListingTagFunction = 5U;
constexpr std::uint32_t kListingTagData = 7U;
constexpr std::uint32_t kListingTagPublicSymbol = 10U;

[[nodiscard]] std::uint32_t current_errno() noexcept { return static_cast<std::uint32_t>(errno); }

// Positional reader over an open image file. Only the headers, symbol/string tables, and note
// sections are read; the whole file is never pulled into memory.
class FileReader {
 public:
  explicit FileReader(const std::filesystem::path& path) {
    fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) {
      throw ElfImageError{"cannot open the ELF image", current_errno()};
    }
    struct stat status {};
    if (::fstat(fd_, &status) != 0) {
      throw ElfImageError{"cannot stat the ELF image", current_errno()};
    }
    if (status.st_size < 0) {
      throw ElfImageError{"the ELF image has an invalid size"};
    }
    size_ = static_cast<std::uint64_t>(status.st_size);
  }

  ~FileReader() {
    if (fd_ >= 0) {
      static_cast<void>(::close(fd_));
    }
  }

  FileReader(const FileReader&) = delete;
  FileReader& operator=(const FileReader&) = delete;

  [[nodiscard]] std::uint64_t size() const noexcept { return size_; }

  void read_exact(std::uint64_t offset, void* buffer, std::size_t count) const {
    if (static_cast<std::uint64_t>(count) > size_ || offset > size_ - count) {
      throw ElfImageError{"the ELF image is truncated"};
    }
    auto* output = static_cast<std::byte*>(buffer);
    std::size_t done = 0;
    while (done < count) {
      const ssize_t chunk =
          ::pread(fd_, output + done, count - done, static_cast<off_t>(offset + done));
      if (chunk < 0) {
        if (errno == EINTR) {
          continue;
        }
        throw ElfImageError{"cannot read the ELF image", current_errno()};
      }
      if (chunk == 0) {
        throw ElfImageError{"the ELF image is truncated"};
      }
      done += static_cast<std::size_t>(chunk);
    }
  }

  template <typename T>
  [[nodiscard]] T read_struct(std::uint64_t offset) const {
    T value{};
    read_exact(offset, &value, sizeof(T));
    return value;
  }

  [[nodiscard]] std::vector<std::byte> read(std::uint64_t offset, std::uint64_t count) const {
    // Bound the allocation by the file size before touching the vector.
    if (count > size_) {
      throw ElfImageError{"the ELF image is truncated"};
    }
    std::vector<std::byte> result(static_cast<std::size_t>(count));
    read_exact(offset, result.data(), result.size());
    return result;
  }

 private:
  int fd_{-1};
  std::uint64_t size_{0};
};

// Throws when [offset, offset + count * entry_size) is not fully inside the file; entry sizes
// are also validated so fixed-size tables cannot be mis-strided.
void ensure_table_span(std::uint64_t file_size, std::uint64_t offset, std::uint64_t entry_size,
                       std::uint64_t minimum_entry_size, std::uint64_t count) {
  if (count == 0U) {
    return;
  }
  if (entry_size < minimum_entry_size) {
    throw ElfImageError{"an ELF table has an invalid entry size"};
  }
  if (offset > file_size || count > (file_size - offset) / entry_size) {
    throw ElfImageError{"an ELF table escapes the image"};
  }
}

[[nodiscard]] std::size_t align4(std::size_t value) noexcept {
  return (value + 3U) & ~std::size_t{3U};
}

[[nodiscard]] std::string read_symbol_name(const std::vector<std::byte>& strings,
                                           std::uint32_t name_offset) {
  if (name_offset == 0U) {
    return {};
  }
  if (name_offset >= strings.size()) {
    throw ElfImageError{"a symbol name escapes the string table"};
  }
  const auto* const begin = strings.data() + name_offset;
  const std::size_t remaining = strings.size() - name_offset;
  const void* const terminator = std::memchr(begin, '\0', remaining);
  if (terminator == nullptr) {
    throw ElfImageError{"a symbol name is not terminated"};
  }
  const auto length = static_cast<const std::byte*>(terminator) - begin;
  return {reinterpret_cast<const char*>(begin), static_cast<std::size_t>(length)};
}

[[nodiscard]] std::vector<ElfSymbol> parse_symbol_table(
    const FileReader& file, const Elf64_Shdr& table, std::uint64_t section_offset,
    std::uint64_t section_entry_size, std::uint64_t section_count, SymbolTable origin) {
  std::vector<ElfSymbol> result;
  if (table.sh_size == 0U) {
    return result;
  }
  if (table.sh_entsize < sizeof(Elf64_Sym)) {
    throw ElfImageError{"a symbol table has an invalid entry size"};
  }
  const std::uint64_t count = table.sh_size / table.sh_entsize;
  ensure_table_span(file.size(), table.sh_offset, table.sh_entsize, sizeof(Elf64_Sym), count);
  if (table.sh_link >= section_count) {
    throw ElfImageError{"a symbol table links an invalid string table"};
  }
  const auto strings_header = file.read_struct<Elf64_Shdr>(
      section_offset + static_cast<std::uint64_t>(table.sh_link) * section_entry_size);
  if (strings_header.sh_type != SHT_STRTAB) {
    throw ElfImageError{"a symbol table links a non-string table"};
  }
  const std::vector<std::byte> strings =
      file.read(strings_header.sh_offset, strings_header.sh_size);
  const std::vector<std::byte> entries = file.read(table.sh_offset, table.sh_size);
  result.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t index = 0; index < count; ++index) {
    Elf64_Sym entry{};
    std::memcpy(&entry, entries.data() + index * table.sh_entsize, sizeof(entry));
    ElfSymbol symbol;
    symbol.name = read_symbol_name(strings, entry.st_name);
    symbol.value = entry.st_value;
    symbol.size = entry.st_size;
    symbol.section_index = entry.st_shndx;
    symbol.type = static_cast<std::uint8_t>(ELF64_ST_TYPE(entry.st_info));
    symbol.binding = static_cast<std::uint8_t>(ELF64_ST_BIND(entry.st_info));
    symbol.table = origin;
    result.push_back(std::move(symbol));
  }
  return result;
}

[[nodiscard]] bool is_lookup_function(const ElfSymbol& symbol) noexcept {
  return (symbol.type == STT_FUNC || symbol.type == STT_GNU_IFUNC) &&
         symbol.section_index != SHN_UNDEF && !symbol.name.empty();
}

[[nodiscard]] std::vector<std::size_t> sorted_function_indices(
    const std::vector<ElfSymbol>& symbols) {
  std::vector<std::size_t> indices;
  for (std::size_t index = 0; index < symbols.size(); ++index) {
    if (is_lookup_function(symbols[index])) {
      indices.push_back(index);
    }
  }
  std::sort(indices.begin(), indices.end(), [&symbols](std::size_t left, std::size_t right) {
    return symbols[left].value < symbols[right].value;
  });
  return indices;
}

[[nodiscard]] bool covers(const ElfSymbol& symbol, std::uint64_t vaddr) noexcept {
  return symbol.size != 0U && vaddr - symbol.value < symbol.size;
}

// All candidates share the same st_value (the nearest below the probe). Prefer a sized symbol
// whose range covers the probe (the tightest such), then a non-local binding, then the
// lexicographically smallest name for determinism.
[[nodiscard]] bool is_better_match(const ElfSymbol& candidate, const ElfSymbol* current,
                                   std::uint64_t vaddr) noexcept {
  if (current == nullptr) {
    return true;
  }
  const bool candidate_covers = covers(candidate, vaddr);
  if (candidate_covers != covers(*current, vaddr)) {
    return candidate_covers;
  }
  if (candidate_covers && candidate.size != current->size) {
    return candidate.size < current->size;
  }
  const bool candidate_global = candidate.binding != STB_LOCAL;
  if (candidate_global != (current->binding != STB_LOCAL)) {
    return candidate_global;
  }
  return candidate.name < current->name;
}

[[nodiscard]] std::optional<ElfSymbol> find_function_in(const std::vector<ElfSymbol>& symbols,
                                                        const std::vector<std::size_t>& functions,
                                                        std::uint64_t vaddr) {
  const auto first_above = std::upper_bound(
      functions.begin(), functions.end(), vaddr,
      [&symbols](std::uint64_t probe, std::size_t index) { return probe < symbols[index].value; });
  if (first_above == functions.begin()) {
    return std::nullopt;
  }
  auto cursor = std::prev(first_above);
  const std::uint64_t base_value = symbols[*cursor].value;
  const ElfSymbol* best = nullptr;
  for (;;) {
    const ElfSymbol& candidate = symbols[*cursor];
    if (is_better_match(candidate, best, vaddr)) {
      best = &candidate;
    }
    if (cursor == functions.begin()) {
      break;
    }
    const auto previous = std::prev(cursor);
    if (symbols[*previous].value != base_value) {
      break;
    }
    cursor = previous;
  }
  if (best == nullptr) {
    return std::nullopt;
  }
  return *best;
}

// Scans one SHT_NOTE section for the GNU build ID note (name "GNU", type NT_GNU_BUILD_ID).
void read_build_id_note(const FileReader& file, const Elf64_Shdr& section,
                        std::vector<std::byte>& build_id) {
  if (!build_id.empty() || section.sh_size == 0U) {
    return;
  }
  const std::vector<std::byte> bytes = file.read(section.sh_offset, section.sh_size);
  std::size_t cursor = 0;
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
    cursor = align4(cursor + name_size);
    if (cursor > bytes.size() || descriptor_size > bytes.size() - cursor) {
      return;
    }
    if (gnu_name && header.n_type == NT_GNU_BUILD_ID) {
      build_id.assign(bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
                      bytes.begin() + static_cast<std::ptrdiff_t>(cursor + descriptor_size));
      return;
    }
    cursor = align4(cursor + descriptor_size);
  }
}

}  // namespace

ElfImage::ElfImage(const std::filesystem::path& path) {
  FileReader file{path};
  const auto header = file.read_struct<Elf64_Ehdr>(0);
  if (header.e_ident[EI_MAG0] != ELFMAG0 || header.e_ident[EI_MAG1] != ELFMAG1 ||
      header.e_ident[EI_MAG2] != ELFMAG2 || header.e_ident[EI_MAG3] != ELFMAG3) {
    throw ElfImageError{"the image is not an ELF file"};
  }
  if (header.e_ident[EI_CLASS] != ELFCLASS64) {
    throw ElfImageError{"the ELF image is not 64-bit"};
  }
  // The reader mirrors the little-endian file layout directly; the hosts this backend builds
  // for are little-endian as well.
  if (header.e_ident[EI_DATA] != ELFDATA2LSB) {
    throw ElfImageError{"the ELF image is not little-endian"};
  }
  if (header.e_ident[EI_VERSION] != EV_CURRENT || header.e_version != EV_CURRENT) {
    throw ElfImageError{"the ELF image has an unsupported version"};
  }
  if (header.e_machine != EM_X86_64) {
    throw ElfImageError{"the ELF image is not an x86-64 image"};
  }
  if (header.e_type != ET_EXEC && header.e_type != ET_DYN) {
    throw ElfImageError{"the ELF image is not a loadable executable or shared object"};
  }

  // Extended numbering: real counts live in section header 0 when the 16-bit fields overflow.
  std::uint64_t section_count = header.e_shnum;
  std::uint64_t program_count = header.e_phnum;
  if (header.e_shoff != 0U && (header.e_shnum == 0U || header.e_phnum == PN_XNUM)) {
    const auto first_section = file.read_struct<Elf64_Shdr>(header.e_shoff);
    if (header.e_shnum == 0U) {
      section_count = first_section.sh_size;
    }
    if (header.e_phnum == PN_XNUM) {
      program_count = first_section.sh_info;
    }
  }

  ensure_table_span(file.size(), header.e_phoff, header.e_phentsize, sizeof(Elf64_Phdr),
                    program_count);
  bool found_load_segment = false;
  for (std::uint64_t index = 0; index < program_count; ++index) {
    const auto segment = file.read_struct<Elf64_Phdr>(
        header.e_phoff + index * static_cast<std::uint64_t>(header.e_phentsize));
    if (segment.p_type != PT_LOAD) {
      continue;
    }
    if (!found_load_segment || segment.p_vaddr < minimum_load_vaddr_) {
      minimum_load_vaddr_ = segment.p_vaddr;
    }
    found_load_segment = true;
  }
  if (!found_load_segment) {
    throw ElfImageError{"the ELF image has no loadable segments"};
  }

  if (section_count != 0U) {
    ensure_table_span(file.size(), header.e_shoff, header.e_shentsize, sizeof(Elf64_Shdr),
                      section_count);
  }
  std::optional<Elf64_Shdr> symtab_header;
  std::optional<Elf64_Shdr> dynsym_header;
  std::vector<Elf64_Shdr> note_headers;
  for (std::uint64_t index = 0; index < section_count; ++index) {
    const auto section = file.read_struct<Elf64_Shdr>(
        header.e_shoff + index * static_cast<std::uint64_t>(header.e_shentsize));
    if (section.sh_type == SHT_SYMTAB && !symtab_header.has_value()) {
      symtab_header = section;
    } else if (section.sh_type == SHT_DYNSYM && !dynsym_header.has_value()) {
      dynsym_header = section;
    } else if (section.sh_type == SHT_NOTE) {
      note_headers.push_back(section);
    }
  }

  if (symtab_header.has_value()) {
    symtab_ = parse_symbol_table(file, *symtab_header, header.e_shoff, header.e_shentsize,
                                 section_count, SymbolTable::kSymtab);
  }
  if (dynsym_header.has_value()) {
    dynsym_ = parse_symbol_table(file, *dynsym_header, header.e_shoff, header.e_shentsize,
                                 section_count, SymbolTable::kDynsym);
  }
  symtab_functions_ = sorted_function_indices(symtab_);
  dynsym_functions_ = sorted_function_indices(dynsym_);
  for (const Elf64_Shdr& note : note_headers) {
    read_build_id_note(file, note, build_id_);
  }
}

std::optional<ElfSymbol> ElfImage::find_function(std::uint64_t vaddr) const {
  if (std::optional<ElfSymbol> match = find_function_in(symtab_, symtab_functions_, vaddr)) {
    return match;
  }
  return find_function_in(dynsym_, dynsym_functions_, vaddr);
}

std::optional<ElfSymbol> ElfImage::find_symbol(std::string_view name) const {
  if (name.empty()) {
    return std::nullopt;
  }
  for (const SymbolTable table : {SymbolTable::kSymtab, SymbolTable::kDynsym}) {
    const std::vector<ElfSymbol>& table_symbols = symbols(table);
    const ElfSymbol* best = nullptr;
    for (const ElfSymbol& symbol : table_symbols) {
      if (symbol.section_index == SHN_UNDEF || symbol.name != name) {
        continue;
      }
      if (best == nullptr || (best->binding == STB_LOCAL && symbol.binding != STB_LOCAL)) {
        best = &symbol;
      }
    }
    if (best != nullptr) {
      return *best;
    }
  }
  return std::nullopt;
}

bool is_displayable(const ElfSymbol& symbol) noexcept {
  return symbol.section_index != SHN_UNDEF && !symbol.name.empty() && symbol.type != STT_FILE &&
         symbol.type != STT_SECTION;
}

std::uint32_t listing_tag(const ElfSymbol& symbol) noexcept {
  if (symbol.type == STT_FUNC || symbol.type == STT_GNU_IFUNC) {
    return kListingTagFunction;
  }
  if (symbol.type == STT_OBJECT || symbol.type == STT_TLS) {
    return kListingTagData;
  }
  return kListingTagPublicSymbol;
}

std::string demangle(std::string_view name) {
  if (name.empty()) {
    return {};
  }
  const std::string mangled{name};
  int status = 0;
  char* const decoded = abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status);
  if (status != 0 || decoded == nullptr) {
    return mangled;
  }
  std::string result{decoded};
  std::free(decoded);
  return result;
}

}  // namespace noleax::analyzer::elf
