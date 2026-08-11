#include "noleax/agent/linux/memory_snapshot.hpp"

#include <cstdio>
#include <cstring>
#include <string_view>

namespace noleax::agent::linux {
namespace {

// /proc/self/status lines look like "VmRSS:\t   12345 kB". This reader walks the
// interesting keys once and reports values in bytes.
struct StatusCounters {
  std::uint64_t vm_rss{0U};
  std::uint64_t vm_hwm{0U};
  std::uint64_t rss_anon{0U};
  std::uint64_t vm_size{0U};
  bool has_rss{false};
  bool has_hwm{false};
  bool has_anon{false};
  bool has_size{false};
};

void parse_status_line(std::string_view line, StatusCounters& counters) noexcept {
  const auto colon = line.find(':');
  if (colon == std::string_view::npos) {
    return;
  }
  const std::string_view key = line.substr(0U, colon);
  std::string_view value = line.substr(colon + 1U);
  const auto begin = value.find_first_not_of(" \t");
  if (begin == std::string_view::npos) {
    return;
  }
  value = value.substr(begin);
  std::uint64_t number = 0U;
  std::size_t digits = 0U;
  while (digits < value.size() && value[digits] >= '0' && value[digits] <= '9') {
    number = number * 10U + static_cast<std::uint64_t>(value[digits] - '0');
    ++digits;
  }
  if (digits == 0U) {
    return;
  }
  number *= 1024U;  // status values are KiB

  if (key == "VmRSS") {
    counters.vm_rss = number;
    counters.has_rss = true;
  } else if (key == "VmHWM") {
    counters.vm_hwm = number;
    counters.has_hwm = true;
  } else if (key == "RssAnon") {
    counters.rss_anon = number;
    counters.has_anon = true;
  } else if (key == "VmSize") {
    counters.vm_size = number;
    counters.has_size = true;
  }
}

struct MapsRegion {
  std::uint64_t begin{0U};
  std::uint64_t end{0U};
  std::string_view permissions;
  std::string_view path;
};

[[nodiscard]] bool parse_maps_line(std::string_view line, MapsRegion& region) noexcept {
  const auto dash = line.find('-');
  if (dash == std::string_view::npos) {
    return false;
  }
  const auto parse_hex = [](std::string_view text, std::uint64_t& value) noexcept {
    value = 0U;
    if (text.empty()) {
      return false;
    }
    for (const char digit : text) {
      unsigned nibble = 0U;
      if (digit >= '0' && digit <= '9') {
        nibble = static_cast<unsigned>(digit) - static_cast<unsigned>('0');
      } else if (digit >= 'a' && digit <= 'f') {
        nibble = static_cast<unsigned>(digit) - static_cast<unsigned>('a') + 10U;
      } else if (digit >= 'A' && digit <= 'F') {
        nibble = static_cast<unsigned>(digit) - static_cast<unsigned>('A') + 10U;
      } else {
        return false;
      }
      value = (value << 4U) | nibble;
    }
    return true;
  };
  if (!parse_hex(line.substr(0U, dash), region.begin)) {
    return false;
  }
  const auto space = line.find(' ', dash);
  if (space == std::string_view::npos ||
      !parse_hex(line.substr(dash + 1U, space - dash - 1U), region.end)) {
    return false;
  }
  region.permissions = line.substr(space + 1U, 4U);
  if (region.permissions.size() != 4U || region.end <= region.begin) {
    return false;
  }
  // The path is whatever follows the fifth field separator, when present.
  std::size_t cursor = space + 1U;
  for (unsigned field = 0U; field < 4U; ++field) {
    cursor = line.find(' ', cursor);
    if (cursor == std::string_view::npos) {
      return true;  // no path column
    }
    ++cursor;
  }
  const auto path_begin = line.find_first_not_of(' ', cursor);
  if (path_begin != std::string_view::npos) {
    region.path = line.substr(path_begin);
  }
  return true;
}

}  // namespace

bool capture_memory_counters(noleax::trace::MemoryCounters& counters) noexcept {
  FILE* const status = std::fopen("/proc/self/status", "re");
  if (status == nullptr) {
    return false;
  }
  StatusCounters parsed;
  char line[512];
  while (std::fgets(line, sizeof(line), status) != nullptr) {
    parse_status_line(line, parsed);
  }
  std::fclose(status);
  if (!parsed.has_rss || !parsed.has_hwm || !parsed.has_size) {
    return false;
  }
  counters.working_set_bytes = parsed.vm_rss;
  counters.peak_working_set_bytes = parsed.vm_hwm;
  counters.private_bytes = parsed.has_anon ? parsed.rss_anon : parsed.vm_rss;
  counters.commit_bytes = parsed.vm_size;
  return true;
}

bool capture_memory_map(noleax::trace::MemoryMap& map) {
  FILE* const maps = std::fopen("/proc/self/maps", "re");
  if (maps == nullptr) {
    return false;
  }
  map.truncated = false;
  map.committed_bytes = 0U;
  map.reserved_bytes = 0U;
  map.free_bytes = 0U;
  map.largest_free_bytes = 0U;
  map.regions.clear();

  char line[1024];
  std::uint64_t previous_end = 0U;
  while (std::fgets(line, sizeof(line), maps) != nullptr) {
    MapsRegion region;
    if (!parse_maps_line(line, region)) {
      continue;
    }
    if (region.begin > previous_end && previous_end != 0U) {
      const std::uint64_t gap = region.begin - previous_end;
      map.free_bytes += gap;
      if (gap > map.largest_free_bytes) {
        map.largest_free_bytes = gap;
      }
    }
    previous_end = region.end;

    const std::uint64_t size = region.end - region.begin;
    // The first three permission columns carry r/w/x; the fourth (p/s) is not a
    // protection bit. A ---p region is PROT_NONE and reports kReserve.
    const bool readable =
        region.permissions.substr(0U, 3U).find_first_not_of('-') != std::string_view::npos;
    if (readable) {
      map.committed_bytes += size;
    } else {
      map.reserved_bytes += size;
    }
    if (map.regions.size() < noleax::trace::kMaximumMemoryMapRegions) {
      noleax::trace::MemoryMapRegion entry;
      entry.base = region.begin;
      entry.size = size;
      entry.state = readable ? noleax::trace::MemoryRegionState::kCommit
                             : noleax::trace::MemoryRegionState::kReserve;
      const bool executable = region.permissions.find('x') != std::string_view::npos;
      entry.type = region.path.empty() ? noleax::trace::MemoryRegionType::kPrivate
                   : executable        ? noleax::trace::MemoryRegionType::kImage
                                       : noleax::trace::MemoryRegionType::kMapped;
      std::uint64_t protect = 0U;
      if (region.permissions.find('r') != std::string_view::npos) {
        protect |= 1U;  // PROT_READ
      }
      if (region.permissions.find('w') != std::string_view::npos) {
        protect |= 2U;  // PROT_WRITE
      }
      if (executable) {
        protect |= 4U;  // PROT_EXEC
      }
      entry.protect = static_cast<std::uint32_t>(protect);
      map.regions.push_back(entry);
    } else {
      map.truncated = true;
    }
  }
  std::fclose(maps);
  return true;
}

}  // namespace noleax::agent::linux
