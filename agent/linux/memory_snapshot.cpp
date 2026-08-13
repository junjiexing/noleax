#include "noleax/agent/linux/memory_snapshot.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string_view>
#include <vector>

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

namespace detail {

MapsSummary summarize_maps_regions(const std::vector<MapsSummaryRegion>& regions,
                                   std::uint64_t canonical_user_end) noexcept {
  MapsSummary summary;
  std::uint64_t previous_end = 0U;
  for (const MapsSummaryRegion& region : regions) {
    if (region.end <= region.begin || region.begin >= canonical_user_end) {
      continue;  // kernel-only mappings (e.g. [vsyscall]) never enter the aggregates
    }
    const std::uint64_t end = (std::min)(region.end, canonical_user_end + 1U);
    // Saturating adds: within the canonical clamp the totals cannot approach 2^64, so
    // saturation is a defensive bound, not a reachable outcome.
    const auto add = [](std::uint64_t& total, std::uint64_t delta) noexcept {
      if (delta > std::numeric_limits<std::uint64_t>::max() - total) {
        total = std::numeric_limits<std::uint64_t>::max();
      } else {
        total += delta;
      }
    };
    if (region.begin > previous_end && previous_end != 0U) {
      const std::uint64_t gap = region.begin - previous_end;
      add(summary.free_bytes, gap);
      if (gap > summary.largest_free_bytes) {
        summary.largest_free_bytes = gap;
      }
    }
    previous_end = (std::max)(previous_end, end);
    add(summary.committed_bytes, region.committed ? end - region.begin : 0U);
    add(summary.reserved_bytes, region.committed ? 0U : end - region.begin);
  }
  return summary;
}

std::uint64_t canonical_user_end() noexcept {
  static const std::uint64_t cached = [] {
    std::uint64_t end = kCanonicalUserEnd4Level;
    if (FILE* const cpuinfo = std::fopen("/proc/cpuinfo", "re")) {
      char line[2048];
      while (std::fgets(line, sizeof(line), cpuinfo) != nullptr) {
        if (std::string_view{line}.find("la57") != std::string_view::npos) {
          end = kCanonicalUserEnd5Level;
          break;
        }
      }
      std::fclose(cpuinfo);
    }
    return end;
  }();
  return cached;
}

}  // namespace detail

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

  std::vector<detail::MapsSummaryRegion> summary_regions;
  char line[1024];
  while (std::fgets(line, sizeof(line), maps) != nullptr) {
    MapsRegion region;
    if (!parse_maps_line(line, region)) {
      continue;
    }
    const std::uint64_t size = region.end - region.begin;
    // The first three permission columns carry r/w/x; the fourth (p/s) is not a
    // protection bit. A ---p region is PROT_NONE and reports kReserve.
    const bool readable =
        region.permissions.substr(0U, 3U).find_first_not_of('-') != std::string_view::npos;
    summary_regions.push_back(detail::MapsSummaryRegion{region.begin, region.end, readable});
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

  // Aggregates only cover the user canonical range; special kernel mappings above it
  // (e.g. [vsyscall] at 0xffffffffff600000) stay in the region list but never enter the
  // totals, so the free-space sum cannot wrap toward UINT64_MAX.
  const detail::MapsSummary summary =
      detail::summarize_maps_regions(summary_regions, detail::canonical_user_end());
  map.committed_bytes = summary.committed_bytes;
  map.reserved_bytes = summary.reserved_bytes;
  map.free_bytes = summary.free_bytes;
  map.largest_free_bytes = summary.largest_free_bytes;
  return true;
}

}  // namespace noleax::agent::linux
