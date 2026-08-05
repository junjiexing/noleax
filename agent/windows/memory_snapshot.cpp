#include "noleax/agent/windows/memory_snapshot.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: psapi.h requires the Windows base types.
#include <windows.h>
#include <psapi.h>
// clang-format on

#include <cstddef>
#include <cstdint>

namespace noleax::agent::windows {
namespace {

[[nodiscard]] noleax::trace::MemoryRegionType region_type(std::uint32_t type) noexcept {
  switch (type) {
    case MEM_IMAGE:
      return noleax::trace::MemoryRegionType::kImage;
    case MEM_MAPPED:
      return noleax::trace::MemoryRegionType::kMapped;
    default:
      return noleax::trace::MemoryRegionType::kPrivate;
  }
}

}  // namespace

bool capture_memory_counters(noleax::trace::MemoryCounters& counters) noexcept {
  PROCESS_MEMORY_COUNTERS_EX info{};
  if (K32GetProcessMemoryInfo(GetCurrentProcess(),
                              reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&info),
                              sizeof(info)) == FALSE) {
    return false;
  }
  counters.working_set_bytes = static_cast<std::uint64_t>(info.WorkingSetSize);
  counters.peak_working_set_bytes = static_cast<std::uint64_t>(info.PeakWorkingSetSize);
  counters.private_bytes = static_cast<std::uint64_t>(info.PrivateUsage);
  counters.commit_bytes = static_cast<std::uint64_t>(info.PagefileUsage);
  return true;
}

bool capture_memory_map(noleax::trace::MemoryMap& map) {
  SYSTEM_INFO system{};
  GetSystemInfo(&system);
  const auto* address = static_cast<const std::byte*>(system.lpMinimumApplicationAddress);
  const auto* maximum = static_cast<const std::byte*>(system.lpMaximumApplicationAddress);

  map.truncated = false;
  map.committed_bytes = 0U;
  map.reserved_bytes = 0U;
  map.free_bytes = 0U;
  map.largest_free_bytes = 0U;
  map.regions.clear();

  bool first_query = true;
  while (address < maximum) {
    MEMORY_BASIC_INFORMATION region{};
    if (VirtualQuery(address, &region, sizeof(region)) == 0U) {
      // A failure on the first query means the walk cannot run at all; later failures just end
      // the walk (the usable address space is not required to be one contiguous range).
      return !first_query;
    }
    first_query = false;
    const auto* base = static_cast<const std::byte*>(region.BaseAddress);
    const auto size = static_cast<std::uint64_t>(region.RegionSize);
    if (region.RegionSize == 0U || base + region.RegionSize <= address) {
      // Defensive: the walk must always advance.
      break;
    }
    if (region.State == MEM_FREE) {
      map.free_bytes += size;
      if (size > map.largest_free_bytes) {
        map.largest_free_bytes = size;
      }
    } else {
      if (region.State == MEM_COMMIT) {
        map.committed_bytes += size;
      } else {
        map.reserved_bytes += size;
      }
      if (map.regions.size() < noleax::trace::kMaximumMemoryMapRegions) {
        noleax::trace::MemoryMapRegion entry;
        entry.base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(base));
        entry.size = size;
        entry.state = region.State == MEM_COMMIT ? noleax::trace::MemoryRegionState::kCommit
                                                 : noleax::trace::MemoryRegionState::kReserve;
        entry.type = region_type(region.Type);
        entry.protect = region.State == MEM_COMMIT ? region.Protect : region.AllocationProtect;
        map.regions.push_back(entry);
      } else {
        map.truncated = true;
      }
    }
    address = base + region.RegionSize;
  }
  return true;
}

}  // namespace noleax::agent::windows
