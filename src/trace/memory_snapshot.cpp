#include "noleax/trace/memory_snapshot.hpp"

#include <cstdint>
#include <limits>

namespace noleax::trace {

void validate_memory_counters(const MemoryCounters& counters) {
  if (counters.peak_working_set_bytes < counters.working_set_bytes) {
    throw MemorySnapshotValidationError{
        "memory counters peak working set is below the current working set"};
  }
}

void validate_memory_map(const MemoryMap& map) {
  if (map.regions.size() > kMaximumMemoryMapRegions) {
    throw MemorySnapshotValidationError{"memory map exceeds the region count limit"};
  }
  std::uint64_t previous_end = 0U;
  for (const MemoryMapRegion& region : map.regions) {
    if (region.size == 0U ||
        region.base > std::numeric_limits<std::uint64_t>::max() - region.size) {
      throw MemorySnapshotValidationError{"memory map region address range is invalid"};
    }
    if (region.base < previous_end) {
      throw MemorySnapshotValidationError{"memory map regions overlap or are out of order"};
    }
    previous_end = region.base + region.size;
  }
}

}  // namespace noleax::trace
