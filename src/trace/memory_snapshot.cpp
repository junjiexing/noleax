#include "noleax/trace/memory_snapshot.hpp"

#include <cstdint>
#include <limits>
#include <unordered_set>

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

void validate_agent_memory(const AgentMemory& memory) {
  if (memory.kind != AgentMemorySampleKind::kPeriodic &&
      memory.kind != AgentMemorySampleKind::kBaselinePreInit &&
      memory.kind != AgentMemorySampleKind::kBaselinePostInit) {
    throw MemorySnapshotValidationError{"agent memory sample kind is not supported"};
  }
  // An empty category list is meaningful: the pre-init baseline is taken before any
  // agent component registered its memory.
  if (memory.categories.size() > kMaximumAgentMemoryCategories) {
    throw MemorySnapshotValidationError{"agent memory category count is out of range"};
  }
  std::unordered_set<std::uint32_t> seen_categories;
  std::uint64_t reserved_total = 0U;
  std::uint64_t resident_total = 0U;
  for (const AgentMemoryCategorySample& category : memory.categories) {
    if (!seen_categories.insert(static_cast<std::uint32_t>(category.category)).second) {
      throw MemorySnapshotValidationError{"agent memory sample contains a duplicate category"};
    }
    if (category.resident_bytes > category.reserved_bytes) {
      throw MemorySnapshotValidationError{
          "agent memory category resident bytes exceed the reserved bytes"};
    }
    if (category.reserved_bytes > std::numeric_limits<std::uint64_t>::max() - reserved_total ||
        category.resident_bytes > std::numeric_limits<std::uint64_t>::max() - resident_total) {
      throw MemorySnapshotValidationError{"agent memory category byte totals overflow"};
    }
    reserved_total += category.reserved_bytes;
    resident_total += category.resident_bytes;
  }
}

void validate_buffer_configuration(const BufferConfiguration& configuration) {
  if (configuration.requested_bytes == 0U || configuration.effective_slots == 0U ||
      configuration.event_size == 0U || configuration.slot_size == 0U ||
      configuration.slot_size < configuration.event_size) {
    throw MemorySnapshotValidationError{"buffer configuration slot math is invalid"};
  }
  if (configuration.effective_slots >
      std::numeric_limits<std::uint64_t>::max() / configuration.slot_size) {
    throw MemorySnapshotValidationError{"buffer configuration reserved bytes overflow"};
  }
  if (configuration.reserved_bytes != configuration.effective_slots * configuration.slot_size ||
      configuration.resident_after_init_bytes > configuration.reserved_bytes) {
    throw MemorySnapshotValidationError{"buffer configuration byte counts are inconsistent"};
  }
}

}  // namespace noleax::trace
