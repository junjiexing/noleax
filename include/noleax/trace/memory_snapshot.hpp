#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace noleax::trace {

// A MemoryMap record lists at most this many regions; the walk's aggregate counters always
// cover the full address space even when the region list is truncated.
inline constexpr std::uint32_t kMaximumMemoryMapRegions = 32'768U;

// Process-wide memory counters sampled from the operating system (Windows:
// K32GetProcessMemoryInfo). All timestamps use the trace's monotonic clock.
struct MemoryCounters {
  std::uint64_t monotonic_ticks{0U};
  std::uint64_t working_set_bytes{0U};
  std::uint64_t peak_working_set_bytes{0U};
  std::uint64_t private_bytes{0U};
  std::uint64_t commit_bytes{0U};

  bool operator==(const MemoryCounters&) const = default;
};

// Region state of a listed virtual memory range. MEM_FREE ranges are never listed; they only
// contribute to the MemoryMap aggregate counters.
enum class MemoryRegionState : std::uint8_t {
  kCommit = 1U,
  kReserve = 2U,
};

// Region type of a listed virtual memory range (Windows MEM_IMAGE/MEM_MAPPED/MEM_PRIVATE).
enum class MemoryRegionType : std::uint8_t {
  kImage = 1U,
  kMapped = 2U,
  kPrivate = 3U,
};

struct MemoryMapRegion {
  std::uint64_t base{0U};
  std::uint64_t size{0U};
  MemoryRegionState state{MemoryRegionState::kCommit};
  MemoryRegionType type{MemoryRegionType::kPrivate};
  std::uint32_t protect{0U};

  bool operator==(const MemoryMapRegion&) const = default;
};

// A full VirtualQuery walk of the process address space: the non-free regions (ordered by
// ascending base, possibly truncated at kMaximumMemoryMapRegions) plus aggregates that always
// describe the complete walk, including MEM_FREE ranges.
struct MemoryMap {
  std::uint64_t monotonic_ticks{0U};
  bool truncated{false};
  std::uint64_t committed_bytes{0U};
  std::uint64_t reserved_bytes{0U};
  std::uint64_t free_bytes{0U};
  std::uint64_t largest_free_bytes{0U};
  std::vector<MemoryMapRegion> regions;

  bool operator==(const MemoryMap&) const = default;
};

class MemorySnapshotValidationError final : public std::invalid_argument {
 public:
  using std::invalid_argument::invalid_argument;
};

void validate_memory_counters(const MemoryCounters& counters);
void validate_memory_map(const MemoryMap& map);

}  // namespace noleax::trace
