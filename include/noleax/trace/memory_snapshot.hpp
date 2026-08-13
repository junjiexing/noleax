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

// ---------------------------------------------------------------------------
// H4 (P0-1): agent-owned memory attribution
// ---------------------------------------------------------------------------

// An AgentMemory record lists at most this many categories; the Linux agent currently
// emits seven.
inline constexpr std::uint32_t kMaximumAgentMemoryCategories = 64U;

// Agent-owned memory category (H4). The wire values are stable; analyzers must tolerate
// ids they do not know (a newer agent may add categories at the same record version) and
// label them "unknown-<id>".
enum class AgentMemoryCategory : std::uint32_t {  // NOLINT(performance-enum-size)
  // The bounded MPSC event queue slot ring (dedicated mapping; resident measured exactly).
  kEventQueue = 1U,
  // The writer's stack dictionary storage.
  kStackDictionary = 2U,
  // Trace chunk assembly and compression buffers.
  kTraceBuffers = 3U,
  // Module tracker and the writer's live allocation/mapping bookkeeping.
  kModuleTracker = 4U,
  // Hook backend: trampolines, patch bookkeeping, agent TLS.
  kHookBackend = 5U,
  // Everything else the agent owns (runtime objects, writer thread stack, heap slack).
  kAgentHeap = 6U,
};

// Why an AgentMemory record was sampled. The two baseline kinds bracket queue/hook/writer
// creation so the startup RSS step is attributable (H4 requirement 4).
enum class AgentMemorySampleKind : std::uint8_t {
  kPeriodic = 1U,
  kBaselinePreInit = 2U,
  kBaselinePostInit = 3U,
};

// Per-category flag: the resident bytes were measured exactly (dedicated mapping +
// page-level residency inspection). When clear, reserved/resident are estimates derived
// from container sizes and are labeled as such in every output.
inline constexpr std::uint32_t kAgentMemoryCategoryFlagExact = 1U << 0U;

struct AgentMemoryCategorySample {
  AgentMemoryCategory category{AgentMemoryCategory::kEventQueue};
  std::uint32_t flags{0U};
  std::uint64_t reserved_bytes{0U};
  std::uint64_t resident_bytes{0U};

  bool operator==(const AgentMemoryCategorySample&) const = default;
};

// Agent-owned memory breakdown riding the periodic memory snapshot (H4): one record per
// sampling tick, emitted into the same kMemory chunk as the MemoryCounters record. The
// application footprint is derived analyzer-side as working_set minus the resident sum.
struct AgentMemory {
  std::uint64_t monotonic_ticks{0U};
  AgentMemorySampleKind kind{AgentMemorySampleKind::kPeriodic};
  std::vector<AgentMemoryCategorySample> categories;

  bool operator==(const AgentMemory&) const = default;
};

void validate_agent_memory(const AgentMemory& memory);

// The buffer_size → event-slot conversion made explicit (H4 requirement 1). Emitted as a
// BufferConfiguration metadata record so the trace itself carries the exact slot math;
// the same values go to the startup log and CaptureStatus.
struct BufferConfiguration {
  // trace.buffer_size as requested.
  std::uint64_t requested_bytes{0U};
  // Effective ring capacity in slots after the cap and power-of-two floor.
  std::uint64_t effective_slots{0U};
  std::uint64_t event_size{0U};
  std::uint64_t slot_size{0U};
  // effective_slots * slot_size: the reserved mapping bytes.
  std::uint64_t reserved_bytes{0U};
  // Resident bytes of the slot ring measured right after initialization.
  std::uint64_t resident_after_init_bytes{0U};
  // kBufferConfigurationFlag* mask.
  std::uint32_t flags{0U};

  bool operator==(const BufferConfiguration&) const = default;
};

// The requested bytes did not survive the conversion unchanged: the capacity cap and/or
// the power-of-two floor moved it. Always a startup warning; capture.strict_buffer turns
// it into a start failure.
inline constexpr std::uint32_t kBufferConfigurationFlagAdjusted = 1U << 0U;

void validate_buffer_configuration(const BufferConfiguration& configuration);

}  // namespace noleax::trace
