#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/trace/memory_snapshot.hpp"

namespace noleax::agent::linux {

// A dedicated agent allocation (anonymous mapping, registry slot) failed. Carries the
// errno of the underlying syscall (0 for a registry-internal failure) so the runtime can
// report a stable start error instead of letting a bad_alloc escape into target code.
class AgentMemoryError final : public std::runtime_error {
 public:
  explicit AgentMemoryError(const std::string& message, std::uint32_t system_error = 0U)
      : std::runtime_error{message}, system_error_{system_error} {}

  [[nodiscard]] std::uint32_t system_error() const noexcept { return system_error_; }

 private:
  std::uint32_t system_error_{0U};
};

// Process-wide registry of agent-owned memory (H4, P0-1).
//
// Two contribution kinds feed the per-category breakdown that rides the periodic memory
// snapshot:
//   - measured regions: dedicated anonymous mappings (the event queue slot ring) whose
//     resident bytes are read back exactly with mincore(2) — for an anonymous private
//     mapping the present-page count is precisely the mapping's RSS;
//   - estimate slots: heap-backed components (stack dictionary, chunk buffers, module
//     tracker, hook backend, remaining agent heap) whose sizes are derived from container
//     capacities and object sizes. One contributor owns each category's slot; estimates
//     never carry the exact flag and are labeled as estimates in every output.
//
// The registry itself never allocates after construction (fixed arrays), so registering
// or sampling cannot recurse into the hooked allocation paths. Registration happens off
// the hot path (capture start); sampling runs on the writer's internal thread.
class AgentMemoryRegistry {
 public:
  static AgentMemoryRegistry& instance() noexcept {
    static AgentMemoryRegistry registry;
    return registry;
  }

  AgentMemoryRegistry(const AgentMemoryRegistry&) = delete;
  AgentMemoryRegistry& operator=(const AgentMemoryRegistry&) = delete;

  // Registers a dedicated mapping. Throws AgentMemoryError when the region table is full
  // (an internal bookkeeping limit, not an allocation failure of the caller's region).
  void register_region(noleax::trace::AgentMemoryCategory category, void* base, std::size_t bytes);
  void unregister_region(void* base) noexcept;

  // Sets (or replaces) the estimate for one heap-backed category. The resident estimate
  // must not exceed the reserved estimate.
  void set_estimate(noleax::trace::AgentMemoryCategory category, std::uint64_t reserved_bytes,
                    std::uint64_t resident_bytes) noexcept;
  void clear_estimate(noleax::trace::AgentMemoryCategory category) noexcept;

  // Resident bytes of one registered region (0 when unknown). mincore cost is
  // proportional to the region's page count; callers use this for one-shot accounting
  // (e.g. resident-after-init), not per event.
  [[nodiscard]] std::uint64_t region_resident_bytes(const void* base) noexcept;

  // Appends the per-category totals (measured regions + estimates, ordered by category
  // id) to `categories`. The vector is reused across ticks by the caller.
  void snapshot(std::vector<noleax::trace::AgentMemoryCategorySample>& categories);

  // Reserved bytes of every registered region of one category (0 when none).
  [[nodiscard]] std::uint64_t region_reserved_bytes(
      noleax::trace::AgentMemoryCategory category) const noexcept;

 private:
  AgentMemoryRegistry() = default;

  static constexpr std::size_t kMaximumRegions = 8U;
  static constexpr std::size_t kCategorySlots =
      static_cast<std::size_t>(noleax::trace::AgentMemoryCategory::kAgentHeap) + 1U;

  struct Region {
    void* base{nullptr};
    std::uint64_t bytes{0U};
    noleax::trace::AgentMemoryCategory category{noleax::trace::AgentMemoryCategory::kEventQueue};
  };

  struct EstimateSlot {
    std::uint64_t reserved_bytes{0U};
    std::uint64_t resident_bytes{0U};
    bool present{false};
  };

  [[nodiscard]] std::uint64_t measured_resident_bytes(const void* base,
                                                      std::uint64_t bytes) noexcept;

  mutable std::mutex mutex_;
  std::array<Region, kMaximumRegions> regions_{};
  std::size_t region_count_{0U};
  std::array<EstimateSlot, kCategorySlots> estimates_{};
  // mincore scratch, grown to the largest registered region; reused across snapshots.
  std::vector<unsigned char> residency_scratch_;
};

// Estimates for the categories no exact measurement exists for. They deliberately err on
// the high side so the application estimate (process RSS minus agent resident) is never
// flattered by the agent.
inline constexpr std::uint64_t kHookBackendBaseEstimateBytes = 512U * 1024U;
inline constexpr std::uint64_t kHookBackendPerHookEstimateBytes = 8U * 1024U;
// One internal writer thread stack (glibc default pthread stack) plus runtime objects.
inline constexpr std::uint64_t kAgentHeapReservedEstimateBytes = 9U * 1024U * 1024U;
inline constexpr std::uint64_t kAgentHeapResidentEstimateBytes = 512U * 1024U;

// The buffer_size → slot conversion (H4 requirement 1), factored pure so the runtime, the
// tests, and the trace record all share one source of truth. configuration carries the
// exact math; resident_after_init_bytes stays 0 until the caller measures the ring.
struct EventQueuePlan {
  std::size_t capacity{0U};
  noleax::trace::BufferConfiguration configuration{};
};
[[nodiscard]] EventQueuePlan plan_event_queue(std::uint64_t requested_bytes);

// Creates the event queue with its slot ring in a dedicated anonymous mapping registered
// under AgentMemoryCategory::kEventQueue. The ring commits pages lazily (see
// bounded_mpsc_queue.hpp). Throws AgentMemoryError (never bad_alloc) on failure.
[[nodiscard]] std::unique_ptr<LinuxHeapEventQueue> make_linux_heap_event_queue(
    std::size_t capacity);

}  // namespace noleax::agent::linux
