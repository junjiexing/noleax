#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <stdexcept>
#include <unordered_set>
#include <vector>

#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"

namespace noleax::analyzer {

enum class GenerationKind : std::uint8_t {
  kHeapAllocation,
  kVirtualAllocation,
  kMappedView,
};

enum class GenerationEndReason : std::uint8_t {
  kReallocated,
  kReallocationFreed,
  kFreed,
  kHeapDestroyed,
  kVirtualFreed,
  kUnmapped,
};

struct MemoryGeneration {
  GenerationKind kind{GenerationKind::kHeapAllocation};
  noleax::trace::AllocationId allocation_id;
  noleax::trace::MappingId mapping_id;
  noleax::trace::HeapId heap_id;
  noleax::trace::RawHandle heap_handle{0};
  noleax::trace::Address address{0};
  std::uint64_t size{0};
  noleax::trace::Event created_by;

  bool operator==(const MemoryGeneration&) const = default;
};

struct GenerationCallbacks {
  std::function<void(const MemoryGeneration&)> on_created;
  std::function<void(const MemoryGeneration&, GenerationEndReason, const noleax::trace::Event&)>
      on_ended;
};

class GenerationStateError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class GenerationTracker {
 public:
  explicit GenerationTracker(GenerationCallbacks callbacks = {});

  void observe(const noleax::trace::Event& event);

  [[nodiscard]] const MemoryGeneration* find_allocation(
      noleax::trace::AllocationId id) const noexcept;
  [[nodiscard]] const MemoryGeneration* find_mapping(noleax::trace::MappingId id) const noexcept;
  [[nodiscard]] std::vector<MemoryGeneration> live_generations() const;

  [[nodiscard]] std::uint64_t created_count() const noexcept;
  [[nodiscard]] std::uint64_t ended_count() const noexcept;
  [[nodiscard]] std::uint64_t live_count() const noexcept;
  [[nodiscard]] std::uint64_t orphaned_allocation_end_count() const noexcept;
  [[nodiscard]] std::uint64_t orphaned_mapping_end_count() const noexcept;

 private:
  void observe_allocation(const noleax::trace::Event& event,
                          const noleax::trace::AllocationEvent& allocation);
  void observe_reallocation(const noleax::trace::Event& event,
                            const noleax::trace::ReallocationEvent& reallocation);
  void observe_free(const noleax::trace::Event& event, const noleax::trace::FreeEvent& free_event);
  void observe_heap_destroy(const noleax::trace::Event& event,
                            const noleax::trace::HeapDestroyEvent& heap_destroy);
  void observe_vm_allocate(const noleax::trace::Event& event,
                           const noleax::trace::VmAllocateEvent& allocation);
  void observe_vm_free(const noleax::trace::Event& event,
                       const noleax::trace::VmFreeEvent& free_event);
  void observe_map(const noleax::trace::Event& event, const noleax::trace::MapEvent& mapping);
  void observe_unmap(const noleax::trace::Event& event, const noleax::trace::UnmapEvent& unmap);

  void add_allocation(MemoryGeneration generation);
  void add_mapping(MemoryGeneration generation);
  void end_allocation(noleax::trace::AllocationId id, noleax::trace::Address expected_address,
                      noleax::trace::HeapId expected_heap_id, GenerationEndReason reason,
                      const noleax::trace::Event& event);
  void end_mapping(noleax::trace::MappingId id, noleax::trace::Address expected_address,
                   GenerationKind expected_kind, GenerationEndReason reason,
                   const noleax::trace::Event& event);
  void require_new_allocation_id(noleax::trace::AllocationId id) const;
  void require_new_mapping_id(noleax::trace::MappingId id) const;
  void notify_created(const MemoryGeneration& generation) const;
  void notify_ended(const MemoryGeneration& generation, GenerationEndReason reason,
                    const noleax::trace::Event& event) const;

  GenerationCallbacks callbacks_;
  std::map<std::uint64_t, MemoryGeneration> live_allocations_;
  std::map<std::uint64_t, MemoryGeneration> live_mappings_;
  std::unordered_set<std::uint64_t> seen_allocation_ids_;
  std::unordered_set<std::uint64_t> seen_mapping_ids_;
  std::uint64_t created_count_{0};
  std::uint64_t ended_count_{0};
  std::uint64_t orphaned_allocation_end_count_{0};
  std::uint64_t orphaned_mapping_end_count_{0};
};

}  // namespace noleax::analyzer
