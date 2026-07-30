#include "noleax/analyzer/generation_tracker.hpp"

#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"

namespace noleax::analyzer {
namespace {

void checked_increment(std::uint64_t& value, const char* subject) {
  if (value == std::numeric_limits<std::uint64_t>::max()) {
    throw GenerationStateError{std::string{subject} + " count overflow"};
  }
  ++value;
}

[[nodiscard]] bool heap_ids_conflict(noleax::trace::HeapId left,
                                     noleax::trace::HeapId right) noexcept {
  return left.is_valid() && right.is_valid() && left != right;
}

}  // namespace

GenerationTracker::GenerationTracker(GenerationCallbacks callbacks)
    : callbacks_{std::move(callbacks)} {}

void GenerationTracker::observe(const noleax::trace::Event& event) {
  noleax::trace::validate_event(event);
  switch (noleax::trace::event_operation(event.payload)) {
    case noleax::trace::EventOperation::kHeapCreate:
      break;
    case noleax::trace::EventOperation::kHeapDestroy:
      observe_heap_destroy(event, std::get<noleax::trace::HeapDestroyEvent>(event.payload));
      break;
    case noleax::trace::EventOperation::kAllocate:
      observe_allocation(event, std::get<noleax::trace::AllocationEvent>(event.payload));
      break;
    case noleax::trace::EventOperation::kReallocate:
      observe_reallocation(event, std::get<noleax::trace::ReallocationEvent>(event.payload));
      break;
    case noleax::trace::EventOperation::kFree:
      observe_free(event, std::get<noleax::trace::FreeEvent>(event.payload));
      break;
    case noleax::trace::EventOperation::kVmAllocate:
      observe_vm_allocate(event, std::get<noleax::trace::VmAllocateEvent>(event.payload));
      break;
    case noleax::trace::EventOperation::kVmFree:
      observe_vm_free(event, std::get<noleax::trace::VmFreeEvent>(event.payload));
      break;
    case noleax::trace::EventOperation::kMap:
      observe_map(event, std::get<noleax::trace::MapEvent>(event.payload));
      break;
    case noleax::trace::EventOperation::kUnmap:
      observe_unmap(event, std::get<noleax::trace::UnmapEvent>(event.payload));
      break;
  }
}

const MemoryGeneration* GenerationTracker::find_allocation(
    noleax::trace::AllocationId id) const noexcept {
  const auto generation = live_allocations_.find(id.value());
  return generation == live_allocations_.end() ? nullptr : &generation->second;
}

const MemoryGeneration* GenerationTracker::find_mapping(
    noleax::trace::MappingId id) const noexcept {
  const auto generation = live_mappings_.find(id.value());
  return generation == live_mappings_.end() ? nullptr : &generation->second;
}

std::vector<MemoryGeneration> GenerationTracker::live_generations() const {
  std::vector<MemoryGeneration> result;
  result.reserve(live_allocations_.size() + live_mappings_.size());
  for (const auto& [id, generation] : live_allocations_) {
    static_cast<void>(id);
    result.push_back(generation);
  }
  for (const auto& [id, generation] : live_mappings_) {
    static_cast<void>(id);
    result.push_back(generation);
  }
  return result;
}

std::uint64_t GenerationTracker::created_count() const noexcept { return created_count_; }

std::uint64_t GenerationTracker::ended_count() const noexcept { return ended_count_; }

std::uint64_t GenerationTracker::live_count() const noexcept {
  return static_cast<std::uint64_t>(live_allocations_.size()) +
         static_cast<std::uint64_t>(live_mappings_.size());
}

std::uint64_t GenerationTracker::orphaned_allocation_end_count() const noexcept {
  return orphaned_allocation_end_count_;
}

std::uint64_t GenerationTracker::orphaned_mapping_end_count() const noexcept {
  return orphaned_mapping_end_count_;
}

void GenerationTracker::observe_allocation(const noleax::trace::Event& event,
                                           const noleax::trace::AllocationEvent& allocation) {
  if (!noleax::trace::allocation_creates_generation(event.header, allocation)) {
    return;
  }
  MemoryGeneration generation;
  generation.kind = GenerationKind::kHeapAllocation;
  generation.allocation_id = allocation.allocation_id;
  generation.heap_id = allocation.heap_id;
  generation.heap_handle = allocation.heap_handle;
  generation.address = allocation.result_address;
  generation.size = allocation.requested_size;
  generation.created_by = event;
  add_allocation(generation);
}

void GenerationTracker::observe_reallocation(const noleax::trace::Event& event,
                                             const noleax::trace::ReallocationEvent& reallocation) {
  const bool creates_new =
      noleax::trace::reallocation_creates_new_generation(event.header, reallocation);
  if (creates_new) {
    require_new_allocation_id(reallocation.new_allocation_id);
  }

  if (noleax::trace::reallocation_ends_old_generation(event.header, reallocation)) {
    const auto reason = reallocation.effect == noleax::trace::ReallocationEffect::kFreed
                            ? GenerationEndReason::kReallocationFreed
                            : GenerationEndReason::kReallocated;
    end_allocation(reallocation.old_allocation_id, reallocation.old_address, reallocation.heap_id,
                   reason, event);
  }
  if (!creates_new) {
    return;
  }

  MemoryGeneration generation;
  generation.kind = GenerationKind::kHeapAllocation;
  generation.allocation_id = reallocation.new_allocation_id;
  generation.heap_id = reallocation.heap_id;
  generation.heap_handle = reallocation.heap_handle;
  generation.address = reallocation.result_address;
  generation.size = reallocation.requested_size;
  generation.created_by = event;
  add_allocation(generation);
}

void GenerationTracker::observe_free(const noleax::trace::Event& event,
                                     const noleax::trace::FreeEvent& free_event) {
  if (!noleax::trace::free_ends_generation(event.header, free_event)) {
    return;
  }
  end_allocation(free_event.allocation_id, free_event.address, free_event.heap_id,
                 GenerationEndReason::kFreed, event);
}

void GenerationTracker::observe_heap_destroy(const noleax::trace::Event& event,
                                             const noleax::trace::HeapDestroyEvent& heap_destroy) {
  if (!noleax::trace::heap_destroy_ends_generations(event.header, heap_destroy)) {
    return;
  }
  for (auto generation = live_allocations_.begin(); generation != live_allocations_.end();) {
    if (generation->second.heap_id != heap_destroy.heap_id) {
      ++generation;
      continue;
    }
    notify_ended(generation->second, GenerationEndReason::kHeapDestroyed, event);
    checked_increment(ended_count_, "ended generation");
    generation = live_allocations_.erase(generation);
  }
}

void GenerationTracker::observe_vm_allocate(const noleax::trace::Event& event,
                                            const noleax::trace::VmAllocateEvent& allocation) {
  if (!noleax::trace::call_succeeded(event.header.status) || !allocation.mapping_id.is_valid()) {
    return;
  }
  if (auto existing_entry = live_mappings_.find(allocation.mapping_id.value());
      existing_entry != live_mappings_.end()) {
    MemoryGeneration& existing = existing_entry->second;
    const noleax::trace::Address update_base =
        allocation.mapping_base == 0U ? allocation.result_base : allocation.mapping_base;
    const std::uint64_t update_size =
        allocation.mapping_size == 0U ? allocation.result_size : allocation.mapping_size;
    if (existing.kind != GenerationKind::kVirtualAllocation || update_base < existing.address) {
      throw GenerationStateError{"virtual memory update does not match its mapping generation"};
    }
    if (update_base == existing.address && update_size > existing.size) {
      existing.size = update_size;
      return;
    }
    const std::uint64_t offset = update_base - existing.address;
    if (offset > existing.size || update_size > existing.size - offset) {
      throw GenerationStateError{"virtual memory update exceeds its mapping generation"};
    }
    return;
  }
  MemoryGeneration generation;
  generation.kind = GenerationKind::kVirtualAllocation;
  generation.mapping_id = allocation.mapping_id;
  generation.address =
      allocation.mapping_base == 0U ? allocation.result_base : allocation.mapping_base;
  generation.size =
      allocation.mapping_size == 0U ? allocation.result_size : allocation.mapping_size;
  generation.created_by = event;
  add_mapping(generation);
}

void GenerationTracker::observe_vm_free(const noleax::trace::Event& event,
                                        const noleax::trace::VmFreeEvent& free_event) {
  if (!noleax::trace::call_succeeded(event.header.status) || !free_event.mapping_id.is_valid()) {
    return;
  }
  constexpr std::uint32_t kMemRelease = 0x00008000U;
  if ((free_event.free_type & kMemRelease) == 0U) {
    return;
  }
  end_mapping(free_event.mapping_id, free_event.base, GenerationKind::kVirtualAllocation,
              GenerationEndReason::kVirtualFreed, event);
}

void GenerationTracker::observe_map(const noleax::trace::Event& event,
                                    const noleax::trace::MapEvent& mapping) {
  if (!noleax::trace::call_succeeded(event.header.status) || !mapping.mapping_id.is_valid()) {
    return;
  }
  MemoryGeneration generation;
  generation.kind = GenerationKind::kMappedView;
  generation.mapping_id = mapping.mapping_id;
  generation.address = mapping.result_base;
  generation.size = mapping.view_size;
  generation.created_by = event;
  add_mapping(generation);
}

void GenerationTracker::observe_unmap(const noleax::trace::Event& event,
                                      const noleax::trace::UnmapEvent& unmap) {
  if (!noleax::trace::call_succeeded(event.header.status) || !unmap.mapping_id.is_valid()) {
    return;
  }
  end_mapping(unmap.mapping_id, unmap.base, GenerationKind::kMappedView,
              GenerationEndReason::kUnmapped, event);
}

void GenerationTracker::add_allocation(MemoryGeneration generation) {
  require_new_allocation_id(generation.allocation_id);
  seen_allocation_ids_.insert(generation.allocation_id.value());
  const auto [inserted, was_inserted] =
      live_allocations_.emplace(generation.allocation_id.value(), generation);
  if (!was_inserted) {
    throw GenerationStateError{"allocation_id is already live"};
  }
  checked_increment(created_count_, "created generation");
  notify_created(inserted->second);
}

void GenerationTracker::add_mapping(MemoryGeneration generation) {
  require_new_mapping_id(generation.mapping_id);
  seen_mapping_ids_.insert(generation.mapping_id.value());
  const auto [inserted, was_inserted] =
      live_mappings_.emplace(generation.mapping_id.value(), generation);
  if (!was_inserted) {
    throw GenerationStateError{"mapping_id is already live"};
  }
  checked_increment(created_count_, "created generation");
  notify_created(inserted->second);
}

void GenerationTracker::end_allocation(noleax::trace::AllocationId id,
                                       noleax::trace::Address expected_address,
                                       noleax::trace::HeapId expected_heap_id,
                                       GenerationEndReason reason,
                                       const noleax::trace::Event& event) {
  auto generation = live_allocations_.find(id.value());
  if (generation == live_allocations_.end()) {
    checked_increment(orphaned_allocation_end_count_, "orphaned allocation end");
    return;
  }
  if (generation->second.address != expected_address) {
    throw GenerationStateError{"allocation end address does not match its allocation_id"};
  }
  if (heap_ids_conflict(generation->second.heap_id, expected_heap_id)) {
    throw GenerationStateError{"allocation end heap_id does not match its allocation_id"};
  }
  notify_ended(generation->second, reason, event);
  checked_increment(ended_count_, "ended generation");
  live_allocations_.erase(generation);
}

void GenerationTracker::end_mapping(noleax::trace::MappingId id,
                                    noleax::trace::Address expected_address,
                                    GenerationKind expected_kind, GenerationEndReason reason,
                                    const noleax::trace::Event& event) {
  auto generation = live_mappings_.find(id.value());
  if (generation == live_mappings_.end()) {
    checked_increment(orphaned_mapping_end_count_, "orphaned mapping end");
    return;
  }
  if (generation->second.kind != expected_kind) {
    throw GenerationStateError{"mapping end operation does not match its mapping_id kind"};
  }
  if (generation->second.address != expected_address) {
    throw GenerationStateError{"mapping end address does not match its mapping_id"};
  }
  notify_ended(generation->second, reason, event);
  checked_increment(ended_count_, "ended generation");
  live_mappings_.erase(generation);
}

void GenerationTracker::require_new_allocation_id(noleax::trace::AllocationId id) const {
  if (!id.is_valid()) {
    throw GenerationStateError{"new allocation generation requires an allocation_id"};
  }
  if (seen_allocation_ids_.contains(id.value())) {
    throw GenerationStateError{"allocation_id is reused by more than one generation"};
  }
}

void GenerationTracker::require_new_mapping_id(noleax::trace::MappingId id) const {
  if (!id.is_valid()) {
    throw GenerationStateError{"new mapping generation requires a mapping_id"};
  }
  if (seen_mapping_ids_.contains(id.value())) {
    throw GenerationStateError{"mapping_id is reused by more than one generation"};
  }
}

void GenerationTracker::notify_created(const MemoryGeneration& generation) const {
  if (callbacks_.on_created) {
    callbacks_.on_created(generation);
  }
}

void GenerationTracker::notify_ended(const MemoryGeneration& generation, GenerationEndReason reason,
                                     const noleax::trace::Event& event) const {
  if (callbacks_.on_ended) {
    callbacks_.on_ended(generation, reason, event);
  }
}

}  // namespace noleax::analyzer
