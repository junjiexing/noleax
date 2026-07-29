#include "noleax/analyzer/generation_tracker.hpp"

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <utility>
#include <variant>
#include <vector>

#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"

namespace {

[[nodiscard]] noleax::trace::EventHeader event_header(
    std::uint64_t sequence,
    noleax::trace::EventStatus status = noleax::trace::EventStatus::kSuccess) {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{sequence};
  header.monotonic_ticks = sequence * 10U;
  header.thread_id = 7U;
  header.api_id = 1U;
  header.status = status;
  header.stack_id = noleax::trace::StackId{sequence + 100U};
  return header;
}

[[nodiscard]] noleax::trace::Event allocation_event(std::uint64_t sequence, std::uint64_t id,
                                                    noleax::trace::Address address,
                                                    std::uint64_t size = 64U,
                                                    std::uint64_t heap_id = 1U) {
  noleax::trace::AllocationEvent allocation;
  allocation.heap_handle = 0x1000U + heap_id;
  allocation.heap_id = noleax::trace::HeapId{heap_id};
  allocation.requested_size = size;
  allocation.result_address = address;
  allocation.allocation_id = noleax::trace::AllocationId{id};
  return noleax::trace::Event{event_header(sequence), allocation};
}

[[nodiscard]] noleax::trace::Event reallocation_event(
    std::uint64_t sequence, std::uint64_t old_id, std::uint64_t new_id,
    noleax::trace::Address old_address, noleax::trace::Address new_address,
    noleax::trace::ReallocationEffect effect = noleax::trace::ReallocationEffect::kNewGeneration,
    noleax::trace::EventStatus status = noleax::trace::EventStatus::kSuccess,
    std::uint64_t heap_id = 1U) {
  noleax::trace::ReallocationEvent reallocation;
  reallocation.heap_handle = 0x1000U + heap_id;
  reallocation.heap_id = noleax::trace::HeapId{heap_id};
  reallocation.old_address = old_address;
  reallocation.old_allocation_id = noleax::trace::AllocationId{old_id};
  reallocation.requested_size = 128U;
  reallocation.result_address = new_address;
  reallocation.new_allocation_id = noleax::trace::AllocationId{new_id};
  reallocation.effect = effect;
  return noleax::trace::Event{event_header(sequence, status), reallocation};
}

[[nodiscard]] noleax::trace::Event free_event(
    std::uint64_t sequence, std::uint64_t id, noleax::trace::Address address,
    noleax::trace::EventStatus status = noleax::trace::EventStatus::kSuccess,
    std::uint64_t heap_id = 1U) {
  noleax::trace::FreeEvent free;
  free.heap_handle = 0x1000U + heap_id;
  free.heap_id = noleax::trace::HeapId{heap_id};
  free.address = address;
  free.allocation_id = noleax::trace::AllocationId{id};
  free.raw_result = status == noleax::trace::EventStatus::kFailure ? 0U : 1U;
  return noleax::trace::Event{event_header(sequence, status), free};
}

[[nodiscard]] noleax::trace::Event heap_destroy_event(std::uint64_t sequence,
                                                      std::uint64_t heap_id) {
  noleax::trace::HeapDestroyEvent destroy;
  destroy.heap_handle = 0x1000U + heap_id;
  destroy.heap_id = noleax::trace::HeapId{heap_id};
  destroy.raw_result = 1U;
  return noleax::trace::Event{event_header(sequence), destroy};
}

[[nodiscard]] noleax::trace::ProcessTarget current_process() {
  noleax::trace::ProcessTarget target;
  target.scope = noleax::trace::ProcessMemoryScope::kCurrentProcess;
  target.process_handle = 0xFFFFU;
  target.process_id = 42U;
  return target;
}

[[nodiscard]] noleax::trace::Event vm_allocate_event(std::uint64_t sequence, std::uint64_t id,
                                                     noleax::trace::Address address) {
  noleax::trace::VmAllocateEvent allocation;
  allocation.target = current_process();
  allocation.result_base = address;
  allocation.requested_size = 4096U;
  allocation.result_size = 8192U;
  allocation.allocation_type = 0x3000U;
  allocation.protection = 4U;
  allocation.mapping_id = noleax::trace::MappingId{id};
  return noleax::trace::Event{event_header(sequence), allocation};
}

[[nodiscard]] noleax::trace::Event vm_free_event(std::uint64_t sequence, std::uint64_t id,
                                                 noleax::trace::Address address) {
  noleax::trace::VmFreeEvent free;
  free.target = current_process();
  free.base = address;
  free.free_type = 0x8000U;
  free.mapping_id = noleax::trace::MappingId{id};
  return noleax::trace::Event{event_header(sequence), free};
}

[[nodiscard]] noleax::trace::Event map_event(std::uint64_t sequence, std::uint64_t id,
                                             noleax::trace::Address address) {
  noleax::trace::MapEvent mapping;
  mapping.section_handle = 0x1234U;
  mapping.target = current_process();
  mapping.result_base = address;
  mapping.view_size = 16384U;
  mapping.protection = 2U;
  mapping.mapping_id = noleax::trace::MappingId{id};
  return noleax::trace::Event{event_header(sequence), mapping};
}

[[nodiscard]] noleax::trace::Event unmap_event(std::uint64_t sequence, std::uint64_t id,
                                               noleax::trace::Address address) {
  noleax::trace::UnmapEvent unmap;
  unmap.target = current_process();
  unmap.base = address;
  unmap.mapping_id = noleax::trace::MappingId{id};
  return noleax::trace::Event{event_header(sequence), unmap};
}

struct EndedGeneration {
  noleax::analyzer::MemoryGeneration generation;
  noleax::analyzer::GenerationEndReason reason;
  noleax::trace::Event event;
};

}  // namespace

TEST_CASE("generation tracker applies alloc realloc free and mapping lifecycles",
          "[analyzer][generation]") {
  using namespace noleax::analyzer;
  std::vector<MemoryGeneration> created;
  std::vector<EndedGeneration> ended;
  GenerationCallbacks callbacks;
  callbacks.on_created = [&created](const MemoryGeneration& generation) {
    created.push_back(generation);
  };
  callbacks.on_ended = [&ended](const MemoryGeneration& generation, GenerationEndReason reason,
                                const noleax::trace::Event& event) {
    ended.push_back(EndedGeneration{generation, reason, event});
  };
  GenerationTracker tracker{callbacks};

  const auto allocation = allocation_event(1U, 10U, 0x2000U);
  const auto reallocation = reallocation_event(2U, 10U, 11U, 0x2000U, 0x2000U);
  const auto free = free_event(3U, 11U, 0x2000U);
  const auto vm_allocate = vm_allocate_event(4U, 20U, 0x4000U);
  const auto vm_free = vm_free_event(5U, 20U, 0x4000U);
  const auto map = map_event(6U, 21U, 0x8000U);
  const auto unmap = unmap_event(7U, 21U, 0x8000U);
  for (const auto& event :
       std::vector{allocation, reallocation, free, vm_allocate, vm_free, map, unmap}) {
    tracker.observe(event);
  }

  REQUIRE(created.size() == 4U);
  CHECK(created[0].allocation_id == noleax::trace::AllocationId{10U});
  CHECK(created[1].allocation_id == noleax::trace::AllocationId{11U});
  CHECK(created[1].address == 0x2000U);
  CHECK(created[1].created_by == reallocation);
  CHECK(created[2].kind == GenerationKind::kVirtualAllocation);
  CHECK(created[2].mapping_id == noleax::trace::MappingId{20U});
  CHECK(created[3].kind == GenerationKind::kMappedView);
  REQUIRE(ended.size() == 4U);
  CHECK(ended[0].reason == GenerationEndReason::kReallocated);
  CHECK(ended[0].event == reallocation);
  CHECK(ended[1].reason == GenerationEndReason::kFreed);
  CHECK(ended[2].reason == GenerationEndReason::kVirtualFreed);
  CHECK(ended[3].reason == GenerationEndReason::kUnmapped);
  CHECK(tracker.created_count() == 4U);
  CHECK(tracker.ended_count() == 4U);
  CHECK(tracker.live_count() == 0U);
  CHECK(tracker.live_generations().empty());
}

TEST_CASE("failed and unmatched operations preserve live generations", "[analyzer][generation]") {
  using namespace noleax::trace;
  noleax::analyzer::GenerationTracker tracker;
  const auto allocation = allocation_event(1U, 10U, 0x2000U);
  tracker.observe(allocation);
  tracker.observe(reallocation_event(2U, 10U, 0U, 0x2000U, 0U, ReallocationEffect::kNoChange,
                                     EventStatus::kFailure));
  tracker.observe(free_event(3U, 10U, 0x2000U, EventStatus::kFailure));
  tracker.observe(free_event(4U, 0U, 0x9000U, EventStatus::kUnmatched));

  REQUIRE(tracker.live_count() == 1U);
  const auto* live = tracker.find_allocation(AllocationId{10U});
  REQUIRE(live != nullptr);
  CHECK(live->created_by == allocation);
  CHECK(tracker.ended_count() == 0U);
  CHECK(tracker.orphaned_allocation_end_count() == 0U);
}

TEST_CASE("reallocation effects preserve free or replace the correct generation",
          "[analyzer][generation]") {
  using namespace noleax::trace;

  SECTION("size-zero adapter frees the old generation") {
    noleax::analyzer::GenerationEndReason observed_reason{};
    noleax::analyzer::GenerationCallbacks callbacks;
    callbacks.on_ended = [&observed_reason](const noleax::analyzer::MemoryGeneration&,
                                            noleax::analyzer::GenerationEndReason reason,
                                            const Event&) { observed_reason = reason; };
    noleax::analyzer::GenerationTracker tracker{callbacks};
    tracker.observe(allocation_event(1U, 10U, 0x2000U));
    tracker.observe(reallocation_event(2U, 10U, 0U, 0x2000U, 0U, ReallocationEffect::kFreed));

    CHECK(tracker.live_count() == 0U);
    CHECK(observed_reason == noleax::analyzer::GenerationEndReason::kReallocationFreed);
  }

  SECTION("reallocating a preexisting block starts a known new generation") {
    noleax::analyzer::GenerationTracker tracker;
    tracker.observe(reallocation_event(1U, 0U, 11U, 0x2000U, 0x3000U,
                                       ReallocationEffect::kNewGeneration,
                                       EventStatus::kPreexisting));

    CHECK(tracker.find_allocation(AllocationId{11U}) != nullptr);
    CHECK(tracker.orphaned_allocation_end_count() == 0U);
  }
}

TEST_CASE("ended addresses can be reused without confusing generation IDs",
          "[analyzer][generation]") {
  noleax::analyzer::GenerationTracker tracker;
  tracker.observe(allocation_event(1U, 10U, 0x2000U));
  tracker.observe(free_event(2U, 10U, 0x2000U));
  tracker.observe(allocation_event(3U, 12U, 0x2000U, 256U));

  CHECK(tracker.find_allocation(noleax::trace::AllocationId{10U}) == nullptr);
  const auto* live = tracker.find_allocation(noleax::trace::AllocationId{12U});
  REQUIRE(live != nullptr);
  CHECK(live->address == 0x2000U);
  CHECK(live->size == 256U);
  CHECK(tracker.created_count() == 2U);
  CHECK(tracker.ended_count() == 1U);
}

TEST_CASE("successful heap destroy ends every live generation in that heap",
          "[analyzer][generation]") {
  using namespace noleax::analyzer;
  std::vector<std::uint64_t> destroyed_ids;
  GenerationCallbacks callbacks;
  callbacks.on_ended = [&destroyed_ids](const MemoryGeneration& generation,
                                        GenerationEndReason reason, const noleax::trace::Event&) {
    if (reason == GenerationEndReason::kHeapDestroyed) {
      destroyed_ids.push_back(generation.allocation_id.value());
    }
  };
  GenerationTracker tracker{callbacks};
  tracker.observe(allocation_event(1U, 10U, 0x2000U, 64U, 1U));
  tracker.observe(allocation_event(2U, 11U, 0x3000U, 64U, 1U));
  tracker.observe(allocation_event(3U, 12U, 0x4000U, 64U, 2U));
  tracker.observe(heap_destroy_event(4U, 1U));

  CHECK(destroyed_ids == std::vector<std::uint64_t>{10U, 11U});
  CHECK(tracker.find_allocation(noleax::trace::AllocationId{10U}) == nullptr);
  CHECK(tracker.find_allocation(noleax::trace::AllocationId{11U}) == nullptr);
  CHECK(tracker.find_allocation(noleax::trace::AllocationId{12U}) != nullptr);
  CHECK(tracker.live_count() == 1U);
}

TEST_CASE("missing creation events become nonfatal orphan end counters", "[analyzer][generation]") {
  noleax::analyzer::GenerationTracker tracker;
  tracker.observe(free_event(1U, 90U, 0x2000U));
  tracker.observe(vm_free_event(2U, 91U, 0x4000U));
  tracker.observe(reallocation_event(3U, 92U, 93U, 0x6000U, 0x7000U));

  CHECK(tracker.orphaned_allocation_end_count() == 2U);
  CHECK(tracker.orphaned_mapping_end_count() == 1U);
  CHECK(tracker.find_allocation(noleax::trace::AllocationId{93U}) != nullptr);
  CHECK(tracker.created_count() == 1U);
}

TEST_CASE("remote virtual memory operations do not enter local generation state",
          "[analyzer][generation]") {
  auto remote = vm_allocate_event(1U, 20U, 0x4000U);
  auto& allocation = std::get<noleax::trace::VmAllocateEvent>(remote.payload);
  allocation.target.scope = noleax::trace::ProcessMemoryScope::kRemoteProcess;
  allocation.mapping_id = noleax::trace::MappingId{};

  noleax::analyzer::GenerationTracker tracker;
  tracker.observe(remote);
  CHECK(tracker.live_count() == 0U);
  CHECK(tracker.created_count() == 0U);
}

TEST_CASE("generation identifiers cannot be reused after a generation ends",
          "[analyzer][generation]") {
  SECTION("allocation_id") {
    noleax::analyzer::GenerationTracker tracker;
    tracker.observe(allocation_event(1U, 10U, 0x2000U));
    tracker.observe(free_event(2U, 10U, 0x2000U));
    CHECK_THROWS_AS(tracker.observe(allocation_event(3U, 10U, 0x3000U)),
                    noleax::analyzer::GenerationStateError);
  }

  SECTION("mapping_id") {
    noleax::analyzer::GenerationTracker tracker;
    tracker.observe(map_event(1U, 20U, 0x4000U));
    tracker.observe(unmap_event(2U, 20U, 0x4000U));
    CHECK_THROWS_AS(tracker.observe(vm_allocate_event(3U, 20U, 0x8000U)),
                    noleax::analyzer::GenerationStateError);
  }
}

TEST_CASE("generation ends must agree with the generation identified by ID",
          "[analyzer][generation]") {
  SECTION("allocation address") {
    noleax::analyzer::GenerationTracker tracker;
    tracker.observe(allocation_event(1U, 10U, 0x2000U));
    CHECK_THROWS_AS(tracker.observe(free_event(2U, 10U, 0x3000U)),
                    noleax::analyzer::GenerationStateError);
    CHECK(tracker.find_allocation(noleax::trace::AllocationId{10U}) != nullptr);
  }

  SECTION("allocation heap") {
    noleax::analyzer::GenerationTracker tracker;
    tracker.observe(allocation_event(1U, 10U, 0x2000U, 64U, 1U));
    CHECK_THROWS_AS(
        tracker.observe(reallocation_event(2U, 10U, 11U, 0x2000U, 0x3000U,
                                           noleax::trace::ReallocationEffect::kNewGeneration,
                                           noleax::trace::EventStatus::kSuccess, 2U)),
        noleax::analyzer::GenerationStateError);
    CHECK(tracker.find_allocation(noleax::trace::AllocationId{10U}) != nullptr);
    CHECK(tracker.find_allocation(noleax::trace::AllocationId{11U}) == nullptr);
  }

  SECTION("mapping kind") {
    noleax::analyzer::GenerationTracker tracker;
    tracker.observe(map_event(1U, 20U, 0x4000U));
    CHECK_THROWS_AS(tracker.observe(vm_free_event(2U, 20U, 0x4000U)),
                    noleax::analyzer::GenerationStateError);
    CHECK(tracker.find_mapping(noleax::trace::MappingId{20U}) != nullptr);
  }
}
