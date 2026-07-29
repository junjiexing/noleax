#include "noleax/trace/event.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <utility>

namespace {

[[nodiscard]] noleax::trace::EventHeader successful_header() {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{1U};
  header.api_id = 1U;
  header.status = noleax::trace::EventStatus::kSuccess;
  return header;
}

[[nodiscard]] noleax::trace::ReallocationEvent reallocation(
    noleax::trace::Address old_address, noleax::trace::AllocationId old_id,
    noleax::trace::Address new_address, noleax::trace::AllocationId new_id,
    noleax::trace::ReallocationEffect effect) {
  noleax::trace::ReallocationEvent event;
  event.old_address = old_address;
  event.old_allocation_id = old_id;
  event.requested_size = 128U;
  event.result_address = new_address;
  event.new_allocation_id = new_id;
  event.effect = effect;
  return event;
}

}  // namespace

TEST_CASE("event payload determines its normalized operation", "[trace][event]") {
  using namespace noleax::trace;
  const std::array cases{
      std::pair{EventPayload{HeapCreateEvent{}}, EventOperation::kHeapCreate},
      std::pair{EventPayload{HeapDestroyEvent{}}, EventOperation::kHeapDestroy},
      std::pair{EventPayload{AllocationEvent{}}, EventOperation::kAllocate},
      std::pair{EventPayload{ReallocationEvent{}}, EventOperation::kReallocate},
      std::pair{EventPayload{FreeEvent{}}, EventOperation::kFree},
      std::pair{EventPayload{VmAllocateEvent{}}, EventOperation::kVmAllocate},
      std::pair{EventPayload{VmFreeEvent{}}, EventOperation::kVmFree},
      std::pair{EventPayload{MapEvent{}}, EventOperation::kMap},
      std::pair{EventPayload{UnmapEvent{}}, EventOperation::kUnmap},
  };

  for (const auto& [payload, expected] : cases) {
    CHECK(event_operation(payload) == expected);
  }
}

TEST_CASE("allocation event validation enforces generation IDs", "[trace][event]") {
  using namespace noleax::trace;
  auto header = successful_header();
  AllocationEvent allocation;
  allocation.result_address = 0x1000U;
  allocation.allocation_id = AllocationId{7U};
  Event event{header, allocation};

  CHECK_NOTHROW(validate_event(event));
  CHECK(allocation_creates_generation(header, allocation));

  std::get<AllocationEvent>(event.payload).allocation_id = AllocationId{};
  CHECK_THROWS_AS(validate_event(event), EventValidationError);

  event.header.status = EventStatus::kFailure;
  auto& failed = std::get<AllocationEvent>(event.payload);
  failed.result_address = 0U;
  failed.allocation_id = AllocationId{};
  CHECK_NOTHROW(validate_event(event));
  CHECK_FALSE(allocation_creates_generation(event.header, failed));

  event.header.status = EventStatus::kUnmatched;
  CHECK_THROWS_AS(validate_event(event), EventValidationError);
}

TEST_CASE("event headers reject missing sequences and inconsistent error domains",
          "[trace][event]") {
  using namespace noleax::trace;
  AllocationEvent allocation;
  allocation.result_address = 0x1000U;
  allocation.allocation_id = AllocationId{1U};

  auto header = successful_header();
  header.sequence = Sequence{};
  CHECK_THROWS_AS(validate_event(Event{header, allocation}), EventValidationError);

  header.sequence = Sequence{1U};
  header.api_id = 0U;
  header.system_error.code = 5U;
  CHECK_THROWS_AS(validate_event(Event{header, allocation}), EventValidationError);

  header.system_error.domain = SystemErrorDomain::kWin32;
  CHECK_NOTHROW(validate_event(Event{header, allocation}));

  header.status = static_cast<EventStatus>(0xFFU);
  CHECK_THROWS_AS(validate_event(Event{header, allocation}), EventValidationError);
  header.status = EventStatus::kSuccess;
  header.system_error.domain = static_cast<SystemErrorDomain>(0xFFU);
  CHECK_THROWS_AS(validate_event(Event{header, allocation}), EventValidationError);
}

TEST_CASE("reallocation lifecycle distinguishes failure in-place move and free", "[trace][event]") {
  using namespace noleax::trace;
  constexpr Address kOldAddress = 0x1000U;
  constexpr Address kNewAddress = 0x2000U;
  const AllocationId old_id{10U};
  const AllocationId new_id{11U};

  auto header = successful_header();

  const auto in_place =
      reallocation(kOldAddress, old_id, kOldAddress, new_id, ReallocationEffect::kNewGeneration);
  CHECK_NOTHROW(validate_event(Event{header, in_place}));
  CHECK(reallocation_ends_old_generation(header, in_place));
  CHECK(reallocation_creates_new_generation(header, in_place));

  const auto moved =
      reallocation(kOldAddress, old_id, kNewAddress, new_id, ReallocationEffect::kNewGeneration);
  CHECK_NOTHROW(validate_event(Event{header, moved}));
  CHECK(reallocation_ends_old_generation(header, moved));
  CHECK(reallocation_creates_new_generation(header, moved));

  const auto null_old =
      reallocation(0U, AllocationId{}, kNewAddress, new_id, ReallocationEffect::kNewGeneration);
  CHECK_NOTHROW(validate_event(Event{header, null_old}));
  CHECK_FALSE(reallocation_ends_old_generation(header, null_old));
  CHECK(reallocation_creates_new_generation(header, null_old));

  const auto freed =
      reallocation(kOldAddress, old_id, 0U, AllocationId{}, ReallocationEffect::kFreed);
  CHECK_NOTHROW(validate_event(Event{header, freed}));
  CHECK(reallocation_ends_old_generation(header, freed));
  CHECK_FALSE(reallocation_creates_new_generation(header, freed));

  header.status = EventStatus::kFailure;
  const auto failed =
      reallocation(kOldAddress, old_id, 0U, AllocationId{}, ReallocationEffect::kNoChange);
  CHECK_NOTHROW(validate_event(Event{header, failed}));
  CHECK_FALSE(reallocation_ends_old_generation(header, failed));
  CHECK_FALSE(reallocation_creates_new_generation(header, failed));
}

TEST_CASE("reallocation rejects reused IDs and failed-call side effects", "[trace][event]") {
  using namespace noleax::trace;
  auto header = successful_header();
  const AllocationId allocation_id{5U};
  const auto reused_id = reallocation(0x1000U, allocation_id, 0x1000U, allocation_id,
                                      ReallocationEffect::kNewGeneration);
  CHECK_THROWS_AS(validate_event(Event{header, reused_id}), EventValidationError);

  header.status = EventStatus::kFailure;
  const auto failed_with_result = reallocation(0x1000U, allocation_id, 0x2000U, AllocationId{6U},
                                               ReallocationEffect::kNewGeneration);
  CHECK_THROWS_AS(validate_event(Event{header, failed_with_result}), EventValidationError);

  header.status = EventStatus::kUnmatched;
  const auto unmatched_with_id = reallocation(0x1000U, allocation_id, 0x2000U, AllocationId{6U},
                                              ReallocationEffect::kNewGeneration);
  CHECK_THROWS_AS(validate_event(Event{header, unmatched_with_id}), EventValidationError);

  header.status = EventStatus::kSuccess;
  const auto freed_without_old_id =
      reallocation(0x1000U, AllocationId{}, 0U, AllocationId{}, ReallocationEffect::kFreed);
  CHECK_THROWS_AS(validate_event(Event{header, freed_without_old_id}), EventValidationError);

  const auto invalid_effect = reallocation(0x1000U, allocation_id, 0U, AllocationId{},
                                           static_cast<ReallocationEffect>(0xFFU));
  CHECK_THROWS_AS(validate_event(Event{header, invalid_effect}), EventValidationError);
}

TEST_CASE("free and heap destroy only end matched successful generations", "[trace][event]") {
  using namespace noleax::trace;
  auto header = successful_header();

  FreeEvent free_event;
  free_event.allocation_id = AllocationId{3U};
  CHECK(free_ends_generation(header, free_event));
  CHECK_NOTHROW(validate_event(Event{header, free_event}));

  header.status = EventStatus::kFailure;
  CHECK_FALSE(free_ends_generation(header, free_event));

  header.status = EventStatus::kUnmatched;
  free_event.allocation_id = AllocationId{};
  CHECK_FALSE(free_ends_generation(header, free_event));
  CHECK_NOTHROW(validate_event(Event{header, free_event}));

  header.status = EventStatus::kSuccess;
  HeapDestroyEvent destroy;
  destroy.heap_id = HeapId{4U};
  CHECK(heap_destroy_ends_generations(header, destroy));
  CHECK_NOTHROW(validate_event(Event{header, destroy}));
}

TEST_CASE("remote virtual memory events never create local mapping IDs", "[trace][event]") {
  using namespace noleax::trace;
  const auto header = successful_header();

  VmAllocateEvent remote;
  remote.target.scope = ProcessMemoryScope::kRemoteProcess;
  remote.target.process_handle = 0x1234U;
  CHECK_NOTHROW(validate_event(Event{header, remote}));

  remote.mapping_id = MappingId{1U};
  CHECK_THROWS_AS(validate_event(Event{header, remote}), EventValidationError);

  VmAllocateEvent local;
  local.target.scope = ProcessMemoryScope::kCurrentProcess;
  local.mapping_id = MappingId{1U};
  CHECK_NOTHROW(validate_event(Event{header, local}));

  local.mapping_id = MappingId{};
  CHECK_THROWS_AS(validate_event(Event{header, local}), EventValidationError);

  VmFreeEvent local_free;
  local_free.target.scope = ProcessMemoryScope::kCurrentProcess;
  CHECK_THROWS_AS(validate_event(Event{header, local_free}), EventValidationError);
  local_free.mapping_id = MappingId{1U};
  CHECK_NOTHROW(validate_event(Event{header, local_free}));

  local_free.target.scope = static_cast<ProcessMemoryScope>(0xFFU);
  CHECK_THROWS_AS(validate_event(Event{header, local_free}), EventValidationError);
}
