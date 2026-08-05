#include "noleax/trace/record_codec.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/memory_snapshot.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/trace_reader.hpp"
#include "noleax/trace/wire_format.hpp"

namespace {

[[nodiscard]] noleax::trace::EventHeader event_header(std::uint64_t sequence) {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{sequence};
  header.monotonic_ticks = sequence * 10U;
  header.thread_id = 7U;
  header.api_id = static_cast<noleax::trace::ApiId>(sequence);
  header.status = noleax::trace::EventStatus::kSuccess;
  header.stack_id = noleax::trace::StackId{sequence + 100U};
  header.flags = static_cast<std::uint32_t>(sequence);
  return header;
}

[[nodiscard]] std::vector<noleax::trace::Event> all_memory_events() {
  using namespace noleax::trace;
  std::vector<Event> events;

  HeapCreateEvent heap_create;
  heap_create.heap_handle = 0x1000U;
  heap_create.heap_id = HeapId{1U};
  heap_create.heap_flags = 2U;
  heap_create.reserve_size = 4096U;
  heap_create.commit_size = 1024U;
  events.emplace_back(Event{event_header(1U), heap_create});

  HeapDestroyEvent heap_destroy;
  heap_destroy.heap_handle = 0x1000U;
  heap_destroy.heap_id = HeapId{1U};
  heap_destroy.raw_result = 1U;
  events.emplace_back(Event{event_header(2U), heap_destroy});

  AllocationEvent allocation;
  allocation.heap_handle = 0x1000U;
  allocation.heap_id = HeapId{1U};
  allocation.requested_size = 64U;
  allocation.result_address = 0x2000U;
  allocation.allocation_id = AllocationId{10U};
  allocation.api_flags = 8U;
  events.emplace_back(Event{event_header(3U), allocation});

  ReallocationEvent reallocation;
  reallocation.heap_handle = 0x1000U;
  reallocation.heap_id = HeapId{1U};
  reallocation.old_address = 0x2000U;
  reallocation.old_allocation_id = AllocationId{10U};
  reallocation.requested_size = 128U;
  reallocation.result_address = 0x3000U;
  reallocation.new_allocation_id = AllocationId{11U};
  reallocation.api_flags = 9U;
  reallocation.effect = ReallocationEffect::kNewGeneration;
  events.emplace_back(Event{event_header(4U), reallocation});

  FreeEvent free_event;
  free_event.heap_handle = 0x1000U;
  free_event.heap_id = HeapId{1U};
  free_event.address = 0x3000U;
  free_event.allocation_id = AllocationId{11U};
  free_event.raw_result = 1U;
  free_event.api_flags = 10U;
  events.emplace_back(Event{event_header(5U), free_event});

  ProcessTarget current_process;
  current_process.scope = ProcessMemoryScope::kCurrentProcess;
  current_process.process_handle = 0xFFFFU;
  current_process.process_id = 42U;

  VmAllocateEvent vm_allocate;
  vm_allocate.target = current_process;
  vm_allocate.requested_base = 0U;
  vm_allocate.result_base = 0x4000U;
  vm_allocate.requested_size = 4096U;
  vm_allocate.result_size = 8192U;
  vm_allocate.mapping_base = 0x4000U;
  vm_allocate.mapping_size = 8192U;
  vm_allocate.allocation_type = 0x3000U;
  vm_allocate.protection = 4U;
  vm_allocate.mapping_id = MappingId{20U};
  events.emplace_back(Event{event_header(6U), vm_allocate});

  VmFreeEvent vm_free;
  vm_free.target = current_process;
  vm_free.base = 0x4000U;
  vm_free.region_size = 0U;
  vm_free.free_type = 0x8000U;
  vm_free.mapping_id = MappingId{20U};
  events.emplace_back(Event{event_header(7U), vm_free});

  MapEvent map;
  map.section_handle = 0x1234U;
  map.target = current_process;
  map.result_base = 0x5000U;
  map.view_size = 16384U;
  map.section_offset = 4096U;
  map.protection = 2U;
  map.mapping_id = MappingId{21U};
  events.emplace_back(Event{event_header(8U), map});

  UnmapEvent unmap;
  unmap.target = current_process;
  unmap.base = 0x5000U;
  unmap.mapping_id = MappingId{21U};
  events.emplace_back(Event{event_header(9U), unmap});

  return events;
}

[[nodiscard]] noleax::trace::LossRecord loss_record() {
  noleax::trace::LossRecord loss;
  loss.reason = noleax::trace::LossReason::kQueueFull;
  loss.location = noleax::trace::LossLocation::kAgentQueue;
  loss.estimated_event_count = 3U;
  loss.sequence_range =
      noleax::trace::SequenceRange{noleax::trace::Sequence{10U}, noleax::trace::Sequence{12U}};
  loss.tick_range = noleax::trace::TickRange{100U, 120U};
  return loss;
}

[[nodiscard]] noleax::trace::CaptureStatistics statistics() {
  noleax::trace::CaptureStatistics result;
  result.observed_calls = 3U;
  result.successful_operations = 2U;
  result.failed_operations = 1U;
  result.filtered_before_queue = 1U;
  result.dropped_events = 0U;
  result.unique_stacks = 1U;
  result.reused_stacks = 1U;
  result.written_uncompressed_bytes = 500U;
  result.written_stored_bytes = 300U;
  result.per_api = {
      noleax::trace::ApiStatistics{1U, 2U, 2U, 0U, 1U, 0U},
      noleax::trace::ApiStatistics{2U, 1U, 0U, 1U, 0U, 0U},
  };
  return result;
}

[[nodiscard]] noleax::trace::StackDefinition stack_definition() {
  noleax::trace::StackDefinition definition;
  definition.stack_id = noleax::trace::StackId{0x0102030405060708ULL};
  definition.status = noleax::trace::StackCaptureStatus::kTruncatedByDepth;
  definition.frames = {
      noleax::trace::StackFrame{noleax::trace::ModuleId{3U}, 0x123U, 0x00007FF612341123ULL, 0U},
      noleax::trace::StackFrame{{}, 0U, 0x00007FF698765432ULL, 0U},
  };
  return definition;
}

[[nodiscard]] noleax::trace::ModuleLoad module_load() {
  noleax::trace::ModuleLoad load;
  load.module_id = noleax::trace::ModuleId{7U};
  load.monotonic_ticks = 55U;
  load.base_address = 0x00007FF612340000ULL;
  load.image_size = 0x5000U;
  load.image_path = "C:/fixtures/noleax-module.dll";
  load.image_identity = noleax::trace::PeImageIdentity{0x12345678U, 0x90ABCDEFU, 0x5000U};
  noleax::trace::PdbIdentity pdb;
  pdb.guid[0] = std::byte{0x42};
  pdb.guid[15] = std::byte{0x99};
  pdb.age = 3U;
  load.pdb_identity = pdb;
  load.pdb_path = "noleax-module.pdb";
  return load;
}

[[nodiscard]] noleax::trace::EndOfTrace end_of_trace() {
  noleax::trace::EndOfTrace end;
  end.final_sequence = noleax::trace::Sequence{12U};
  end.final_monotonic_ticks = 120U;
  end.normal_stop = true;
  end.target_exit_code = -7;
  end.aggregate_completeness.add(noleax::trace::CompletenessIssue::kEventLoss);
  return end;
}

[[nodiscard]] std::uint32_t read_u32(std::span<const std::byte> input, std::size_t offset) {
  std::uint32_t value = 0U;
  for (std::size_t index = 0; index < sizeof(value); ++index) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(input[offset + index]))
             << (index * 8U);
  }
  return value;
}

[[nodiscard]] std::uint64_t read_u64(std::span<const std::byte> input, std::size_t offset) {
  std::uint64_t value = 0U;
  for (std::size_t index = 0; index < sizeof(value); ++index) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(input[offset + index]))
             << (index * 8U);
  }
  return value;
}

void write_u32(std::vector<std::byte>& output, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < sizeof(value); ++index) {
    output.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xFFU);
  }
}

void write_u64(std::vector<std::byte>& output, std::size_t offset, std::uint64_t value) {
  for (std::size_t index = 0; index < sizeof(value); ++index) {
    output.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xFFU);
  }
}

}  // namespace

TEST_CASE("capture scope record has stable bytes and round trips", "[trace][record-codec]") {
  using namespace noleax::trace;
  const CaptureScope expected{true, false};
  std::vector<std::byte> encoded;
  append_capture_scope_record(encoded, expected);
  const std::vector<std::byte> golden{
      std::byte{0x01}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
      std::byte{0x10}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
      std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
      std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
  };
  CHECK(encoded == golden);

  RecordCursor cursor{encoded};
  const auto record = cursor.next();
  REQUIRE(record.has_value());
  const auto decoded = decode_capture_scope_record(*record);
  REQUIRE(decoded.has_value());
  CHECK(*decoded == expected);
  CHECK(cursor.done());
}

TEST_CASE("stack definition record has stable layout and round trips", "[trace][record-codec]") {
  using namespace noleax::trace;
  const StackDefinition expected = stack_definition();
  std::vector<std::byte> encoded;
  append_stack_definition_record(encoded, expected);

  REQUIRE(encoded.size() == 88U);
  CHECK(std::to_integer<std::uint8_t>(encoded[0]) ==
        static_cast<std::uint8_t>(StackRecordType::kDefinition));
  CHECK(read_u32(encoded, 4U) == 88U);
  CHECK(read_u64(encoded, 8U) == expected.stack_id.value());
  CHECK(std::to_integer<std::uint8_t>(encoded[16]) ==
        static_cast<std::uint8_t>(StackCaptureStatus::kTruncatedByDepth));
  CHECK(read_u32(encoded, 20U) == 2U);
  CHECK(read_u64(encoded, 24U) == expected.frames[0].module_id.value());
  CHECK(read_u64(encoded, 32U) == expected.frames[0].module_offset);
  CHECK(read_u64(encoded, 40U) == expected.frames[0].absolute_address);
  CHECK(read_u64(encoded, 56U) == 0U);
  CHECK(read_u64(encoded, 72U) == expected.frames[1].absolute_address);

  RecordCursor cursor{encoded};
  const auto decoded = decode_stack_definition_record(*cursor.next());
  REQUIRE(decoded.has_value());
  CHECK(*decoded == expected);
  CHECK(cursor.done());
}

TEST_CASE("module generation records have stable layouts and round trip",
          "[trace][record-codec][module]") {
  using namespace noleax::trace;
  const ModuleLoad expected_load = module_load();
  const ModuleUnload expected_unload{expected_load.module_id, 99U};
  std::vector<std::byte> encoded;
  append_module_load_record(encoded, expected_load);
  const std::size_t unload_offset = encoded.size();
  append_module_unload_record(encoded, expected_unload);

  REQUIRE(unload_offset == 88U + expected_load.image_path.size() + expected_load.pdb_path.size());
  CHECK(read_u32(encoded, 4U) == unload_offset);
  CHECK(read_u64(encoded, 8U) == expected_load.module_id.value());
  CHECK(read_u64(encoded, 16U) == expected_load.monotonic_ticks);
  CHECK(read_u64(encoded, 24U) == expected_load.base_address);
  CHECK(read_u64(encoded, 32U) == expected_load.image_size);
  CHECK(read_u32(encoded, 48U) == expected_load.image_identity->timestamp);
  CHECK(read_u32(encoded, 64U) == expected_load.image_path.size());
  CHECK(read_u32(encoded, unload_offset + 4U) == 24U);

  RecordCursor cursor{encoded};
  const auto decoded_load = decode_module_record(*cursor.next());
  REQUIRE(decoded_load.has_value());
  REQUIRE(std::holds_alternative<ModuleLoad>(*decoded_load));
  CHECK(std::get<ModuleLoad>(*decoded_load) == expected_load);
  const auto decoded_unload = decode_module_record(*cursor.next());
  REQUIRE(decoded_unload.has_value());
  REQUIRE(std::holds_alternative<ModuleUnload>(*decoded_unload));
  CHECK(std::get<ModuleUnload>(*decoded_unload) == expected_unload);
  CHECK(cursor.done());
}

TEST_CASE("module codec rejects inconsistent identities and path lengths",
          "[trace][record-codec][module]") {
  using namespace noleax::trace;
  auto load = module_load();
  load.image_identity->image_size += 1U;
  std::vector<std::byte> encoded;
  CHECK_THROWS_AS(append_module_load_record(encoded, load), ModuleValidationError);

  load = module_load();
  append_module_load_record(encoded, load);
  write_u32(encoded, 64U, 0x7FFFFFFFU);
  RecordCursor cursor{encoded};
  CHECK_THROWS_AS(decode_module_record(*cursor.next()), RecordCodecError);
}

TEST_CASE("stack definition validation distinguishes captured and unavailable stacks",
          "[trace][record-codec]") {
  using namespace noleax::trace;
  StackDefinition unavailable;
  unavailable.stack_id = StackId{9U};
  unavailable.status = StackCaptureStatus::kUnwindFailed;
  std::vector<std::byte> encoded;
  append_stack_definition_record(encoded, unavailable);
  REQUIRE(encoded.size() == 24U);
  RecordCursor cursor{encoded};
  CHECK(decode_stack_definition_record(*cursor.next()) == unavailable);

  StackDefinition invalid = unavailable;
  invalid.status = StackCaptureStatus::kComplete;
  CHECK_THROWS_AS(append_stack_definition_record(encoded, invalid), StackValidationError);
  invalid = stack_definition();
  invalid.status = StackCaptureStatus::kUnavailable;
  CHECK_THROWS_AS(append_stack_definition_record(encoded, invalid), StackValidationError);
}

TEST_CASE("all normalized memory event records round trip", "[trace][record-codec]") {
  using namespace noleax::trace;
  const auto events = all_memory_events();
  std::vector<std::byte> encoded;
  for (const auto& event : events) {
    append_event_record(encoded, event);
  }

  RecordCursor cursor{encoded};
  for (const auto& expected : events) {
    const auto record = cursor.next();
    REQUIRE(record.has_value());
    const auto decoded = decode_event_chunk_record(*record);
    REQUIRE(decoded.has_value());
    REQUIRE(std::holds_alternative<Event>(*decoded));
    CHECK(std::get<Event>(*decoded) == expected);
  }
  CHECK(cursor.done());
}

TEST_CASE("failed memory event preserves status and system error", "[trace][record-codec]") {
  using namespace noleax::trace;
  auto header = event_header(20U);
  header.status = EventStatus::kFailure;
  header.system_error = SystemError{SystemErrorDomain::kWin32, 8U};
  const Event expected{header, AllocationEvent{}};
  std::vector<std::byte> encoded;
  append_event_record(encoded, expected);

  RecordCursor cursor{encoded};
  const auto decoded = decode_event_chunk_record(*cursor.next());
  REQUIRE(decoded.has_value());
  REQUIRE(std::holds_alternative<Event>(*decoded));
  CHECK(std::get<Event>(*decoded) == expected);
}

TEST_CASE("allocation record offsets and size are stable", "[trace][record-codec]") {
  using namespace noleax::trace;
  const auto events = all_memory_events();
  const auto& allocation = events[2];
  std::vector<std::byte> encoded;
  append_event_record(encoded, allocation);

  REQUIRE(encoded.size() == 112U);
  CHECK(std::to_integer<std::uint8_t>(encoded[0]) ==
        static_cast<std::uint8_t>(EventRecordType::kAllocate));
  CHECK(read_u32(encoded, 4U) == 112U);
  CHECK(read_u64(encoded, 8U) == allocation.header.sequence.value());
  CHECK(read_u64(encoded, 40U) == allocation.header.stack_id.value());
  CHECK(read_u64(encoded, 88U) == std::get<AllocationEvent>(allocation.payload).result_address);
  CHECK(read_u64(encoded, 96U) ==
        std::get<AllocationEvent>(allocation.payload).allocation_id.value());
}

TEST_CASE("loss statistics and end records round trip", "[trace][record-codec]") {
  using namespace noleax::trace;

  SECTION("loss") {
    const auto expected = loss_record();
    std::vector<std::byte> encoded;
    append_loss_record(encoded, expected);
    RecordCursor cursor{encoded};
    const auto decoded = decode_event_chunk_record(*cursor.next());
    REQUIRE(decoded.has_value());
    REQUIRE(std::holds_alternative<LossRecord>(*decoded));
    CHECK(std::get<LossRecord>(*decoded) == expected);
  }

  SECTION("loss with unknown count and ranges") {
    LossRecord expected;
    expected.reason = LossReason::kStackCaptureFailed;
    expected.location = LossLocation::kAgentQueue;
    std::vector<std::byte> encoded;
    append_loss_record(encoded, expected);
    RecordCursor cursor{encoded};
    const auto decoded = decode_event_chunk_record(*cursor.next());
    REQUIRE(decoded.has_value());
    REQUIRE(std::holds_alternative<LossRecord>(*decoded));
    CHECK(std::get<LossRecord>(*decoded) == expected);
  }

  SECTION("statistics") {
    const auto expected = statistics();
    std::vector<std::byte> encoded;
    append_statistics_record(encoded, expected);
    RecordCursor cursor{encoded};
    const auto decoded = decode_statistics_record(*cursor.next());
    REQUIRE(decoded.has_value());
    CHECK(*decoded == expected);
  }

  SECTION("end") {
    const auto expected = end_of_trace();
    std::vector<std::byte> encoded;
    append_end_of_trace_record(encoded, expected);
    RecordCursor cursor{encoded};
    const auto decoded = decode_end_of_trace_record(*cursor.next());
    REQUIRE(decoded.has_value());
    CHECK(*decoded == expected);
  }
}

TEST_CASE("record decoders skip unknown types and versions", "[trace][record-codec]") {
  using namespace noleax::trace;
  const std::array<std::byte, 1> payload{std::byte{0}};
  const RecordView unknown_type{0xFFFFU, 1U, payload};
  const RecordView unknown_version{1U, 2U, payload};

  CHECK_FALSE(decode_capture_scope_record(unknown_type).has_value());
  CHECK_FALSE(decode_stack_definition_record(unknown_type).has_value());
  CHECK_FALSE(decode_event_chunk_record(unknown_type).has_value());
  CHECK_FALSE(decode_statistics_record(unknown_type).has_value());
  CHECK_FALSE(decode_end_of_trace_record(unknown_type).has_value());
  CHECK_FALSE(decode_capture_scope_record(unknown_version).has_value());
  CHECK_FALSE(decode_stack_definition_record(unknown_version).has_value());
  CHECK_FALSE(decode_event_chunk_record(unknown_version).has_value());
  CHECK_FALSE(decode_statistics_record(unknown_version).has_value());
  CHECK_FALSE(decode_end_of_trace_record(unknown_version).has_value());
}

TEST_CASE("record decoders reject malformed known payloads", "[trace][record-codec]") {
  using namespace noleax::trace;

  SECTION("truncated capture scope") {
    const std::array<std::byte, 7> payload{};
    CHECK_THROWS_AS(decode_capture_scope_record(RecordView{1U, 1U, payload}), RecordCodecError);
  }

  SECTION("invalid capture boolean") {
    std::vector<std::byte> encoded;
    append_capture_scope_record(encoded, CaptureScope{true, false});
    encoded[8] = std::byte{2};
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_capture_scope_record(*cursor.next()), RecordCodecError);
  }

  SECTION("contradictory capture scope") {
    std::vector<std::byte> encoded;
    append_capture_scope_record(encoded, CaptureScope{false, true});
    encoded[8] = std::byte{1};
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_capture_scope_record(*cursor.next()), RecordCodecError);
  }

  SECTION("invalid stack status") {
    std::vector<std::byte> encoded;
    append_stack_definition_record(encoded, stack_definition());
    encoded[16] = std::byte{0xFF};
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_stack_definition_record(*cursor.next()), RecordCodecError);
  }

  SECTION("stack frame count exceeds payload") {
    std::vector<std::byte> encoded;
    append_stack_definition_record(encoded, stack_definition());
    write_u32(encoded, 20U, 3U);
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_stack_definition_record(*cursor.next()), RecordCodecError);
  }

  SECTION("stack frame without module has an offset") {
    std::vector<std::byte> encoded;
    append_stack_definition_record(encoded, stack_definition());
    write_u64(encoded, 64U, 1U);
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_stack_definition_record(*cursor.next()), RecordCodecError);
  }

  SECTION("stack fixed and frame reserved fields must be zero") {
    std::vector<std::byte> encoded;
    append_stack_definition_record(encoded, stack_definition());
    encoded[17] = std::byte{1U};
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_stack_definition_record(*cursor.next()), RecordCodecError);

    encoded[17] = std::byte{0U};
    encoded[52] = std::byte{1U};
    RecordCursor frame_cursor{encoded};
    CHECK_THROWS_AS(decode_stack_definition_record(*frame_cursor.next()), RecordCodecError);
  }

  SECTION("invalid event status") {
    std::vector<std::byte> encoded;
    append_event_record(encoded, all_memory_events()[2]);
    encoded[36] = std::byte{0xFF};
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_event_chunk_record(*cursor.next()), RecordCodecError);
  }

  SECTION("semantically invalid allocation") {
    std::vector<std::byte> encoded;
    append_event_record(encoded, all_memory_events()[2]);
    write_u64(encoded, 96U, 0U);
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_event_chunk_record(*cursor.next()), RecordCodecError);
  }

  SECTION("invalid process scope") {
    std::vector<std::byte> encoded;
    append_event_record(encoded, all_memory_events()[5]);
    encoded[64] = std::byte{0xFF};
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_event_chunk_record(*cursor.next()), RecordCodecError);
  }

  SECTION("statistics count exceeds payload") {
    std::vector<std::byte> encoded;
    append_statistics_record(encoded, statistics());
    write_u32(encoded, 80U, 0xFFFFFFFFU);
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_statistics_record(*cursor.next()), RecordCodecError);
  }

  SECTION("absent target exit code is nonzero") {
    auto end = end_of_trace();
    end.target_exit_code.reset();
    std::vector<std::byte> encoded;
    append_end_of_trace_record(encoded, end);
    write_u32(encoded, 32U, 1U);
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_end_of_trace_record(*cursor.next()), RecordCodecError);
  }
}

TEST_CASE("record encoders honor the configured record size limit", "[trace][record-codec]") {
  using namespace noleax::trace;
  std::vector<std::byte> encoded;
  CHECK_THROWS_AS(append_event_record(encoded, all_memory_events()[2], 111U), WireFormatError);
  CHECK(encoded.empty());
  CHECK_THROWS_AS(append_stack_definition_record(encoded, stack_definition(), 87U),
                  RecordCodecError);
  CHECK(encoded.empty());
  CHECK_THROWS_AS(append_module_load_record(encoded, module_load(), 87U), RecordCodecError);
  CHECK(encoded.empty());
}

TEST_CASE("memory counters record has stable layout and round trips", "[trace][record-codec]") {
  using namespace noleax::trace;
  const MemoryCounters expected{0x0102030405060708ULL, 0x1111U, 0x2222U, 0x3333U, 0x4444U};
  std::vector<std::byte> encoded;
  append_memory_counters_record(encoded, expected);

  REQUIRE(encoded.size() == 56U);
  CHECK(std::to_integer<std::uint8_t>(encoded[0]) ==
        static_cast<std::uint8_t>(MemoryRecordType::kCounters));
  CHECK(read_u32(encoded, 4U) == 56U);
  CHECK(read_u64(encoded, 8U) == expected.monotonic_ticks);
  CHECK(read_u64(encoded, 16U) == expected.working_set_bytes);
  CHECK(read_u64(encoded, 24U) == expected.peak_working_set_bytes);
  CHECK(read_u64(encoded, 32U) == expected.private_bytes);
  CHECK(read_u64(encoded, 40U) == expected.commit_bytes);
  CHECK(read_u64(encoded, 48U) == 0U);

  RecordCursor cursor{encoded};
  const auto decoded = decode_memory_counters_record(*cursor.next());
  REQUIRE(decoded.has_value());
  CHECK(*decoded == expected);
  CHECK(cursor.done());
}

TEST_CASE("memory map record has stable layout and round trips", "[trace][record-codec]") {
  using namespace noleax::trace;
  MemoryMap expected;
  expected.monotonic_ticks = 0x0102030405060708ULL;
  expected.committed_bytes = 0x1000U;
  expected.reserved_bytes = 0x2000U;
  expected.free_bytes = 0x3000U;
  expected.largest_free_bytes = 0x2800U;
  expected.regions = {
      MemoryMapRegion{0x10000U, 0x2000U, MemoryRegionState::kCommit, MemoryRegionType::kPrivate,
                      0x04U},
      MemoryMapRegion{0x40000000U, 0x100000U, MemoryRegionState::kReserve,
                      MemoryRegionType::kMapped, 0x02U},
  };
  std::vector<std::byte> encoded;
  append_memory_map_record(encoded, expected);

  REQUIRE(encoded.size() == 8U + 48U + 2U * 24U);
  CHECK(std::to_integer<std::uint8_t>(encoded[0]) ==
        static_cast<std::uint8_t>(MemoryRecordType::kMap));
  CHECK(read_u32(encoded, 4U) == 8U + 48U + 2U * 24U);
  CHECK(read_u64(encoded, 8U) == expected.monotonic_ticks);
  CHECK(std::to_integer<std::uint8_t>(encoded[16]) == 0U);
  CHECK(read_u32(encoded, 20U) == 2U);
  CHECK(read_u64(encoded, 24U) == expected.committed_bytes);
  CHECK(read_u64(encoded, 32U) == expected.reserved_bytes);
  CHECK(read_u64(encoded, 40U) == expected.free_bytes);
  CHECK(read_u64(encoded, 48U) == expected.largest_free_bytes);
  CHECK(read_u64(encoded, 56U) == expected.regions[0].base);
  CHECK(read_u64(encoded, 64U) == expected.regions[0].size);
  CHECK(std::to_integer<std::uint8_t>(encoded[72]) ==
        static_cast<std::uint8_t>(MemoryRegionState::kCommit));
  CHECK(std::to_integer<std::uint8_t>(encoded[73]) ==
        static_cast<std::uint8_t>(MemoryRegionType::kPrivate));
  CHECK(read_u32(encoded, 74U) == expected.regions[0].protect);

  RecordCursor cursor{encoded};
  const auto decoded = decode_memory_map_record(*cursor.next());
  REQUIRE(decoded.has_value());
  CHECK(*decoded == expected);
  CHECK(cursor.done());
}

TEST_CASE("memory map record supports the region limit and the truncated flag",
          "[trace][record-codec]") {
  using namespace noleax::trace;
  MemoryMap map;
  map.monotonic_ticks = 42U;
  map.truncated = true;
  map.regions.reserve(kMaximumMemoryMapRegions);
  for (std::uint32_t index = 0U; index < kMaximumMemoryMapRegions; ++index) {
    map.regions.push_back(MemoryMapRegion{0x10000ULL + 0x3000ULL * index, 0x1000U,
                                          MemoryRegionState::kReserve, MemoryRegionType::kImage,
                                          0x01U});
  }
  std::vector<std::byte> encoded;
  append_memory_map_record(encoded, map);
  RecordCursor cursor{encoded};
  const auto decoded = decode_memory_map_record(*cursor.next());
  REQUIRE(decoded.has_value());
  CHECK(*decoded == map);

  MemoryMap too_many = map;
  too_many.regions.push_back(MemoryMapRegion{0x7F0000000000ULL, 0x1000U, MemoryRegionState::kCommit,
                                             MemoryRegionType::kPrivate, 0x04U});
  std::vector<std::byte> overflow;
  CHECK_THROWS_AS(append_memory_map_record(overflow, too_many), MemorySnapshotValidationError);
  CHECK(overflow.empty());
}

TEST_CASE("memory record decoders skip unknown types and versions", "[trace][record-codec]") {
  using namespace noleax::trace;
  const std::array<std::byte, 1> payload{std::byte{0}};
  const RecordView unknown_type{0xFFFFU, 1U, payload};
  const RecordView unknown_version{1U, 2U, payload};
  const RecordView unknown_map_version{2U, 2U, payload};

  CHECK_FALSE(decode_memory_counters_record(unknown_type).has_value());
  CHECK_FALSE(decode_memory_map_record(unknown_type).has_value());
  CHECK_FALSE(decode_memory_counters_record(unknown_version).has_value());
  CHECK_FALSE(decode_memory_map_record(unknown_version).has_value());
  // type=1 matches the counters decoder but never reaches the map decoder's version check.
  CHECK_FALSE(decode_memory_map_record(unknown_map_version).has_value());
}

TEST_CASE("memory record decoders reject malformed payloads", "[trace][record-codec]") {
  using namespace noleax::trace;

  SECTION("counters payload has trailing bytes") {
    const std::array<std::byte, 49> payload{};
    CHECK_THROWS_AS(decode_memory_counters_record(RecordView{
                        static_cast<std::uint16_t>(MemoryRecordType::kCounters), 1U, payload}),
                    RecordCodecError);
  }

  SECTION("counters peak below working set") {
    std::vector<std::byte> encoded;
    append_memory_counters_record(encoded, MemoryCounters{1U, 0x2000U, 0x2000U, 0U, 0U});
    write_u64(encoded, 24U, 0x1000U);
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_memory_counters_record(*cursor.next()), RecordCodecError);
  }

  SECTION("map region count exceeds payload") {
    MemoryMap map;
    map.regions.push_back(MemoryMapRegion{0x10000U, 0x1000U, MemoryRegionState::kCommit,
                                          MemoryRegionType::kPrivate, 0x04U});
    std::vector<std::byte> encoded;
    append_memory_map_record(encoded, map);
    write_u32(encoded, 20U, 2U);
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_memory_map_record(*cursor.next()), RecordCodecError);
  }

  SECTION("map region state is unknown") {
    MemoryMap map;
    map.regions.push_back(MemoryMapRegion{0x10000U, 0x1000U, MemoryRegionState::kCommit,
                                          MemoryRegionType::kPrivate, 0x04U});
    std::vector<std::byte> encoded;
    append_memory_map_record(encoded, map);
    encoded[72] = std::byte{0xFF};
    RecordCursor cursor{encoded};
    CHECK_THROWS_AS(decode_memory_map_record(*cursor.next()), RecordCodecError);
  }

  SECTION("map regions overlap") {
    MemoryMap map;
    map.regions.push_back(MemoryMapRegion{0x10000U, 0x2000U, MemoryRegionState::kCommit,
                                          MemoryRegionType::kPrivate, 0x04U});
    map.regions.push_back(MemoryMapRegion{0x11000U, 0x1000U, MemoryRegionState::kCommit,
                                          MemoryRegionType::kPrivate, 0x04U});
    std::vector<std::byte> encoded;
    CHECK_THROWS_AS(append_memory_map_record(encoded, map), MemorySnapshotValidationError);
  }

  SECTION("memory map exceeds the configured record size limit") {
    MemoryMap map;
    map.regions.push_back(MemoryMapRegion{0x10000U, 0x1000U, MemoryRegionState::kCommit,
                                          MemoryRegionType::kPrivate, 0x04U});
    std::vector<std::byte> encoded;
    CHECK_THROWS_AS(append_memory_map_record(encoded, map, 79U), RecordCodecError);
    CHECK(encoded.empty());
  }
}
