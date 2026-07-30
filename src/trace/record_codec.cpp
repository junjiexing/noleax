#include "noleax/trace/record_codec.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/trace_reader.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::trace {
namespace {

inline constexpr std::uint16_t kRecordVersion = 1;
inline constexpr std::size_t kEventHeaderPayloadSize = 56U;
inline constexpr std::size_t kStackDefinitionFixedPayloadSize = 16U;
inline constexpr std::size_t kStackFramePayloadSize = 32U;
inline constexpr std::size_t kStatisticsFixedPayloadSize = 80U;
inline constexpr std::size_t kPerApiStatisticsSize = 48U;

template <typename... Visitors>
struct Overloaded : Visitors... {
  using Visitors::operator()...;
};

template <typename... Visitors>
Overloaded(Visitors...) -> Overloaded<Visitors...>;

void append_u8(std::vector<std::byte>& output, std::uint8_t value) {
  output.push_back(static_cast<std::byte>(value));
}

void append_u16(std::vector<std::byte>& output, std::uint16_t value) {
  append_u8(output, static_cast<std::uint8_t>(value & 0xFFU));
  append_u8(output, static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void append_u32(std::vector<std::byte>& output, std::uint32_t value) {
  for (std::uint32_t shift = 0U; shift < 32U; shift += 8U) {
    append_u8(output, static_cast<std::uint8_t>((value >> shift) & 0xFFU));
  }
}

void append_u64(std::vector<std::byte>& output, std::uint64_t value) {
  for (std::uint32_t shift = 0U; shift < 64U; shift += 8U) {
    append_u8(output, static_cast<std::uint8_t>((value >> shift) & 0xFFU));
  }
}

void append_i32(std::vector<std::byte>& output, std::int32_t value) {
  append_u32(output, std::bit_cast<std::uint32_t>(value));
}

void append_zeros(std::vector<std::byte>& output, std::size_t count) {
  output.insert(output.end(), count, std::byte{0});
}

class PayloadReader {
 public:
  explicit PayloadReader(std::span<const std::byte> payload) : payload_{payload} {}

  [[nodiscard]] std::uint8_t read_u8() {
    require(1U);
    return std::to_integer<std::uint8_t>(payload_[offset_++]);
  }

  [[nodiscard]] std::uint16_t read_u16() {
    require(2U);
    const std::uint16_t value =
        static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(payload_[offset_])) |
        static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(payload_[offset_ + 1U]))
            << 8U);
    offset_ += 2U;
    return value;
  }

  [[nodiscard]] std::uint32_t read_u32() {
    require(4U);
    std::uint32_t value = 0U;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
      value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(payload_[offset_ + index]))
               << (index * 8U);
    }
    offset_ += sizeof(value);
    return value;
  }

  [[nodiscard]] std::uint64_t read_u64() {
    require(8U);
    std::uint64_t value = 0U;
    for (std::size_t index = 0; index < sizeof(value); ++index) {
      value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(payload_[offset_ + index]))
               << (index * 8U);
    }
    offset_ += sizeof(value);
    return value;
  }

  [[nodiscard]] std::int32_t read_i32() { return std::bit_cast<std::int32_t>(read_u32()); }

  void expect_zeros(std::size_t count) {
    require(count);
    for (std::size_t index = 0; index < count; ++index) {
      if (payload_[offset_ + index] != std::byte{0}) {
        throw RecordCodecError{"record reserved bytes must be zero"};
      }
    }
    offset_ += count;
  }

  void expect_done() const {
    if (offset_ != payload_.size()) {
      throw RecordCodecError{"record payload has trailing bytes"};
    }
  }

 private:
  void require(std::size_t count) const {
    if (count > payload_.size() - offset_) {
      throw RecordCodecError{"record payload is truncated"};
    }
  }

  std::span<const std::byte> payload_;
  std::size_t offset_{0};
};

[[nodiscard]] bool decode_bool(PayloadReader& reader, const char* field) {
  const std::uint8_t value = reader.read_u8();
  if (value > 1U) {
    throw RecordCodecError{field};
  }
  return value != 0U;
}

[[nodiscard]] EventStatus decode_event_status(std::uint8_t value) {
  switch (value) {
    case static_cast<std::uint8_t>(EventStatus::kSuccess):
      return EventStatus::kSuccess;
    case static_cast<std::uint8_t>(EventStatus::kFailure):
      return EventStatus::kFailure;
    case static_cast<std::uint8_t>(EventStatus::kUnmatched):
      return EventStatus::kUnmatched;
    case static_cast<std::uint8_t>(EventStatus::kPreexisting):
      return EventStatus::kPreexisting;
    default:
      throw RecordCodecError{"event status is not supported"};
  }
}

[[nodiscard]] StackCaptureStatus decode_stack_capture_status(std::uint8_t value) {
  switch (value) {
    case static_cast<std::uint8_t>(StackCaptureStatus::kComplete):
      return StackCaptureStatus::kComplete;
    case static_cast<std::uint8_t>(StackCaptureStatus::kTruncatedByDepth):
      return StackCaptureStatus::kTruncatedByDepth;
    case static_cast<std::uint8_t>(StackCaptureStatus::kUnwindFailed):
      return StackCaptureStatus::kUnwindFailed;
    case static_cast<std::uint8_t>(StackCaptureStatus::kUnavailable):
      return StackCaptureStatus::kUnavailable;
    default:
      throw RecordCodecError{"stack capture status is not supported"};
  }
}

[[nodiscard]] SystemErrorDomain decode_error_domain(std::uint8_t value) {
  switch (value) {
    case static_cast<std::uint8_t>(SystemErrorDomain::kNone):
      return SystemErrorDomain::kNone;
    case static_cast<std::uint8_t>(SystemErrorDomain::kWin32):
      return SystemErrorDomain::kWin32;
    case static_cast<std::uint8_t>(SystemErrorDomain::kNtStatus):
      return SystemErrorDomain::kNtStatus;
    case static_cast<std::uint8_t>(SystemErrorDomain::kPosix):
      return SystemErrorDomain::kPosix;
    case static_cast<std::uint8_t>(SystemErrorDomain::kMach):
      return SystemErrorDomain::kMach;
    default:
      throw RecordCodecError{"event error domain is not supported"};
  }
}

[[nodiscard]] ProcessMemoryScope decode_process_scope(std::uint8_t value) {
  switch (value) {
    case static_cast<std::uint8_t>(ProcessMemoryScope::kCurrentProcess):
      return ProcessMemoryScope::kCurrentProcess;
    case static_cast<std::uint8_t>(ProcessMemoryScope::kRemoteProcess):
      return ProcessMemoryScope::kRemoteProcess;
    case static_cast<std::uint8_t>(ProcessMemoryScope::kUnknown):
      return ProcessMemoryScope::kUnknown;
    default:
      throw RecordCodecError{"process memory scope is not supported"};
  }
}

[[nodiscard]] ReallocationEffect decode_reallocation_effect(std::uint8_t value) {
  switch (value) {
    case static_cast<std::uint8_t>(ReallocationEffect::kNoChange):
      return ReallocationEffect::kNoChange;
    case static_cast<std::uint8_t>(ReallocationEffect::kNewGeneration):
      return ReallocationEffect::kNewGeneration;
    case static_cast<std::uint8_t>(ReallocationEffect::kFreed):
      return ReallocationEffect::kFreed;
    default:
      throw RecordCodecError{"reallocation effect is not supported"};
  }
}

[[nodiscard]] LossReason decode_loss_reason(std::uint8_t value) {
  switch (value) {
    case static_cast<std::uint8_t>(LossReason::kQueueFull):
      return LossReason::kQueueFull;
    case static_cast<std::uint8_t>(LossReason::kTraceFull):
      return LossReason::kTraceFull;
    case static_cast<std::uint8_t>(LossReason::kWriterError):
      return LossReason::kWriterError;
    case static_cast<std::uint8_t>(LossReason::kStackCaptureFailed):
      return LossReason::kStackCaptureFailed;
    case static_cast<std::uint8_t>(LossReason::kRotationLimit):
      return LossReason::kRotationLimit;
    case static_cast<std::uint8_t>(LossReason::kDecoderError):
      return LossReason::kDecoderError;
    default:
      throw RecordCodecError{"loss reason is not supported"};
  }
}

[[nodiscard]] LossLocation decode_loss_location(std::uint8_t value) {
  switch (value) {
    case static_cast<std::uint8_t>(LossLocation::kAgentQueue):
      return LossLocation::kAgentQueue;
    case static_cast<std::uint8_t>(LossLocation::kWriter):
      return LossLocation::kWriter;
    case static_cast<std::uint8_t>(LossLocation::kRotation):
      return LossLocation::kRotation;
    case static_cast<std::uint8_t>(LossLocation::kDecoder):
      return LossLocation::kDecoder;
    default:
      throw RecordCodecError{"loss location is not supported"};
  }
}

void append_event_header(std::vector<std::byte>& output, const EventHeader& header) {
  append_u64(output, header.sequence.value());
  append_u64(output, header.monotonic_ticks);
  append_u64(output, header.thread_id);
  append_u32(output, header.api_id);
  append_u8(output, static_cast<std::uint8_t>(header.status));
  append_u8(output, static_cast<std::uint8_t>(header.system_error.domain));
  append_u16(output, 0U);
  append_u64(output, header.stack_id.value());
  append_u32(output, header.flags);
  append_u32(output, 0U);
  append_u64(output, header.system_error.code);
}

[[nodiscard]] EventHeader decode_event_header(PayloadReader& reader) {
  EventHeader header;
  header.sequence = Sequence{reader.read_u64()};
  header.monotonic_ticks = reader.read_u64();
  header.thread_id = reader.read_u64();
  header.api_id = reader.read_u32();
  header.status = decode_event_status(reader.read_u8());
  header.system_error.domain = decode_error_domain(reader.read_u8());
  reader.expect_zeros(2U);
  header.stack_id = StackId{reader.read_u64()};
  header.flags = reader.read_u32();
  reader.expect_zeros(4U);
  header.system_error.code = reader.read_u64();
  return header;
}

void append_process_target(std::vector<std::byte>& output, const ProcessTarget& target) {
  append_u8(output, static_cast<std::uint8_t>(target.scope));
  append_zeros(output, 7U);
  append_u64(output, target.process_handle);
  append_u64(output, target.process_id);
}

[[nodiscard]] ProcessTarget decode_process_target(PayloadReader& reader) {
  ProcessTarget target;
  target.scope = decode_process_scope(reader.read_u8());
  reader.expect_zeros(7U);
  target.process_handle = reader.read_u64();
  target.process_id = reader.read_u64();
  return target;
}

[[nodiscard]] EventRecordType event_record_type(const EventPayload& payload) noexcept {
  return std::visit(Overloaded{
                        [](const HeapCreateEvent&) { return EventRecordType::kHeapCreate; },
                        [](const HeapDestroyEvent&) { return EventRecordType::kHeapDestroy; },
                        [](const AllocationEvent&) { return EventRecordType::kAllocate; },
                        [](const ReallocationEvent&) { return EventRecordType::kReallocate; },
                        [](const FreeEvent&) { return EventRecordType::kFree; },
                        [](const VmAllocateEvent&) { return EventRecordType::kVmAllocate; },
                        [](const VmFreeEvent&) { return EventRecordType::kVmFree; },
                        [](const MapEvent&) { return EventRecordType::kMap; },
                        [](const UnmapEvent&) { return EventRecordType::kUnmap; },
                    },
                    payload);
}

void append_event_payload(std::vector<std::byte>& output, const EventPayload& payload) {
  std::visit(Overloaded{
                 [&output](const HeapCreateEvent& event) {
                   append_u64(output, event.heap_handle);
                   append_u64(output, event.heap_id.value());
                   append_u64(output, event.heap_flags);
                   append_u64(output, event.reserve_size);
                   append_u64(output, event.commit_size);
                 },
                 [&output](const HeapDestroyEvent& event) {
                   append_u64(output, event.heap_handle);
                   append_u64(output, event.heap_id.value());
                   append_u64(output, event.raw_result);
                 },
                 [&output](const AllocationEvent& event) {
                   append_u64(output, event.heap_handle);
                   append_u64(output, event.heap_id.value());
                   append_u64(output, event.requested_size);
                   append_u64(output, event.result_address);
                   append_u64(output, event.allocation_id.value());
                   append_u64(output, event.api_flags);
                 },
                 [&output](const ReallocationEvent& event) {
                   append_u64(output, event.heap_handle);
                   append_u64(output, event.heap_id.value());
                   append_u64(output, event.old_address);
                   append_u64(output, event.old_allocation_id.value());
                   append_u64(output, event.requested_size);
                   append_u64(output, event.result_address);
                   append_u64(output, event.new_allocation_id.value());
                   append_u64(output, event.api_flags);
                   append_u8(output, static_cast<std::uint8_t>(event.effect));
                   append_zeros(output, 7U);
                 },
                 [&output](const FreeEvent& event) {
                   append_u64(output, event.heap_handle);
                   append_u64(output, event.heap_id.value());
                   append_u64(output, event.address);
                   append_u64(output, event.allocation_id.value());
                   append_u64(output, event.raw_result);
                   append_u64(output, event.api_flags);
                 },
                 [&output](const VmAllocateEvent& event) {
                   append_process_target(output, event.target);
                   append_u64(output, event.requested_base);
                   append_u64(output, event.result_base);
                   append_u64(output, event.requested_size);
                   append_u64(output, event.result_size);
                   append_u64(output, event.mapping_base);
                   append_u64(output, event.mapping_size);
                   append_u32(output, event.allocation_type);
                   append_u32(output, event.protection);
                   append_u64(output, event.mapping_id.value());
                 },
                 [&output](const VmFreeEvent& event) {
                   append_process_target(output, event.target);
                   append_u64(output, event.base);
                   append_u64(output, event.region_size);
                   append_u32(output, event.free_type);
                   append_u32(output, 0U);
                   append_u64(output, event.mapping_id.value());
                 },
                 [&output](const MapEvent& event) {
                   append_u64(output, event.section_handle);
                   append_process_target(output, event.target);
                   append_u64(output, event.result_base);
                   append_u64(output, event.view_size);
                   append_u64(output, event.section_offset);
                   append_u32(output, event.protection);
                   append_u32(output, 0U);
                   append_u64(output, event.mapping_id.value());
                 },
                 [&output](const UnmapEvent& event) {
                   append_process_target(output, event.target);
                   append_u64(output, event.base);
                   append_u64(output, event.mapping_id.value());
                 },
             },
             payload);
}

[[nodiscard]] std::optional<EventRecordType> decode_event_record_type(
    std::uint16_t value) noexcept {
  switch (value) {
    case static_cast<std::uint16_t>(EventRecordType::kHeapCreate):
      return EventRecordType::kHeapCreate;
    case static_cast<std::uint16_t>(EventRecordType::kHeapDestroy):
      return EventRecordType::kHeapDestroy;
    case static_cast<std::uint16_t>(EventRecordType::kAllocate):
      return EventRecordType::kAllocate;
    case static_cast<std::uint16_t>(EventRecordType::kReallocate):
      return EventRecordType::kReallocate;
    case static_cast<std::uint16_t>(EventRecordType::kFree):
      return EventRecordType::kFree;
    case static_cast<std::uint16_t>(EventRecordType::kVmAllocate):
      return EventRecordType::kVmAllocate;
    case static_cast<std::uint16_t>(EventRecordType::kVmFree):
      return EventRecordType::kVmFree;
    case static_cast<std::uint16_t>(EventRecordType::kMap):
      return EventRecordType::kMap;
    case static_cast<std::uint16_t>(EventRecordType::kUnmap):
      return EventRecordType::kUnmap;
    case static_cast<std::uint16_t>(EventRecordType::kLoss):
      return EventRecordType::kLoss;
    default:
      return std::nullopt;
  }
}

[[nodiscard]] EventPayload decode_memory_event_payload(EventRecordType type,
                                                       PayloadReader& reader) {
  switch (type) {
    case EventRecordType::kHeapCreate: {
      HeapCreateEvent event;
      event.heap_handle = reader.read_u64();
      event.heap_id = HeapId{reader.read_u64()};
      event.heap_flags = reader.read_u64();
      event.reserve_size = reader.read_u64();
      event.commit_size = reader.read_u64();
      return event;
    }
    case EventRecordType::kHeapDestroy: {
      HeapDestroyEvent event;
      event.heap_handle = reader.read_u64();
      event.heap_id = HeapId{reader.read_u64()};
      event.raw_result = reader.read_u64();
      return event;
    }
    case EventRecordType::kAllocate: {
      AllocationEvent event;
      event.heap_handle = reader.read_u64();
      event.heap_id = HeapId{reader.read_u64()};
      event.requested_size = reader.read_u64();
      event.result_address = reader.read_u64();
      event.allocation_id = AllocationId{reader.read_u64()};
      event.api_flags = reader.read_u64();
      return event;
    }
    case EventRecordType::kReallocate: {
      ReallocationEvent event;
      event.heap_handle = reader.read_u64();
      event.heap_id = HeapId{reader.read_u64()};
      event.old_address = reader.read_u64();
      event.old_allocation_id = AllocationId{reader.read_u64()};
      event.requested_size = reader.read_u64();
      event.result_address = reader.read_u64();
      event.new_allocation_id = AllocationId{reader.read_u64()};
      event.api_flags = reader.read_u64();
      event.effect = decode_reallocation_effect(reader.read_u8());
      reader.expect_zeros(7U);
      return event;
    }
    case EventRecordType::kFree: {
      FreeEvent event;
      event.heap_handle = reader.read_u64();
      event.heap_id = HeapId{reader.read_u64()};
      event.address = reader.read_u64();
      event.allocation_id = AllocationId{reader.read_u64()};
      event.raw_result = reader.read_u64();
      event.api_flags = reader.read_u64();
      return event;
    }
    case EventRecordType::kVmAllocate: {
      VmAllocateEvent event;
      event.target = decode_process_target(reader);
      event.requested_base = reader.read_u64();
      event.result_base = reader.read_u64();
      event.requested_size = reader.read_u64();
      event.result_size = reader.read_u64();
      event.mapping_base = reader.read_u64();
      event.mapping_size = reader.read_u64();
      event.allocation_type = reader.read_u32();
      event.protection = reader.read_u32();
      event.mapping_id = MappingId{reader.read_u64()};
      return event;
    }
    case EventRecordType::kVmFree: {
      VmFreeEvent event;
      event.target = decode_process_target(reader);
      event.base = reader.read_u64();
      event.region_size = reader.read_u64();
      event.free_type = reader.read_u32();
      reader.expect_zeros(4U);
      event.mapping_id = MappingId{reader.read_u64()};
      return event;
    }
    case EventRecordType::kMap: {
      MapEvent event;
      event.section_handle = reader.read_u64();
      event.target = decode_process_target(reader);
      event.result_base = reader.read_u64();
      event.view_size = reader.read_u64();
      event.section_offset = reader.read_u64();
      event.protection = reader.read_u32();
      reader.expect_zeros(4U);
      event.mapping_id = MappingId{reader.read_u64()};
      return event;
    }
    case EventRecordType::kUnmap: {
      UnmapEvent event;
      event.target = decode_process_target(reader);
      event.base = reader.read_u64();
      event.mapping_id = MappingId{reader.read_u64()};
      return event;
    }
    case EventRecordType::kLoss:
      break;
  }
  throw RecordCodecError{"Loss is not a memory event payload"};
}

[[nodiscard]] LossRecord decode_loss_payload(PayloadReader& reader) {
  LossRecord loss;
  loss.reason = decode_loss_reason(reader.read_u8());
  loss.location = decode_loss_location(reader.read_u8());
  const std::uint8_t presence = reader.read_u8();
  if ((presence & ~0x07U) != 0U) {
    throw RecordCodecError{"loss presence flags are not supported"};
  }
  reader.expect_zeros(5U);

  const std::uint64_t count = reader.read_u64();
  const std::uint64_t sequence_begin = reader.read_u64();
  const std::uint64_t sequence_end = reader.read_u64();
  const std::uint64_t tick_begin = reader.read_u64();
  const std::uint64_t tick_end = reader.read_u64();
  if ((presence & 0x01U) != 0U) {
    loss.estimated_event_count = count;
  } else if (count != 0U) {
    throw RecordCodecError{"absent loss count must be zero"};
  }
  if ((presence & 0x02U) != 0U) {
    loss.sequence_range = SequenceRange{Sequence{sequence_begin}, Sequence{sequence_end}};
  } else if (sequence_begin != 0U || sequence_end != 0U) {
    throw RecordCodecError{"absent loss sequence range must be zero"};
  }
  if ((presence & 0x04U) != 0U) {
    loss.tick_range = TickRange{tick_begin, tick_end};
  } else if (tick_begin != 0U || tick_end != 0U) {
    throw RecordCodecError{"absent loss tick range must be zero"};
  }
  reader.expect_done();
  try {
    validate_loss_record(loss);
  } catch (const CompletenessValidationError& error) {
    throw RecordCodecError{"invalid Loss record: " + std::string{error.what()}};
  }
  return loss;
}

}  // namespace

void append_capture_scope_record(std::vector<std::byte>& chunk_payload, const CaptureScope& scope,
                                 std::uint32_t maximum_record_size) {
  validate_capture_scope(scope);
  std::vector<std::byte> payload;
  payload.reserve(8U);
  append_u8(payload, scope.started_at_process_start ? 1U : 0U);
  append_u8(payload, scope.preexisting_allocations_unknown ? 1U : 0U);
  append_zeros(payload, 6U);
  append_record(chunk_payload, static_cast<std::uint16_t>(MetadataRecordType::kCaptureScope),
                kRecordVersion, payload, maximum_record_size);
}

std::optional<CaptureScope> decode_capture_scope_record(const RecordView& record) {
  if (record.type != static_cast<std::uint16_t>(MetadataRecordType::kCaptureScope) ||
      record.version != kRecordVersion) {
    return std::nullopt;
  }
  PayloadReader reader{record.payload};
  CaptureScope scope;
  scope.started_at_process_start = decode_bool(reader, "capture-start boolean is not zero or one");
  scope.preexisting_allocations_unknown =
      decode_bool(reader, "preexisting-allocation boolean is not zero or one");
  reader.expect_zeros(6U);
  reader.expect_done();
  try {
    validate_capture_scope(scope);
  } catch (const CompletenessValidationError& error) {
    throw RecordCodecError{"invalid CaptureScope record: " + std::string{error.what()}};
  }
  return scope;
}

void append_stack_definition_record(std::vector<std::byte>& chunk_payload,
                                    const StackDefinition& definition,
                                    std::uint32_t maximum_record_size) {
  validate_stack_definition(definition);
  if (definition.frames.size() > std::numeric_limits<std::uint32_t>::max() ||
      maximum_record_size < kRecordHeaderSize + kStackDefinitionFixedPayloadSize ||
      definition.frames.size() >
          (maximum_record_size - kRecordHeaderSize - kStackDefinitionFixedPayloadSize) /
              kStackFramePayloadSize) {
    throw RecordCodecError{"stack definition exceeds the configured record size limit"};
  }

  std::vector<std::byte> payload;
  payload.reserve(kStackDefinitionFixedPayloadSize +
                  definition.frames.size() * kStackFramePayloadSize);
  append_u64(payload, definition.stack_id.value());
  append_u8(payload, static_cast<std::uint8_t>(definition.status));
  append_zeros(payload, 3U);
  append_u32(payload, static_cast<std::uint32_t>(definition.frames.size()));
  for (const StackFrame& frame : definition.frames) {
    append_u64(payload, frame.module_id.value());
    append_u64(payload, frame.module_offset);
    append_u64(payload, frame.absolute_address);
    append_u32(payload, frame.flags);
    append_u32(payload, 0U);
  }
  append_record(chunk_payload, static_cast<std::uint16_t>(StackRecordType::kDefinition),
                kRecordVersion, payload, maximum_record_size);
}

std::optional<StackDefinition> decode_stack_definition_record(const RecordView& record) {
  if (record.type != static_cast<std::uint16_t>(StackRecordType::kDefinition) ||
      record.version != kRecordVersion) {
    return std::nullopt;
  }
  if (record.payload.size() < kStackDefinitionFixedPayloadSize) {
    throw RecordCodecError{"stack definition payload is truncated"};
  }

  PayloadReader reader{record.payload};
  StackDefinition definition;
  definition.stack_id = StackId{reader.read_u64()};
  definition.status = decode_stack_capture_status(reader.read_u8());
  reader.expect_zeros(3U);
  const std::uint32_t frame_count = reader.read_u32();
  if (frame_count >
          (record.payload.size() - kStackDefinitionFixedPayloadSize) / kStackFramePayloadSize ||
      kStackDefinitionFixedPayloadSize +
              static_cast<std::size_t>(frame_count) * kStackFramePayloadSize !=
          record.payload.size()) {
    throw RecordCodecError{"stack frame count does not match the record payload"};
  }
  definition.frames.reserve(frame_count);
  for (std::uint32_t index = 0U; index < frame_count; ++index) {
    StackFrame frame;
    frame.module_id = ModuleId{reader.read_u64()};
    frame.module_offset = reader.read_u64();
    frame.absolute_address = reader.read_u64();
    frame.flags = reader.read_u32();
    reader.expect_zeros(4U);
    definition.frames.push_back(frame);
  }
  reader.expect_done();
  try {
    validate_stack_definition(definition);
  } catch (const StackValidationError& error) {
    throw RecordCodecError{"invalid StackDefinition record: " + std::string{error.what()}};
  }
  return definition;
}

void append_event_record(std::vector<std::byte>& chunk_payload, const Event& event,
                         std::uint32_t maximum_record_size) {
  validate_event(event);
  std::vector<std::byte> payload;
  payload.reserve(kEventHeaderPayloadSize + 72U);
  append_event_header(payload, event.header);
  append_event_payload(payload, event.payload);
  append_record(chunk_payload, static_cast<std::uint16_t>(event_record_type(event.payload)),
                kRecordVersion, payload, maximum_record_size);
}

void append_loss_record(std::vector<std::byte>& chunk_payload, const LossRecord& loss,
                        std::uint32_t maximum_record_size) {
  validate_loss_record(loss);
  std::vector<std::byte> payload;
  payload.reserve(48U);
  append_u8(payload, static_cast<std::uint8_t>(loss.reason));
  append_u8(payload, static_cast<std::uint8_t>(loss.location));
  std::uint8_t presence = 0U;
  presence |= loss.estimated_event_count.has_value() ? 0x01U : 0U;
  presence |= loss.sequence_range.has_value() ? 0x02U : 0U;
  presence |= loss.tick_range.has_value() ? 0x04U : 0U;
  append_u8(payload, presence);
  append_zeros(payload, 5U);
  append_u64(payload, loss.estimated_event_count.value_or(0U));
  append_u64(payload, loss.sequence_range.has_value() ? loss.sequence_range->begin.value() : 0U);
  append_u64(payload, loss.sequence_range.has_value() ? loss.sequence_range->end.value() : 0U);
  append_u64(payload, loss.tick_range.has_value() ? loss.tick_range->begin : 0U);
  append_u64(payload, loss.tick_range.has_value() ? loss.tick_range->end : 0U);
  append_record(chunk_payload, static_cast<std::uint16_t>(EventRecordType::kLoss), kRecordVersion,
                payload, maximum_record_size);
}

std::optional<EventChunkRecord> decode_event_chunk_record(const RecordView& record) {
  const auto type = decode_event_record_type(record.type);
  if (!type.has_value() || record.version != kRecordVersion) {
    return std::nullopt;
  }
  PayloadReader reader{record.payload};
  if (*type == EventRecordType::kLoss) {
    return EventChunkRecord{decode_loss_payload(reader)};
  }
  Event event;
  event.header = decode_event_header(reader);
  event.payload = decode_memory_event_payload(*type, reader);
  reader.expect_done();
  try {
    validate_event(event);
  } catch (const EventValidationError& error) {
    throw RecordCodecError{"invalid memory event record: " + std::string{error.what()}};
  }
  return EventChunkRecord{event};
}

void append_statistics_record(std::vector<std::byte>& chunk_payload,
                              const CaptureStatistics& statistics,
                              std::uint32_t maximum_record_size) {
  validate_statistics(statistics);
  if (statistics.per_api.size() > std::numeric_limits<std::uint32_t>::max() ||
      statistics.per_api.size() >
          (std::numeric_limits<std::uint32_t>::max() - kStatisticsFixedPayloadSize) /
              kPerApiStatisticsSize) {
    throw RecordCodecError{"too many per-API statistics entries"};
  }

  std::vector<std::byte> payload;
  payload.reserve(kStatisticsFixedPayloadSize + statistics.per_api.size() * kPerApiStatisticsSize);
  append_u64(payload, statistics.observed_calls);
  append_u64(payload, statistics.successful_operations);
  append_u64(payload, statistics.failed_operations);
  append_u64(payload, statistics.filtered_before_queue);
  append_u64(payload, statistics.dropped_events);
  append_u64(payload, statistics.unique_stacks);
  append_u64(payload, statistics.reused_stacks);
  append_u64(payload, statistics.written_uncompressed_bytes);
  append_u64(payload, statistics.written_stored_bytes);
  append_u32(payload, static_cast<std::uint32_t>(statistics.per_api.size()));
  append_u32(payload, 0U);
  for (const auto& api : statistics.per_api) {
    append_u32(payload, api.api_id);
    append_u32(payload, 0U);
    append_u64(payload, api.observed_calls);
    append_u64(payload, api.successful_operations);
    append_u64(payload, api.failed_operations);
    append_u64(payload, api.filtered_before_queue);
    append_u64(payload, api.dropped_events);
  }
  append_record(chunk_payload, static_cast<std::uint16_t>(StatisticsRecordType::kCaptureStatistics),
                kRecordVersion, payload, maximum_record_size);
}

std::optional<CaptureStatistics> decode_statistics_record(const RecordView& record) {
  if (record.type != static_cast<std::uint16_t>(StatisticsRecordType::kCaptureStatistics) ||
      record.version != kRecordVersion) {
    return std::nullopt;
  }
  PayloadReader reader{record.payload};
  CaptureStatistics statistics;
  statistics.observed_calls = reader.read_u64();
  statistics.successful_operations = reader.read_u64();
  statistics.failed_operations = reader.read_u64();
  statistics.filtered_before_queue = reader.read_u64();
  statistics.dropped_events = reader.read_u64();
  statistics.unique_stacks = reader.read_u64();
  statistics.reused_stacks = reader.read_u64();
  statistics.written_uncompressed_bytes = reader.read_u64();
  statistics.written_stored_bytes = reader.read_u64();
  const std::uint32_t api_count = reader.read_u32();
  reader.expect_zeros(4U);
  if (api_count > (record.payload.size() - kStatisticsFixedPayloadSize) / kPerApiStatisticsSize) {
    throw RecordCodecError{"per-API statistics count exceeds the record payload"};
  }
  statistics.per_api.reserve(api_count);
  for (std::uint32_t index = 0U; index < api_count; ++index) {
    ApiStatistics api;
    api.api_id = reader.read_u32();
    reader.expect_zeros(4U);
    api.observed_calls = reader.read_u64();
    api.successful_operations = reader.read_u64();
    api.failed_operations = reader.read_u64();
    api.filtered_before_queue = reader.read_u64();
    api.dropped_events = reader.read_u64();
    statistics.per_api.push_back(api);
  }
  reader.expect_done();
  try {
    validate_statistics(statistics);
  } catch (const CompletenessValidationError& error) {
    throw RecordCodecError{"invalid Statistics record: " + std::string{error.what()}};
  }
  return statistics;
}

void append_end_of_trace_record(std::vector<std::byte>& chunk_payload, const EndOfTrace& end,
                                std::uint32_t maximum_record_size) {
  validate_end_of_trace(end);
  std::vector<std::byte> payload;
  payload.reserve(40U);
  append_u64(payload, end.final_sequence.value());
  append_u64(payload, end.final_monotonic_ticks);
  append_u8(payload, end.normal_stop ? 1U : 0U);
  append_u8(payload, end.target_exit_code.has_value() ? 1U : 0U);
  append_zeros(payload, 6U);
  append_i32(payload, end.target_exit_code.value_or(0));
  append_u32(payload, 0U);
  append_u32(payload, end.aggregate_completeness.mask());
  append_u32(payload, 0U);
  append_record(chunk_payload, static_cast<std::uint16_t>(EndRecordType::kEndOfTrace),
                kRecordVersion, payload, maximum_record_size);
}

std::optional<EndOfTrace> decode_end_of_trace_record(const RecordView& record) {
  if (record.type != static_cast<std::uint16_t>(EndRecordType::kEndOfTrace) ||
      record.version != kRecordVersion) {
    return std::nullopt;
  }
  PayloadReader reader{record.payload};
  EndOfTrace end;
  end.final_sequence = Sequence{reader.read_u64()};
  end.final_monotonic_ticks = reader.read_u64();
  end.normal_stop = decode_bool(reader, "normal-stop boolean is not zero or one");
  const bool has_target_exit_code =
      decode_bool(reader, "target-exit-code presence is not zero or one");
  reader.expect_zeros(6U);
  const std::int32_t target_exit_code = reader.read_i32();
  reader.expect_zeros(4U);
  end.aggregate_completeness = CompletenessReport::from_mask(reader.read_u32());
  reader.expect_zeros(4U);
  reader.expect_done();
  if (has_target_exit_code) {
    end.target_exit_code = target_exit_code;
  } else if (target_exit_code != 0) {
    throw RecordCodecError{"absent target exit code must be zero"};
  }
  try {
    validate_end_of_trace(end);
  } catch (const CompletenessValidationError& error) {
    throw RecordCodecError{"invalid EndOfTrace record: " + std::string{error.what()}};
  }
  return end;
}

}  // namespace noleax::trace
