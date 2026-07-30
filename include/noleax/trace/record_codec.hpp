#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <variant>
#include <vector>

#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/trace_reader.hpp"

namespace noleax::trace {

// These underlying types intentionally match record_type's uint16 wire field.
enum class MetadataRecordType : std::uint16_t {  // NOLINT(performance-enum-size)
  kCaptureScope = 1,
};

enum class EventRecordType : std::uint16_t {  // NOLINT(performance-enum-size)
  kHeapCreate = 1,
  kHeapDestroy = 2,
  kAllocate = 3,
  kReallocate = 4,
  kFree = 5,
  kVmAllocate = 6,
  kVmFree = 7,
  kMap = 8,
  kUnmap = 9,
  kLoss = 10,
};

enum class StackRecordType : std::uint16_t {  // NOLINT(performance-enum-size)
  kDefinition = 1,
};

enum class StatisticsRecordType : std::uint16_t {  // NOLINT(performance-enum-size)
  kCaptureStatistics = 1,
};

enum class EndRecordType : std::uint16_t {  // NOLINT(performance-enum-size)
  kEndOfTrace = 1,
};

using EventChunkRecord = std::variant<Event, LossRecord>;

class RecordCodecError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

void append_capture_scope_record(std::vector<std::byte>& chunk_payload, const CaptureScope& scope,
                                 std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
[[nodiscard]] std::optional<CaptureScope> decode_capture_scope_record(const RecordView& record);

void append_stack_definition_record(std::vector<std::byte>& chunk_payload,
                                    const StackDefinition& definition,
                                    std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
[[nodiscard]] std::optional<StackDefinition> decode_stack_definition_record(
    const RecordView& record);

void append_event_record(std::vector<std::byte>& chunk_payload, const Event& event,
                         std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
void append_loss_record(std::vector<std::byte>& chunk_payload, const LossRecord& loss,
                        std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
[[nodiscard]] std::optional<EventChunkRecord> decode_event_chunk_record(const RecordView& record);

void append_statistics_record(std::vector<std::byte>& chunk_payload,
                              const CaptureStatistics& statistics,
                              std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
[[nodiscard]] std::optional<CaptureStatistics> decode_statistics_record(const RecordView& record);

void append_end_of_trace_record(std::vector<std::byte>& chunk_payload, const EndOfTrace& end,
                                std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
[[nodiscard]] std::optional<EndOfTrace> decode_end_of_trace_record(const RecordView& record);

}  // namespace noleax::trace
