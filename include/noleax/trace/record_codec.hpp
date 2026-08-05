#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <variant>
#include <vector>

#include "noleax/trace/completeness.hpp"
#include "noleax/trace/custom_hook.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/memory_snapshot.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/trace_reader.hpp"

namespace noleax::trace {

// These underlying types intentionally match record_type's uint16 wire field.
enum class MetadataRecordType : std::uint16_t {  // NOLINT(performance-enum-size)
  kCaptureScope = 1,
  kCustomHookDefinition = 2,
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

enum class ModuleRecordType : std::uint16_t {  // NOLINT(performance-enum-size)
  kLoad = 1,
  kUnload = 2,
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

enum class MemoryRecordType : std::uint16_t {  // NOLINT(performance-enum-size)
  kCounters = 1,
  kMap = 2,
};

using EventChunkRecord = std::variant<Event, LossRecord>;

class RecordCodecError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

void append_capture_scope_record(std::vector<std::byte>& chunk_payload, const CaptureScope& scope,
                                 std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
[[nodiscard]] std::optional<CaptureScope> decode_capture_scope_record(const RecordView& record);

void append_custom_hook_definition_record(
    std::vector<std::byte>& chunk_payload, const CustomHookDefinition& definition,
    std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
[[nodiscard]] std::optional<CustomHookDefinition> decode_custom_hook_definition_record(
    const RecordView& record);

void append_module_load_record(std::vector<std::byte>& chunk_payload, const ModuleLoad& load,
                               std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
void append_module_unload_record(std::vector<std::byte>& chunk_payload, const ModuleUnload& unload,
                                 std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
[[nodiscard]] std::optional<ModuleRecord> decode_module_record(const RecordView& record);

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

void append_memory_counters_record(std::vector<std::byte>& chunk_payload,
                                   const MemoryCounters& counters,
                                   std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
[[nodiscard]] std::optional<MemoryCounters> decode_memory_counters_record(const RecordView& record);

void append_memory_map_record(std::vector<std::byte>& chunk_payload, const MemoryMap& map,
                              std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);
[[nodiscard]] std::optional<MemoryMap> decode_memory_map_record(const RecordView& record);

}  // namespace noleax::trace
