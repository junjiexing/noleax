#include "noleax/analyzer/csv.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <variant>

#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/analyzer/time.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/wire_format.hpp"
#include "utf8.hpp"

namespace noleax::analyzer {
namespace {

class CsvEmitter {
 public:
  explicit CsvEmitter(std::ostream& output) : output_{output} {}

  template <typename Field, std::size_t Size>
  void row(const std::array<Field, Size>& fields) {
    for (const auto& field : fields) {
      if (!detail::is_valid_utf8(field)) {
        throw CsvFormatError{"CSV field is not valid UTF-8"};
      }
    }
    bool first = true;
    for (const auto& field : fields) {
      if (!first) {
        output_.put(',');
      }
      first = false;
      write_field(field);
    }
    output_.write("\r\n", 2);
  }

 private:
  void write_field(std::string_view value) {
    if (value.find_first_of(",\"\r\n") == std::string_view::npos) {
      output_.write(value.data(), static_cast<std::streamsize>(value.size()));
      return;
    }
    output_.put('"');
    for (const char character : value) {
      if (character == '"') {
        output_.write("\"\"", 2);
      } else {
        output_.put(character);
      }
    }
    output_.put('"');
  }

  std::ostream& output_;
};

template <typename Integer>
[[nodiscard]] std::string decimal(Integer value) {
  std::array<char, 32> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  if (result.ec != std::errc{}) {
    throw CsvFormatError{"cannot format a CSV integer"};
  }
  return {buffer.data(), result.ptr};
}

[[nodiscard]] std::string hex_value(std::uint64_t value, std::size_t minimum_digits = 0U) {
  std::array<char, 16> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
  if (result.ec != std::errc{}) {
    throw CsvFormatError{"cannot format a hexadecimal CSV value"};
  }
  const std::size_t digit_count = static_cast<std::size_t>(result.ptr - buffer.data());
  std::string output{"0x"};
  if (minimum_digits > digit_count) {
    output.append(minimum_digits - digit_count, '0');
  }
  output.append(buffer.data(), digit_count);
  return output;
}

[[nodiscard]] std::size_t pointer_digits(const noleax::trace::FileHeader& header) {
  return static_cast<std::size_t>(header.pointer_width) * 2U;
}

[[nodiscard]] std::string address_value(noleax::trace::Address address,
                                        const noleax::trace::FileHeader& header) {
  return hex_value(address, pointer_digits(header));
}

template <typename Identifier>
[[nodiscard]] std::string identifier_value(Identifier identifier) {
  return identifier.is_valid() ? decimal(identifier.value()) : std::string{};
}

[[nodiscard]] const char* operation_name(noleax::trace::EventOperation operation) noexcept {
  switch (operation) {
    case noleax::trace::EventOperation::kHeapCreate:
      return "heap_create";
    case noleax::trace::EventOperation::kHeapDestroy:
      return "heap_destroy";
    case noleax::trace::EventOperation::kAllocate:
      return "alloc";
    case noleax::trace::EventOperation::kReallocate:
      return "realloc";
    case noleax::trace::EventOperation::kFree:
      return "free";
    case noleax::trace::EventOperation::kVmAllocate:
      return "vm_alloc";
    case noleax::trace::EventOperation::kVmFree:
      return "vm_free";
    case noleax::trace::EventOperation::kMap:
      return "map";
    case noleax::trace::EventOperation::kUnmap:
      return "unmap";
  }
  return "unknown";
}

[[nodiscard]] const char* status_name(noleax::trace::EventStatus status) noexcept {
  switch (status) {
    case noleax::trace::EventStatus::kSuccess:
      return "success";
    case noleax::trace::EventStatus::kFailure:
      return "failure";
    case noleax::trace::EventStatus::kUnmatched:
      return "unmatched";
    case noleax::trace::EventStatus::kPreexisting:
      return "preexisting";
  }
  return "unknown";
}

[[nodiscard]] const char* error_domain_name(noleax::trace::SystemErrorDomain domain) noexcept {
  switch (domain) {
    case noleax::trace::SystemErrorDomain::kNone:
      return "none";
    case noleax::trace::SystemErrorDomain::kWin32:
      return "win32";
    case noleax::trace::SystemErrorDomain::kNtStatus:
      return "ntstatus";
    case noleax::trace::SystemErrorDomain::kPosix:
      return "posix";
    case noleax::trace::SystemErrorDomain::kMach:
      return "mach";
  }
  return "unknown";
}

[[nodiscard]] const char* process_scope_name(noleax::trace::ProcessMemoryScope scope) noexcept {
  switch (scope) {
    case noleax::trace::ProcessMemoryScope::kCurrentProcess:
      return "current_process";
    case noleax::trace::ProcessMemoryScope::kRemoteProcess:
      return "remote_process";
    case noleax::trace::ProcessMemoryScope::kUnknown:
      return "unknown";
  }
  return "unknown";
}

[[nodiscard]] const char* reallocation_effect_name(
    noleax::trace::ReallocationEffect effect) noexcept {
  switch (effect) {
    case noleax::trace::ReallocationEffect::kNoChange:
      return "no_change";
    case noleax::trace::ReallocationEffect::kNewGeneration:
      return "new_generation";
    case noleax::trace::ReallocationEffect::kFreed:
      return "freed";
  }
  return "unknown";
}

[[nodiscard]] const char* generation_kind_name(GenerationKind kind) noexcept {
  switch (kind) {
    case GenerationKind::kHeapAllocation:
      return "heap_allocation";
    case GenerationKind::kVirtualAllocation:
      return "virtual_allocation";
    case GenerationKind::kMappedView:
      return "mapped_view";
  }
  return "unknown";
}

[[nodiscard]] const char* stack_status_name(StackCaptureStatus status) noexcept {
  switch (status) {
    case StackCaptureStatus::kComplete:
      return "complete";
    case StackCaptureStatus::kTruncatedByDepth:
      return "truncated_by_depth";
    case StackCaptureStatus::kUnwindFailed:
      return "unwind_failed";
    case StackCaptureStatus::kUnavailable:
      return "unavailable";
  }
  return "unknown";
}

[[nodiscard]] const char* loss_reason_name(noleax::trace::LossReason reason) noexcept {
  switch (reason) {
    case noleax::trace::LossReason::kUnknown:
      return "unknown";
    case noleax::trace::LossReason::kQueueFull:
      return "queue_full";
    case noleax::trace::LossReason::kTraceFull:
      return "trace_full";
    case noleax::trace::LossReason::kWriterError:
      return "writer_error";
    case noleax::trace::LossReason::kStackCaptureFailed:
      return "stack_capture_failed";
    case noleax::trace::LossReason::kRotationLimit:
      return "rotation_limit";
    case noleax::trace::LossReason::kDecoderError:
      return "decoder_error";
  }
  return "unknown";
}

[[nodiscard]] const char* loss_location_name(noleax::trace::LossLocation location) noexcept {
  switch (location) {
    case noleax::trace::LossLocation::kUnknown:
      return "unknown";
    case noleax::trace::LossLocation::kAgentQueue:
      return "agent_queue";
    case noleax::trace::LossLocation::kWriter:
      return "writer";
    case noleax::trace::LossLocation::kRotation:
      return "rotation";
    case noleax::trace::LossLocation::kDecoder:
      return "decoder";
  }
  return "unknown";
}

[[nodiscard]] const char* completeness_state_name(noleax::trace::CompletenessState state) noexcept {
  return state == noleax::trace::CompletenessState::kComplete ? "complete" : "incomplete";
}

[[nodiscard]] const char* understanding_state_name(
    noleax::trace::UnderstandingState state) noexcept {
  return state == noleax::trace::UnderstandingState::kFull ? "full" : "partial";
}

struct IssueDescription {
  noleax::trace::CompletenessIssue issue;
  std::string_view name;
};

constexpr std::array kIssueDescriptions{
    IssueDescription{noleax::trace::CompletenessIssue::kCaptureDidNotStartAtProcessStart,
                     "capture_did_not_start_at_process_start"},
    IssueDescription{noleax::trace::CompletenessIssue::kPreexistingAllocationsUnknown,
                     "preexisting_allocations_unknown"},
    IssueDescription{noleax::trace::CompletenessIssue::kEventLoss, "event_loss"},
    IssueDescription{noleax::trace::CompletenessIssue::kTraceTruncated, "trace_truncated"},
    IssueDescription{noleax::trace::CompletenessIssue::kWriterError, "writer_error"},
    IssueDescription{noleax::trace::CompletenessIssue::kUnknownRecordSkipped,
                     "unknown_record_skipped"},
    IssueDescription{noleax::trace::CompletenessIssue::kMissingEndOfTrace, "missing_end_of_trace"},
    IssueDescription{noleax::trace::CompletenessIssue::kAbnormalStop, "abnormal_stop"},
    IssueDescription{noleax::trace::CompletenessIssue::kStackDataLoss, "stack_data_loss"},
    IssueDescription{noleax::trace::CompletenessIssue::kPartiallyUnderstoodFormat,
                     "partially_understood_format"},
};

[[nodiscard]] constexpr std::uint32_t known_issue_mask() noexcept {
  std::uint32_t result = 0U;
  for (const auto& description : kIssueDescriptions) {
    result |= static_cast<std::uint32_t>(description.issue);
  }
  return result;
}

[[nodiscard]] std::string completeness_issues(
    const noleax::trace::CompletenessReport& completeness) {
  std::string result;
  for (const auto& description : kIssueDescriptions) {
    if (!completeness.has(description.issue)) {
      continue;
    }
    if (!result.empty()) {
      result.push_back(';');
    }
    result.append(description.name);
  }
  const std::uint32_t unknown = completeness.mask() & ~known_issue_mask();
  if (unknown != 0U) {
    if (!result.empty()) {
      result.push_back(';');
    }
    result.append("unknown_");
    result.append(hex_value(unknown));
  }
  return result;
}

void checked_increment(std::uint64_t& value, const char* subject) {
  if (value == std::numeric_limits<std::uint64_t>::max()) {
    throw CsvFormatError{std::string{subject} + " count overflow"};
  }
  ++value;
}

[[nodiscard]] std::string escape_stack_component(std::string_view value) {
  if (!detail::is_valid_utf8(value)) {
    throw CsvFormatError{"stack frame text is not valid UTF-8"};
  }
  constexpr std::string_view digits{"0123456789abcdef"};
  std::string result;
  for (const unsigned char byte : value) {
    switch (byte) {
      case '\\':
        result.append("\\\\");
        break;
      case '|':
        result.append("\\|");
        break;
      case ';':
        result.append("\\;");
        break;
      case '\n':
        result.append("\\n");
        break;
      case '\r':
        result.append("\\r");
        break;
      case '\t':
        result.append("\\t");
        break;
      default:
        if (byte < 0x20U) {
          result.append("\\x");
          result.push_back(digits[byte >> 4U]);
          result.push_back(digits[byte & 0x0fU]);
        } else {
          result.push_back(static_cast<char>(byte));
        }
        break;
    }
  }
  return result;
}

[[nodiscard]] std::string stack_frames_value(const EventPresentation& presentation,
                                             const noleax::trace::FileHeader& header) {
  std::string result;
  bool first = true;
  for (const auto& frame : presentation.stack_frames) {
    if (frame.module_offset.has_value() && !frame.module_name.has_value()) {
      throw CsvFormatError{"stack frame module offset requires a module name"};
    }
    if (frame.symbol_offset.has_value() && !frame.symbol_name.has_value()) {
      throw CsvFormatError{"stack frame symbol offset requires a symbol name"};
    }
    if (!first) {
      result.push_back(';');
    }
    first = false;
    result.append(address_value(frame.absolute_address, header));
    result.push_back('|');
    if (frame.module_name.has_value()) {
      result.append(escape_stack_component(*frame.module_name));
    }
    result.push_back('|');
    if (frame.module_offset.has_value()) {
      result.append(hex_value(*frame.module_offset));
    }
    result.push_back('|');
    if (frame.symbol_name.has_value()) {
      result.append(escape_stack_component(*frame.symbol_name));
    }
    result.push_back('|');
    if (frame.symbol_offset.has_value()) {
      result.append(hex_value(*frame.symbol_offset));
    }
  }
  return result;
}

void validate_stack_presentation(const noleax::trace::Event& event,
                                 const EventPresentation& presentation) {
  if (!event.header.stack_id.is_valid() &&
      (presentation.stack_status.has_value() || !presentation.stack_frames.empty())) {
    throw CsvFormatError{"presentation supplies stack data for an event without a stack ID"};
  }
}

[[nodiscard]] std::optional<std::uint64_t> event_size(const noleax::trace::Event& event) {
  return std::visit(
      [&event](const auto& payload) -> std::optional<std::uint64_t> {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, noleax::trace::AllocationEvent> ||
                      std::is_same_v<Payload, noleax::trace::ReallocationEvent>) {
          return payload.requested_size;
        } else if constexpr (std::is_same_v<Payload, noleax::trace::VmAllocateEvent>) {
          return noleax::trace::call_succeeded(event.header.status) ? payload.result_size
                                                                    : payload.requested_size;
        } else if constexpr (std::is_same_v<Payload, noleax::trace::VmFreeEvent>) {
          return payload.region_size;
        } else if constexpr (std::is_same_v<Payload, noleax::trace::MapEvent>) {
          return payload.view_size;
        } else {
          return std::nullopt;
        }
      },
      event.payload);
}

enum class EventColumn : std::uint8_t {
  kCsvSchemaVersion,
  kRecordType,
  kSequence,
  kRelativeTimeNs,
  kMonotonicTicks,
  kThreadId,
  kApiId,
  kApiName,
  kApiModule,
  kOperation,
  kStatus,
  kEventFlags,
  kErrorDomain,
  kErrorCode,
  kStackId,
  kStackStatus,
  kStackFrames,
  kPayloadKind,
  kSize,
  kHeapHandle,
  kHeapId,
  kHeapFlags,
  kReserveSize,
  kCommitSize,
  kRequestedSize,
  kResultSize,
  kAddress,
  kOldAddress,
  kResultAddress,
  kRequestedBase,
  kResultBase,
  kBase,
  kRegionSize,
  kAllocationId,
  kOldAllocationId,
  kNewAllocationId,
  kApiFlags,
  kRawResult,
  kReallocationEffect,
  kProcessScope,
  kProcessHandle,
  kProcessId,
  kAllocationType,
  kFreeType,
  kProtection,
  kMappingId,
  kSectionHandle,
  kViewSize,
  kSectionOffset,
  kLossReason,
  kLossLocation,
  kLostEventCount,
  kLossSequenceBegin,
  kLossSequenceEnd,
  kLossTickBegin,
  kLossTickEnd,
  kMatchedEvents,
  kFilteredEvents,
  kTraceEvents,
  kLossRecords,
  kBytesRead,
  kKnownSequenceEnd,
  kKnownMonotonicEnd,
  kTruncated,
  kPartiallyUnderstood,
  kCompletenessMask,
  kCompletenessOverall,
  kCompletenessLifecycle,
  kCompletenessStackDetail,
  kCompletenessUnderstanding,
  kCompletenessIssues,
  kCaptureObservedCalls,
  kCaptureSuccessfulOperations,
  kCaptureFailedOperations,
  kCaptureFilteredBeforeQueue,
  kCaptureDroppedEvents,
  kCaptureUniqueStacks,
  kCaptureReusedStacks,
  kCaptureWrittenUncompressedBytes,
  kCaptureWrittenStoredBytes,
  kFinalSequence,
  kFinalMonotonicTicks,
  kNormalStop,
  kTargetExitCode,
  kCount,
};

constexpr std::size_t kEventColumnCount = static_cast<std::size_t>(EventColumn::kCount);
using EventRow = std::array<std::string, kEventColumnCount>;

constexpr std::array<std::string_view, kEventColumnCount> kEventHeader{
    "csv_schema_version",
    "record_type",
    "sequence",
    "relative_time_ns",
    "monotonic_ticks",
    "thread_id",
    "api_id",
    "api_name",
    "api_module",
    "operation",
    "status",
    "event_flags",
    "error_domain",
    "error_code",
    "stack_id",
    "stack_status",
    "stack_frames",
    "payload_kind",
    "size",
    "heap_handle",
    "heap_id",
    "heap_flags",
    "reserve_size",
    "commit_size",
    "requested_size",
    "result_size",
    "address",
    "old_address",
    "result_address",
    "requested_base",
    "result_base",
    "base",
    "region_size",
    "allocation_id",
    "old_allocation_id",
    "new_allocation_id",
    "api_flags",
    "raw_result",
    "reallocation_effect",
    "process_scope",
    "process_handle",
    "process_id",
    "allocation_type",
    "free_type",
    "protection",
    "mapping_id",
    "section_handle",
    "view_size",
    "section_offset",
    "loss_reason",
    "loss_location",
    "lost_event_count",
    "loss_sequence_begin",
    "loss_sequence_end",
    "loss_tick_begin",
    "loss_tick_end",
    "matched_events",
    "filtered_events",
    "trace_events",
    "loss_records",
    "bytes_read",
    "known_sequence_end",
    "known_monotonic_end",
    "truncated",
    "partially_understood",
    "completeness_mask",
    "completeness_overall",
    "completeness_lifecycle",
    "completeness_stack_detail",
    "completeness_understanding",
    "completeness_issues",
    "capture_observed_calls",
    "capture_successful_operations",
    "capture_failed_operations",
    "capture_filtered_before_queue",
    "capture_dropped_events",
    "capture_unique_stacks",
    "capture_reused_stacks",
    "capture_written_uncompressed_bytes",
    "capture_written_stored_bytes",
    "final_sequence",
    "final_monotonic_ticks",
    "normal_stop",
    "target_exit_code",
};

template <typename Column>
[[nodiscard]] constexpr std::size_t column_index(Column column) noexcept {
  return static_cast<std::size_t>(column);
}

void set(EventRow& row, EventColumn column, std::string value) {
  row[column_index(column)] = std::move(value);
}

void set_process_target(EventRow& row, const noleax::trace::ProcessTarget& target,
                        const noleax::trace::FileHeader& header) {
  set(row, EventColumn::kProcessScope, process_scope_name(target.scope));
  set(row, EventColumn::kProcessHandle, address_value(target.process_handle, header));
  set(row, EventColumn::kProcessId, decimal(target.process_id));
}

void set_event_presentation(EventRow& row, const noleax::trace::Event& event,
                            const EventPresentation& presentation,
                            const noleax::trace::FileHeader& header) {
  validate_stack_presentation(event, presentation);
  set(row, EventColumn::kApiName, presentation.api_name.value_or(""));
  set(row, EventColumn::kApiModule, presentation.api_module.value_or(""));
  set(row, EventColumn::kStackId, identifier_value(event.header.stack_id));
  if (!event.header.stack_id.is_valid()) {
    set(row, EventColumn::kStackStatus, "unavailable");
  } else if (presentation.stack_status.has_value()) {
    set(row, EventColumn::kStackStatus, stack_status_name(*presentation.stack_status));
  }
  set(row, EventColumn::kStackFrames, stack_frames_value(presentation, header));
}

void set_event_payload(EventRow& row, const noleax::trace::Event& event,
                       const noleax::trace::FileHeader& header) {
  if (const auto size = event_size(event); size.has_value()) {
    set(row, EventColumn::kSize, decimal(*size));
  }
  std::visit(
      [&row, &header](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, noleax::trace::HeapCreateEvent>) {
          set(row, EventColumn::kPayloadKind, "heap_create");
          set(row, EventColumn::kHeapHandle, address_value(payload.heap_handle, header));
          set(row, EventColumn::kHeapId, identifier_value(payload.heap_id));
          set(row, EventColumn::kHeapFlags, hex_value(payload.heap_flags));
          set(row, EventColumn::kReserveSize, decimal(payload.reserve_size));
          set(row, EventColumn::kCommitSize, decimal(payload.commit_size));
        } else if constexpr (std::is_same_v<Payload, noleax::trace::HeapDestroyEvent>) {
          set(row, EventColumn::kPayloadKind, "heap_destroy");
          set(row, EventColumn::kHeapHandle, address_value(payload.heap_handle, header));
          set(row, EventColumn::kHeapId, identifier_value(payload.heap_id));
          set(row, EventColumn::kRawResult, hex_value(payload.raw_result));
        } else if constexpr (std::is_same_v<Payload, noleax::trace::AllocationEvent>) {
          set(row, EventColumn::kPayloadKind, "allocation");
          set(row, EventColumn::kHeapHandle, address_value(payload.heap_handle, header));
          set(row, EventColumn::kHeapId, identifier_value(payload.heap_id));
          set(row, EventColumn::kRequestedSize, decimal(payload.requested_size));
          set(row, EventColumn::kResultAddress, address_value(payload.result_address, header));
          set(row, EventColumn::kAllocationId, identifier_value(payload.allocation_id));
          set(row, EventColumn::kApiFlags, hex_value(payload.api_flags));
        } else if constexpr (std::is_same_v<Payload, noleax::trace::ReallocationEvent>) {
          set(row, EventColumn::kPayloadKind, "reallocation");
          set(row, EventColumn::kHeapHandle, address_value(payload.heap_handle, header));
          set(row, EventColumn::kHeapId, identifier_value(payload.heap_id));
          set(row, EventColumn::kOldAddress, address_value(payload.old_address, header));
          set(row, EventColumn::kOldAllocationId, identifier_value(payload.old_allocation_id));
          set(row, EventColumn::kRequestedSize, decimal(payload.requested_size));
          set(row, EventColumn::kResultAddress, address_value(payload.result_address, header));
          set(row, EventColumn::kNewAllocationId, identifier_value(payload.new_allocation_id));
          set(row, EventColumn::kApiFlags, hex_value(payload.api_flags));
          set(row, EventColumn::kReallocationEffect, reallocation_effect_name(payload.effect));
        } else if constexpr (std::is_same_v<Payload, noleax::trace::FreeEvent>) {
          set(row, EventColumn::kPayloadKind, "free");
          set(row, EventColumn::kHeapHandle, address_value(payload.heap_handle, header));
          set(row, EventColumn::kHeapId, identifier_value(payload.heap_id));
          set(row, EventColumn::kAddress, address_value(payload.address, header));
          set(row, EventColumn::kAllocationId, identifier_value(payload.allocation_id));
          set(row, EventColumn::kRawResult, hex_value(payload.raw_result));
          set(row, EventColumn::kApiFlags, hex_value(payload.api_flags));
        } else if constexpr (std::is_same_v<Payload, noleax::trace::VmAllocateEvent>) {
          set(row, EventColumn::kPayloadKind, "vm_allocation");
          set_process_target(row, payload.target, header);
          set(row, EventColumn::kRequestedBase, address_value(payload.requested_base, header));
          set(row, EventColumn::kResultBase, address_value(payload.result_base, header));
          set(row, EventColumn::kRequestedSize, decimal(payload.requested_size));
          set(row, EventColumn::kResultSize, decimal(payload.result_size));
          set(row, EventColumn::kAllocationType, hex_value(payload.allocation_type));
          set(row, EventColumn::kProtection, hex_value(payload.protection));
          set(row, EventColumn::kMappingId, identifier_value(payload.mapping_id));
        } else if constexpr (std::is_same_v<Payload, noleax::trace::VmFreeEvent>) {
          set(row, EventColumn::kPayloadKind, "vm_free");
          set_process_target(row, payload.target, header);
          set(row, EventColumn::kBase, address_value(payload.base, header));
          set(row, EventColumn::kRegionSize, decimal(payload.region_size));
          set(row, EventColumn::kFreeType, hex_value(payload.free_type));
          set(row, EventColumn::kMappingId, identifier_value(payload.mapping_id));
        } else if constexpr (std::is_same_v<Payload, noleax::trace::MapEvent>) {
          set(row, EventColumn::kPayloadKind, "map");
          set(row, EventColumn::kSectionHandle, address_value(payload.section_handle, header));
          set_process_target(row, payload.target, header);
          set(row, EventColumn::kResultBase, address_value(payload.result_base, header));
          set(row, EventColumn::kViewSize, decimal(payload.view_size));
          set(row, EventColumn::kSectionOffset, decimal(payload.section_offset));
          set(row, EventColumn::kProtection, hex_value(payload.protection));
          set(row, EventColumn::kMappingId, identifier_value(payload.mapping_id));
        } else if constexpr (std::is_same_v<Payload, noleax::trace::UnmapEvent>) {
          set(row, EventColumn::kPayloadKind, "unmap");
          set_process_target(row, payload.target, header);
          set(row, EventColumn::kBase, address_value(payload.base, header));
          set(row, EventColumn::kMappingId, identifier_value(payload.mapping_id));
        }
      },
      event.payload);
}

void set_common_event_summary(EventRow& row, const EventStreamResult& trace) {
  set(row, EventColumn::kTraceEvents, decimal(trace.event_count));
  set(row, EventColumn::kLossRecords, decimal(trace.loss_record_count));
  set(row, EventColumn::kBytesRead, decimal(trace.bytes_read));
  set(row, EventColumn::kKnownSequenceEnd, identifier_value(trace.known_sequence_end));
  set(row, EventColumn::kKnownMonotonicEnd, decimal(trace.known_monotonic_end));
  set(row, EventColumn::kTruncated, trace.truncated ? "true" : "false");
  set(row, EventColumn::kPartiallyUnderstood, trace.partially_understood ? "true" : "false");
  set(row, EventColumn::kCompletenessMask, hex_value(trace.completeness.mask()));
  set(row, EventColumn::kCompletenessOverall,
      completeness_state_name(trace.completeness.overall_state()));
  set(row, EventColumn::kCompletenessLifecycle,
      completeness_state_name(trace.completeness.lifecycle_state()));
  set(row, EventColumn::kCompletenessStackDetail,
      completeness_state_name(trace.completeness.stack_detail_state()));
  set(row, EventColumn::kCompletenessUnderstanding,
      understanding_state_name(trace.completeness.understanding_state()));
  set(row, EventColumn::kCompletenessIssues, completeness_issues(trace.completeness));
  if (trace.statistics.has_value()) {
    const auto& statistics = *trace.statistics;
    set(row, EventColumn::kCaptureObservedCalls, decimal(statistics.observed_calls));
    set(row, EventColumn::kCaptureSuccessfulOperations, decimal(statistics.successful_operations));
    set(row, EventColumn::kCaptureFailedOperations, decimal(statistics.failed_operations));
    set(row, EventColumn::kCaptureFilteredBeforeQueue, decimal(statistics.filtered_before_queue));
    set(row, EventColumn::kCaptureDroppedEvents, decimal(statistics.dropped_events));
    set(row, EventColumn::kCaptureUniqueStacks, decimal(statistics.unique_stacks));
    set(row, EventColumn::kCaptureReusedStacks, decimal(statistics.reused_stacks));
    set(row, EventColumn::kCaptureWrittenUncompressedBytes,
        decimal(statistics.written_uncompressed_bytes));
    set(row, EventColumn::kCaptureWrittenStoredBytes, decimal(statistics.written_stored_bytes));
  }
  if (trace.end_of_trace.has_value()) {
    const auto& end = *trace.end_of_trace;
    set(row, EventColumn::kFinalSequence, identifier_value(end.final_sequence));
    set(row, EventColumn::kFinalMonotonicTicks, decimal(end.final_monotonic_ticks));
    set(row, EventColumn::kNormalStop, end.normal_stop ? "true" : "false");
    if (end.target_exit_code.has_value()) {
      set(row, EventColumn::kTargetExitCode, decimal(*end.target_exit_code));
    }
  }
}

enum class OutstandingColumn : std::uint8_t {
  kCsvSchemaVersion,
  kRecordType,
  kGenerationKind,
  kAllocationId,
  kMappingId,
  kHeapId,
  kHeapHandle,
  kAddress,
  kSize,
  kWindowANs,
  kWindowBNs,
  kRequestedCNs,
  kEffectiveCNs,
  kObservationUsesTraceEnd,
  kTraceEndMonotonicTicks,
  kCreationSequence,
  kCreationRelativeTimeNs,
  kCreationMonotonicTicks,
  kThreadId,
  kApiId,
  kApiName,
  kApiModule,
  kOperation,
  kStatus,
  kEventFlags,
  kErrorDomain,
  kErrorCode,
  kStackId,
  kStackStatus,
  kStackFrames,
  kCandidates,
  kEndedByC,
  kFilteredOut,
  kOutstanding,
  kOrphanedAllocationEnds,
  kOrphanedMappingEnds,
  kTraceEvents,
  kLossRecords,
  kBytesRead,
  kTruncated,
  kPartiallyUnderstood,
  kCompletenessMask,
  kCompletenessOverall,
  kCompletenessLifecycle,
  kCompletenessStackDetail,
  kCompletenessUnderstanding,
  kCompletenessIssues,
  kNormalStop,
  kTargetExitCode,
  kCount,
};

constexpr std::size_t kOutstandingColumnCount = static_cast<std::size_t>(OutstandingColumn::kCount);
using OutstandingRow = std::array<std::string, kOutstandingColumnCount>;

constexpr std::array<std::string_view, kOutstandingColumnCount> kOutstandingHeader{
    "csv_schema_version",
    "record_type",
    "generation_kind",
    "allocation_id",
    "mapping_id",
    "heap_id",
    "heap_handle",
    "address",
    "size",
    "window_a_ns",
    "window_b_ns",
    "requested_c_ns",
    "effective_c_ns",
    "observation_uses_trace_end",
    "trace_end_monotonic_ticks",
    "creation_sequence",
    "creation_relative_time_ns",
    "creation_monotonic_ticks",
    "thread_id",
    "api_id",
    "api_name",
    "api_module",
    "operation",
    "status",
    "event_flags",
    "error_domain",
    "error_code",
    "stack_id",
    "stack_status",
    "stack_frames",
    "candidates",
    "ended_by_c",
    "filtered_out",
    "outstanding",
    "orphaned_allocation_ends",
    "orphaned_mapping_ends",
    "trace_events",
    "loss_records",
    "bytes_read",
    "truncated",
    "partially_understood",
    "completeness_mask",
    "completeness_overall",
    "completeness_lifecycle",
    "completeness_stack_detail",
    "completeness_understanding",
    "completeness_issues",
    "normal_stop",
    "target_exit_code",
};

void set(OutstandingRow& row, OutstandingColumn column, std::string value) {
  row[column_index(column)] = std::move(value);
}

void set_outstanding_presentation(OutstandingRow& row, const noleax::trace::Event& event,
                                  const EventPresentation& presentation,
                                  const noleax::trace::FileHeader& header) {
  validate_stack_presentation(event, presentation);
  set(row, OutstandingColumn::kApiName, presentation.api_name.value_or(""));
  set(row, OutstandingColumn::kApiModule, presentation.api_module.value_or(""));
  set(row, OutstandingColumn::kStackId, identifier_value(event.header.stack_id));
  if (!event.header.stack_id.is_valid()) {
    set(row, OutstandingColumn::kStackStatus, "unavailable");
  } else if (presentation.stack_status.has_value()) {
    set(row, OutstandingColumn::kStackStatus, stack_status_name(*presentation.stack_status));
  }
  set(row, OutstandingColumn::kStackFrames, stack_frames_value(presentation, header));
}

void set_common_outstanding_summary(OutstandingRow& row, const EventStreamResult& trace) {
  set(row, OutstandingColumn::kTraceEvents, decimal(trace.event_count));
  set(row, OutstandingColumn::kLossRecords, decimal(trace.loss_record_count));
  set(row, OutstandingColumn::kBytesRead, decimal(trace.bytes_read));
  set(row, OutstandingColumn::kTruncated, trace.truncated ? "true" : "false");
  set(row, OutstandingColumn::kPartiallyUnderstood, trace.partially_understood ? "true" : "false");
  set(row, OutstandingColumn::kCompletenessMask, hex_value(trace.completeness.mask()));
  set(row, OutstandingColumn::kCompletenessOverall,
      completeness_state_name(trace.completeness.overall_state()));
  set(row, OutstandingColumn::kCompletenessLifecycle,
      completeness_state_name(trace.completeness.lifecycle_state()));
  set(row, OutstandingColumn::kCompletenessStackDetail,
      completeness_state_name(trace.completeness.stack_detail_state()));
  set(row, OutstandingColumn::kCompletenessUnderstanding,
      understanding_state_name(trace.completeness.understanding_state()));
  set(row, OutstandingColumn::kCompletenessIssues, completeness_issues(trace.completeness));
  if (trace.end_of_trace.has_value()) {
    const auto& end = *trace.end_of_trace;
    set(row, OutstandingColumn::kNormalStop, end.normal_stop ? "true" : "false");
    if (end.target_exit_code.has_value()) {
      set(row, OutstandingColumn::kTargetExitCode, decimal(*end.target_exit_code));
    }
  }
}

}  // namespace

CsvWriter::CsvWriter(std::ostream& output) : output_{output} {}

void CsvWriter::begin_events(const noleax::trace::FileHeader& header,
                             const noleax::trace::CaptureScope& scope) {
  require_state(State::kReady, "begin events");
  header_ = header;
  capture_scope_ = scope;
  CsvEmitter{output_}.row(kEventHeader);
  state_ = State::kEvents;
  ensure_output();
}

void CsvWriter::write_event(const noleax::trace::Event& event,
                            const EventPresentation& presentation) {
  require_state(State::kEvents, "write event");
  noleax::trace::validate_event(event);
  write_event_row(event, presentation);
  checked_increment(written_event_count_, "written event");
  ensure_output();
}

void CsvWriter::write_loss(const noleax::trace::LossRecord& loss) {
  require_state(State::kEvents, "write loss");
  noleax::trace::validate_loss_record(loss);
  write_loss_row(loss);
  checked_increment(written_loss_count_, "written loss");
  ensure_output();
}

void CsvWriter::finish_events(const FilteredEventsResult& result) {
  require_state(State::kEvents, "finish events");
  if (header_ != result.trace.file_header || capture_scope_ != result.trace.capture_scope) {
    throw CsvFormatError{"events summary belongs to a different trace"};
  }
  if (written_event_count_ != result.matched_event_count ||
      written_loss_count_ != result.trace.loss_record_count) {
    throw CsvFormatError{"written CSV records do not match the analysis result"};
  }
  if (result.filtered_event_count > result.trace.event_count ||
      result.matched_event_count != result.trace.event_count - result.filtered_event_count) {
    throw CsvFormatError{"matched and filtered counts do not cover all trace events"};
  }
  write_event_summary(result);
  state_ = State::kFinished;
  ensure_output();
}

void CsvWriter::write_outstanding(const OutstandingResult& result,
                                  const EventPresentationResolver& resolver) {
  require_state(State::kReady, "write outstanding report");
  if (result.ended_by_c_count > result.candidate_count ||
      result.filtered_out_count > result.candidate_count - result.ended_by_c_count) {
    throw CsvFormatError{"outstanding result counts are inconsistent"};
  }
  const std::uint64_t survivors =
      result.candidate_count - result.ended_by_c_count - result.filtered_out_count;
  if (static_cast<std::uint64_t>(result.outstanding.size()) != survivors) {
    throw CsvFormatError{"outstanding generation count is inconsistent"};
  }
  for (const auto& generation : result.outstanding) {
    noleax::trace::validate_event(generation.created_by);
  }

  header_ = result.trace.file_header;
  capture_scope_ = result.trace.capture_scope;
  CsvEmitter{output_}.row(kOutstandingHeader);
  for (const auto& generation : result.outstanding) {
    write_outstanding_row(generation,
                          resolver ? resolver(generation.created_by) : EventPresentation{});
  }
  write_outstanding_summary(result);
  state_ = State::kFinished;
  ensure_output();
}

void CsvWriter::write_event_row(const noleax::trace::Event& event,
                                const EventPresentation& presentation) {
  EventRow row;
  set(row, EventColumn::kCsvSchemaVersion, decimal(kAnalysisCsvSchemaVersion));
  set(row, EventColumn::kRecordType, "event");
  set(row, EventColumn::kSequence, decimal(event.header.sequence.value()));
  set(row, EventColumn::kRelativeTimeNs,
      decimal(trace_time_floor(event.header.monotonic_ticks, header_).count()));
  set(row, EventColumn::kMonotonicTicks, decimal(event.header.monotonic_ticks));
  set(row, EventColumn::kThreadId, decimal(event.header.thread_id));
  set(row, EventColumn::kApiId, decimal(event.header.api_id));
  set(row, EventColumn::kOperation, operation_name(noleax::trace::event_operation(event.payload)));
  set(row, EventColumn::kStatus, status_name(event.header.status));
  set(row, EventColumn::kEventFlags, hex_value(event.header.flags));
  if (event.header.system_error.domain != noleax::trace::SystemErrorDomain::kNone) {
    set(row, EventColumn::kErrorDomain, error_domain_name(event.header.system_error.domain));
    set(row, EventColumn::kErrorCode, hex_value(event.header.system_error.code));
  }
  set_event_presentation(row, event, presentation, header_);
  set_event_payload(row, event, header_);
  CsvEmitter{output_}.row(row);
}

void CsvWriter::write_loss_row(const noleax::trace::LossRecord& loss) {
  EventRow row;
  set(row, EventColumn::kCsvSchemaVersion, decimal(kAnalysisCsvSchemaVersion));
  set(row, EventColumn::kRecordType, "loss");
  set(row, EventColumn::kLossReason, loss_reason_name(loss.reason));
  set(row, EventColumn::kLossLocation, loss_location_name(loss.location));
  if (loss.estimated_event_count.has_value()) {
    set(row, EventColumn::kLostEventCount, decimal(*loss.estimated_event_count));
  }
  if (loss.sequence_range.has_value()) {
    set(row, EventColumn::kLossSequenceBegin, decimal(loss.sequence_range->begin.value()));
    set(row, EventColumn::kLossSequenceEnd, decimal(loss.sequence_range->end.value()));
  }
  if (loss.tick_range.has_value()) {
    set(row, EventColumn::kLossTickBegin, decimal(loss.tick_range->begin));
    set(row, EventColumn::kLossTickEnd, decimal(loss.tick_range->end));
  }
  CsvEmitter{output_}.row(row);
}

void CsvWriter::write_event_summary(const FilteredEventsResult& result) {
  EventRow row;
  set(row, EventColumn::kCsvSchemaVersion, decimal(kAnalysisCsvSchemaVersion));
  set(row, EventColumn::kRecordType, "summary");
  set(row, EventColumn::kMatchedEvents, decimal(result.matched_event_count));
  set(row, EventColumn::kFilteredEvents, decimal(result.filtered_event_count));
  set_common_event_summary(row, result.trace);
  CsvEmitter{output_}.row(row);
}

void CsvWriter::write_outstanding_row(const MemoryGeneration& generation,
                                      const EventPresentation& presentation) {
  OutstandingRow row;
  set(row, OutstandingColumn::kCsvSchemaVersion, decimal(kAnalysisCsvSchemaVersion));
  set(row, OutstandingColumn::kRecordType, "allocation");
  set(row, OutstandingColumn::kGenerationKind, generation_kind_name(generation.kind));
  set(row, OutstandingColumn::kAllocationId, identifier_value(generation.allocation_id));
  set(row, OutstandingColumn::kMappingId, identifier_value(generation.mapping_id));
  set(row, OutstandingColumn::kHeapId, identifier_value(generation.heap_id));
  if (generation.kind == GenerationKind::kHeapAllocation) {
    set(row, OutstandingColumn::kHeapHandle, address_value(generation.heap_handle, header_));
  }
  set(row, OutstandingColumn::kAddress, address_value(generation.address, header_));
  set(row, OutstandingColumn::kSize, decimal(generation.size));

  const auto& event = generation.created_by;
  set(row, OutstandingColumn::kCreationSequence, decimal(event.header.sequence.value()));
  set(row, OutstandingColumn::kCreationRelativeTimeNs,
      decimal(trace_time_floor(event.header.monotonic_ticks, header_).count()));
  set(row, OutstandingColumn::kCreationMonotonicTicks, decimal(event.header.monotonic_ticks));
  set(row, OutstandingColumn::kThreadId, decimal(event.header.thread_id));
  set(row, OutstandingColumn::kApiId, decimal(event.header.api_id));
  set(row, OutstandingColumn::kOperation,
      operation_name(noleax::trace::event_operation(event.payload)));
  set(row, OutstandingColumn::kStatus, status_name(event.header.status));
  set(row, OutstandingColumn::kEventFlags, hex_value(event.header.flags));
  if (event.header.system_error.domain != noleax::trace::SystemErrorDomain::kNone) {
    set(row, OutstandingColumn::kErrorDomain, error_domain_name(event.header.system_error.domain));
    set(row, OutstandingColumn::kErrorCode, hex_value(event.header.system_error.code));
  }
  set_outstanding_presentation(row, event, presentation, header_);
  CsvEmitter{output_}.row(row);
}

void CsvWriter::write_outstanding_summary(const OutstandingResult& result) {
  OutstandingRow row;
  set(row, OutstandingColumn::kCsvSchemaVersion, decimal(kAnalysisCsvSchemaVersion));
  set(row, OutstandingColumn::kRecordType, "summary");
  set(row, OutstandingColumn::kWindowANs, decimal(result.requested_window.a.count()));
  set(row, OutstandingColumn::kWindowBNs, decimal(result.requested_window.b.count()));
  if (result.requested_window.c.has_value()) {
    set(row, OutstandingColumn::kRequestedCNs, decimal(result.requested_window.c->count()));
  }
  set(row, OutstandingColumn::kEffectiveCNs, decimal(result.effective_c.count()));
  set(row, OutstandingColumn::kObservationUsesTraceEnd,
      result.observation_uses_trace_end ? "true" : "false");
  set(row, OutstandingColumn::kTraceEndMonotonicTicks, decimal(result.trace_end_monotonic_ticks));
  set(row, OutstandingColumn::kCandidates, decimal(result.candidate_count));
  set(row, OutstandingColumn::kEndedByC, decimal(result.ended_by_c_count));
  set(row, OutstandingColumn::kFilteredOut, decimal(result.filtered_out_count));
  set(row, OutstandingColumn::kOutstanding,
      decimal(static_cast<std::uint64_t>(result.outstanding.size())));
  set(row, OutstandingColumn::kOrphanedAllocationEnds,
      decimal(result.orphaned_allocation_end_count));
  set(row, OutstandingColumn::kOrphanedMappingEnds, decimal(result.orphaned_mapping_end_count));
  set_common_outstanding_summary(row, result.trace);
  CsvEmitter{output_}.row(row);
}

void CsvWriter::require_state(State expected, const char* operation) const {
  if (state_ != expected) {
    throw CsvFormatError{std::string{"cannot "} + operation + " in the current writer state"};
  }
}

void CsvWriter::ensure_output() const {
  if (!output_) {
    throw CsvFormatError{"cannot write CSV output"};
  }
}

FilteredEventsResult analyze_events_to_csv(std::istream& input, std::ostream& output,
                                           const AnalysisFilter& filter,
                                           const EventMetadataResolver& filter_resolver,
                                           const EventPresentationResolver& presentation_resolver,
                                           EventStreamOptions stream_options) {
  CsvWriter writer{output};
  std::optional<noleax::trace::FileHeader> file_header;
  EventStreamCallbacks callbacks;
  callbacks.on_file_header = [&file_header](const noleax::trace::FileHeader& header) {
    file_header = header;
  };
  callbacks.on_capture_scope = [&file_header, &writer](const noleax::trace::CaptureScope& scope) {
    if (!file_header.has_value()) {
      throw CsvFormatError{"capture scope appeared before the trace header"};
    }
    writer.begin_events(*file_header, scope);
  };
  callbacks.on_event = [&writer, &presentation_resolver](const noleax::trace::Event& event) {
    writer.write_event(event,
                       presentation_resolver ? presentation_resolver(event) : EventPresentation{});
  };
  callbacks.on_loss = [&writer](const noleax::trace::LossRecord& loss) { writer.write_loss(loss); };

  auto result = analyze_filtered_events(input, filter, callbacks, filter_resolver, stream_options);
  writer.finish_events(result);
  return result;
}

OutstandingResult analyze_outstanding_to_csv(std::istream& input, std::ostream& output,
                                             OutstandingWindow window, const AnalysisFilter& filter,
                                             const EventMetadataResolver& filter_resolver,
                                             const EventPresentationResolver& presentation_resolver,
                                             EventStreamOptions stream_options) {
  auto result =
      analyze_filtered_outstanding(input, window, filter, filter_resolver, stream_options);
  CsvWriter writer{output};
  writer.write_outstanding(result, presentation_resolver);
  return result;
}

}  // namespace noleax::analyzer
