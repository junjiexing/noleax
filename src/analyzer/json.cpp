#include "noleax/analyzer/json.hpp"

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

#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/analyzer/presentation.hpp"
#include "noleax/analyzer/time.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/wire_format.hpp"
#include "utf8.hpp"

namespace noleax::analyzer {
namespace {

class JsonEmitter {
 public:
  explicit JsonEmitter(std::ostream& output) : output_{output} {}

  void raw(std::string_view value) {
    output_.write(value.data(), static_cast<std::streamsize>(value.size()));
  }

  void string(std::string_view value) {
    if (!detail::is_valid_utf8(value)) {
      throw JsonFormatError{"JSON string is not valid UTF-8"};
    }
    raw("\"");
    for (const char byte_char : value) {
      const auto byte = static_cast<unsigned char>(byte_char);
      switch (byte) {
        case '"':
          raw("\\\"");
          break;
        case '\\':
          raw("\\\\");
          break;
        case '\b':
          raw("\\b");
          break;
        case '\f':
          raw("\\f");
          break;
        case '\n':
          raw("\\n");
          break;
        case '\r':
          raw("\\r");
          break;
        case '\t':
          raw("\\t");
          break;
        default:
          if (byte < 0x20U) {
            constexpr std::string_view digits{"0123456789abcdef"};
            const std::array escaped{'\\', 'u', '0', '0', digits[byte >> 4U], digits[byte & 0x0fU]};
            output_.write(escaped.data(), static_cast<std::streamsize>(escaped.size()));
          } else {
            output_.put(static_cast<char>(byte));
          }
          break;
      }
    }
    raw("\"");
  }

  void unsigned_number(std::uint64_t value) {
    std::array<char, 32> buffer{};
    const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    if (result.ec != std::errc{}) {
      throw JsonFormatError{"cannot format an unsigned JSON integer"};
    }
    output_.write(buffer.data(), result.ptr - buffer.data());
  }

  void signed_number(std::int64_t value) {
    std::array<char, 32> buffer{};
    const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    if (result.ec != std::errc{}) {
      throw JsonFormatError{"cannot format a signed JSON integer"};
    }
    output_.write(buffer.data(), result.ptr - buffer.data());
  }

  void boolean(bool value) { raw(value ? "true" : "false"); }
  void null() { raw("null"); }

 private:
  std::ostream& output_;
};

template <typename Identifier>
void write_identifier(JsonEmitter& json, Identifier identifier) {
  if (identifier.is_valid()) {
    json.unsigned_number(identifier.value());
  } else {
    json.null();
  }
}

void write_optional_string(JsonEmitter& json, const std::optional<std::string>& value) {
  if (value.has_value()) {
    json.string(*value);
  } else {
    json.null();
  }
}

[[nodiscard]] std::string hex_value(std::uint64_t value, std::size_t minimum_digits = 0U) {
  std::array<char, 16> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
  if (result.ec != std::errc{}) {
    throw JsonFormatError{"cannot format a hexadecimal JSON string"};
  }
  const std::size_t digit_count = static_cast<std::size_t>(result.ptr - buffer.data());
  std::string output{"0x"};
  if (minimum_digits > digit_count) {
    output.append(minimum_digits - digit_count, '0');
  }
  output.append(buffer.data(), digit_count);
  return output;
}

void write_hex(JsonEmitter& json, std::uint64_t value, std::size_t minimum_digits = 0U) {
  json.string(hex_value(value, minimum_digits));
}

[[nodiscard]] std::size_t pointer_digits(const noleax::trace::FileHeader& header) {
  return static_cast<std::size_t>(header.pointer_width) * 2U;
}

void write_address(JsonEmitter& json, noleax::trace::Address address,
                   const noleax::trace::FileHeader& header) {
  write_hex(json, address, pointer_digits(header));
}

[[nodiscard]] const char* platform_name(noleax::trace::Platform platform) noexcept {
  switch (platform) {
    case noleax::trace::Platform::kUnknown:
      return "unknown";
    case noleax::trace::Platform::kWindows:
      return "windows";
    case noleax::trace::Platform::kLinux:
      return "linux";
    case noleax::trace::Platform::kMacos:
      return "macos";
  }
  return "unknown";
}

[[nodiscard]] const char* architecture_name(noleax::trace::Architecture architecture) noexcept {
  switch (architecture) {
    case noleax::trace::Architecture::kUnknown:
      return "unknown";
    case noleax::trace::Architecture::kX86:
      return "x86";
    case noleax::trace::Architecture::kX64:
      return "x64";
    case noleax::trace::Architecture::kArm64:
      return "arm64";
  }
  return "unknown";
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

void checked_increment(std::uint64_t& value, const char* subject) {
  if (value == std::numeric_limits<std::uint64_t>::max()) {
    throw JsonFormatError{std::string{subject} + " count overflow"};
  }
  ++value;
}

void write_process_target(JsonEmitter& json, const noleax::trace::ProcessTarget& target,
                          const noleax::trace::FileHeader& header) {
  json.raw("{\"scope\":");
  json.string(process_scope_name(target.scope));
  json.raw(",\"process_handle\":");
  write_address(json, target.process_handle, header);
  json.raw(",\"process_id\":");
  json.unsigned_number(target.process_id);
  json.raw("}");
}

void write_filter(JsonEmitter& json, const AnalysisFilter& filter) {
  const auto& criteria = filter.criteria();
  json.raw("{\"minimum_size\":");
  if (criteria.minimum_size.has_value()) {
    json.unsigned_number(*criteria.minimum_size);
  } else {
    json.null();
  }
  json.raw(",\"maximum_size\":");
  if (criteria.maximum_size.has_value()) {
    json.unsigned_number(*criteria.maximum_size);
  } else {
    json.null();
  }

  const auto write_string_array = [&json](std::string_view key,
                                          const std::vector<std::string>& values) {
    json.raw(",");
    json.string(key);
    json.raw(":[");
    bool first = true;
    for (const auto& value : values) {
      if (!first) {
        json.raw(",");
      }
      first = false;
      json.string(value);
    }
    json.raw("]");
  };
  const auto write_integer_array = [&json](std::string_view key,
                                           const std::vector<std::uint64_t>& values) {
    json.raw(",");
    json.string(key);
    json.raw(":[");
    bool first = true;
    for (const auto value : values) {
      if (!first) {
        json.raw(",");
      }
      first = false;
      json.unsigned_number(value);
    }
    json.raw("]");
  };

  json.raw(",\"operations\":[");
  bool first = true;
  for (const auto operation : criteria.operations) {
    if (!first) {
      json.raw(",");
    }
    first = false;
    json.string(operation_name(operation));
  }
  json.raw("]");
  write_integer_array("thread_ids", criteria.thread_ids);
  write_string_array("api_names", criteria.api_names);
  write_string_array("module_patterns", criteria.module_patterns);
  write_string_array("stack_module_patterns", criteria.stack_module_patterns);
  write_integer_array("allocation_ids", criteria.allocation_ids);
  json.raw(",\"statuses\":[");
  first = true;
  for (const auto status : criteria.statuses) {
    if (!first) {
      json.raw(",");
    }
    first = false;
    json.string(status_name(status));
  }
  json.raw("]}");
}

void write_capture_statistics(JsonEmitter& json,
                              const std::optional<noleax::trace::CaptureStatistics>& value) {
  if (!value.has_value()) {
    json.null();
    return;
  }
  const auto& statistics = *value;
  json.raw("{\"observed_calls\":");
  json.unsigned_number(statistics.observed_calls);
  json.raw(",\"successful_operations\":");
  json.unsigned_number(statistics.successful_operations);
  json.raw(",\"failed_operations\":");
  json.unsigned_number(statistics.failed_operations);
  json.raw(",\"filtered_before_queue\":");
  json.unsigned_number(statistics.filtered_before_queue);
  json.raw(",\"dropped_events\":");
  json.unsigned_number(statistics.dropped_events);
  json.raw(",\"unique_stacks\":");
  json.unsigned_number(statistics.unique_stacks);
  json.raw(",\"reused_stacks\":");
  json.unsigned_number(statistics.reused_stacks);
  json.raw(",\"written_uncompressed_bytes\":");
  json.unsigned_number(statistics.written_uncompressed_bytes);
  json.raw(",\"written_stored_bytes\":");
  json.unsigned_number(statistics.written_stored_bytes);
  json.raw(",\"per_api\":[");
  bool first = true;
  for (const auto& api : statistics.per_api) {
    if (!first) {
      json.raw(",");
    }
    first = false;
    json.raw("{\"api_id\":");
    json.unsigned_number(api.api_id);
    json.raw(",\"observed_calls\":");
    json.unsigned_number(api.observed_calls);
    json.raw(",\"successful_operations\":");
    json.unsigned_number(api.successful_operations);
    json.raw(",\"failed_operations\":");
    json.unsigned_number(api.failed_operations);
    json.raw(",\"filtered_before_queue\":");
    json.unsigned_number(api.filtered_before_queue);
    json.raw(",\"dropped_events\":");
    json.unsigned_number(api.dropped_events);
    json.raw("}");
  }
  json.raw("]}");
}

void write_termination(JsonEmitter& json, const std::optional<noleax::trace::EndOfTrace>& value) {
  if (!value.has_value()) {
    json.null();
    return;
  }
  json.raw("{\"final_sequence\":");
  write_identifier(json, value->final_sequence);
  json.raw(",\"final_monotonic_ticks\":");
  json.unsigned_number(value->final_monotonic_ticks);
  json.raw(",\"normal_stop\":");
  json.boolean(value->normal_stop);
  json.raw(",\"target_exit_code\":");
  if (value->target_exit_code.has_value()) {
    json.signed_number(*value->target_exit_code);
  } else {
    json.null();
  }
  json.raw("}");
}

}  // namespace

JsonWriter::JsonWriter(std::ostream& output) : output_{output} {}

void JsonWriter::begin_events(const noleax::trace::FileHeader& header,
                              const noleax::trace::CaptureScope& scope,
                              const AnalysisFilter& filter) {
  require_state(State::kReady, "begin events");
  header_ = header;
  capture_scope_ = scope;
  write_document_prefix("events", header, scope, filter);
  JsonEmitter{output_}.raw(",\"events\":[");
  state_ = State::kEvents;
  ensure_output();
}

void JsonWriter::write_event(const noleax::trace::Event& event,
                             const EventPresentation& presentation) {
  require_state(State::kEvents, "write event");
  noleax::trace::validate_event(event);
  write_record_separator();
  write_event_object(event, presentation);
  checked_increment(written_event_count_, "written event");
  ensure_output();
}

void JsonWriter::write_loss(const noleax::trace::LossRecord& loss) {
  require_state(State::kEvents, "write loss");
  noleax::trace::validate_loss_record(loss);
  write_record_separator();
  JsonEmitter json{output_};
  json.raw("{\"record_type\":\"loss\",\"reason\":");
  json.string(loss_reason_name(loss.reason));
  json.raw(",\"location\":");
  json.string(loss_location_name(loss.location));
  json.raw(",\"estimated_event_count\":");
  if (loss.estimated_event_count.has_value()) {
    json.unsigned_number(*loss.estimated_event_count);
  } else {
    json.null();
  }
  json.raw(",\"sequence_range\":");
  if (loss.sequence_range.has_value()) {
    json.raw("{\"begin\":");
    json.unsigned_number(loss.sequence_range->begin.value());
    json.raw(",\"end\":");
    json.unsigned_number(loss.sequence_range->end.value());
    json.raw("}");
  } else {
    json.null();
  }
  json.raw(",\"tick_range\":");
  if (loss.tick_range.has_value()) {
    json.raw("{\"begin\":");
    json.unsigned_number(loss.tick_range->begin);
    json.raw(",\"end\":");
    json.unsigned_number(loss.tick_range->end);
    json.raw("}");
  } else {
    json.null();
  }
  json.raw("}");
  checked_increment(written_loss_count_, "written loss");
  ensure_output();
}

void JsonWriter::finish_events(const FilteredEventsResult& result) {
  require_state(State::kEvents, "finish events");
  if (header_ != result.trace.file_header || capture_scope_ != result.trace.capture_scope) {
    throw JsonFormatError{"events summary belongs to a different trace"};
  }
  if (written_event_count_ != result.matched_event_count ||
      written_loss_count_ != result.trace.loss_record_count) {
    throw JsonFormatError{"written JSON records do not match the analysis result"};
  }
  if (result.filtered_event_count > result.trace.event_count ||
      result.matched_event_count != result.trace.event_count - result.filtered_event_count) {
    throw JsonFormatError{"matched and filtered counts do not cover all trace events"};
  }

  JsonEmitter json{output_};
  json.raw("],\"summary\":{\"matched_events\":");
  json.unsigned_number(result.matched_event_count);
  json.raw(",\"filtered_events\":");
  json.unsigned_number(result.filtered_event_count);
  json.raw(",");
  write_summary(result.trace);
  json.raw("}}\n");
  state_ = State::kFinished;
  ensure_output();
}

void JsonWriter::write_outstanding(const OutstandingResult& result, const AnalysisFilter& filter,
                                   const EventPresentationResolver& resolver) {
  require_state(State::kReady, "write outstanding report");
  if (result.ended_by_c_count > result.candidate_count ||
      result.filtered_out_count > result.candidate_count - result.ended_by_c_count) {
    throw JsonFormatError{"outstanding result counts are inconsistent"};
  }
  const std::uint64_t survivors =
      result.candidate_count - result.ended_by_c_count - result.filtered_out_count;
  if (static_cast<std::uint64_t>(result.outstanding.size()) != survivors) {
    throw JsonFormatError{"outstanding generation count is inconsistent"};
  }
  for (const auto& generation : result.outstanding) {
    noleax::trace::validate_event(generation.created_by);
  }

  header_ = result.trace.file_header;
  capture_scope_ = result.trace.capture_scope;
  write_document_prefix("leaks", header_, capture_scope_, filter);
  JsonEmitter json{output_};
  json.raw(",\"window\":{\"a_ns\":");
  json.signed_number(result.requested_window.a.count());
  json.raw(",\"b_ns\":");
  if (result.requested_window.b.has_value()) {
    json.signed_number(result.requested_window.b->count());
  } else {
    json.null();
  }
  json.raw(",\"effective_b_ns\":");
  json.signed_number(result.effective_b.count());
  json.raw(",\"requested_c_ns\":");
  if (result.requested_window.c.has_value()) {
    json.signed_number(result.requested_window.c->count());
  } else {
    json.null();
  }
  json.raw(",\"effective_c_ns\":");
  json.signed_number(result.effective_c.count());
  json.raw(",\"observation_uses_trace_end\":");
  json.boolean(result.observation_uses_trace_end);
  json.raw(",\"trace_end_monotonic_ticks\":");
  json.unsigned_number(result.trace_end_monotonic_ticks);
  json.raw("},\"allocations\":[");

  bool first = true;
  for (const auto& generation : result.outstanding) {
    if (!first) {
      json.raw(",");
    }
    first = false;
    const EventPresentation presentation =
        resolver ? resolver(generation.created_by) : EventPresentation{};
    json.raw("{\"generation_kind\":");
    json.string(generation_kind_name(generation.kind));
    json.raw(",\"allocation_id\":");
    write_identifier(json, generation.allocation_id);
    json.raw(",\"mapping_id\":");
    write_identifier(json, generation.mapping_id);
    json.raw(",\"heap_id\":");
    write_identifier(json, generation.heap_id);
    json.raw(",\"heap_handle\":");
    if (generation.kind == GenerationKind::kHeapAllocation) {
      write_address(json, generation.heap_handle, header_);
    } else {
      json.null();
    }
    json.raw(",\"address\":");
    write_address(json, generation.address, header_);
    json.raw(",\"size\":");
    json.unsigned_number(generation.size);
    json.raw(",\"created_by\":");
    write_event_object(generation.created_by, presentation);
    json.raw("}");
  }

  json.raw("],\"summary\":{\"candidates\":");
  json.unsigned_number(result.candidate_count);
  json.raw(",\"ended_by_c\":");
  json.unsigned_number(result.ended_by_c_count);
  json.raw(",\"filtered_out\":");
  json.unsigned_number(result.filtered_out_count);
  json.raw(",\"outstanding\":");
  json.unsigned_number(static_cast<std::uint64_t>(result.outstanding.size()));
  json.raw(",\"orphaned_allocation_ends\":");
  json.unsigned_number(result.orphaned_allocation_end_count);
  json.raw(",\"orphaned_mapping_ends\":");
  json.unsigned_number(result.orphaned_mapping_end_count);
  json.raw(",");
  write_summary(result.trace);
  json.raw("}}\n");
  state_ = State::kFinished;
  ensure_output();
}

void JsonWriter::write_event_stacks(const EventsStacksResult& result, const AnalysisFilter& filter,
                                    const EventPresentationResolver& resolver) {
  require_state(State::kReady, "write event stacks report");
  header_ = result.trace.file_header;
  capture_scope_ = result.trace.capture_scope;
  write_document_prefix("stacks", header_, capture_scope_, filter);
  JsonEmitter json{output_};
  json.raw(",\"dataset\":\"events\",\"window\":{\"from_ns\":");
  json.signed_number(result.window.from.count());
  json.raw(",\"to_ns\":");
  if (result.window.to.has_value()) {
    json.signed_number(result.window.to->count());
  } else {
    json.null();
  }
  json.raw("},\"groups\":[");

  bool first = true;
  std::uint64_t rank = 0U;
  std::uint64_t total_calls = 0U;
  std::uint64_t total_alloc_bytes = 0U;
  std::uint64_t total_free_bytes = 0U;
  for (const auto& group : result.groups) {
    ++rank;
    total_calls += group.calls;
    total_alloc_bytes += group.alloc_bytes;
    total_free_bytes += group.free_bytes;
    if (!first) {
      json.raw(",");
    }
    first = false;
    const EventPresentation presentation =
        resolver ? resolver(group.sample_event) : EventPresentation{};
    json.raw("{\"rank\":");
    json.unsigned_number(rank);
    json.raw(",\"calls\":");
    json.unsigned_number(group.calls);
    json.raw(",\"alloc_calls\":");
    json.unsigned_number(group.alloc_calls);
    json.raw(",\"alloc_bytes\":");
    json.unsigned_number(group.alloc_bytes);
    json.raw(",\"free_calls\":");
    json.unsigned_number(group.free_calls);
    json.raw(",\"free_bytes\":");
    json.unsigned_number(group.free_bytes);
    json.raw(",\"net_bytes\":");
    json.signed_number(group.net_bytes());
    json.raw(",\"stack_id\":");
    write_identifier(json, group.stack_id);
    json.raw(",\"apis\":[");
    const auto names = group_api_names(group.api_ids);
    for (std::size_t index = 0U; index < names.size(); ++index) {
      if (index != 0U) {
        json.raw(",");
      }
      json.string(names[index]);
    }
    json.raw("]");
    json.raw(",\"sample_event\":");
    write_event_object(group.sample_event, presentation);
    json.raw("}");
  }

  json.raw("],\"summary\":{\"groups\":");
  json.unsigned_number(static_cast<std::uint64_t>(result.groups.size()));
  json.raw(",\"calls\":");
  json.unsigned_number(total_calls);
  json.raw(",\"alloc_bytes\":");
  json.unsigned_number(total_alloc_bytes);
  json.raw(",\"free_bytes\":");
  json.unsigned_number(total_free_bytes);
  json.raw(",\"net_bytes\":");
  json.signed_number(saturating_net_bytes(total_alloc_bytes, total_free_bytes));
  json.raw(",\"aggregated_events\":");
  json.unsigned_number(result.aggregated_event_count);
  json.raw(",\"unmatched_frees\":");
  json.unsigned_number(result.unmatched_free_count);
  json.raw(",");
  write_summary(result.trace);
  json.raw("}}\n");
  state_ = State::kFinished;
  ensure_output();
}

void JsonWriter::write_leak_stacks(const LeaksStacksResult& result, const AnalysisFilter& filter,
                                   const EventPresentationResolver& resolver) {
  require_state(State::kReady, "write leak stacks report");
  const OutstandingResult& outstanding = result.outstanding;
  header_ = outstanding.trace.file_header;
  capture_scope_ = outstanding.trace.capture_scope;
  write_document_prefix("stacks", header_, capture_scope_, filter);
  JsonEmitter json{output_};
  json.raw(",\"dataset\":\"leaks\",\"window\":{\"a_ns\":");
  json.signed_number(outstanding.requested_window.a.count());
  json.raw(",\"b_ns\":");
  if (outstanding.requested_window.b.has_value()) {
    json.signed_number(outstanding.requested_window.b->count());
  } else {
    json.null();
  }
  json.raw(",\"effective_b_ns\":");
  json.signed_number(outstanding.effective_b.count());
  json.raw(",\"requested_c_ns\":");
  if (outstanding.requested_window.c.has_value()) {
    json.signed_number(outstanding.requested_window.c->count());
  } else {
    json.null();
  }
  json.raw(",\"effective_c_ns\":");
  json.signed_number(outstanding.effective_c.count());
  json.raw(",\"observation_uses_trace_end\":");
  json.boolean(outstanding.observation_uses_trace_end);
  json.raw("},\"groups\":[");

  bool first = true;
  std::uint64_t rank = 0U;
  std::uint64_t total_calls = 0U;
  std::uint64_t total_bytes = 0U;
  for (const auto& group : result.groups) {
    ++rank;
    total_calls += group.calls;
    total_bytes += group.bytes;
    if (!first) {
      json.raw(",");
    }
    first = false;
    const EventPresentation presentation =
        resolver ? resolver(group.sample_event) : EventPresentation{};
    json.raw("{\"rank\":");
    json.unsigned_number(rank);
    json.raw(",\"calls\":");
    json.unsigned_number(group.calls);
    json.raw(",\"bytes\":");
    json.unsigned_number(group.bytes);
    json.raw(",\"stack_id\":");
    write_identifier(json, group.stack_id);
    json.raw(",\"apis\":[");
    const auto names = group_api_names(group.api_ids);
    for (std::size_t index = 0U; index < names.size(); ++index) {
      if (index != 0U) {
        json.raw(",");
      }
      json.string(names[index]);
    }
    json.raw("]");
    json.raw(",\"sample_event\":");
    write_event_object(group.sample_event, presentation);
    json.raw("}");
  }

  json.raw("],\"summary\":{\"groups\":");
  json.unsigned_number(static_cast<std::uint64_t>(result.groups.size()));
  json.raw(",\"calls\":");
  json.unsigned_number(total_calls);
  json.raw(",\"bytes\":");
  json.unsigned_number(total_bytes);
  json.raw(",");
  write_summary(outstanding.trace);
  json.raw("}}\n");
  state_ = State::kFinished;
  ensure_output();
}

void JsonWriter::write_document_prefix(const char* mode, const noleax::trace::FileHeader& header,
                                       const noleax::trace::CaptureScope& scope,
                                       const AnalysisFilter& filter) {
  JsonEmitter json{output_};
  json.raw("{\"schema\":\"noleax.analysis\",\"schema_version\":");
  json.unsigned_number(kAnalysisJsonSchemaVersion);
  json.raw(",\"mode\":");
  json.string(mode);
  json.raw(",\"metadata\":{\"trace\":{\"format_major\":");
  json.unsigned_number(noleax::trace::kTraceFormatMajor);
  json.raw(",\"format_minor\":");
  json.unsigned_number(noleax::trace::kTraceFormatMinor);
  json.raw(",\"platform\":");
  json.string(platform_name(header.platform));
  json.raw(",\"architecture\":");
  json.string(architecture_name(header.architecture));
  json.raw(",\"pointer_width\":");
  json.unsigned_number(header.pointer_width);
  json.raw(",\"flags\":");
  write_hex(json, header.flags);
  json.raw(",\"session_id\":");
  std::string session_id;
  session_id.reserve(header.session_id.size() * 2U);
  constexpr std::string_view digits{"0123456789abcdef"};
  for (const auto byte : header.session_id) {
    const auto value = std::to_integer<unsigned int>(byte);
    session_id.push_back(digits[value >> 4U]);
    session_id.push_back(digits[value & 0x0fU]);
  }
  json.string(session_id);
  json.raw(",\"file_index\":");
  json.unsigned_number(header.file_index);
  json.raw(",\"monotonic_frequency\":");
  json.unsigned_number(header.monotonic_frequency);
  json.raw(",\"monotonic_origin\":");
  json.unsigned_number(header.monotonic_origin);
  json.raw(",\"utc_origin_ns\":");
  json.signed_number(header.utc_origin_ns);
  json.raw("},\"capture\":{\"started_at_process_start\":");
  json.boolean(scope.started_at_process_start);
  json.raw(",\"preexisting_allocations_unknown\":");
  json.boolean(scope.preexisting_allocations_unknown);
  json.raw("}},\"filters\":");
  write_filter(json, filter);
}

void JsonWriter::write_event_object(const noleax::trace::Event& event,
                                    const EventPresentation& presentation) {
  JsonEmitter json{output_};
  json.raw("{\"record_type\":\"event\",\"sequence\":");
  json.unsigned_number(event.header.sequence.value());
  json.raw(",\"monotonic_ticks\":");
  json.unsigned_number(event.header.monotonic_ticks);
  json.raw(",\"relative_time_ns\":");
  json.signed_number(trace_time_floor(event.header.monotonic_ticks, header_).count());
  json.raw(",\"thread_id\":");
  json.unsigned_number(event.header.thread_id);
  json.raw(",\"api\":{\"id\":");
  json.unsigned_number(event.header.api_id);
  json.raw(",\"name\":");
  write_optional_string(json, presentation.api_name);
  json.raw(",\"module\":");
  write_optional_string(json, presentation.api_module);
  json.raw("},\"operation\":");
  json.string(operation_name(noleax::trace::event_operation(event.payload)));
  json.raw(",\"status\":");
  json.string(status_name(event.header.status));
  json.raw(",\"stack\":");
  write_stack(event, presentation);
  json.raw(",\"event_flags\":");
  write_hex(json, event.header.flags);
  json.raw(",\"system_error\":");
  if (event.header.system_error.domain == noleax::trace::SystemErrorDomain::kNone) {
    json.null();
  } else {
    json.raw("{\"domain\":");
    json.string(error_domain_name(event.header.system_error.domain));
    json.raw(",\"code\":");
    write_hex(json, event.header.system_error.code);
    json.raw("}");
  }
  json.raw(",\"payload\":");
  write_event_payload(event);
  json.raw("}");
}

void JsonWriter::write_event_payload(const noleax::trace::Event& event) {
  JsonEmitter json{output_};
  std::visit(
      [this, &json](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, noleax::trace::HeapCreateEvent>) {
          json.raw("{\"kind\":\"heap_create\",\"heap_handle\":");
          write_address(json, payload.heap_handle, header_);
          json.raw(",\"heap_id\":");
          write_identifier(json, payload.heap_id);
          json.raw(",\"heap_flags\":");
          write_hex(json, payload.heap_flags);
          json.raw(",\"reserve_size\":");
          json.unsigned_number(payload.reserve_size);
          json.raw(",\"commit_size\":");
          json.unsigned_number(payload.commit_size);
        } else if constexpr (std::is_same_v<Payload, noleax::trace::HeapDestroyEvent>) {
          json.raw("{\"kind\":\"heap_destroy\",\"heap_handle\":");
          write_address(json, payload.heap_handle, header_);
          json.raw(",\"heap_id\":");
          write_identifier(json, payload.heap_id);
          json.raw(",\"raw_result\":");
          write_hex(json, payload.raw_result);
        } else if constexpr (std::is_same_v<Payload, noleax::trace::AllocationEvent>) {
          json.raw("{\"kind\":\"allocation\",\"heap_handle\":");
          write_address(json, payload.heap_handle, header_);
          json.raw(",\"heap_id\":");
          write_identifier(json, payload.heap_id);
          json.raw(",\"requested_size\":");
          json.unsigned_number(payload.requested_size);
          json.raw(",\"result_address\":");
          write_address(json, payload.result_address, header_);
          json.raw(",\"allocation_id\":");
          write_identifier(json, payload.allocation_id);
          json.raw(",\"api_flags\":");
          write_hex(json, payload.api_flags);
        } else if constexpr (std::is_same_v<Payload, noleax::trace::ReallocationEvent>) {
          json.raw("{\"kind\":\"reallocation\",\"heap_handle\":");
          write_address(json, payload.heap_handle, header_);
          json.raw(",\"heap_id\":");
          write_identifier(json, payload.heap_id);
          json.raw(",\"old_address\":");
          write_address(json, payload.old_address, header_);
          json.raw(",\"old_allocation_id\":");
          write_identifier(json, payload.old_allocation_id);
          json.raw(",\"requested_size\":");
          json.unsigned_number(payload.requested_size);
          json.raw(",\"result_address\":");
          write_address(json, payload.result_address, header_);
          json.raw(",\"new_allocation_id\":");
          write_identifier(json, payload.new_allocation_id);
          json.raw(",\"api_flags\":");
          write_hex(json, payload.api_flags);
          json.raw(",\"effect\":");
          json.string(reallocation_effect_name(payload.effect));
        } else if constexpr (std::is_same_v<Payload, noleax::trace::FreeEvent>) {
          json.raw("{\"kind\":\"free\",\"heap_handle\":");
          write_address(json, payload.heap_handle, header_);
          json.raw(",\"heap_id\":");
          write_identifier(json, payload.heap_id);
          json.raw(",\"address\":");
          write_address(json, payload.address, header_);
          json.raw(",\"allocation_id\":");
          write_identifier(json, payload.allocation_id);
          json.raw(",\"raw_result\":");
          write_hex(json, payload.raw_result);
          json.raw(",\"api_flags\":");
          write_hex(json, payload.api_flags);
        } else if constexpr (std::is_same_v<Payload, noleax::trace::VmAllocateEvent>) {
          json.raw("{\"kind\":\"vm_allocation\",\"target\":");
          write_process_target(json, payload.target, header_);
          json.raw(",\"requested_base\":");
          write_address(json, payload.requested_base, header_);
          json.raw(",\"result_base\":");
          write_address(json, payload.result_base, header_);
          json.raw(",\"requested_size\":");
          json.unsigned_number(payload.requested_size);
          json.raw(",\"result_size\":");
          json.unsigned_number(payload.result_size);
          json.raw(",\"allocation_type\":");
          write_hex(json, payload.allocation_type);
          json.raw(",\"protection\":");
          write_hex(json, payload.protection);
          json.raw(",\"mapping_id\":");
          write_identifier(json, payload.mapping_id);
        } else if constexpr (std::is_same_v<Payload, noleax::trace::VmFreeEvent>) {
          json.raw("{\"kind\":\"vm_free\",\"target\":");
          write_process_target(json, payload.target, header_);
          json.raw(",\"base\":");
          write_address(json, payload.base, header_);
          json.raw(",\"region_size\":");
          json.unsigned_number(payload.region_size);
          json.raw(",\"free_type\":");
          write_hex(json, payload.free_type);
          json.raw(",\"mapping_id\":");
          write_identifier(json, payload.mapping_id);
        } else if constexpr (std::is_same_v<Payload, noleax::trace::MapEvent>) {
          json.raw("{\"kind\":\"map\",\"section_handle\":");
          write_address(json, payload.section_handle, header_);
          json.raw(",\"target\":");
          write_process_target(json, payload.target, header_);
          json.raw(",\"result_base\":");
          write_address(json, payload.result_base, header_);
          json.raw(",\"view_size\":");
          json.unsigned_number(payload.view_size);
          json.raw(",\"section_offset\":");
          json.unsigned_number(payload.section_offset);
          json.raw(",\"protection\":");
          write_hex(json, payload.protection);
          json.raw(",\"mapping_id\":");
          write_identifier(json, payload.mapping_id);
        } else if constexpr (std::is_same_v<Payload, noleax::trace::UnmapEvent>) {
          json.raw("{\"kind\":\"unmap\",\"target\":");
          write_process_target(json, payload.target, header_);
          json.raw(",\"base\":");
          write_address(json, payload.base, header_);
          json.raw(",\"mapping_id\":");
          write_identifier(json, payload.mapping_id);
        }
        json.raw("}");
      },
      event.payload);
}

void JsonWriter::write_stack(const noleax::trace::Event& event,
                             const EventPresentation& presentation) {
  if (!event.header.stack_id.is_valid() &&
      (presentation.stack_status.has_value() || !presentation.stack_frames.empty())) {
    throw JsonFormatError{"presentation supplies stack data for an event without a stack ID"};
  }
  JsonEmitter json{output_};
  json.raw("{\"id\":");
  write_identifier(json, event.header.stack_id);
  json.raw(",\"status\":");
  if (!event.header.stack_id.is_valid()) {
    json.string("unavailable");
  } else if (presentation.stack_status.has_value()) {
    json.string(stack_status_name(*presentation.stack_status));
  } else {
    json.null();
  }
  json.raw(",\"definition_available\":");
  json.boolean(event.header.stack_id.is_valid() &&
               (presentation.stack_status.has_value() || !presentation.stack_frames.empty()));
  json.raw(",\"frames\":[");
  bool first = true;
  for (const auto& frame : presentation.stack_frames) {
    if (frame.module_offset.has_value() && !frame.module_name.has_value()) {
      throw JsonFormatError{"stack frame module offset requires a module name"};
    }
    if (frame.symbol_offset.has_value() && !frame.symbol_name.has_value()) {
      throw JsonFormatError{"stack frame symbol offset requires a symbol name"};
    }
    if (!first) {
      json.raw(",");
    }
    first = false;
    json.raw("{\"absolute_address\":");
    write_address(json, frame.absolute_address, header_);
    json.raw(",\"module\":");
    write_optional_string(json, frame.module_name);
    json.raw(",\"module_offset\":");
    if (frame.module_offset.has_value()) {
      write_hex(json, *frame.module_offset);
    } else {
      json.null();
    }
    json.raw(",\"symbol\":");
    write_optional_string(json, frame.symbol_name);
    json.raw(",\"symbol_offset\":");
    if (frame.symbol_offset.has_value()) {
      write_hex(json, *frame.symbol_offset);
    } else {
      json.null();
    }
    json.raw("}");
  }
  json.raw("]}");
}

void JsonWriter::write_summary(const EventStreamResult& trace) {
  JsonEmitter json{output_};
  json.raw("\"trace_events\":");
  json.unsigned_number(trace.event_count);
  json.raw(",\"loss_records\":");
  json.unsigned_number(trace.loss_record_count);
  json.raw(",\"bytes_read\":");
  json.unsigned_number(trace.bytes_read);
  json.raw(",\"known_sequence_end\":");
  write_identifier(json, trace.known_sequence_end);
  json.raw(",\"known_monotonic_end\":");
  json.unsigned_number(trace.known_monotonic_end);
  json.raw(",\"truncated\":");
  json.boolean(trace.truncated);
  json.raw(",\"partially_understood\":");
  json.boolean(trace.partially_understood);
  json.raw(",\"capture_statistics\":");
  write_capture_statistics(json, trace.statistics);
  json.raw(",\"termination\":");
  write_termination(json, trace.end_of_trace);
  json.raw(",\"completeness\":");
  write_completeness(trace.completeness);
}

void JsonWriter::write_completeness(const noleax::trace::CompletenessReport& completeness) {
  JsonEmitter json{output_};
  json.raw("{\"mask\":");
  write_hex(json, completeness.mask());
  json.raw(",\"overall\":");
  json.string(completeness_state_name(completeness.overall_state()));
  json.raw(",\"lifecycle\":");
  json.string(completeness_state_name(completeness.lifecycle_state()));
  json.raw(",\"stack_detail\":");
  json.string(completeness_state_name(completeness.stack_detail_state()));
  json.raw(",\"understanding\":");
  json.string(understanding_state_name(completeness.understanding_state()));
  json.raw(",\"issues\":[");
  bool first = true;
  for (const auto& description : kIssueDescriptions) {
    if (!completeness.has(description.issue)) {
      continue;
    }
    if (!first) {
      json.raw(",");
    }
    first = false;
    json.string(description.name);
  }
  json.raw("],\"unknown_issue_bits\":");
  write_hex(json, completeness.mask() & ~known_issue_mask());
  json.raw("}");
}

void JsonWriter::write_record_separator() {
  if (!first_record_) {
    JsonEmitter{output_}.raw(",");
  }
  first_record_ = false;
}

void JsonWriter::require_state(State expected, const char* operation) const {
  if (state_ != expected) {
    throw JsonFormatError{std::string{"cannot "} + operation + " in the current writer state"};
  }
}

void JsonWriter::ensure_output() const {
  if (!output_) {
    throw JsonFormatError{"cannot write JSON output"};
  }
}

FilteredEventsResult analyze_events_to_json(std::istream& input, std::ostream& output,
                                            const AnalysisFilter& filter,
                                            const EventMetadataResolver& filter_resolver,
                                            const EventPresentationResolver& presentation_resolver,
                                            EventStreamOptions stream_options) {
  JsonWriter writer{output};
  std::optional<noleax::trace::FileHeader> file_header;
  EventStreamCallbacks callbacks;
  callbacks.on_file_header = [&file_header](const noleax::trace::FileHeader& header) {
    file_header = header;
  };
  callbacks.on_capture_scope = [&file_header, &writer,
                                &filter](const noleax::trace::CaptureScope& scope) {
    if (!file_header.has_value()) {
      throw JsonFormatError{"capture scope appeared before the trace header"};
    }
    writer.begin_events(*file_header, scope, filter);
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

OutstandingResult analyze_outstanding_to_json(
    std::istream& input, std::ostream& output, OutstandingWindow window,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver,
    const EventPresentationResolver& presentation_resolver, EventStreamOptions stream_options) {
  auto result =
      analyze_filtered_outstanding(input, window, filter, filter_resolver, stream_options);
  JsonWriter writer{output};
  writer.write_outstanding(result, filter, presentation_resolver);
  return result;
}

EventsStacksResult analyze_event_stacks_to_json(
    std::istream& input, std::ostream& output, StacksWindow window, StacksSort sort,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver,
    const EventPresentationResolver& presentation_resolver, EventStreamOptions stream_options) {
  auto result = analyze_event_stacks(input, window, sort, filter, filter_resolver, stream_options);
  JsonWriter writer{output};
  writer.write_event_stacks(result, filter, presentation_resolver);
  return result;
}

LeaksStacksResult analyze_leak_stacks_to_json(
    std::istream& input, std::ostream& output, OutstandingWindow window, StacksSort sort,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver,
    const EventPresentationResolver& presentation_resolver, EventStreamOptions stream_options) {
  auto result = analyze_leak_stacks(input, window, sort, filter, filter_resolver, stream_options);
  JsonWriter writer{output};
  writer.write_leak_stacks(result, filter, presentation_resolver);
  return result;
}

}  // namespace noleax::analyzer
