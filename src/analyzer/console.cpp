#include "noleax/analyzer/console.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/analyzer/time.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {
namespace {

constexpr std::string_view kBold = "\x1b[1m";
constexpr std::string_view kGreen = "\x1b[32m";
constexpr std::string_view kRed = "\x1b[31m";
constexpr std::string_view kYellow = "\x1b[33m";
constexpr std::string_view kReset = "\x1b[0m";

template <typename Identifier>
[[nodiscard]] std::string identifier_text(Identifier identifier) {
  return identifier.is_valid() ? std::to_string(identifier.value()) : "none";
}

[[nodiscard]] std::string hex_value(std::uint64_t value, std::size_t digits = 0U) {
  std::ostringstream output;
  output << "0x" << std::hex << std::nouppercase << std::setfill('0');
  if (digits != 0U) {
    output << std::setw(static_cast<int>(digits));
  }
  output << value;
  return output.str();
}

[[nodiscard]] std::size_t pointer_digits(const noleax::trace::FileHeader& header) {
  return static_cast<std::size_t>(header.pointer_width) * 2U;
}

[[nodiscard]] std::string address_text(noleax::trace::Address address,
                                       const noleax::trace::FileHeader& header) {
  return hex_value(address, pointer_digits(header));
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
      return "heap-create";
    case noleax::trace::EventOperation::kHeapDestroy:
      return "heap-destroy";
    case noleax::trace::EventOperation::kAllocate:
      return "alloc";
    case noleax::trace::EventOperation::kReallocate:
      return "realloc";
    case noleax::trace::EventOperation::kFree:
      return "free";
    case noleax::trace::EventOperation::kVmAllocate:
      return "vm-alloc";
    case noleax::trace::EventOperation::kVmFree:
      return "vm-free";
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
      return "current";
    case noleax::trace::ProcessMemoryScope::kRemoteProcess:
      return "remote";
    case noleax::trace::ProcessMemoryScope::kUnknown:
      return "unknown";
  }
  return "unknown";
}

[[nodiscard]] const char* reallocation_effect_name(
    noleax::trace::ReallocationEffect effect) noexcept {
  switch (effect) {
    case noleax::trace::ReallocationEffect::kNoChange:
      return "no-change";
    case noleax::trace::ReallocationEffect::kNewGeneration:
      return "new-generation";
    case noleax::trace::ReallocationEffect::kFreed:
      return "freed";
  }
  return "unknown";
}

[[nodiscard]] const char* generation_kind_name(GenerationKind kind) noexcept {
  switch (kind) {
    case GenerationKind::kHeapAllocation:
      return "heap-allocation";
    case GenerationKind::kVirtualAllocation:
      return "virtual-allocation";
    case GenerationKind::kMappedView:
      return "mapped-view";
  }
  return "unknown";
}

[[nodiscard]] const char* loss_reason_name(noleax::trace::LossReason reason) noexcept {
  switch (reason) {
    case noleax::trace::LossReason::kUnknown:
      return "unknown";
    case noleax::trace::LossReason::kQueueFull:
      return "queue-full";
    case noleax::trace::LossReason::kTraceFull:
      return "trace-full";
    case noleax::trace::LossReason::kWriterError:
      return "writer-error";
    case noleax::trace::LossReason::kStackCaptureFailed:
      return "stack-capture-failed";
    case noleax::trace::LossReason::kRotationLimit:
      return "rotation-limit";
    case noleax::trace::LossReason::kDecoderError:
      return "decoder-error";
  }
  return "unknown";
}

[[nodiscard]] const char* loss_location_name(noleax::trace::LossLocation location) noexcept {
  switch (location) {
    case noleax::trace::LossLocation::kUnknown:
      return "unknown";
    case noleax::trace::LossLocation::kAgentQueue:
      return "agent-queue";
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

[[nodiscard]] const char* stack_status_name(StackCaptureStatus status) noexcept {
  switch (status) {
    case StackCaptureStatus::kComplete:
      return "complete";
    case StackCaptureStatus::kTruncatedByDepth:
      return "truncated-by-depth";
    case StackCaptureStatus::kUnwindFailed:
      return "unwind-failed";
    case StackCaptureStatus::kUnavailable:
      return "unavailable";
  }
  return "unknown";
}

[[nodiscard]] std::string api_name(const noleax::trace::Event& event,
                                   const ConsoleEventMetadata& metadata) {
  std::string result;
  if (metadata.api_module.has_value()) {
    result.append(*metadata.api_module);
    result.push_back('!');
  }
  if (metadata.api_name.has_value()) {
    result.append(*metadata.api_name);
  } else {
    result.append("api#");
    result.append(std::to_string(event.header.api_id));
  }
  return result;
}

[[nodiscard]] std::string relative_time(std::uint64_t ticks,
                                        const noleax::trace::FileHeader& header) {
  return "+" + std::to_string(trace_time_floor(ticks, header).count()) + "ns";
}

// Window endpoint text: time as "123ns", sequence as "#123", both joined with '+', and an empty
// (unbounded) endpoint as "0ns".
[[nodiscard]] std::string window_bound_text(const WindowBound& bound) {
  std::string result;
  if (bound.time.has_value()) {
    result.append(std::to_string(bound.time->count()));
    result.append("ns");
  }
  if (bound.sequence.has_value()) {
    if (!result.empty()) {
      result.push_back('+');
    }
    result.push_back('#');
    result.append(std::to_string(*bound.sequence));
  }
  if (result.empty()) {
    result.append("0ns");
  }
  return result;
}

[[nodiscard]] std::string process_target_text(const noleax::trace::ProcessTarget& target,
                                              const noleax::trace::FileHeader& header) {
  std::string result{"scope="};
  result.append(process_scope_name(target.scope));
  result.append(" process-handle=");
  result.append(address_text(target.process_handle, header));
  result.append(" pid=");
  result.append(std::to_string(target.process_id));
  return result;
}

[[nodiscard]] std::string_view event_color(noleax::trace::EventStatus status) noexcept {
  switch (status) {
    case noleax::trace::EventStatus::kSuccess:
      return kGreen;
    case noleax::trace::EventStatus::kFailure:
      return kRed;
    case noleax::trace::EventStatus::kUnmatched:
    case noleax::trace::EventStatus::kPreexisting:
      return kYellow;
  }
  return {};
}

void checked_increment(std::uint64_t& value, const char* subject) {
  if (value == std::numeric_limits<std::uint64_t>::max()) {
    throw ConsoleFormatError{std::string{subject} + " count overflow"};
  }
  ++value;
}

struct IssueDescription {
  noleax::trace::CompletenessIssue issue;
  std::string_view name;
};

constexpr std::array kIssueDescriptions{
    IssueDescription{noleax::trace::CompletenessIssue::kCaptureDidNotStartAtProcessStart,
                     "capture-did-not-start-at-process-start"},
    IssueDescription{noleax::trace::CompletenessIssue::kPreexistingAllocationsUnknown,
                     "preexisting-allocations-unknown"},
    IssueDescription{noleax::trace::CompletenessIssue::kEventLoss, "event-loss"},
    IssueDescription{noleax::trace::CompletenessIssue::kTraceTruncated, "trace-truncated"},
    IssueDescription{noleax::trace::CompletenessIssue::kWriterError, "writer-error"},
    IssueDescription{noleax::trace::CompletenessIssue::kUnknownRecordSkipped,
                     "unknown-record-skipped"},
    IssueDescription{noleax::trace::CompletenessIssue::kMissingEndOfTrace, "missing-end-of-trace"},
    IssueDescription{noleax::trace::CompletenessIssue::kAbnormalStop, "abnormal-stop"},
    IssueDescription{noleax::trace::CompletenessIssue::kStackDataLoss, "stack-data-loss"},
    IssueDescription{noleax::trace::CompletenessIssue::kPartiallyUnderstoodFormat,
                     "partially-understood-format"},
};

[[nodiscard]] constexpr std::uint32_t known_issue_mask() noexcept {
  std::uint32_t result = 0U;
  for (const auto& description : kIssueDescriptions) {
    result |= static_cast<std::uint32_t>(description.issue);
  }
  return result;
}

}  // namespace

ConsoleWriter::ConsoleWriter(std::ostream& output, ConsoleOptions options)
    : output_{output}, options_{options} {}

void ConsoleWriter::begin_events(const noleax::trace::FileHeader& header,
                                 const noleax::trace::CaptureScope& scope) {
  require_state(State::kReady, "begin events");
  header_ = header;
  capture_scope_ = scope;
  write_preamble("noleax events", header, scope);
  output_ << "events:\n";
  state_ = State::kEvents;
  ensure_output();
}

void ConsoleWriter::write_event(const noleax::trace::Event& event,
                                const ConsoleEventMetadata& metadata) {
  require_state(State::kEvents, "write event");
  noleax::trace::validate_event(event);
  write_event_header(event, metadata);
  write_event_payload(event);
  write_stack(event, metadata);
  checked_increment(written_event_count_, "written event");
  ensure_output();
}

void ConsoleWriter::write_loss(const noleax::trace::LossRecord& loss) {
  require_state(State::kEvents, "write loss");
  noleax::trace::validate_loss_record(loss);
  if (options_.use_color) {
    output_ << kYellow;
  }
  output_ << "loss: reason=" << loss_reason_name(loss.reason)
          << " location=" << loss_location_name(loss.location);
  if (loss.estimated_event_count.has_value()) {
    output_ << " estimated-events=" << *loss.estimated_event_count;
  }
  if (loss.sequence_range.has_value()) {
    output_ << " sequence=" << loss.sequence_range->begin.value() << ".."
            << loss.sequence_range->end.value();
  }
  if (loss.tick_range.has_value()) {
    output_ << " ticks=" << loss.tick_range->begin << ".." << loss.tick_range->end;
  }
  if (options_.use_color) {
    output_ << kReset;
  }
  output_ << '\n';
  checked_increment(written_loss_count_, "written loss");
  ensure_output();
}

void ConsoleWriter::finish_events(const FilteredEventsResult& result) {
  require_state(State::kEvents, "finish events");
  if (!header_.has_value() || !capture_scope_.has_value() || *header_ != result.trace.file_header ||
      *capture_scope_ != result.trace.capture_scope) {
    throw ConsoleFormatError{"events summary belongs to a different trace"};
  }
  if (written_event_count_ != result.matched_event_count) {
    throw ConsoleFormatError{"written event count does not match the filtered result"};
  }
  if (written_loss_count_ != result.trace.loss_record_count) {
    throw ConsoleFormatError{"written loss count does not match the trace result"};
  }
  if (result.filtered_event_count > result.trace.event_count ||
      result.matched_event_count != result.trace.event_count - result.filtered_event_count) {
    throw ConsoleFormatError{"matched and filtered counts do not cover all trace events"};
  }

  output_ << "\nsummary:\n"
          << "  matched-events: " << result.matched_event_count << '\n'
          << "  filtered-events: " << result.filtered_event_count << '\n';
  write_common_summary(result.trace);
  state_ = State::kFinished;
  ensure_output();
}

void ConsoleWriter::write_outstanding(const OutstandingResult& result,
                                      const ConsoleMetadataResolver& resolver) {
  require_state(State::kReady, "write outstanding report");
  if (result.ended_by_c_count > result.candidate_count ||
      result.filtered_out_count > result.candidate_count - result.ended_by_c_count) {
    throw ConsoleFormatError{"outstanding result counts are inconsistent"};
  }
  const auto survivors =
      result.candidate_count - result.ended_by_c_count - result.filtered_out_count;
  if (static_cast<std::uint64_t>(result.outstanding.size()) != survivors) {
    throw ConsoleFormatError{"outstanding generation count is inconsistent"};
  }

  header_ = result.trace.file_header;
  capture_scope_ = result.trace.capture_scope;
  write_preamble("noleax leaks", *header_, *capture_scope_);
  output_ << "window: [" << window_bound_text(result.requested_window.a) << ", "
          << window_bound_text(result.effective_b)
          << ") observed-at=" << window_bound_text(result.effective_c) << " ("
          << (result.observation_uses_trace_end ? "trace-end" : "configured") << ")\n"
          << "trace-end: " << trace_time_floor(result.trace_end_monotonic_ticks, *header_).count()
          << "ns [ticks=" << result.trace_end_monotonic_ticks << "]\n"
          << "outstanding:\n";

  if (result.outstanding.empty()) {
    output_ << "  none\n";
  }
  for (const auto& generation : result.outstanding) {
    const auto metadata = resolver ? resolver(generation.created_by) : ConsoleEventMetadata{};
    output_ << "generation: kind=" << generation_kind_name(generation.kind)
            << " allocation-id=" << identifier_text(generation.allocation_id)
            << " mapping-id=" << identifier_text(generation.mapping_id)
            << " size=" << generation.size
            << "B address=" << address_text(generation.address, *header_) << '\n';
    if (generation.kind == GenerationKind::kHeapAllocation) {
      output_ << "  heap=" << address_text(generation.heap_handle, *header_)
              << " heap-id=" << identifier_text(generation.heap_id) << '\n';
    }
    output_ << "  created: ";
    write_event_header(generation.created_by, metadata);
    write_stack(generation.created_by, metadata);
  }

  output_ << "\nsummary:\n"
          << "  candidates: " << result.candidate_count << '\n'
          << "  ended-by-c: " << result.ended_by_c_count << '\n'
          << "  filtered-out: " << result.filtered_out_count << '\n'
          << "  outstanding: " << result.outstanding.size() << '\n';
  write_common_summary(result.trace);
  state_ = State::kFinished;
  ensure_output();
}

void ConsoleWriter::write_event_stacks(const EventsStacksResult& result,
                                       const ConsoleMetadataResolver& resolver) {
  require_state(State::kReady, "write event stacks report");
  header_ = result.trace.file_header;
  capture_scope_ = result.trace.capture_scope;
  write_preamble("noleax event stacks", *header_, *capture_scope_);
  output_ << "window: [" << window_bound_text(result.window.from) << ", ";
  if (result.window.to.has_value()) {
    output_ << window_bound_text(*result.window.to);
  } else {
    output_ << "trace-end";
  }
  output_ << ")\ngroups:\n";

  std::uint64_t rank = 0U;
  std::uint64_t total_calls = 0U;
  std::uint64_t total_alloc_bytes = 0U;
  std::uint64_t total_free_bytes = 0U;
  if (result.groups.empty()) {
    output_ << "  none\n";
  }
  for (const auto& group : result.groups) {
    ++rank;
    total_calls += group.calls;
    total_alloc_bytes += group.alloc_bytes;
    total_free_bytes += group.free_bytes;
    output_ << "#" << rank << " calls=" << group.calls << " alloc=" << group.alloc_calls << "/"
            << group.alloc_bytes << "B free=" << group.free_calls << "/" << group.free_bytes
            << "B net=" << group.net_bytes() << "B";
    const auto names = group_api_names(group.api_ids, result.trace.custom_hooks);
    if (!names.empty()) {
      output_ << " apis=";
      for (std::size_t index = 0U; index < names.size(); ++index) {
        if (index != 0U) {
          output_ << ',';
        }
        output_ << names[index];
      }
    }
    output_ << '\n';
    const auto metadata = resolver ? resolver(group.sample_event) : ConsoleEventMetadata{};
    write_stack(group.sample_event, metadata);
  }

  output_ << "\nsummary:\n"
          << "  groups: " << result.groups.size() << '\n'
          << "  calls: " << total_calls << '\n'
          << "  alloc-bytes: " << total_alloc_bytes << '\n'
          << "  free-bytes: " << total_free_bytes << '\n'
          << "  net-bytes: " << saturating_net_bytes(total_alloc_bytes, total_free_bytes) << '\n'
          << '\n'
          << "  aggregated-events: " << result.aggregated_event_count << '\n'
          << "  unmatched-frees: " << result.unmatched_free_count << '\n';
  write_common_summary(result.trace);
  state_ = State::kFinished;
  ensure_output();
}

void ConsoleWriter::write_leak_stacks(const LeaksStacksResult& result,
                                      const ConsoleMetadataResolver& resolver) {
  require_state(State::kReady, "write leak stacks report");
  const OutstandingResult& outstanding = result.outstanding;
  header_ = outstanding.trace.file_header;
  capture_scope_ = outstanding.trace.capture_scope;
  write_preamble("noleax leak stacks", *header_, *capture_scope_);
  output_ << "window: [" << window_bound_text(outstanding.requested_window.a) << ", "
          << window_bound_text(outstanding.effective_b)
          << ") observed-at=" << window_bound_text(outstanding.effective_c) << " ("
          << (outstanding.observation_uses_trace_end ? "trace-end" : "configured")
          << ")\ngroups:\n";

  std::uint64_t rank = 0U;
  std::uint64_t total_calls = 0U;
  std::uint64_t total_bytes = 0U;
  if (result.groups.empty()) {
    output_ << "  none\n";
  }
  for (const auto& group : result.groups) {
    ++rank;
    total_calls += group.calls;
    total_bytes += group.bytes;
    output_ << "#" << rank << " calls=" << group.calls << " bytes=" << group.bytes << "B";
    const auto names = group_api_names(group.api_ids, outstanding.trace.custom_hooks);
    if (!names.empty()) {
      output_ << " apis=";
      for (std::size_t index = 0U; index < names.size(); ++index) {
        if (index != 0U) {
          output_ << ',';
        }
        output_ << names[index];
      }
    }
    output_ << '\n';
    const auto metadata = resolver ? resolver(group.sample_event) : ConsoleEventMetadata{};
    write_stack(group.sample_event, metadata);
  }

  output_ << "\nsummary:\n"
          << "  groups: " << result.groups.size() << '\n'
          << "  calls: " << total_calls << '\n'
          << "  bytes: " << total_bytes << '\n';
  write_common_summary(outstanding.trace);
  state_ = State::kFinished;
  ensure_output();
}

void ConsoleWriter::write_preamble(const char* title, const noleax::trace::FileHeader& header,
                                   const noleax::trace::CaptureScope& scope) {
  if (options_.use_color) {
    output_ << kBold;
  }
  output_ << title;
  if (options_.use_color) {
    output_ << kReset;
  }
  output_ << '\n'
          << "trace: platform=" << platform_name(header.platform)
          << " architecture=" << architecture_name(header.architecture)
          << " pointer-width=" << static_cast<unsigned int>(header.pointer_width) * 8U
          << " file-index=" << header.file_index << '\n'
          << "clock: frequency=" << header.monotonic_frequency
          << "Hz origin=" << header.monotonic_origin << " utc-origin-ns=" << header.utc_origin_ns
          << '\n'
          << "capture: ";
  if (scope.started_at_process_start) {
    output_ << "process-start";
  } else {
    output_ << "mid-process";
    if (scope.preexisting_allocations_unknown) {
      output_ << " (preexisting allocations unknown)";
    }
  }
  output_ << '\n';
}

void ConsoleWriter::write_event_header(const noleax::trace::Event& event,
                                       const ConsoleEventMetadata& metadata) {
  if (!header_.has_value()) {
    throw ConsoleFormatError{"event output does not have a trace header"};
  }
  if (options_.use_color) {
    output_ << event_color(event.header.status);
  }
  output_ << "event #" << event.header.sequence.value() << ' '
          << relative_time(event.header.monotonic_ticks, *header_)
          << " [ticks=" << event.header.monotonic_ticks << "] tid=" << event.header.thread_id << ' '
          << api_name(event, metadata) << ' '
          << operation_name(noleax::trace::event_operation(event.payload)) << ' '
          << status_name(event.header.status);
  if (event.header.flags != 0U) {
    output_ << " event-flags=" << hex_value(event.header.flags);
  }
  if (event.header.system_error.domain != noleax::trace::SystemErrorDomain::kNone) {
    output_ << " error=" << error_domain_name(event.header.system_error.domain) << ':'
            << hex_value(event.header.system_error.code);
  }
  if (options_.use_color) {
    output_ << kReset;
  }
  output_ << '\n';
}

void ConsoleWriter::write_event_payload(const noleax::trace::Event& event) {
  if (!header_.has_value()) {
    throw ConsoleFormatError{"event output does not have a trace header"};
  }
  const auto& header = *header_;
  std::visit(
      [this, &header](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, noleax::trace::HeapCreateEvent>) {
          output_ << "  heap: handle=" << address_text(payload.heap_handle, header)
                  << " heap-id=" << identifier_text(payload.heap_id)
                  << " flags=" << hex_value(payload.heap_flags)
                  << " reserve=" << payload.reserve_size << "B commit=" << payload.commit_size
                  << "B\n";
        } else if constexpr (std::is_same_v<Payload, noleax::trace::HeapDestroyEvent>) {
          output_ << "  heap: handle=" << address_text(payload.heap_handle, header)
                  << " heap-id=" << identifier_text(payload.heap_id)
                  << " result=" << hex_value(payload.raw_result) << '\n';
        } else if constexpr (std::is_same_v<Payload, noleax::trace::AllocationEvent>) {
          output_ << "  allocation: heap=" << address_text(payload.heap_handle, header)
                  << " heap-id=" << identifier_text(payload.heap_id)
                  << " requested=" << payload.requested_size
                  << "B result=" << address_text(payload.result_address, header)
                  << " allocation-id=" << identifier_text(payload.allocation_id)
                  << " api-flags=" << hex_value(payload.api_flags) << '\n';
        } else if constexpr (std::is_same_v<Payload, noleax::trace::ReallocationEvent>) {
          output_ << "  reallocation: heap=" << address_text(payload.heap_handle, header)
                  << " heap-id=" << identifier_text(payload.heap_id)
                  << " old-address=" << address_text(payload.old_address, header)
                  << " old-allocation-id=" << identifier_text(payload.old_allocation_id)
                  << " requested=" << payload.requested_size
                  << "B result=" << address_text(payload.result_address, header)
                  << " new-allocation-id=" << identifier_text(payload.new_allocation_id)
                  << " effect=" << reallocation_effect_name(payload.effect)
                  << " api-flags=" << hex_value(payload.api_flags) << '\n';
        } else if constexpr (std::is_same_v<Payload, noleax::trace::FreeEvent>) {
          output_ << "  free: heap=" << address_text(payload.heap_handle, header)
                  << " heap-id=" << identifier_text(payload.heap_id)
                  << " address=" << address_text(payload.address, header)
                  << " allocation-id=" << identifier_text(payload.allocation_id)
                  << " result=" << hex_value(payload.raw_result)
                  << " api-flags=" << hex_value(payload.api_flags) << '\n';
        } else if constexpr (std::is_same_v<Payload, noleax::trace::VmAllocateEvent>) {
          output_ << "  vm-allocation: " << process_target_text(payload.target, header)
                  << " requested-base=" << address_text(payload.requested_base, header)
                  << " result-base=" << address_text(payload.result_base, header)
                  << " requested=" << payload.requested_size
                  << "B result-size=" << payload.result_size
                  << "B allocation-type=" << hex_value(payload.allocation_type)
                  << " protection=" << hex_value(payload.protection)
                  << " mapping-id=" << identifier_text(payload.mapping_id) << '\n';
        } else if constexpr (std::is_same_v<Payload, noleax::trace::VmFreeEvent>) {
          output_ << "  vm-free: " << process_target_text(payload.target, header)
                  << " base=" << address_text(payload.base, header)
                  << " region-size=" << payload.region_size
                  << "B free-type=" << hex_value(payload.free_type)
                  << " mapping-id=" << identifier_text(payload.mapping_id) << '\n';
        } else if constexpr (std::is_same_v<Payload, noleax::trace::MapEvent>) {
          output_ << "  map: section=" << address_text(payload.section_handle, header) << ' '
                  << process_target_text(payload.target, header)
                  << " result-base=" << address_text(payload.result_base, header)
                  << " view-size=" << payload.view_size
                  << "B section-offset=" << payload.section_offset
                  << " protection=" << hex_value(payload.protection)
                  << " mapping-id=" << identifier_text(payload.mapping_id) << '\n';
        } else if constexpr (std::is_same_v<Payload, noleax::trace::UnmapEvent>) {
          output_ << "  unmap: " << process_target_text(payload.target, header)
                  << " base=" << address_text(payload.base, header)
                  << " mapping-id=" << identifier_text(payload.mapping_id) << '\n';
        }
      },
      event.payload);
}

void ConsoleWriter::write_stack(const noleax::trace::Event& event,
                                const ConsoleEventMetadata& metadata) {
  if (!header_.has_value()) {
    throw ConsoleFormatError{"stack output does not have a trace header"};
  }
  if (!event.header.stack_id.is_valid()) {
    output_ << "  stack: unavailable\n";
    return;
  }
  output_ << "  stack #" << event.header.stack_id.value();
  if (metadata.stack_status.has_value()) {
    output_ << " (" << stack_status_name(*metadata.stack_status) << ')';
  }
  output_ << ':';
  if (metadata.stack_frames.empty()) {
    output_ << (metadata.stack_status.has_value() ? " no frames\n" : " definition unavailable\n");
    return;
  }
  output_ << '\n';
  for (std::size_t index = 0U; index < metadata.stack_frames.size(); ++index) {
    const auto& frame = metadata.stack_frames[index];
    output_ << "    #" << index << ' ';
    if (frame.module_name.has_value()) {
      output_ << *frame.module_name;
    }
    if (frame.symbol_name.has_value()) {
      if (frame.module_name.has_value()) {
        output_ << '!';
      }
      output_ << *frame.symbol_name;
      if (frame.symbol_offset.has_value()) {
        output_ << '+' << hex_value(*frame.symbol_offset);
      }
    } else if (frame.module_name.has_value() && frame.module_offset.has_value()) {
      output_ << '+' << hex_value(*frame.module_offset);
    }
    if (frame.module_name.has_value() || frame.symbol_name.has_value()) {
      output_ << ' ';
    }
    output_ << '[' << address_text(frame.absolute_address, *header_) << "]\n";
  }
}

void ConsoleWriter::write_common_summary(const EventStreamResult& trace) {
  output_ << "  trace-events: " << trace.event_count << '\n'
          << "  loss-records: " << trace.loss_record_count << '\n'
          << "  bytes-read: " << trace.bytes_read << '\n';
  if (trace.statistics.has_value()) {
    const auto& statistics = *trace.statistics;
    output_ << "  capture-calls: observed=" << statistics.observed_calls
            << " success=" << statistics.successful_operations
            << " failure=" << statistics.failed_operations
            << " filtered=" << statistics.filtered_before_queue
            << " dropped=" << statistics.dropped_events << '\n'
            << "  stack-dedup: unique=" << statistics.unique_stacks
            << " reused=" << statistics.reused_stacks << '\n'
            << "  trace-bytes: uncompressed=" << statistics.written_uncompressed_bytes
            << " stored=" << statistics.written_stored_bytes << '\n';
  }
  if (trace.end_of_trace.has_value()) {
    output_ << "  termination: " << (trace.end_of_trace->normal_stop ? "normal" : "abnormal");
    if (trace.end_of_trace->target_exit_code.has_value()) {
      output_ << " target-exit-code=" << *trace.end_of_trace->target_exit_code;
    }
    output_ << '\n';
  } else {
    output_ << "  termination: end-record-missing\n";
  }
  write_completeness(trace.completeness);
}

void ConsoleWriter::write_completeness(const noleax::trace::CompletenessReport& completeness) {
  const bool complete = completeness.overall_state() == noleax::trace::CompletenessState::kComplete;
  output_ << "  completeness: " << completeness_state_name(completeness.overall_state())
          << " (lifecycle=" << completeness_state_name(completeness.lifecycle_state())
          << " stack-detail=" << completeness_state_name(completeness.stack_detail_state())
          << " understanding=" << understanding_state_name(completeness.understanding_state())
          << ")\n";
  if (complete) {
    return;
  }
  if (options_.use_color) {
    output_ << kYellow;
  }
  output_ << "  warnings:\n";
  for (const auto& description : kIssueDescriptions) {
    if (completeness.has(description.issue)) {
      output_ << "    - " << description.name << '\n';
    }
  }
  const std::uint32_t unknown = completeness.mask() & ~known_issue_mask();
  if (unknown != 0U) {
    output_ << "    - unknown-issue-bits=" << hex_value(unknown) << '\n';
  }
  if (options_.use_color) {
    output_ << kReset;
  }
}

void ConsoleWriter::require_state(State expected, const char* operation) const {
  if (state_ != expected) {
    throw ConsoleFormatError{std::string{"cannot "} + operation + " in the current writer state"};
  }
}

void ConsoleWriter::ensure_output() const {
  if (!output_) {
    throw ConsoleFormatError{"cannot write console output"};
  }
}

FilteredEventsResult analyze_events_to_console(std::istream& input, std::ostream& output,
                                               const AnalysisFilter& filter,
                                               const EventMetadataResolver& filter_resolver,
                                               const ConsoleMetadataResolver& console_resolver,
                                               ConsoleOptions console_options,
                                               EventStreamOptions stream_options,
                                               FilteredEventsWindow window) {
  ConsoleWriter writer{output, console_options};
  std::optional<noleax::trace::FileHeader> file_header;
  EventStreamCallbacks callbacks;
  callbacks.on_file_header = [&file_header](const noleax::trace::FileHeader& header) {
    file_header = header;
  };
  callbacks.on_capture_scope = [&file_header, &writer](const noleax::trace::CaptureScope& scope) {
    if (!file_header.has_value()) {
      throw ConsoleFormatError{"capture scope appeared before the trace header"};
    }
    writer.begin_events(*file_header, scope);
  };
  callbacks.on_event = [&writer, &console_resolver](const noleax::trace::Event& event) {
    writer.write_event(event, console_resolver ? console_resolver(event) : ConsoleEventMetadata{});
  };
  callbacks.on_loss = [&writer](const noleax::trace::LossRecord& loss) { writer.write_loss(loss); };

  auto result =
      analyze_filtered_events(input, filter, callbacks, filter_resolver, stream_options, window);
  writer.finish_events(result);
  return result;
}

OutstandingResult analyze_outstanding_to_console(std::istream& input, std::ostream& output,
                                                 OutstandingWindow window,
                                                 const AnalysisFilter& filter,
                                                 const EventMetadataResolver& filter_resolver,
                                                 const ConsoleMetadataResolver& console_resolver,
                                                 ConsoleOptions console_options,
                                                 EventStreamOptions stream_options) {
  auto result =
      analyze_filtered_outstanding(input, window, filter, filter_resolver, stream_options);
  ConsoleWriter writer{output, console_options};
  writer.write_outstanding(result, console_resolver);
  return result;
}

EventsStacksResult analyze_event_stacks_to_console(std::istream& input, std::ostream& output,
                                                   StacksWindow window, StacksSort sort,
                                                   const AnalysisFilter& filter,
                                                   const EventMetadataResolver& filter_resolver,
                                                   const ConsoleMetadataResolver& console_resolver,
                                                   ConsoleOptions console_options,
                                                   EventStreamOptions stream_options) {
  auto result = analyze_event_stacks(input, window, sort, filter, filter_resolver, stream_options);
  ConsoleWriter writer{output, console_options};
  writer.write_event_stacks(result, console_resolver);
  return result;
}

LeaksStacksResult analyze_leak_stacks_to_console(std::istream& input, std::ostream& output,
                                                 OutstandingWindow window, StacksSort sort,
                                                 const AnalysisFilter& filter,
                                                 const EventMetadataResolver& filter_resolver,
                                                 const ConsoleMetadataResolver& console_resolver,
                                                 ConsoleOptions console_options,
                                                 EventStreamOptions stream_options) {
  auto result = analyze_leak_stacks(input, window, sort, filter, filter_resolver, stream_options);
  ConsoleWriter writer{output, console_options};
  writer.write_leak_stacks(result, console_resolver);
  return result;
}

}  // namespace noleax::analyzer
