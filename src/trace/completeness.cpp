#include "noleax/trace/completeness.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_set>

namespace noleax::trace {
namespace {

inline constexpr std::uint32_t kKnownIssueMask =
    static_cast<std::uint32_t>(CompletenessIssue::kCaptureDidNotStartAtProcessStart) |
    static_cast<std::uint32_t>(CompletenessIssue::kPreexistingAllocationsUnknown) |
    static_cast<std::uint32_t>(CompletenessIssue::kEventLoss) |
    static_cast<std::uint32_t>(CompletenessIssue::kTraceTruncated) |
    static_cast<std::uint32_t>(CompletenessIssue::kWriterError) |
    static_cast<std::uint32_t>(CompletenessIssue::kUnknownRecordSkipped) |
    static_cast<std::uint32_t>(CompletenessIssue::kMissingEndOfTrace) |
    static_cast<std::uint32_t>(CompletenessIssue::kAbnormalStop) |
    static_cast<std::uint32_t>(CompletenessIssue::kStackDataLoss) |
    static_cast<std::uint32_t>(CompletenessIssue::kPartiallyUnderstoodFormat) |
    static_cast<std::uint32_t>(CompletenessIssue::kCustomHookInstallFailed);

inline constexpr std::uint32_t kLifecycleIssueMask =
    kKnownIssueMask & ~static_cast<std::uint32_t>(CompletenessIssue::kStackDataLoss);

inline constexpr std::uint32_t kStackDetailIssueMask =
    static_cast<std::uint32_t>(CompletenessIssue::kEventLoss) |
    static_cast<std::uint32_t>(CompletenessIssue::kTraceTruncated) |
    static_cast<std::uint32_t>(CompletenessIssue::kWriterError) |
    static_cast<std::uint32_t>(CompletenessIssue::kUnknownRecordSkipped) |
    static_cast<std::uint32_t>(CompletenessIssue::kMissingEndOfTrace) |
    static_cast<std::uint32_t>(CompletenessIssue::kAbnormalStop) |
    static_cast<std::uint32_t>(CompletenessIssue::kStackDataLoss) |
    static_cast<std::uint32_t>(CompletenessIssue::kPartiallyUnderstoodFormat) |
    static_cast<std::uint32_t>(CompletenessIssue::kCustomHookInstallFailed);

inline constexpr std::uint32_t kUnderstandingIssueMask =
    static_cast<std::uint32_t>(CompletenessIssue::kUnknownRecordSkipped) |
    static_cast<std::uint32_t>(CompletenessIssue::kPartiallyUnderstoodFormat);

[[nodiscard]] std::uint32_t issue_bit(CompletenessIssue issue) {
  const auto bit = static_cast<std::uint32_t>(issue);
  if (bit == 0U || (bit & (bit - 1U)) != 0U || (bit & kKnownIssueMask) == 0U) {
    throw CompletenessValidationError{"completeness issue is not a known single-bit value"};
  }
  return bit;
}

[[nodiscard]] bool is_known_loss_reason(LossReason reason) noexcept {
  switch (reason) {
    case LossReason::kQueueFull:
    case LossReason::kTraceFull:
    case LossReason::kWriterError:
    case LossReason::kStackCaptureFailed:
    case LossReason::kRotationLimit:
    case LossReason::kDecoderError:
      return true;
    case LossReason::kUnknown:
      return false;
  }
  return false;
}

[[nodiscard]] bool is_known_loss_location(LossLocation location) noexcept {
  switch (location) {
    case LossLocation::kAgentQueue:
    case LossLocation::kWriter:
    case LossLocation::kRotation:
    case LossLocation::kDecoder:
      return true;
    case LossLocation::kUnknown:
      return false;
  }
  return false;
}

void validate_call_counts(std::uint64_t observed, std::uint64_t succeeded, std::uint64_t failed,
                          std::uint64_t filtered, std::uint64_t dropped, std::string_view subject) {
  if (succeeded > observed || failed > observed || succeeded != observed - failed) {
    throw CompletenessValidationError{std::string{subject} +
                                      " successful and failed counts must sum to observed calls"};
  }
  if (filtered > observed || dropped > observed - filtered) {
    throw CompletenessValidationError{std::string{subject} +
                                      " filtered and dropped counts exceed observed calls"};
  }
}

void checked_add(std::uint64_t& total, std::uint64_t value) {
  if (total > std::numeric_limits<std::uint64_t>::max() - value) {
    throw CompletenessValidationError{"per-API statistics overflow their aggregate"};
  }
  total += value;
}

}  // namespace

CompletenessReport::CompletenessReport(std::uint32_t mask) noexcept : mask_{mask} {}

CompletenessReport CompletenessReport::from_mask(std::uint32_t mask) noexcept {
  return CompletenessReport{mask};
}

void CompletenessReport::add(CompletenessIssue issue) { mask_ |= issue_bit(issue); }

void CompletenessReport::remove(CompletenessIssue issue) { mask_ &= ~issue_bit(issue); }

void CompletenessReport::merge(const CompletenessReport& other) noexcept { mask_ |= other.mask_; }

bool CompletenessReport::has(CompletenessIssue issue) const {
  return (mask_ & issue_bit(issue)) != 0U;
}

std::uint32_t CompletenessReport::mask() const noexcept { return mask_; }

CompletenessState CompletenessReport::overall_state() const noexcept {
  return mask_ == 0U ? CompletenessState::kComplete : CompletenessState::kIncomplete;
}

CompletenessState CompletenessReport::lifecycle_state() const noexcept {
  const std::uint32_t unknown_issues = mask_ & ~kKnownIssueMask;
  return (mask_ & kLifecycleIssueMask) == 0U && unknown_issues == 0U
             ? CompletenessState::kComplete
             : CompletenessState::kIncomplete;
}

CompletenessState CompletenessReport::stack_detail_state() const noexcept {
  const std::uint32_t unknown_issues = mask_ & ~kKnownIssueMask;
  return (mask_ & kStackDetailIssueMask) == 0U && unknown_issues == 0U
             ? CompletenessState::kComplete
             : CompletenessState::kIncomplete;
}

UnderstandingState CompletenessReport::understanding_state() const noexcept {
  const std::uint32_t unknown_issues = mask_ & ~kKnownIssueMask;
  return (mask_ & kUnderstandingIssueMask) == 0U && unknown_issues == 0U
             ? UnderstandingState::kFull
             : UnderstandingState::kPartial;
}

int CompletenessReport::recommended_exit_code() const noexcept {
  return overall_state() == CompletenessState::kComplete ? 0 : 2;
}

void validate_loss_record(const LossRecord& loss) {
  if (!is_known_loss_reason(loss.reason)) {
    throw CompletenessValidationError{"loss reason must be specified"};
  }
  if (!is_known_loss_location(loss.location)) {
    throw CompletenessValidationError{"loss location must be specified"};
  }
  if (loss.estimated_event_count.has_value() && *loss.estimated_event_count == 0U) {
    throw CompletenessValidationError{"known loss event count must not be zero"};
  }
  if (loss.sequence_range.has_value()) {
    const auto& range = *loss.sequence_range;
    if (!range.begin || !range.end || range.begin > range.end) {
      throw CompletenessValidationError{"loss sequence range is invalid"};
    }
  }
  if (loss.tick_range.has_value() && loss.tick_range->begin > loss.tick_range->end) {
    throw CompletenessValidationError{"loss tick range is reversed"};
  }
}

void validate_statistics(const CaptureStatistics& statistics) {
  validate_call_counts(statistics.observed_calls, statistics.successful_operations,
                       statistics.failed_operations, statistics.filtered_before_queue,
                       statistics.dropped_events, "aggregate");

  std::uint64_t observed = 0U;
  std::uint64_t succeeded = 0U;
  std::uint64_t failed = 0U;
  std::uint64_t filtered = 0U;
  std::uint64_t dropped = 0U;
  std::unordered_set<std::uint32_t> seen_api_ids;
  for (std::size_t index = 0; index < statistics.per_api.size(); ++index) {
    const auto& api = statistics.per_api[index];
    if (api.api_id == 0U) {
      throw CompletenessValidationError{"per-API statistics require a nonzero api_id"};
    }
    if (!seen_api_ids.insert(api.api_id).second) {
      throw CompletenessValidationError{"per-API statistics contain a duplicate api_id"};
    }
    validate_call_counts(api.observed_calls, api.successful_operations, api.failed_operations,
                         api.filtered_before_queue, api.dropped_events, "per-API");
    checked_add(observed, api.observed_calls);
    checked_add(succeeded, api.successful_operations);
    checked_add(failed, api.failed_operations);
    checked_add(filtered, api.filtered_before_queue);
    checked_add(dropped, api.dropped_events);
  }

  if (observed != statistics.observed_calls || succeeded != statistics.successful_operations ||
      failed != statistics.failed_operations || filtered != statistics.filtered_before_queue ||
      dropped != statistics.dropped_events) {
    throw CompletenessValidationError{"per-API statistics do not match their aggregate"};
  }

  const std::uint64_t recorded_events =
      statistics.observed_calls - statistics.filtered_before_queue - statistics.dropped_events;
  if (statistics.unique_stacks > recorded_events ||
      statistics.reused_stacks > recorded_events - statistics.unique_stacks) {
    throw CompletenessValidationError{"stack statistics exceed recorded event count"};
  }
}

void validate_capture_scope(const CaptureScope& scope) {
  if (scope.started_at_process_start && scope.preexisting_allocations_unknown) {
    throw CompletenessValidationError{
        "process-start capture cannot have unknown preexisting allocations"};
  }
}

void validate_end_of_trace(const EndOfTrace& end) {
  if (end.aggregate_completeness.has(CompletenessIssue::kMissingEndOfTrace)) {
    throw CompletenessValidationError{"EndOfTrace cannot report itself as missing"};
  }
  if (end.normal_stop && end.aggregate_completeness.has(CompletenessIssue::kAbnormalStop)) {
    throw CompletenessValidationError{"normal EndOfTrace cannot report an abnormal stop"};
  }
}

CompletenessTracker::CompletenessTracker(const CaptureScope& scope) {
  validate_capture_scope(scope);
  report_.add(CompletenessIssue::kMissingEndOfTrace);
  if (!scope.started_at_process_start) {
    report_.add(CompletenessIssue::kCaptureDidNotStartAtProcessStart);
  }
  if (scope.preexisting_allocations_unknown) {
    report_.add(CompletenessIssue::kPreexistingAllocationsUnknown);
  }
}

void CompletenessTracker::observe_loss(const LossRecord& loss) {
  if (saw_end_of_trace_) {
    throw CompletenessValidationError{"Loss record appears after EndOfTrace"};
  }
  validate_loss_record(loss);
  if (loss.reason == LossReason::kStackCaptureFailed) {
    report_.add(CompletenessIssue::kStackDataLoss);
    return;
  }
  report_.add(CompletenessIssue::kEventLoss);
  if (loss.reason == LossReason::kWriterError) {
    report_.add(CompletenessIssue::kWriterError);
  }
}

void CompletenessTracker::observe_end_of_trace(const EndOfTrace& end) {
  if (saw_end_of_trace_) {
    throw CompletenessValidationError{"trace contains more than one EndOfTrace record"};
  }
  validate_end_of_trace(end);
  saw_end_of_trace_ = true;
  report_.remove(CompletenessIssue::kMissingEndOfTrace);
  report_.merge(end.aggregate_completeness);
  if (!end.normal_stop) {
    report_.add(CompletenessIssue::kAbnormalStop);
  }
}

void CompletenessTracker::mark_trace_truncated() {
  report_.add(CompletenessIssue::kTraceTruncated);
}

void CompletenessTracker::mark_writer_error() {
  report_.add(CompletenessIssue::kWriterError);
  report_.add(CompletenessIssue::kEventLoss);
}

void CompletenessTracker::mark_unknown_record_skipped() {
  report_.add(CompletenessIssue::kUnknownRecordSkipped);
}

void CompletenessTracker::mark_partially_understood_format() {
  report_.add(CompletenessIssue::kPartiallyUnderstoodFormat);
}

void CompletenessTracker::mark_custom_hook_install_failed() {
  report_.add(CompletenessIssue::kCustomHookInstallFailed);
}

bool CompletenessTracker::saw_end_of_trace() const noexcept { return saw_end_of_trace_; }

const CompletenessReport& CompletenessTracker::report() const noexcept { return report_; }

}  // namespace noleax::trace
