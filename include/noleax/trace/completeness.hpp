#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

#include "noleax/trace/identifiers.hpp"

namespace noleax::trace {

enum class LossReason : std::uint8_t {
  kUnknown = 0,
  kQueueFull = 1,
  kTraceFull = 2,
  kWriterError = 3,
  kStackCaptureFailed = 4,
  kRotationLimit = 5,
  kDecoderError = 6,
};

enum class LossLocation : std::uint8_t {
  kUnknown = 0,
  kAgentQueue = 1,
  kWriter = 2,
  kRotation = 3,
  kDecoder = 4,
};

struct SequenceRange {
  Sequence begin;
  Sequence end;

  bool operator==(const SequenceRange&) const = default;
};

struct TickRange {
  std::uint64_t begin{0};
  std::uint64_t end{0};

  bool operator==(const TickRange&) const = default;
};

struct LossRecord {
  LossReason reason{LossReason::kUnknown};
  LossLocation location{LossLocation::kUnknown};
  std::optional<std::uint64_t> estimated_event_count;
  std::optional<SequenceRange> sequence_range;
  std::optional<TickRange> tick_range;

  bool operator==(const LossRecord&) const = default;
};

struct ApiStatistics {
  ApiId api_id{0};
  std::uint64_t observed_calls{0};
  std::uint64_t successful_operations{0};
  std::uint64_t failed_operations{0};
  std::uint64_t filtered_before_queue{0};
  std::uint64_t dropped_events{0};

  bool operator==(const ApiStatistics&) const = default;
};

struct CaptureStatistics {
  std::uint64_t observed_calls{0};
  std::uint64_t successful_operations{0};
  std::uint64_t failed_operations{0};
  std::uint64_t filtered_before_queue{0};
  std::uint64_t dropped_events{0};
  std::uint64_t unique_stacks{0};
  std::uint64_t reused_stacks{0};
  std::uint64_t written_uncompressed_bytes{0};
  std::uint64_t written_stored_bytes{0};
  std::vector<ApiStatistics> per_api;

  bool operator==(const CaptureStatistics&) const = default;
};

// The underlying type is the stable uint32 issue-mask representation.
enum class CompletenessIssue : std::uint32_t {  // NOLINT(performance-enum-size)
  kCaptureDidNotStartAtProcessStart = 1U << 0U,
  kPreexistingAllocationsUnknown = 1U << 1U,
  kEventLoss = 1U << 2U,
  kTraceTruncated = 1U << 3U,
  kWriterError = 1U << 4U,
  kUnknownRecordSkipped = 1U << 5U,
  kMissingEndOfTrace = 1U << 6U,
  kAbnormalStop = 1U << 7U,
  kStackDataLoss = 1U << 8U,
  kPartiallyUnderstoodFormat = 1U << 9U,
};

enum class CompletenessState : std::uint8_t {
  kComplete,
  kIncomplete,
};

enum class UnderstandingState : std::uint8_t {
  kFull,
  kPartial,
};

class CompletenessReport {
 public:
  [[nodiscard]] static CompletenessReport from_mask(std::uint32_t mask) noexcept;

  void add(CompletenessIssue issue);
  void remove(CompletenessIssue issue);
  void merge(const CompletenessReport& other) noexcept;

  [[nodiscard]] bool has(CompletenessIssue issue) const;
  [[nodiscard]] std::uint32_t mask() const noexcept;
  [[nodiscard]] CompletenessState overall_state() const noexcept;
  [[nodiscard]] CompletenessState lifecycle_state() const noexcept;
  [[nodiscard]] CompletenessState stack_detail_state() const noexcept;
  [[nodiscard]] UnderstandingState understanding_state() const noexcept;
  [[nodiscard]] int recommended_exit_code() const noexcept;

  bool operator==(const CompletenessReport&) const = default;

 private:
  explicit CompletenessReport(std::uint32_t mask) noexcept;

  std::uint32_t mask_{0};
};

struct CaptureScope {
  bool started_at_process_start{false};
  bool preexisting_allocations_unknown{true};

  bool operator==(const CaptureScope&) const = default;
};

struct EndOfTrace {
  Sequence final_sequence;
  std::uint64_t final_monotonic_ticks{0};
  bool normal_stop{false};
  std::optional<std::int32_t> target_exit_code;
  CompletenessReport aggregate_completeness = CompletenessReport::from_mask(0U);

  bool operator==(const EndOfTrace&) const = default;
};

class CompletenessValidationError final : public std::invalid_argument {
 public:
  using std::invalid_argument::invalid_argument;
};

void validate_loss_record(const LossRecord& loss);
void validate_statistics(const CaptureStatistics& statistics);
void validate_capture_scope(const CaptureScope& scope);
void validate_end_of_trace(const EndOfTrace& end);

class CompletenessTracker {
 public:
  explicit CompletenessTracker(const CaptureScope& scope);

  void observe_loss(const LossRecord& loss);
  void observe_end_of_trace(const EndOfTrace& end);
  void mark_trace_truncated();
  void mark_writer_error();
  void mark_unknown_record_skipped();
  void mark_partially_understood_format();

  [[nodiscard]] bool saw_end_of_trace() const noexcept;
  [[nodiscard]] const CompletenessReport& report() const noexcept;

 private:
  CompletenessReport report_ = CompletenessReport::from_mask(0U);
  bool saw_end_of_trace_{false};
};

}  // namespace noleax::trace
