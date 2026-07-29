#include "noleax/trace/completeness.hpp"

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <limits>

namespace {

[[nodiscard]] noleax::trace::CaptureScope process_start_scope() {
  return noleax::trace::CaptureScope{true, false};
}

[[nodiscard]] noleax::trace::EndOfTrace normal_end() {
  noleax::trace::EndOfTrace end;
  end.final_sequence = noleax::trace::Sequence{10U};
  end.final_monotonic_ticks = 20U;
  end.normal_stop = true;
  end.target_exit_code = 0;
  return end;
}

[[nodiscard]] noleax::trace::LossRecord queue_loss() {
  noleax::trace::LossRecord loss;
  loss.reason = noleax::trace::LossReason::kQueueFull;
  loss.location = noleax::trace::LossLocation::kAgentQueue;
  loss.estimated_event_count = 2U;
  loss.sequence_range =
      noleax::trace::SequenceRange{noleax::trace::Sequence{7U}, noleax::trace::Sequence{8U}};
  loss.tick_range = noleax::trace::TickRange{100U, 200U};
  return loss;
}

[[nodiscard]] noleax::trace::CaptureStatistics valid_statistics() {
  noleax::trace::CaptureStatistics statistics;
  statistics.observed_calls = 10U;
  statistics.successful_operations = 7U;
  statistics.failed_operations = 3U;
  statistics.filtered_before_queue = 1U;
  statistics.dropped_events = 2U;
  statistics.unique_stacks = 3U;
  statistics.reused_stacks = 4U;
  statistics.written_uncompressed_bytes = 1000U;
  statistics.written_stored_bytes = 600U;
  statistics.per_api = {
      noleax::trace::ApiStatistics{1U, 6U, 5U, 1U, 1U, 1U},
      noleax::trace::ApiStatistics{2U, 4U, 2U, 2U, 0U, 1U},
  };
  return statistics;
}

}  // namespace

TEST_CASE("completeness report composes known and future issue bits", "[trace][completeness]") {
  using namespace noleax::trace;
  auto report = CompletenessReport::from_mask(0U);
  CHECK(report.overall_state() == CompletenessState::kComplete);
  CHECK(report.lifecycle_state() == CompletenessState::kComplete);
  CHECK(report.stack_detail_state() == CompletenessState::kComplete);
  CHECK(report.understanding_state() == UnderstandingState::kFull);
  CHECK(report.recommended_exit_code() == 0);

  report.add(CompletenessIssue::kStackDataLoss);
  CHECK(report.overall_state() == CompletenessState::kIncomplete);
  CHECK(report.lifecycle_state() == CompletenessState::kComplete);
  CHECK(report.stack_detail_state() == CompletenessState::kIncomplete);
  CHECK(report.recommended_exit_code() == 2);
  report.remove(CompletenessIssue::kStackDataLoss);
  CHECK(report.overall_state() == CompletenessState::kComplete);

  constexpr std::uint32_t kFutureIssue = 1U << 31U;
  const auto future = CompletenessReport::from_mask(kFutureIssue);
  CHECK(future.overall_state() == CompletenessState::kIncomplete);
  CHECK(future.lifecycle_state() == CompletenessState::kIncomplete);
  CHECK(future.understanding_state() == UnderstandingState::kPartial);
  report.merge(future);
  CHECK(report.mask() == kFutureIssue);

  CHECK_THROWS_AS(report.add(static_cast<CompletenessIssue>(3U)), CompletenessValidationError);
  CHECK_THROWS_AS(report.has(static_cast<CompletenessIssue>(0U)), CompletenessValidationError);
}

TEST_CASE("normal process-start capture becomes complete after EndOfTrace",
          "[trace][completeness]") {
  using namespace noleax::trace;
  CompletenessTracker tracker{process_start_scope()};
  CHECK(tracker.report().has(CompletenessIssue::kMissingEndOfTrace));
  CHECK_FALSE(tracker.saw_end_of_trace());

  tracker.observe_end_of_trace(normal_end());
  CHECK(tracker.saw_end_of_trace());
  CHECK(tracker.report().overall_state() == CompletenessState::kComplete);
  CHECK(tracker.report().recommended_exit_code() == 0);
}

TEST_CASE("attach scope remains lifecycle-incomplete after a normal stop",
          "[trace][completeness]") {
  using namespace noleax::trace;
  CompletenessTracker tracker{CaptureScope{false, true}};
  tracker.observe_end_of_trace(normal_end());

  CHECK(tracker.report().has(CompletenessIssue::kCaptureDidNotStartAtProcessStart));
  CHECK(tracker.report().has(CompletenessIssue::kPreexistingAllocationsUnknown));
  CHECK(tracker.report().lifecycle_state() == CompletenessState::kIncomplete);
  CHECK(tracker.report().understanding_state() == UnderstandingState::kFull);
  CHECK(tracker.report().recommended_exit_code() == 2);
}

TEST_CASE("loss reasons distinguish lifecycle loss from stack-detail loss",
          "[trace][completeness]") {
  using namespace noleax::trace;

  SECTION("queue loss") {
    CompletenessTracker tracker{process_start_scope()};
    tracker.observe_loss(queue_loss());
    tracker.observe_end_of_trace(normal_end());
    CHECK(tracker.report().has(CompletenessIssue::kEventLoss));
    CHECK(tracker.report().lifecycle_state() == CompletenessState::kIncomplete);
  }

  SECTION("stack capture loss") {
    CompletenessTracker tracker{process_start_scope()};
    LossRecord loss;
    loss.reason = LossReason::kStackCaptureFailed;
    loss.location = LossLocation::kAgentQueue;
    tracker.observe_loss(loss);
    tracker.observe_end_of_trace(normal_end());
    CHECK(tracker.report().has(CompletenessIssue::kStackDataLoss));
    CHECK_FALSE(tracker.report().has(CompletenessIssue::kEventLoss));
    CHECK(tracker.report().lifecycle_state() == CompletenessState::kComplete);
    CHECK(tracker.report().stack_detail_state() == CompletenessState::kIncomplete);
  }

  SECTION("writer loss") {
    CompletenessTracker tracker{process_start_scope()};
    auto loss = queue_loss();
    loss.reason = LossReason::kWriterError;
    loss.location = LossLocation::kWriter;
    tracker.observe_loss(loss);
    tracker.observe_end_of_trace(normal_end());
    CHECK(tracker.report().has(CompletenessIssue::kEventLoss));
    CHECK(tracker.report().has(CompletenessIssue::kWriterError));
  }
}

TEST_CASE("reader integrity signals map to stable completeness states", "[trace][completeness]") {
  using namespace noleax::trace;
  CompletenessTracker tracker{process_start_scope()};
  tracker.mark_trace_truncated();
  tracker.mark_writer_error();
  tracker.mark_unknown_record_skipped();
  tracker.mark_partially_understood_format();

  CHECK(tracker.report().has(CompletenessIssue::kTraceTruncated));
  CHECK(tracker.report().has(CompletenessIssue::kWriterError));
  CHECK(tracker.report().has(CompletenessIssue::kEventLoss));
  CHECK(tracker.report().has(CompletenessIssue::kMissingEndOfTrace));
  CHECK(tracker.report().understanding_state() == UnderstandingState::kPartial);
  CHECK(tracker.report().lifecycle_state() == CompletenessState::kIncomplete);
  CHECK(tracker.report().recommended_exit_code() == 2);
}

TEST_CASE("EndOfTrace merges agent issues and rejects impossible or duplicate records",
          "[trace][completeness]") {
  using namespace noleax::trace;
  CompletenessTracker tracker{process_start_scope()};
  auto end = normal_end();
  end.normal_stop = false;
  end.aggregate_completeness.add(CompletenessIssue::kEventLoss);
  tracker.observe_end_of_trace(end);

  CHECK(tracker.report().has(CompletenessIssue::kEventLoss));
  CHECK(tracker.report().has(CompletenessIssue::kAbnormalStop));
  CHECK_FALSE(tracker.report().has(CompletenessIssue::kMissingEndOfTrace));
  CHECK_THROWS_AS(tracker.observe_end_of_trace(end), CompletenessValidationError);
  CHECK_THROWS_AS(tracker.observe_loss(queue_loss()), CompletenessValidationError);

  auto impossible = normal_end();
  impossible.aggregate_completeness.add(CompletenessIssue::kMissingEndOfTrace);
  CHECK_THROWS_AS(validate_end_of_trace(impossible), CompletenessValidationError);

  impossible = normal_end();
  impossible.aggregate_completeness.add(CompletenessIssue::kAbnormalStop);
  CHECK_THROWS_AS(validate_end_of_trace(impossible), CompletenessValidationError);
}

TEST_CASE("loss record validation enforces identifiers counts and ranges",
          "[trace][completeness]") {
  using namespace noleax::trace;
  const auto valid = queue_loss();
  CHECK_NOTHROW(validate_loss_record(valid));

  auto invalid = valid;
  invalid.reason = LossReason::kUnknown;
  CHECK_THROWS_AS(validate_loss_record(invalid), CompletenessValidationError);

  invalid = valid;
  invalid.location = LossLocation::kUnknown;
  CHECK_THROWS_AS(validate_loss_record(invalid), CompletenessValidationError);

  invalid = valid;
  invalid.estimated_event_count = 0U;
  CHECK_THROWS_AS(validate_loss_record(invalid), CompletenessValidationError);

  invalid = valid;
  invalid.sequence_range = SequenceRange{Sequence{}, Sequence{2U}};
  CHECK_THROWS_AS(validate_loss_record(invalid), CompletenessValidationError);

  invalid = valid;
  invalid.sequence_range = SequenceRange{Sequence{3U}, Sequence{2U}};
  CHECK_THROWS_AS(validate_loss_record(invalid), CompletenessValidationError);

  invalid = valid;
  invalid.tick_range = TickRange{2U, 1U};
  CHECK_THROWS_AS(validate_loss_record(invalid), CompletenessValidationError);
}

TEST_CASE("statistics validation reconciles per-API and aggregate counters",
          "[trace][completeness]") {
  using namespace noleax::trace;
  const auto valid = valid_statistics();
  CHECK_NOTHROW(validate_statistics(valid));

  auto invalid = valid;
  invalid.successful_operations = 8U;
  CHECK_THROWS_AS(validate_statistics(invalid), CompletenessValidationError);

  invalid = valid;
  invalid.dropped_events = 10U;
  CHECK_THROWS_AS(validate_statistics(invalid), CompletenessValidationError);

  invalid = valid;
  invalid.per_api[1].api_id = invalid.per_api[0].api_id;
  CHECK_THROWS_AS(validate_statistics(invalid), CompletenessValidationError);

  invalid = valid;
  invalid.per_api[0].api_id = 0U;
  CHECK_THROWS_AS(validate_statistics(invalid), CompletenessValidationError);

  invalid = valid;
  invalid.per_api[0].observed_calls += 1U;
  invalid.per_api[0].successful_operations += 1U;
  CHECK_THROWS_AS(validate_statistics(invalid), CompletenessValidationError);

  invalid = valid;
  invalid.unique_stacks = 8U;
  CHECK_THROWS_AS(validate_statistics(invalid), CompletenessValidationError);
}

TEST_CASE("statistics validation detects uint64 aggregation overflow", "[trace][completeness]") {
  using namespace noleax::trace;
  constexpr auto kMaximum = std::numeric_limits<std::uint64_t>::max();
  CaptureStatistics statistics;
  statistics.observed_calls = kMaximum;
  statistics.successful_operations = kMaximum;
  statistics.per_api = {
      ApiStatistics{1U, kMaximum, kMaximum, 0U, 0U, 0U},
      ApiStatistics{2U, kMaximum, kMaximum, 0U, 0U, 0U},
  };
  CHECK_THROWS_AS(validate_statistics(statistics), CompletenessValidationError);
}

TEST_CASE("capture scope rejects contradictory process-start metadata", "[trace][completeness]") {
  using namespace noleax::trace;
  CHECK_NOTHROW(validate_capture_scope(process_start_scope()));
  CHECK_NOTHROW(validate_capture_scope(CaptureScope{false, true}));
  CHECK_THROWS_AS(validate_capture_scope(CaptureScope{true, true}), CompletenessValidationError);
}
