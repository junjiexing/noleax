#include "noleax/analyzer/csv.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/analyzer/presentation.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/wire_format.hpp"
#include "support/csv_table.hpp"
#include "support/synthetic_trace.hpp"

namespace {

[[nodiscard]] noleax::trace::FileHeader file_header() {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.monotonic_frequency = 1'000'000'000U;
  header.monotonic_origin = 100U;
  header.utc_origin_ns = 1'000U;
  return header;
}

[[nodiscard]] noleax::analyzer::WindowBound at(std::chrono::nanoseconds time) {
  noleax::analyzer::WindowBound bound;
  bound.time = time;
  return bound;
}

[[nodiscard]] noleax::analyzer::WindowBound seq(std::uint64_t sequence) {
  noleax::analyzer::WindowBound bound;
  bound.sequence = sequence;
  return bound;
}

[[nodiscard]] noleax::trace::CaptureScope capture_scope() { return {true, false}; }

[[nodiscard]] noleax::trace::Event allocation_event(std::uint64_t sequence = 1U,
                                                    std::uint64_t ticks = 110U,
                                                    std::uint64_t allocation_id = 10U) {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{sequence};
  header.monotonic_ticks = ticks;
  header.thread_id = 7U;
  header.api_id = 1U;
  header.status = noleax::trace::EventStatus::kSuccess;
  header.stack_id = noleax::trace::StackId{11U};
  header.flags = 2U;

  noleax::trace::AllocationEvent allocation;
  allocation.heap_handle = 0x1000U;
  allocation.heap_id = noleax::trace::HeapId{1U};
  allocation.requested_size = 64U;
  allocation.result_address = 0x2000U + allocation_id;
  allocation.allocation_id = noleax::trace::AllocationId{allocation_id};
  allocation.api_flags = 8U;
  return {header, allocation};
}

[[nodiscard]] noleax::trace::Event failed_allocation_event(std::uint64_t sequence,
                                                           std::uint64_t ticks) {
  auto event = allocation_event(sequence, ticks, sequence + 20U);
  event.header.status = noleax::trace::EventStatus::kFailure;
  event.header.stack_id = {};
  auto& payload = std::get<noleax::trace::AllocationEvent>(event.payload);
  payload.result_address = 0U;
  payload.allocation_id = {};
  return event;
}

[[nodiscard]] noleax::trace::LossRecord loss_record() {
  noleax::trace::LossRecord loss;
  loss.reason = noleax::trace::LossReason::kQueueFull;
  loss.location = noleax::trace::LossLocation::kAgentQueue;
  loss.estimated_event_count = 2U;
  loss.sequence_range =
      noleax::trace::SequenceRange{noleax::trace::Sequence{2U}, noleax::trace::Sequence{3U}};
  loss.tick_range = noleax::trace::TickRange{115U, 116U};
  return loss;
}

[[nodiscard]] noleax::analyzer::EventPresentation presentation() {
  noleax::analyzer::EventPresentation value;
  value.api_name = "Rtl,\"分配\"\r\nHeap";
  value.api_module = "ntdll.dll";
  value.stack_status = noleax::analyzer::StackCaptureStatus::kComplete;

  noleax::analyzer::ResolvedStackFrame frame;
  frame.absolute_address = 0x0000000140001234U;
  frame.module_name = "app|core;模块.dll";
  frame.module_offset = 0x1234U;
  frame.symbol_name = "operator,\"x\"\n";
  frame.symbol_offset = 4U;
  value.stack_frames.push_back(std::move(frame));
  return value;
}

[[nodiscard]] noleax::analyzer::FilteredEventsResult event_result(
    const noleax::trace::FileHeader& header, std::uint64_t event_count,
    std::uint64_t loss_count = 0U) {
  noleax::analyzer::FilteredEventsResult result;
  result.trace.file_header = header;
  result.trace.capture_scope = capture_scope();
  result.trace.event_count = event_count;
  result.trace.loss_record_count = loss_count;
  result.matched_event_count = event_count;
  return result;
}

[[nodiscard]] std::string write_events(
    const noleax::trace::FileHeader& header, const std::vector<noleax::trace::Event>& events,
    const noleax::analyzer::EventPresentationResolver& resolver = {}) {
  std::ostringstream output;
  noleax::analyzer::CsvWriter writer{output};
  writer.begin_events(header, capture_scope());
  for (const auto& event : events) {
    writer.write_event(event, resolver ? resolver(event) : noleax::analyzer::EventPresentation{});
  }
  writer.finish_events(event_result(header, static_cast<std::uint64_t>(events.size())));
  return output.str();
}

[[nodiscard]] const std::vector<std::string>& expected_event_header() {
  static const std::vector<std::string> header{
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
  return header;
}

[[nodiscard]] const std::vector<std::string>& expected_outstanding_header() {
  static const std::vector<std::string> header{
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
      "window_a_sequence",
      "window_b_sequence",
      "requested_c_sequence",
      "effective_c_sequence",
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
  return header;
}

}  // namespace

TEST_CASE("analysis CSV schema version and column order are stable", "[analyzer][csv]") {
  CHECK(noleax::analyzer::kAnalysisCsvSchemaVersion == 1U);
  const auto events = noleax::testing::parse_csv(write_events(file_header(), {}));
  CHECK(events.header == expected_event_header());
  REQUIRE(events.rows.size() == 1U);
  CHECK(events.at(0U, "record_type") == "summary");

  noleax::analyzer::OutstandingResult result;
  result.trace.file_header = file_header();
  result.trace.capture_scope = capture_scope();
  std::ostringstream output;
  noleax::analyzer::CsvWriter writer{output};
  writer.write_outstanding(result);
  const auto outstanding = noleax::testing::parse_csv(output.str());
  CHECK(outstanding.header == expected_outstanding_header());
  REQUIRE(outstanding.rows.size() == 1U);
  CHECK(outstanding.at(0U, "record_type") == "summary");
}

TEST_CASE("events CSV pipeline preserves quoted UTF-8 Event Loss and summary rows",
          "[analyzer][csv]") {
  noleax::testing::SyntheticTraceBuilder builder{file_header(), capture_scope()};
  builder.add_event(allocation_event());
  builder.add_loss(loss_record());

  noleax::trace::CaptureStatistics statistics;
  statistics.observed_calls = 1U;
  statistics.successful_operations = 1U;
  statistics.unique_stacks = 1U;
  statistics.written_uncompressed_bytes = 512U;
  statistics.written_stored_bytes = 256U;
  statistics.per_api.push_back({1U, 1U, 1U, 0U, 0U, 0U});
  builder.set_statistics(statistics).finish_normally(0);

  const auto encoded = builder.build();
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  const auto result = noleax::analyzer::analyze_events_to_csv(
      input, output, noleax::analyzer::AnalysisFilter{}, {},
      [](const noleax::trace::Event&) { return presentation(); });

  CHECK(result.matched_event_count == 1U);
  CHECK(output.str().find("\"Rtl,\"\"分配\"\"\r\nHeap\"") != std::string::npos);
  const auto table = noleax::testing::parse_csv(output.str());
  REQUIRE(table.rows.size() == 3U);

  CHECK(table.at(0U, "csv_schema_version") == "1");
  CHECK(table.at(0U, "record_type") == "event");
  CHECK(table.at(0U, "api_name") == "Rtl,\"分配\"\r\nHeap");
  CHECK(table.at(0U, "payload_kind") == "allocation");
  CHECK(table.at(0U, "size") == "64");
  CHECK(table.at(0U, "result_address") == "0x000000000000200a");
  CHECK(table.at(0U, "stack_frames") ==
        "0x0000000140001234|app\\|core\\;模块.dll|0x1234|operator,\"x\"\\n|0x4");

  CHECK(table.at(1U, "record_type") == "loss");
  CHECK(table.at(1U, "loss_reason") == "queue_full");
  CHECK(table.at(1U, "loss_sequence_end") == "3");

  CHECK(table.at(2U, "record_type") == "summary");
  CHECK(table.at(2U, "matched_events") == "1");
  CHECK(table.at(2U, "loss_records") == "1");
  CHECK(table.at(2U, "capture_observed_calls") == "1");
  CHECK(table.at(2U, "completeness_overall") == "incomplete");
  CHECK(table.at(2U, "completeness_issues").find("event_loss") != std::string::npos);
  CHECK(table.at(2U, "normal_stop") == "true");
  CHECK(table.at(2U, "target_exit_code") == "0");
}

TEST_CASE("events CSV provides columns for every normalized payload", "[analyzer][csv]") {
  auto header = file_header();
  header.monotonic_origin = 0U;
  const auto events = noleax::testing::make_all_memory_event_kinds();
  const auto table = noleax::testing::parse_csv(write_events(header, events));

  constexpr std::array<std::string_view, 9> expected_kinds{
      "heap_create",   "heap_destroy", "allocation", "reallocation", "free",
      "vm_allocation", "vm_free",      "map",        "unmap",
  };
  REQUIRE(table.rows.size() == expected_kinds.size() + 1U);
  for (std::size_t index = 0U; index < expected_kinds.size(); ++index) {
    CAPTURE(index);
    CHECK(table.at(index, "record_type") == "event");
    CHECK(table.at(index, "payload_kind") == expected_kinds[index]);
  }
  CHECK(table.at(0U, "reserve_size") == "4096");
  CHECK(table.at(1U, "raw_result") == "0x1");
  CHECK(table.at(3U, "reallocation_effect") == "new_generation");
  CHECK(table.at(5U, "allocation_type") == "0x3000");
  CHECK(table.at(6U, "free_type") == "0x8000");
  CHECK(table.at(7U, "section_handle") == "0x0000000000001234");
  CHECK(table.at(8U, "base") == "0x0000000000005000");
}

TEST_CASE("outstanding CSV pipeline emits allocation and window summary rows", "[analyzer][csv]") {
  using namespace std::chrono_literals;
  noleax::testing::SyntheticTraceBuilder builder{file_header(), capture_scope()};
  builder.add_event(allocation_event());
  builder.add_event(failed_allocation_event(2U, 140U));
  const auto encoded = builder.finish_normally().build();

  noleax::analyzer::AnalysisFilterCriteria criteria;
  criteria.minimum_size = 64U;
  criteria.maximum_size = 64U;
  const noleax::analyzer::AnalysisFilter filter{std::move(criteria)};

  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  const auto result = noleax::analyzer::analyze_outstanding_to_csv(
      input, output, {at(10ns), at(20ns), std::nullopt}, filter, {},
      [](const noleax::trace::Event&) { return presentation(); });

  REQUIRE(result.outstanding.size() == 1U);
  const auto table = noleax::testing::parse_csv(output.str());
  REQUIRE(table.rows.size() == 2U);
  CHECK(table.at(0U, "record_type") == "allocation");
  CHECK(table.at(0U, "generation_kind") == "heap_allocation");
  CHECK(table.at(0U, "allocation_id") == "10");
  CHECK(table.at(0U, "address") == "0x000000000000200a");
  CHECK(table.at(0U, "creation_relative_time_ns") == "10");
  CHECK(table.at(0U, "api_name") == "Rtl,\"分配\"\r\nHeap");

  CHECK(table.at(1U, "record_type") == "summary");
  CHECK(table.at(1U, "window_a_ns") == "10");
  CHECK(table.at(1U, "window_b_ns") == "20");
  CHECK(table.at(1U, "requested_c_ns").empty());
  CHECK(table.at(1U, "effective_c_ns") == "40");
  CHECK(table.at(1U, "observation_uses_trace_end") == "true");
  CHECK(table.at(1U, "outstanding") == "1");
}

TEST_CASE("outstanding CSV pipeline emits sequence window columns", "[analyzer][csv][window]") {
  noleax::testing::SyntheticTraceBuilder builder{file_header(), capture_scope()};
  builder.add_event(allocation_event());
  builder.add_event(failed_allocation_event(2U, 140U));
  const auto encoded = builder.finish_normally().build();

  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  const auto result = noleax::analyzer::analyze_outstanding_to_csv(
      input, output, {seq(1U), seq(2U), std::nullopt}, noleax::analyzer::AnalysisFilter{}, {},
      [](const noleax::trace::Event&) { return presentation(); });

  REQUIRE(result.outstanding.size() == 1U);
  const auto table = noleax::testing::parse_csv(output.str());
  REQUIRE(table.rows.size() == 2U);
  CHECK(table.column("window_a_sequence") == table.column("effective_c_ns") + 1U);
  CHECK(table.column("effective_c_sequence") == table.column("requested_c_sequence") + 1U);
  CHECK(table.at(1U, "window_a_ns").empty());
  CHECK(table.at(1U, "window_a_sequence") == "1");
  CHECK(table.at(1U, "window_b_ns").empty());
  CHECK(table.at(1U, "window_b_sequence") == "2");
  CHECK(table.at(1U, "requested_c_ns").empty());
  CHECK(table.at(1U, "requested_c_sequence").empty());
  CHECK(table.at(1U, "effective_c_ns") == "40");
  CHECK(table.at(1U, "effective_c_sequence") == "2");
}

TEST_CASE("event stacks CSV pipeline emits sequence window columns", "[analyzer][csv][window]") {
  noleax::testing::SyntheticTraceBuilder builder{file_header(), capture_scope()};
  builder.add_event(allocation_event());
  builder.add_event(failed_allocation_event(2U, 140U));
  const auto encoded = builder.finish_normally().build();

  noleax::analyzer::StacksWindow window;
  window.from = seq(1U);
  window.to = seq(2U);
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  const auto result = noleax::analyzer::analyze_event_stacks_to_csv(
      input, output, window, noleax::analyzer::StacksSort::kAllocBytes,
      noleax::analyzer::AnalysisFilter{}, {},
      [](const noleax::trace::Event&) { return presentation(); });

  REQUIRE(result.groups.size() == 1U);
  const auto table = noleax::testing::parse_csv(output.str());
  REQUIRE(table.rows.size() == 2U);
  CHECK(table.column("window_from_sequence") == table.column("window_to_ns") + 1U);
  CHECK(table.column("window_to_sequence") == table.column("window_from_sequence") + 1U);
  CHECK(table.at(1U, "window_from_ns").empty());
  CHECK(table.at(1U, "window_from_sequence") == "1");
  CHECK(table.at(1U, "window_to_ns").empty());
  CHECK(table.at(1U, "window_to_sequence") == "2");
}

TEST_CASE("events CSV writes exact 64-bit integer and hexadecimal boundaries", "[analyzer][csv]") {
  auto event = allocation_event();
  event.header.sequence = noleax::trace::Sequence{std::numeric_limits<std::uint64_t>::max()};
  event.header.thread_id = std::numeric_limits<std::uint64_t>::max();
  event.header.system_error = {noleax::trace::SystemErrorDomain::kWin32,
                               std::numeric_limits<std::uint64_t>::max()};
  auto& allocation = std::get<noleax::trace::AllocationEvent>(event.payload);
  allocation.requested_size = std::numeric_limits<std::uint64_t>::max();
  allocation.allocation_id = noleax::trace::AllocationId{std::numeric_limits<std::uint64_t>::max()};

  const auto table = noleax::testing::parse_csv(write_events(file_header(), {event}));
  CHECK(table.at(0U, "sequence") == "18446744073709551615");
  CHECK(table.at(0U, "thread_id") == "18446744073709551615");
  CHECK(table.at(0U, "requested_size") == "18446744073709551615");
  CHECK(table.at(0U, "allocation_id") == "18446744073709551615");
  CHECK(table.at(0U, "error_code") == "0xffffffffffffffff");
}

TEST_CASE("CSV writer rejects malformed UTF-8 and inconsistent stack presentation",
          "[analyzer][csv]") {
  SECTION("malformed API name") {
    auto value = presentation();
    value.api_name = std::string{"\xC0\xAF", 2U};
    std::ostringstream output;
    noleax::analyzer::CsvWriter writer{output};
    writer.begin_events(file_header(), capture_scope());
    const auto header_only = output.str();
    CHECK_THROWS_AS(writer.write_event(allocation_event(), value),
                    noleax::analyzer::CsvFormatError);
    CHECK(output.str() == header_only);
  }

  SECTION("stack without ID") {
    auto event = allocation_event();
    event.header.stack_id = {};
    std::ostringstream output;
    noleax::analyzer::CsvWriter writer{output};
    writer.begin_events(file_header(), capture_scope());
    CHECK_THROWS_AS(writer.write_event(event, presentation()), noleax::analyzer::CsvFormatError);
  }

  SECTION("offset without module") {
    auto value = presentation();
    value.stack_frames.front().module_name.reset();
    std::ostringstream output;
    noleax::analyzer::CsvWriter writer{output};
    writer.begin_events(file_header(), capture_scope());
    CHECK_THROWS_AS(writer.write_event(allocation_event(), value),
                    noleax::analyzer::CsvFormatError);
  }
}

TEST_CASE("CSV writer rejects invalid state summaries and output streams", "[analyzer][csv]") {
  SECTION("call order") {
    std::ostringstream output;
    noleax::analyzer::CsvWriter writer{output};
    CHECK_THROWS_AS(writer.write_event(allocation_event()), noleax::analyzer::CsvFormatError);
    writer.begin_events(file_header(), capture_scope());
    CHECK_THROWS_AS(writer.begin_events(file_header(), capture_scope()),
                    noleax::analyzer::CsvFormatError);
    writer.write_event(allocation_event());
    writer.finish_events(event_result(file_header(), 1U));
    CHECK_THROWS_AS(writer.finish_events(event_result(file_header(), 1U)),
                    noleax::analyzer::CsvFormatError);
  }

  SECTION("record count") {
    std::ostringstream output;
    noleax::analyzer::CsvWriter writer{output};
    writer.begin_events(file_header(), capture_scope());
    writer.write_event(allocation_event());
    CHECK_THROWS_AS(writer.finish_events(event_result(file_header(), 2U)),
                    noleax::analyzer::CsvFormatError);
  }

  SECTION("failed stream") {
    std::ostringstream output;
    output.setstate(std::ios::badbit);
    noleax::analyzer::CsvWriter writer{output};
    CHECK_THROWS_AS(writer.begin_events(file_header(), capture_scope()),
                    noleax::analyzer::CsvFormatError);
  }
}

TEST_CASE("event stacks CSV pipeline lists group api names", "[analyzer][csv]") {
  noleax::testing::SyntheticTraceBuilder builder{file_header(), capture_scope()};
  builder.add_event(allocation_event());
  const auto encoded = builder.finish_normally().build();

  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  const auto result = noleax::analyzer::analyze_event_stacks_to_csv(
      input, output, {}, noleax::analyzer::StacksSort::kAllocBytes,
      noleax::analyzer::AnalysisFilter{}, {},
      [](const noleax::trace::Event&) { return presentation(); });

  REQUIRE(result.groups.size() == 1U);
  const auto table = noleax::testing::parse_csv(output.str());
  REQUIRE(table.rows.size() == 2U);
  CHECK(table.at(0U, "record_type") == "group");
  CHECK(table.at(0U, "api_names") == "RtlAllocateHeap");
  CHECK(table.at(1U, "record_type") == "summary");
}
