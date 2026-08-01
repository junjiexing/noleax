#include "noleax/analyzer/console.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <ios>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/wire_format.hpp"
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

[[nodiscard]] noleax::trace::CaptureScope capture_scope() { return {true, false}; }

[[nodiscard]] noleax::trace::Event allocation_event() {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{1U};
  header.monotonic_ticks = 110U;
  header.thread_id = 7U;
  header.api_id = 1U;
  header.status = noleax::trace::EventStatus::kSuccess;
  header.stack_id = noleax::trace::StackId{11U};
  header.flags = 2U;

  noleax::trace::AllocationEvent allocation;
  allocation.heap_handle = 0x1000U;
  allocation.heap_id = noleax::trace::HeapId{1U};
  allocation.requested_size = 64U;
  allocation.result_address = 0x2000U;
  allocation.allocation_id = noleax::trace::AllocationId{10U};
  allocation.api_flags = 8U;
  return {header, allocation};
}

[[nodiscard]] noleax::trace::Event failed_free_event() {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{2U};
  header.monotonic_ticks = 120U;
  header.thread_id = 8U;
  header.api_id = 2U;
  header.status = noleax::trace::EventStatus::kFailure;
  header.system_error = {noleax::trace::SystemErrorDomain::kNtStatus, 0xc0000017U};

  noleax::trace::FreeEvent free;
  free.heap_handle = 0x1000U;
  free.heap_id = noleax::trace::HeapId{1U};
  free.address = 0x2000U;
  return {header, free};
}

[[nodiscard]] noleax::analyzer::ConsoleEventMetadata allocation_metadata() {
  noleax::analyzer::ConsoleEventMetadata metadata;
  metadata.api_name = "RtlAllocateHeap";
  metadata.api_module = "ntdll.dll";
  metadata.stack_status = noleax::analyzer::ConsoleStackStatus::kComplete;

  noleax::analyzer::ConsoleStackFrame first;
  first.absolute_address = 0x0000000140001234U;
  first.module_name = "app.exe";
  first.module_offset = 0x1234U;
  first.symbol_name = "main";
  first.symbol_offset = 4U;
  metadata.stack_frames.push_back(first);

  noleax::analyzer::ConsoleStackFrame second;
  second.absolute_address = 0x00007ffb00005678U;
  second.module_name = "ntdll.dll";
  second.module_offset = 0x5678U;
  metadata.stack_frames.push_back(second);
  return metadata;
}

[[nodiscard]] noleax::trace::LossRecord loss_record() {
  noleax::trace::LossRecord loss;
  loss.reason = noleax::trace::LossReason::kQueueFull;
  loss.location = noleax::trace::LossLocation::kAgentQueue;
  loss.estimated_event_count = 2U;
  loss.sequence_range =
      noleax::trace::SequenceRange{noleax::trace::Sequence{3U}, noleax::trace::Sequence{4U}};
  loss.tick_range = noleax::trace::TickRange{125U, 126U};
  return loss;
}

[[nodiscard]] noleax::analyzer::EventStreamResult trace_result(bool incomplete) {
  noleax::analyzer::EventStreamResult result;
  result.file_header = file_header();
  result.capture_scope = capture_scope();
  result.event_count = 2U;
  result.loss_record_count = incomplete ? 1U : 0U;
  result.bytes_read = incomplete ? 512U : 768U;

  noleax::trace::EndOfTrace end;
  end.final_sequence = noleax::trace::Sequence{4U};
  end.final_monotonic_ticks = 140U;
  end.normal_stop = true;
  if (incomplete) {
    end.target_exit_code = 0;
    result.completeness.add(noleax::trace::CompletenessIssue::kEventLoss);
    result.completeness.add(noleax::trace::CompletenessIssue::kStackDataLoss);

    noleax::trace::CaptureStatistics statistics;
    statistics.observed_calls = 4U;
    statistics.successful_operations = 2U;
    statistics.failed_operations = 2U;
    statistics.dropped_events = 2U;
    statistics.unique_stacks = 1U;
    statistics.reused_stacks = 1U;
    statistics.written_uncompressed_bytes = 1024U;
    statistics.written_stored_bytes = 512U;
    result.statistics = statistics;
  }
  result.end_of_trace = end;
  return result;
}

}  // namespace

TEST_CASE("console events output has a stable human-readable snapshot", "[analyzer][console]") {
  std::ostringstream output;
  noleax::analyzer::ConsoleWriter writer{output};
  writer.begin_events(file_header(), capture_scope());
  writer.write_event(allocation_event(), allocation_metadata());
  writer.write_loss(loss_record());
  writer.write_event(failed_free_event());

  noleax::analyzer::FilteredEventsResult result;
  result.trace = trace_result(true);
  result.matched_event_count = 2U;
  writer.finish_events(result);

  const std::string expected = R"(noleax events
trace: platform=windows architecture=x64 pointer-width=64 file-index=0
clock: frequency=1000000000Hz origin=100 utc-origin-ns=1000
capture: process-start
events:
event #1 +10ns [ticks=110] tid=7 ntdll.dll!RtlAllocateHeap alloc success event-flags=0x2
  allocation: heap=0x0000000000001000 heap-id=1 requested=64B result=0x0000000000002000 allocation-id=10 api-flags=0x8
  stack #11 (complete):
    #0 app.exe!main+0x4 [0x0000000140001234]
    #1 ntdll.dll+0x5678 [0x00007ffb00005678]
loss: reason=queue-full location=agent-queue estimated-events=2 sequence=3..4 ticks=125..126
event #2 +20ns [ticks=120] tid=8 api#2 free failure error=ntstatus:0xc0000017
  free: heap=0x0000000000001000 heap-id=1 address=0x0000000000002000 allocation-id=none result=0x0 api-flags=0x0
  stack: unavailable

summary:
  matched-events: 2
  filtered-events: 0
  trace-events: 2
  loss-records: 1
  bytes-read: 512
  capture-calls: observed=4 success=2 failure=2 filtered=0 dropped=2
  stack-dedup: unique=1 reused=1
  trace-bytes: uncompressed=1024 stored=512
  termination: normal target-exit-code=0
  completeness: incomplete (lifecycle=incomplete stack-detail=incomplete understanding=full)
  warnings:
    - event-loss
    - stack-data-loss
)";
  CHECK(output.str() == expected);
}

TEST_CASE("console outstanding output has a stable snapshot", "[analyzer][console]") {
  using namespace std::chrono_literals;
  noleax::analyzer::OutstandingResult result;
  result.trace = trace_result(false);
  result.trace.event_count = 3U;
  result.requested_window = {10ns, 20ns, 30ns};
  result.effective_b = 20ns;
  result.effective_c = 30ns;
  result.trace_end_monotonic_ticks = 140U;
  result.candidate_count = 3U;
  result.ended_by_c_count = 1U;
  result.filtered_out_count = 1U;

  noleax::analyzer::MemoryGeneration generation;
  generation.kind = noleax::analyzer::GenerationKind::kHeapAllocation;
  generation.allocation_id = noleax::trace::AllocationId{10U};
  generation.heap_id = noleax::trace::HeapId{1U};
  generation.heap_handle = 0x1000U;
  generation.address = 0x2000U;
  generation.size = 64U;
  generation.created_by = allocation_event();
  result.outstanding.push_back(generation);

  std::ostringstream output;
  noleax::analyzer::ConsoleWriter writer{output};
  writer.write_outstanding(result,
                           [](const noleax::trace::Event&) { return allocation_metadata(); });

  const std::string expected = R"(noleax leaks
trace: platform=windows architecture=x64 pointer-width=64 file-index=0
clock: frequency=1000000000Hz origin=100 utc-origin-ns=1000
capture: process-start
window: [10ns, 20ns) observed-at=30ns (configured)
trace-end: 40ns [ticks=140]
outstanding:
generation: kind=heap-allocation allocation-id=10 mapping-id=none size=64B address=0x0000000000002000
  heap=0x0000000000001000 heap-id=1
  created: event #1 +10ns [ticks=110] tid=7 ntdll.dll!RtlAllocateHeap alloc success event-flags=0x2
  stack #11 (complete):
    #0 app.exe!main+0x4 [0x0000000140001234]
    #1 ntdll.dll+0x5678 [0x00007ffb00005678]

summary:
  candidates: 3
  ended-by-c: 1
  filtered-out: 1
  outstanding: 1
  trace-events: 3
  loss-records: 0
  bytes-read: 768
  termination: normal
  completeness: complete (lifecycle=complete stack-detail=complete understanding=full)
)";
  CHECK(output.str() == expected);
}

TEST_CASE("console events format every normalized payload", "[analyzer][console]") {
  auto header = file_header();
  header.monotonic_origin = 0U;
  const auto events = noleax::testing::make_all_memory_event_kinds();

  std::ostringstream output;
  noleax::analyzer::ConsoleWriter writer{output};
  writer.begin_events(header, capture_scope());
  for (const auto& event : events) {
    writer.write_event(event);
  }

  noleax::analyzer::FilteredEventsResult result;
  result.trace.file_header = header;
  result.trace.capture_scope = capture_scope();
  result.trace.event_count = static_cast<std::uint64_t>(events.size());
  result.trace.end_of_trace = noleax::trace::EndOfTrace{};
  result.matched_event_count = static_cast<std::uint64_t>(events.size());
  writer.finish_events(result);

  for (const std::string marker :
       {"  heap: handle=", "  allocation: heap=", "  reallocation: heap=", "  free: heap=",
        "  vm-allocation: scope=", "  vm-free: scope=", "  map: section=", "  unmap: scope="}) {
    CAPTURE(marker);
    CHECK(output.str().find(marker) != std::string::npos);
  }
}

TEST_CASE("console events pipeline streams analyzer callbacks into the writer",
          "[analyzer][console]") {
  noleax::testing::SyntheticTraceBuilder builder{file_header(), capture_scope()};
  builder.add_event(allocation_event());
  builder.add_loss(loss_record());
  const auto encoded = builder.finish_normally().build();

  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  const auto result = noleax::analyzer::analyze_events_to_console(
      input, output, noleax::analyzer::AnalysisFilter{});

  CHECK(result.matched_event_count == 1U);
  CHECK(result.trace.loss_record_count == 1U);
  CHECK(output.str().find("event #1 +10ns") != std::string::npos);
  CHECK(output.str().find("loss: reason=queue-full") != std::string::npos);
  CHECK(output.str().find("completeness: incomplete") != std::string::npos);
}

TEST_CASE("console writer emits optional ANSI colors and rejects invalid call order",
          "[analyzer][console]") {
  std::ostringstream output;
  noleax::analyzer::ConsoleWriter writer{output, {.use_color = true}};
  CHECK_THROWS_AS(writer.write_event(allocation_event()), noleax::analyzer::ConsoleFormatError);

  writer.begin_events(file_header(), capture_scope());
  writer.write_event(allocation_event());
  noleax::analyzer::FilteredEventsResult result;
  result.trace = trace_result(false);
  result.trace.event_count = 1U;
  result.matched_event_count = 1U;
  writer.finish_events(result);

  CHECK(output.str().find("\x1b[1mnoleax events\x1b[0m") != std::string::npos);
  CHECK(output.str().find("\x1b[32mevent #1") != std::string::npos);
  CHECK_THROWS_AS(writer.finish_events(result), noleax::analyzer::ConsoleFormatError);
}

TEST_CASE("console summary names every completeness issue including future bits",
          "[analyzer][console]") {
  using Issue = noleax::trace::CompletenessIssue;
  constexpr std::array cases{
      std::pair{Issue::kCaptureDidNotStartAtProcessStart, "capture-did-not-start-at-process-start"},
      std::pair{Issue::kPreexistingAllocationsUnknown, "preexisting-allocations-unknown"},
      std::pair{Issue::kEventLoss, "event-loss"},
      std::pair{Issue::kTraceTruncated, "trace-truncated"},
      std::pair{Issue::kWriterError, "writer-error"},
      std::pair{Issue::kUnknownRecordSkipped, "unknown-record-skipped"},
      std::pair{Issue::kMissingEndOfTrace, "missing-end-of-trace"},
      std::pair{Issue::kAbnormalStop, "abnormal-stop"},
      std::pair{Issue::kStackDataLoss, "stack-data-loss"},
      std::pair{Issue::kPartiallyUnderstoodFormat, "partially-understood-format"},
  };

  for (const auto& [issue, name] : cases) {
    noleax::analyzer::FilteredEventsResult result;
    result.trace.file_header = file_header();
    result.trace.capture_scope = capture_scope();
    result.trace.completeness.add(issue);

    std::ostringstream output;
    noleax::analyzer::ConsoleWriter writer{output};
    writer.begin_events(file_header(), capture_scope());
    writer.finish_events(result);
    CAPTURE(name);
    CHECK(output.str().find(name) != std::string::npos);
  }

  noleax::analyzer::FilteredEventsResult future;
  future.trace.file_header = file_header();
  future.trace.capture_scope = capture_scope();
  future.trace.completeness = noleax::trace::CompletenessReport::from_mask(0x80000000U);
  std::ostringstream output;
  noleax::analyzer::ConsoleWriter writer{output};
  writer.begin_events(file_header(), capture_scope());
  writer.finish_events(future);
  CHECK(output.str().find("unknown-issue-bits=0x80000000") != std::string::npos);
}
