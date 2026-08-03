#include "noleax/analyzer/outstanding.hpp"

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <optional>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

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

[[nodiscard]] noleax::trace::EventHeader event_header(std::uint64_t sequence, std::uint64_t ticks) {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{sequence};
  header.monotonic_ticks = ticks;
  header.thread_id = 7U;
  header.api_id = 1U;
  header.status = noleax::trace::EventStatus::kSuccess;
  header.stack_id = noleax::trace::StackId{sequence + 100U};
  return header;
}

[[nodiscard]] noleax::trace::Event allocation_event(std::uint64_t sequence, std::uint64_t ticks,
                                                    std::uint64_t id,
                                                    noleax::trace::Address address,
                                                    std::uint64_t heap_id = 1U) {
  noleax::trace::AllocationEvent allocation;
  allocation.heap_handle = 0x1000U + heap_id;
  allocation.heap_id = noleax::trace::HeapId{heap_id};
  allocation.requested_size = id * 16U;
  allocation.result_address = address;
  allocation.allocation_id = noleax::trace::AllocationId{id};
  return noleax::trace::Event{event_header(sequence, ticks), allocation};
}

[[nodiscard]] noleax::trace::Event reallocation_event(std::uint64_t sequence, std::uint64_t ticks,
                                                      std::uint64_t old_id, std::uint64_t new_id,
                                                      noleax::trace::Address address) {
  noleax::trace::ReallocationEvent reallocation;
  reallocation.heap_handle = 0x1001U;
  reallocation.heap_id = noleax::trace::HeapId{1U};
  reallocation.old_address = address;
  reallocation.old_allocation_id = noleax::trace::AllocationId{old_id};
  reallocation.requested_size = new_id * 16U;
  reallocation.result_address = address;
  reallocation.new_allocation_id = noleax::trace::AllocationId{new_id};
  reallocation.effect = noleax::trace::ReallocationEffect::kNewGeneration;
  return noleax::trace::Event{event_header(sequence, ticks), reallocation};
}

[[nodiscard]] noleax::trace::Event free_event(std::uint64_t sequence, std::uint64_t ticks,
                                              std::uint64_t id, noleax::trace::Address address) {
  noleax::trace::FreeEvent free;
  free.heap_handle = 0x1001U;
  free.heap_id = noleax::trace::HeapId{1U};
  free.address = address;
  free.allocation_id = noleax::trace::AllocationId{id};
  free.raw_result = 1U;
  return noleax::trace::Event{event_header(sequence, ticks), free};
}

[[nodiscard]] std::string make_trace(const std::vector<noleax::trace::Event>& events,
                                     std::optional<noleax::trace::LossRecord> loss = std::nullopt) {
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
  for (const auto& event : events) {
    builder.add_event(event);
  }
  if (loss.has_value()) {
    builder.add_loss(*loss);
  }
  return builder.finish_normally().build();
}

[[nodiscard]] noleax::analyzer::OutstandingResult analyze(
    const std::string& encoded, noleax::analyzer::OutstandingWindow window) {
  std::istringstream input{encoded, std::ios::binary};
  return noleax::analyzer::analyze_outstanding(input, window);
}

[[nodiscard]] std::vector<std::uint64_t> allocation_ids(
    const std::vector<noleax::analyzer::MemoryGeneration>& generations) {
  std::vector<std::uint64_t> result;
  result.reserve(generations.size());
  for (const auto& generation : generations) {
    result.push_back(generation.allocation_id.value());
  }
  return result;
}

}  // namespace

TEST_CASE("outstanding window uses closed a open b and includes all end events at c",
          "[analyzer][outstanding]") {
  using namespace std::chrono_literals;
  const std::vector events{
      allocation_event(1U, 109U, 5U, 0x5000U), allocation_event(2U, 110U, 1U, 0x1000U),
      allocation_event(3U, 115U, 3U, 0x3000U), allocation_event(4U, 116U, 4U, 0x4000U),
      allocation_event(5U, 120U, 2U, 0x2000U), free_event(6U, 130U, 3U, 0x3000U),
      free_event(7U, 131U, 4U, 0x4000U),
  };

  const auto result = analyze(make_trace(events), {at(10ns), at(20ns), at(30ns)});
  CHECK(result.candidate_count == 3U);
  CHECK(result.ended_by_c_count == 1U);
  CHECK(allocation_ids(result.outstanding) == std::vector<std::uint64_t>{1U, 4U});
  CHECK(result.effective_c.time == 30ns);
  CHECK_FALSE(result.observation_uses_trace_end);
  CHECK(result.trace.completeness.recommended_exit_code() == 0);
}

TEST_CASE("omitted or oversized c observes state at the trace end", "[analyzer][outstanding]") {
  using namespace std::chrono_literals;
  const std::vector events{
      allocation_event(1U, 110U, 1U, 0x1000U),
      allocation_event(2U, 115U, 2U, 0x2000U),
      free_event(3U, 131U, 2U, 0x2000U),
  };
  const auto encoded = make_trace(events);

  SECTION("omitted") {
    const auto result = analyze(encoded, {at(10ns), at(20ns), std::nullopt});
    CHECK(result.observation_uses_trace_end);
    CHECK(result.effective_c.time == 31ns);
    CHECK(allocation_ids(result.outstanding) == std::vector<std::uint64_t>{1U});
  }

  SECTION("larger than trace") {
    const auto result = analyze(encoded, {at(10ns), at(20ns), at(1s)});
    CHECK(result.observation_uses_trace_end);
    CHECK(result.effective_c.time == 31ns);
    CHECK(allocation_ids(result.outstanding) == std::vector<std::uint64_t>{1U});
  }
}

TEST_CASE("generation ended after c remains outstanding at c", "[analyzer][outstanding]") {
  using namespace std::chrono_literals;
  const std::vector events{
      allocation_event(1U, 105U, 10U, 0x2000U),
      reallocation_event(2U, 112U, 10U, 11U, 0x2000U),
      reallocation_event(3U, 125U, 11U, 12U, 0x2000U),
  };
  const auto encoded = make_trace(events);

  const auto at_twenty = analyze(encoded, {at(10ns), at(20ns), at(20ns)});
  CHECK(allocation_ids(at_twenty.outstanding) == std::vector<std::uint64_t>{11U});
  CHECK(at_twenty.candidate_count == 1U);

  const auto at_trace_end = analyze(encoded, {at(10ns), at(20ns), std::nullopt});
  CHECK(at_trace_end.outstanding.empty());
  CHECK(at_trace_end.ended_by_c_count == 1U);
}

TEST_CASE("outstanding sequence windows match the equivalent time windows",
          "[analyzer][outstanding][window]") {
  using namespace std::chrono_literals;
  const std::vector events{
      allocation_event(1U, 109U, 5U, 0x5000U), allocation_event(2U, 110U, 1U, 0x1000U),
      allocation_event(3U, 115U, 3U, 0x3000U), allocation_event(4U, 116U, 4U, 0x4000U),
      allocation_event(5U, 120U, 2U, 0x2000U), free_event(6U, 130U, 3U, 0x3000U),
      free_event(7U, 131U, 4U, 0x4000U),
  };

  const auto by_time = analyze(make_trace(events), {at(10ns), at(20ns), at(30ns)});
  const auto by_sequence = analyze(make_trace(events), {seq(2U), seq(5U), seq(6U)});
  CHECK(by_sequence.candidate_count == by_time.candidate_count);
  CHECK(by_sequence.ended_by_c_count == by_time.ended_by_c_count);
  CHECK(allocation_ids(by_sequence.outstanding) == allocation_ids(by_time.outstanding));
  CHECK(allocation_ids(by_sequence.outstanding) == std::vector<std::uint64_t>{1U, 4U});
  CHECK(by_sequence.effective_c.sequence == 6U);
  CHECK_FALSE(by_sequence.observation_uses_trace_end);
}

TEST_CASE("sequence bounds clamp to the trace end sequence", "[analyzer][outstanding][window]") {
  using namespace std::chrono_literals;
  const auto encoded =
      make_trace({allocation_event(1U, 110U, 1U, 0x1000U), allocation_event(2U, 115U, 2U, 0x2000U),
                  free_event(3U, 131U, 2U, 0x2000U)});

  SECTION("b beyond the final sequence becomes the trace end") {
    const auto result = analyze(encoded, {at(0ns), seq(999U), std::nullopt});
    CHECK(result.effective_b.sequence == 3U);
    CHECK(result.effective_b.time == 31ns);
    CHECK(result.effective_b == result.effective_c);
  }

  SECTION("b within the trace keeps its sequence kind") {
    const auto result = analyze(encoded, {at(0ns), seq(2U), std::nullopt});
    CHECK(result.effective_b.sequence == 2U);
    CHECK_FALSE(result.effective_b.time.has_value());
    CHECK(result.candidate_count == 1U);
  }

  SECTION("c beyond the final sequence observes at the trace end") {
    const auto result = analyze(encoded, {at(0ns), std::nullopt, seq(999U)});
    CHECK(result.observation_uses_trace_end);
    CHECK(result.effective_c.sequence == 3U);
    CHECK(result.effective_c.time == 31ns);
    CHECK(result.ended_by_c_count == 1U);
    CHECK(allocation_ids(result.outstanding) == std::vector<std::uint64_t>{1U});
  }

  SECTION("c sequence includes end events at that sequence") {
    const auto at_two = analyze(encoded, {at(0ns), std::nullopt, seq(2U)});
    CHECK_FALSE(at_two.observation_uses_trace_end);
    CHECK(at_two.effective_c.sequence == 2U);
    CHECK(at_two.ended_by_c_count == 0U);
    CHECK(allocation_ids(at_two.outstanding) == std::vector<std::uint64_t>{1U, 2U});

    const auto at_three = analyze(encoded, {at(0ns), std::nullopt, seq(3U)});
    CHECK(at_three.ended_by_c_count == 1U);
    CHECK(allocation_ids(at_three.outstanding) == std::vector<std::uint64_t>{1U});
  }
}

TEST_CASE("current-process virtual memory generations participate in outstanding windows",
          "[analyzer][outstanding]") {
  using namespace std::chrono_literals;
  auto all_events = noleax::testing::make_all_memory_event_kinds();
  auto allocation = all_events[5];
  allocation.header.sequence = noleax::trace::Sequence{1U};
  allocation.header.monotonic_ticks = 110U;
  auto free = all_events[6];
  free.header.sequence = noleax::trace::Sequence{2U};
  free.header.monotonic_ticks = 130U;

  const auto result = analyze(make_trace({allocation, free}), {at(10ns), at(20ns), at(20ns)});
  REQUIRE(result.outstanding.size() == 1U);
  CHECK(result.outstanding.front().kind == noleax::analyzer::GenerationKind::kVirtualAllocation);
  CHECK(result.outstanding.front().mapping_id == noleax::trace::MappingId{20U});
}

TEST_CASE("outstanding analysis validates its window against itself and the trace",
          "[analyzer][outstanding]") {
  using namespace std::chrono_literals;
  const auto encoded = make_trace({allocation_event(1U, 110U, 1U, 0x1000U)});

  SECTION("a after b") {
    std::istringstream input{encoded, std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_outstanding(input, {at(20ns), at(10ns), at(30ns)}),
                    noleax::analyzer::OutstandingAnalysisError);
  }

  SECTION("c before b") {
    std::istringstream input{encoded, std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_outstanding(input, {at(0ns), at(10ns), at(9ns)}),
                    noleax::analyzer::OutstandingAnalysisError);
  }

  SECTION("b after trace end clamps to the trace end") {
    const auto result = analyze(encoded, {at(0ns), at(1'000'000ns), std::nullopt});
    CHECK(result.effective_b == result.effective_c);
    REQUIRE(result.outstanding.size() == 1U);
    CHECK(result.outstanding.front().allocation_id == noleax::trace::AllocationId{1U});
  }

  SECTION("a after c without b is rejected") {
    std::istringstream input{encoded, std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_outstanding(input, {at(10ns), std::nullopt, at(5ns)}),
                    noleax::analyzer::OutstandingAnalysisError);
  }

  SECTION("empty window") {
    const auto result = analyze(encoded, {at(10ns), at(10ns), at(10ns)});
    CHECK(result.candidate_count == 0U);
    CHECK(result.outstanding.empty());
  }
}

TEST_CASE("Loss and orphan ends keep outstanding results explicitly incomplete",
          "[analyzer][outstanding]") {
  using namespace std::chrono_literals;
  using namespace noleax::trace;

  SECTION("Loss record") {
    LossRecord loss;
    loss.reason = LossReason::kQueueFull;
    loss.location = LossLocation::kAgentQueue;
    loss.estimated_event_count = 1U;
    loss.sequence_range = SequenceRange{Sequence{2U}, Sequence{2U}};
    loss.tick_range = TickRange{112U, 112U};
    const auto result = analyze(make_trace({allocation_event(1U, 110U, 1U, 0x1000U)}, loss),
                                {at(10ns), at(11ns), std::nullopt});
    CHECK(result.trace.completeness.has(CompletenessIssue::kEventLoss));
    CHECK(result.trace.completeness.recommended_exit_code() == 2);
  }

  SECTION("orphan end") {
    const auto result = analyze(make_trace({free_event(1U, 110U, 99U, 0x9000U)}),
                                {at(0ns), at(10ns), std::nullopt});
    CHECK(result.orphaned_allocation_end_count == 1U);
    CHECK(result.trace.completeness.has(CompletenessIssue::kEventLoss));
    CHECK(result.trace.completeness.recommended_exit_code() == 2);
  }
}
