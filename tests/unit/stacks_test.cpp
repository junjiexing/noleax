#include "noleax/analyzer/stacks.hpp"

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <ios>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "noleax/agent/windows/hook_registry.hpp"
#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/wire_format.hpp"
#include "support/synthetic_trace.hpp"

namespace {

using namespace std::chrono_literals;

[[nodiscard]] noleax::trace::FileHeader file_header() {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.monotonic_frequency = 1'000'000'000U;
  header.monotonic_origin = 100U;
  return header;
}

[[nodiscard]] noleax::trace::EventHeader event_header(std::uint64_t sequence, std::uint64_t ticks,
                                                      std::uint64_t stack_id) {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{sequence};
  header.monotonic_ticks = ticks;
  header.thread_id = 7U;
  header.api_id = 1U;
  header.status = noleax::trace::EventStatus::kSuccess;
  header.stack_id = noleax::trace::StackId{stack_id};
  return header;
}

[[nodiscard]] noleax::trace::Event allocation_event(std::uint64_t sequence, std::uint64_t ticks,
                                                    std::uint64_t stack_id, std::uint64_t id,
                                                    std::uint64_t size) {
  noleax::trace::AllocationEvent allocation;
  allocation.heap_handle = 0x1001U;
  allocation.heap_id = noleax::trace::HeapId{1U};
  allocation.requested_size = size;
  allocation.result_address = 0x2000U + id * 0x10U;
  allocation.allocation_id = noleax::trace::AllocationId{id};
  return noleax::trace::Event{event_header(sequence, ticks, stack_id), allocation};
}

[[nodiscard]] noleax::trace::Event reallocation_event(std::uint64_t sequence, std::uint64_t ticks,
                                                      std::uint64_t stack_id, std::uint64_t old_id,
                                                      std::uint64_t new_id, std::uint64_t size) {
  noleax::trace::ReallocationEvent reallocation;
  reallocation.heap_handle = 0x1001U;
  reallocation.heap_id = noleax::trace::HeapId{1U};
  reallocation.old_address = 0x2000U + old_id * 0x10U;
  reallocation.old_allocation_id = noleax::trace::AllocationId{old_id};
  reallocation.requested_size = size;
  reallocation.result_address = 0x2000U + new_id * 0x10U;
  reallocation.new_allocation_id = noleax::trace::AllocationId{new_id};
  reallocation.effect = noleax::trace::ReallocationEffect::kNewGeneration;
  return noleax::trace::Event{event_header(sequence, ticks, stack_id), reallocation};
}

[[nodiscard]] noleax::trace::Event free_event(std::uint64_t sequence, std::uint64_t ticks,
                                              std::uint64_t stack_id, std::uint64_t id) {
  noleax::trace::FreeEvent free;
  free.heap_handle = 0x1001U;
  free.heap_id = noleax::trace::HeapId{1U};
  free.address = 0x2000U + id * 0x10U;
  free.allocation_id = noleax::trace::AllocationId{id};
  free.raw_result = 1U;
  return noleax::trace::Event{event_header(sequence, ticks, stack_id), free};
}

[[nodiscard]] noleax::trace::Event failed_allocation_event(std::uint64_t sequence,
                                                           std::uint64_t ticks,
                                                           std::uint64_t stack_id) {
  noleax::trace::AllocationEvent allocation;
  allocation.heap_handle = 0x1001U;
  allocation.heap_id = noleax::trace::HeapId{1U};
  allocation.requested_size = 64U;
  auto event = noleax::trace::Event{event_header(sequence, ticks, stack_id), allocation};
  event.header.status = noleax::trace::EventStatus::kFailure;
  return event;
}

[[nodiscard]] std::string make_trace(const std::vector<noleax::trace::Event>& events) {
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
  for (const auto& event : events) {
    builder.add_event(event);
  }
  return builder.finish_normally().build();
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

[[nodiscard]] noleax::analyzer::EventsStacksResult analyze_events(
    const std::string& encoded, noleax::analyzer::StacksSort sort,
    noleax::analyzer::StacksWindow window = {},
    const noleax::analyzer::AnalysisFilter& filter = {}) {
  std::istringstream input{encoded, std::ios::binary};
  return noleax::analyzer::analyze_event_stacks(input, window, sort, filter);
}

[[nodiscard]] noleax::analyzer::LeaksStacksResult analyze_leaks(
    const std::string& encoded, noleax::analyzer::StacksSort sort,
    noleax::analyzer::OutstandingWindow window = {},
    const noleax::analyzer::AnalysisFilter& filter = {}) {
  std::istringstream input{encoded, std::ios::binary};
  return noleax::analyzer::analyze_leak_stacks(input, window, sort, filter);
}

}  // namespace

TEST_CASE("event stacks merge alloc and realloc sharing a call stack", "[analyzer][stacks]") {
  const auto encoded = make_trace({
      allocation_event(1U, 110U, 11U, 1U, 64U),
      allocation_event(2U, 120U, 11U, 2U, 32U),
      reallocation_event(3U, 130U, 11U, 1U, 3U, 80U),
      allocation_event(4U, 140U, 22U, 4U, 16U),
  });

  const auto result = analyze_events(encoded, noleax::analyzer::StacksSort::kAllocBytes);
  REQUIRE(result.groups.size() == 2U);
  const auto& first = result.groups.front();
  CHECK(first.stack_id == noleax::trace::StackId{11U});
  CHECK(first.calls == 3U);
  CHECK(first.alloc_calls == 3U);
  CHECK(first.alloc_bytes == 64U + 32U + 80U);
  CHECK(first.free_calls == 0U);
  CHECK(result.groups.back().stack_id == noleax::trace::StackId{22U});
  CHECK(result.aggregated_event_count == 4U);
}

TEST_CASE("event stacks track free bytes and unmatched frees", "[analyzer][stacks]") {
  const auto encoded = make_trace({
      allocation_event(1U, 110U, 11U, 1U, 96U),
      free_event(2U, 120U, 11U, 1U),
      free_event(3U, 130U, 11U, 99U),
  });

  const auto result = analyze_events(encoded, noleax::analyzer::StacksSort::kCalls);
  REQUIRE(result.groups.size() == 1U);
  const auto& group = result.groups.front();
  CHECK(group.calls == 3U);
  CHECK(group.alloc_calls == 1U);
  CHECK(group.alloc_bytes == 96U);
  CHECK(group.free_calls == 2U);
  CHECK(group.free_bytes == 96U);
  CHECK(group.net_bytes() == 0);
  CHECK(result.unmatched_free_count == 1U);
}

TEST_CASE("event stacks skip failed calls and events outside the window", "[analyzer][stacks]") {
  const auto encoded = make_trace({
      failed_allocation_event(1U, 105U, 11U),
      allocation_event(2U, 110U, 11U, 1U, 64U),
      allocation_event(3U, 120U, 11U, 2U, 32U),
      allocation_event(4U, 130U, 11U, 3U, 16U),
  });

  noleax::analyzer::StacksWindow window;
  window.from = at(15ns);
  window.to = at(25ns);
  const auto result = analyze_events(encoded, noleax::analyzer::StacksSort::kCalls, window);
  REQUIRE(result.groups.size() == 1U);
  CHECK(result.groups.front().calls == 1U);
  CHECK(result.groups.front().alloc_bytes == 32U);
  CHECK(result.aggregated_event_count == 1U);
}

TEST_CASE("event stacks apply sequence bounds like time bounds", "[analyzer][stacks][window]") {
  const auto encoded = make_trace({
      failed_allocation_event(1U, 105U, 11U),
      allocation_event(2U, 110U, 11U, 1U, 64U),
      allocation_event(3U, 120U, 11U, 2U, 32U),
      allocation_event(4U, 130U, 11U, 3U, 16U),
  });

  noleax::analyzer::StacksWindow window;
  window.from = seq(3U);
  window.to = seq(4U);
  const auto result = analyze_events(encoded, noleax::analyzer::StacksSort::kCalls, window);
  REQUIRE(result.groups.size() == 1U);
  CHECK(result.groups.front().calls == 1U);
  CHECK(result.groups.front().alloc_bytes == 32U);
  CHECK(result.aggregated_event_count == 1U);
}

TEST_CASE("event stacks honor the analysis filter", "[analyzer][stacks]") {
  const auto encoded = make_trace({
      allocation_event(1U, 110U, 11U, 1U, 64U),
      allocation_event(2U, 120U, 11U, 2U, 32U),
  });
  noleax::analyzer::AnalysisFilterCriteria criteria;
  criteria.minimum_size = 64U;
  const noleax::analyzer::AnalysisFilter filter{std::move(criteria)};

  const auto result = analyze_events(encoded, noleax::analyzer::StacksSort::kCalls, {}, filter);
  REQUIRE(result.groups.size() == 1U);
  CHECK(result.groups.front().calls == 1U);
  CHECK(result.groups.front().alloc_bytes == 64U);
}

TEST_CASE("event stacks sort by every key with stable stack id ties", "[analyzer][stacks]") {
  const auto encoded = make_trace({
      allocation_event(1U, 110U, 11U, 1U, 16U),
      allocation_event(2U, 120U, 11U, 2U, 16U),
      allocation_event(3U, 130U, 22U, 3U, 128U),
      allocation_event(4U, 140U, 33U, 4U, 8U),
      free_event(5U, 150U, 33U, 4U),
  });

  const auto by_calls = analyze_events(encoded, noleax::analyzer::StacksSort::kCalls);
  REQUIRE(by_calls.groups.size() == 3U);
  CHECK(by_calls.groups[0].stack_id == noleax::trace::StackId{11U});
  CHECK(by_calls.groups[1].stack_id == noleax::trace::StackId{33U});

  const auto by_alloc = analyze_events(encoded, noleax::analyzer::StacksSort::kAllocBytes);
  CHECK(by_alloc.groups[0].stack_id == noleax::trace::StackId{22U});

  const auto by_free = analyze_events(encoded, noleax::analyzer::StacksSort::kFreeBytes);
  CHECK(by_free.groups[0].stack_id == noleax::trace::StackId{33U});
  CHECK(by_free.groups[0].free_bytes == 8U);

  const auto by_net = analyze_events(encoded, noleax::analyzer::StacksSort::kNetBytes);
  CHECK(by_net.groups[0].stack_id == noleax::trace::StackId{22U});
  CHECK(by_net.groups[0].net_bytes() == 128);
}

TEST_CASE("leak stacks merge surviving generations sharing a call stack", "[analyzer][stacks]") {
  const auto encoded = make_trace({
      allocation_event(1U, 110U, 11U, 1U, 64U),
      allocation_event(2U, 120U, 11U, 2U, 32U),
      allocation_event(3U, 130U, 22U, 3U, 48U),
      free_event(4U, 140U, 22U, 3U),
  });

  const auto result = analyze_leaks(encoded, noleax::analyzer::StacksSort::kBytes);
  REQUIRE(result.groups.size() == 1U);
  const auto& group = result.groups.front();
  CHECK(group.stack_id == noleax::trace::StackId{11U});
  CHECK(group.calls == 2U);
  CHECK(group.bytes == 96U);
  CHECK(result.outstanding.outstanding.size() == 2U);
}

TEST_CASE("leak stacks respect the creation window and sort by calls", "[analyzer][stacks]") {
  const auto encoded = make_trace({
      allocation_event(1U, 105U, 11U, 1U, 64U),
      allocation_event(2U, 115U, 11U, 2U, 64U),
      allocation_event(3U, 125U, 22U, 3U, 8U),
      allocation_event(4U, 135U, 22U, 4U, 8U),
  });

  noleax::analyzer::OutstandingWindow window;
  window.a = at(12ns);
  const auto result = analyze_leaks(encoded, noleax::analyzer::StacksSort::kCalls, window);
  REQUIRE(result.groups.size() == 2U);
  CHECK(result.groups[0].stack_id == noleax::trace::StackId{22U});
  CHECK(result.groups[0].calls == 2U);
  CHECK(result.groups[0].bytes == 16U);
  CHECK(result.groups[1].stack_id == noleax::trace::StackId{11U});
  CHECK(result.groups[1].calls == 1U);
}

TEST_CASE("leak stacks apply sequence creation windows", "[analyzer][stacks][window]") {
  const auto encoded = make_trace({
      allocation_event(1U, 105U, 11U, 1U, 64U),
      allocation_event(2U, 115U, 11U, 2U, 64U),
      allocation_event(3U, 125U, 22U, 3U, 8U),
      allocation_event(4U, 135U, 22U, 4U, 8U),
  });

  noleax::analyzer::OutstandingWindow window;
  window.a = seq(2U);
  window.b = seq(3U);
  const auto result = analyze_leaks(encoded, noleax::analyzer::StacksSort::kCalls, window);
  REQUIRE(result.groups.size() == 1U);
  CHECK(result.groups[0].stack_id == noleax::trace::StackId{11U});
  CHECK(result.groups[0].calls == 1U);
  CHECK(result.outstanding.candidate_count == 1U);
}

TEST_CASE("leak stacks default the window to the whole trace", "[analyzer][stacks]") {
  const auto encoded = make_trace({
      allocation_event(1U, 110U, 11U, 1U, 64U),
      free_event(2U, 120U, 11U, 1U),
      allocation_event(3U, 130U, 11U, 2U, 48U),
  });

  const auto result = analyze_leaks(encoded, noleax::analyzer::StacksSort::kBytes);
  REQUIRE(result.groups.size() == 1U);
  CHECK(result.groups.front().calls == 1U);
  CHECK(result.groups.front().bytes == 48U);
  CHECK(result.outstanding.effective_b == result.outstanding.effective_c);
  CHECK(result.outstanding.observation_uses_trace_end);
}

TEST_CASE("event stacks record group api ids in first-seen order", "[analyzer][stacks]") {
  auto free = free_event(3U, 130U, 11U, 1U);
  free.header.api_id = noleax::agent::windows::kRtlFreeHeapApiId;
  const auto encoded = make_trace({
      allocation_event(1U, 110U, 11U, 1U, 64U),
      allocation_event(2U, 120U, 11U, 2U, 32U),
      free,
  });

  const auto result = analyze_events(encoded, noleax::analyzer::StacksSort::kCalls);
  REQUIRE(result.groups.size() == 1U);
  const auto& group = result.groups.front();
  REQUIRE(group.api_ids.size() == 2U);
  CHECK(group.api_ids.front() == noleax::agent::windows::kRtlAllocateHeapApiId);
  CHECK(group.api_ids.back() == noleax::agent::windows::kRtlFreeHeapApiId);
}

TEST_CASE("leak stacks record group api ids", "[analyzer][stacks]") {
  const auto encoded = make_trace({
      allocation_event(1U, 110U, 11U, 1U, 64U),
      allocation_event(2U, 120U, 11U, 2U, 32U),
  });

  const auto result = analyze_leaks(encoded, noleax::analyzer::StacksSort::kBytes);
  REQUIRE(result.groups.size() == 1U);
  REQUIRE(result.groups.front().api_ids.size() == 1U);
  CHECK(result.groups.front().api_ids.front() == noleax::agent::windows::kRtlAllocateHeapApiId);
}

TEST_CASE("group api names resolve canonical hook names", "[analyzer][stacks]") {
  const std::vector<noleax::trace::ApiId> ids{noleax::agent::windows::kRtlAllocateHeapApiId,
                                              noleax::agent::windows::kRtlFreeHeapApiId, 9999U};
  const auto names = noleax::analyzer::group_api_names(ids);
  REQUIRE(names.size() == 3U);
  CHECK(names[0] == "RtlAllocateHeap");
  CHECK(names[1] == "RtlFreeHeap");
  CHECK(names[2] == "api-9999");
}
