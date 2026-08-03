#include "noleax/analyzer/filter.hpp"

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <ios>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "noleax/analyzer/console.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/wire_format.hpp"
#include "support/synthetic_trace.hpp"

namespace {

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

[[nodiscard]] noleax::trace::FileHeader file_header() {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.monotonic_frequency = 1'000'000'000U;
  header.monotonic_origin = 100U;
  return header;
}

[[nodiscard]] noleax::trace::EventHeader event_header(
    std::uint64_t sequence, std::uint64_t ticks, std::uint64_t thread_id = 7U,
    noleax::trace::EventStatus status = noleax::trace::EventStatus::kSuccess) {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{sequence};
  header.monotonic_ticks = ticks;
  header.thread_id = thread_id;
  header.api_id = 1U;
  header.status = status;
  header.stack_id = noleax::trace::StackId{sequence + 100U};
  return header;
}

[[nodiscard]] noleax::trace::Event allocation_event(std::uint64_t sequence, std::uint64_t ticks,
                                                    std::uint64_t id, std::uint64_t size,
                                                    std::uint64_t thread_id = 7U) {
  noleax::trace::AllocationEvent allocation;
  allocation.heap_handle = 0x1001U;
  allocation.heap_id = noleax::trace::HeapId{1U};
  allocation.requested_size = size;
  allocation.result_address = 0x1000U * id;
  allocation.allocation_id = noleax::trace::AllocationId{id};
  return noleax::trace::Event{event_header(sequence, ticks, thread_id), allocation};
}

[[nodiscard]] noleax::trace::Event reallocation_event(std::uint64_t old_id, std::uint64_t new_id) {
  noleax::trace::ReallocationEvent reallocation;
  reallocation.heap_handle = 0x1001U;
  reallocation.heap_id = noleax::trace::HeapId{1U};
  reallocation.old_address = 0x1000U * old_id;
  reallocation.old_allocation_id = noleax::trace::AllocationId{old_id};
  reallocation.requested_size = 128U;
  reallocation.result_address = 0x1000U * new_id;
  reallocation.new_allocation_id = noleax::trace::AllocationId{new_id};
  reallocation.effect = noleax::trace::ReallocationEffect::kNewGeneration;
  return noleax::trace::Event{event_header(1U, 110U), reallocation};
}

[[nodiscard]] noleax::trace::Event free_event(std::uint64_t sequence, std::uint64_t ticks,
                                              std::uint64_t id, std::uint64_t thread_id) {
  noleax::trace::FreeEvent free;
  free.heap_handle = 0x1001U;
  free.heap_id = noleax::trace::HeapId{1U};
  free.address = 0x1000U * id;
  free.allocation_id = noleax::trace::AllocationId{id};
  free.raw_result = 1U;
  return noleax::trace::Event{event_header(sequence, ticks, thread_id), free};
}

[[nodiscard]] std::string make_trace(const std::vector<noleax::trace::Event>& events) {
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
  for (const auto& event : events) {
    builder.add_event(event);
  }
  return builder.finish_normally().build();
}

}  // namespace

TEST_CASE("analysis filter combines categories with AND and values with OR", "[analyzer][filter]") {
  using noleax::trace::EventOperation;
  using noleax::trace::EventStatus;

  noleax::analyzer::AnalysisFilterCriteria criteria;
  criteria.minimum_size = 64U;
  criteria.maximum_size = 64U;
  criteria.operations = {EventOperation::kAllocate, EventOperation::kFree};
  criteria.thread_ids = {6U, 7U};
  criteria.allocation_ids = {9U, 10U};
  criteria.statuses = {EventStatus::kFailure, EventStatus::kSuccess};
  const noleax::analyzer::AnalysisFilter filter{std::move(criteria)};

  const auto matching = allocation_event(1U, 110U, 10U, 64U);
  CHECK(filter.matches_event(matching));

  auto wrong_thread = matching;
  wrong_thread.header.thread_id = 8U;
  CHECK_FALSE(filter.matches_event(wrong_thread));

  auto wrong_size = matching;
  std::get<noleax::trace::AllocationEvent>(wrong_size.payload).requested_size = 65U;
  CHECK_FALSE(filter.matches_event(wrong_size));

  auto wrong_operation = matching;
  noleax::trace::HeapCreateEvent heap_create;
  heap_create.heap_handle = 0x5000U;
  heap_create.heap_id = noleax::trace::HeapId{5U};
  wrong_operation.payload = heap_create;
  CHECK_FALSE(filter.matches_event(wrong_operation));
}

TEST_CASE("allocation ID filters recognize both realloc generations", "[analyzer][filter]") {
  for (const auto id : {10U, 11U}) {
    noleax::analyzer::AnalysisFilterCriteria criteria;
    criteria.allocation_ids = {id};
    CHECK(noleax::analyzer::AnalysisFilter{std::move(criteria)}.matches_event(
        reallocation_event(10U, 11U)));
  }

  noleax::analyzer::AnalysisFilterCriteria criteria;
  criteria.allocation_ids = {12U};
  CHECK_FALSE(noleax::analyzer::AnalysisFilter{std::move(criteria)}.matches_event(
      reallocation_event(10U, 11U)));
}

TEST_CASE("size filters reject events without an intrinsic size", "[analyzer][filter]") {
  noleax::analyzer::AnalysisFilterCriteria criteria;
  criteria.minimum_size = 1U;
  const noleax::analyzer::AnalysisFilter filter{std::move(criteria)};
  CHECK_FALSE(filter.matches_event(free_event(1U, 110U, 1U, 7U)));

  auto events = noleax::testing::make_all_memory_event_kinds();
  CHECK(filter.matches_event(events[5]));
  CHECK_FALSE(filter.matches_event(events[6]));
  CHECK(filter.matches_event(events[7]));
  CHECK_FALSE(filter.matches_event(events[8]));
}

TEST_CASE("API names and module globs use documented matching rules", "[analyzer][filter]") {
  noleax::analyzer::EventMetadata metadata;
  metadata.api_name = "RtlAllocateHeap";
  metadata.api_module = R"(C:\Windows\System32\KernelBase.DLL)";
  metadata.stack_modules = {R"(C:\apps\EngineCore.dll)", R"(C:\Windows\ntdll.dll)"};

  noleax::analyzer::AnalysisFilterCriteria criteria;
  criteria.api_names = {"RtlAllocateHeap"};
  criteria.module_patterns = {"kernel*.dll"};
  criteria.stack_module_patterns = {"ENGINE?ORE.DLL"};
  const noleax::analyzer::AnalysisFilter filter{std::move(criteria)};
  CHECK(filter.requires_metadata());
  CHECK(filter.matches_event(allocation_event(1U, 110U, 1U, 64U), metadata));
  CHECK_FALSE(filter.matches_event(allocation_event(1U, 110U, 1U, 64U)));

  noleax::analyzer::AnalysisFilterCriteria path_criteria;
  path_criteria.module_patterns = {"c:/windows/*/kernelbase.dll"};
  CHECK(noleax::analyzer::AnalysisFilter{std::move(path_criteria)}.matches_event(
      allocation_event(1U, 110U, 1U, 64U), metadata));

  noleax::analyzer::AnalysisFilterCriteria case_sensitive_api;
  case_sensitive_api.api_names = {"rtlallocateheap"};
  CHECK_FALSE(noleax::analyzer::AnalysisFilter{std::move(case_sensitive_api)}.matches_event(
      allocation_event(1U, 110U, 1U, 64U), metadata));
}

TEST_CASE("analysis filter rejects invalid ranges and empty names", "[analyzer][filter]") {
  noleax::analyzer::AnalysisFilterCriteria invalid_range;
  invalid_range.minimum_size = 2U;
  invalid_range.maximum_size = 1U;
  CHECK_THROWS_AS(noleax::analyzer::AnalysisFilter{std::move(invalid_range)},
                  noleax::analyzer::AnalysisFilterError);

  noleax::analyzer::AnalysisFilterCriteria empty_pattern;
  empty_pattern.module_patterns = {""};
  CHECK_THROWS_AS(noleax::analyzer::AnalysisFilter{std::move(empty_pattern)},
                  noleax::analyzer::AnalysisFilterError);
}

TEST_CASE("events mode streams only matching events", "[analyzer][filter]") {
  const auto encoded =
      make_trace({allocation_event(1U, 110U, 1U, 32U, 7U), allocation_event(2U, 111U, 2U, 128U, 8U),
                  allocation_event(3U, 112U, 3U, 256U, 7U)});
  noleax::analyzer::AnalysisFilterCriteria criteria;
  criteria.minimum_size = 64U;
  criteria.maximum_size = 256U;
  criteria.operations = {noleax::trace::EventOperation::kAllocate};
  criteria.thread_ids = {7U};
  criteria.api_names = {"RtlAllocateHeap"};
  const noleax::analyzer::AnalysisFilter filter{std::move(criteria)};

  std::vector<std::uint64_t> matched_ids;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_event = [&matched_ids](const noleax::trace::Event& event) {
    matched_ids.push_back(
        std::get<noleax::trace::AllocationEvent>(event.payload).allocation_id.value());
  };
  std::istringstream input{encoded, std::ios::binary};
  const auto result = noleax::analyzer::analyze_filtered_events(
      input, filter, callbacks, [](const noleax::trace::Event&) {
        noleax::analyzer::EventMetadata metadata;
        metadata.api_name = "RtlAllocateHeap";
        return metadata;
      });

  CHECK(matched_ids == std::vector<std::uint64_t>{3U});
  CHECK(result.matched_event_count == 1U);
  CHECK(result.filtered_event_count == 2U);
  CHECK(result.trace.event_count == 3U);

  std::istringstream missing_resolver{encoded, std::ios::binary};
  CHECK_THROWS_AS(noleax::analyzer::analyze_filtered_events(missing_resolver, filter),
                  noleax::analyzer::AnalysisFilterError);
}

TEST_CASE("events mode applies the analysis window before the filter",
          "[analyzer][filter][window]") {
  using namespace std::chrono_literals;
  const auto encoded =
      make_trace({allocation_event(1U, 110U, 1U, 64U, 7U), allocation_event(2U, 111U, 2U, 64U, 7U),
                  allocation_event(3U, 112U, 3U, 64U, 7U)});

  SECTION("time window") {
    noleax::analyzer::FilteredEventsWindow window;
    window.from = at(11ns);
    window.to = at(12ns);
    std::vector<std::uint64_t> matched_ids;
    noleax::analyzer::EventStreamCallbacks callbacks;
    callbacks.on_event = [&matched_ids](const noleax::trace::Event& event) {
      matched_ids.push_back(
          std::get<noleax::trace::AllocationEvent>(event.payload).allocation_id.value());
    };
    std::istringstream input{encoded, std::ios::binary};
    const auto result = noleax::analyzer::analyze_filtered_events(
        input, noleax::analyzer::AnalysisFilter{}, callbacks, {}, {}, window);
    CHECK(matched_ids == std::vector<std::uint64_t>{2U});
    CHECK(result.matched_event_count == 1U);
    CHECK(result.filtered_event_count == 2U);
    CHECK(result.trace.event_count == 3U);
  }

  SECTION("sequence window") {
    noleax::analyzer::FilteredEventsWindow window;
    window.from = seq(2U);
    window.to = seq(3U);
    std::vector<std::uint64_t> matched_ids;
    noleax::analyzer::EventStreamCallbacks callbacks;
    callbacks.on_event = [&matched_ids](const noleax::trace::Event& event) {
      matched_ids.push_back(
          std::get<noleax::trace::AllocationEvent>(event.payload).allocation_id.value());
    };
    std::istringstream input{encoded, std::ios::binary};
    const auto result = noleax::analyzer::analyze_filtered_events(
        input, noleax::analyzer::AnalysisFilter{}, callbacks, {}, {}, window);
    CHECK(matched_ids == std::vector<std::uint64_t>{2U});
    CHECK(result.matched_event_count == 1U);
    CHECK(result.filtered_event_count == 2U);
  }

  SECTION("mixed window requires time and sequence") {
    noleax::analyzer::FilteredEventsWindow window;
    window.from = at(11ns);
    window.from.sequence = 3U;
    std::istringstream input{encoded, std::ios::binary};
    const auto result = noleax::analyzer::analyze_filtered_events(
        input, noleax::analyzer::AnalysisFilter{}, {}, {}, {}, window);
    CHECK(result.matched_event_count == 1U);
    CHECK(result.filtered_event_count == 2U);
  }

  SECTION("default window keeps every event") {
    std::istringstream input{encoded, std::ios::binary};
    const auto result =
        noleax::analyzer::analyze_filtered_events(input, noleax::analyzer::AnalysisFilter{});
    CHECK(result.matched_event_count == 3U);
    CHECK(result.filtered_event_count == 0U);
  }
}

TEST_CASE("events console pipeline honors the analysis window", "[analyzer][filter][window]") {
  const auto encoded =
      make_trace({allocation_event(1U, 110U, 1U, 64U, 7U), allocation_event(2U, 111U, 2U, 64U, 7U),
                  allocation_event(3U, 112U, 3U, 64U, 7U)});
  noleax::analyzer::FilteredEventsWindow window;
  window.from = seq(2U);

  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  const auto result = noleax::analyzer::analyze_events_to_console(
      input, output, noleax::analyzer::AnalysisFilter{}, {}, {}, {}, {}, window);
  CHECK(result.matched_event_count == 2U);
  CHECK(result.filtered_event_count == 1U);
  CHECK(output.str().find("event #1 ") == std::string::npos);
  CHECK(output.str().find("event #2 ") != std::string::npos);
  CHECK(output.str().find("event #3 ") != std::string::npos);
}

TEST_CASE("outstanding mode restores all state before filtering final candidates",
          "[analyzer][filter][outstanding]") {
  using namespace std::chrono_literals;
  const auto encoded =
      make_trace({allocation_event(1U, 110U, 1U, 64U, 7U), allocation_event(2U, 111U, 2U, 64U, 8U),
                  free_event(3U, 120U, 1U, 99U)});
  noleax::analyzer::AnalysisFilterCriteria criteria;
  criteria.thread_ids = {7U};
  const noleax::analyzer::AnalysisFilter filter{std::move(criteria)};

  std::istringstream input{encoded, std::ios::binary};
  const auto result =
      noleax::analyzer::analyze_filtered_outstanding(input, {at(10ns), at(12ns), at(20ns)}, filter);

  CHECK(result.candidate_count == 2U);
  CHECK(result.ended_by_c_count == 1U);
  CHECK(result.filtered_out_count == 1U);
  CHECK(result.outstanding.empty());
}
