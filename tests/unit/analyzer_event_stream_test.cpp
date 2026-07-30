#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/record_codec.hpp"
#include "noleax/trace/trace_writer.hpp"
#include "noleax/trace/wire_format.hpp"
#include "support/synthetic_trace.hpp"

namespace {

[[nodiscard]] noleax::trace::FileHeader file_header() {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.session_id[0] = std::byte{0x42};
  header.monotonic_frequency = 10'000'000U;
  return header;
}

[[nodiscard]] noleax::trace::CaptureStatistics statistics_for_count(std::uint64_t count) {
  noleax::trace::CaptureStatistics statistics;
  statistics.observed_calls = count;
  statistics.successful_operations = count;
  statistics.unique_stacks = count;
  if (count != 0U) {
    noleax::trace::ApiStatistics api;
    api.api_id = 1U;
    api.observed_calls = count;
    api.successful_operations = count;
    statistics.per_api.push_back(api);
  }
  return statistics;
}

[[nodiscard]] noleax::trace::CaptureStatistics statistics_for_events(
    const std::vector<noleax::trace::Event>& events) {
  noleax::trace::CaptureStatistics statistics;
  for (const auto& event : events) {
    ++statistics.observed_calls;
    if (noleax::trace::call_succeeded(event.header.status)) {
      ++statistics.successful_operations;
    } else {
      ++statistics.failed_operations;
    }
    ++statistics.unique_stacks;

    auto api = std::find_if(statistics.per_api.begin(), statistics.per_api.end(),
                            [&event](const noleax::trace::ApiStatistics& candidate) {
                              return candidate.api_id == event.header.api_id;
                            });
    if (api == statistics.per_api.end()) {
      noleax::trace::ApiStatistics new_api;
      new_api.api_id = event.header.api_id;
      statistics.per_api.push_back(new_api);
      api = statistics.per_api.end() - 1;
    }
    ++api->observed_calls;
    if (noleax::trace::call_succeeded(event.header.status)) {
      ++api->successful_operations;
    } else {
      ++api->failed_operations;
    }
  }
  return statistics;
}

[[nodiscard]] noleax::trace::EndOfTrace normal_end(std::uint64_t sequence, std::uint64_t ticks) {
  noleax::trace::EndOfTrace end;
  end.final_sequence = noleax::trace::Sequence{sequence};
  end.final_monotonic_ticks = ticks;
  end.normal_stop = true;
  end.target_exit_code = 0;
  return end;
}

struct ChunkInput {
  noleax::trace::ChunkDescriptor descriptor;
  std::vector<std::byte> payload;
};

[[nodiscard]] noleax::trace::ChunkDescriptor descriptor(noleax::trace::ChunkType type,
                                                        std::uint64_t sequence_begin = 0U,
                                                        std::uint64_t sequence_end = 0U) {
  noleax::trace::ChunkDescriptor result;
  result.type = type;
  result.sequence_begin = noleax::trace::Sequence{sequence_begin};
  result.sequence_end = noleax::trace::Sequence{sequence_end};
  return result;
}

[[nodiscard]] std::string write_trace(const std::vector<ChunkInput>& chunks) {
  std::ostringstream output{std::ios::binary};
  noleax::trace::TraceWriter writer{output, file_header()};
  for (const auto& chunk : chunks) {
    if (writer.write_chunk(chunk.descriptor, chunk.payload) !=
        noleax::trace::ChunkWriteResult::kWritten) {
      throw std::runtime_error{"test trace unexpectedly reached its file size limit"};
    }
  }
  return output.str();
}

[[nodiscard]] std::vector<std::byte> metadata_payload(noleax::trace::CaptureScope scope = {true,
                                                                                           false}) {
  std::vector<std::byte> payload;
  noleax::trace::append_capture_scope_record(payload, scope);
  return payload;
}

[[nodiscard]] std::vector<std::byte> event_payload(
    const std::vector<noleax::trace::Event>& events) {
  std::vector<std::byte> payload;
  for (const auto& event : events) {
    noleax::trace::append_event_record(payload, event);
  }
  return payload;
}

[[nodiscard]] noleax::trace::StackDefinition stack_definition(std::uint64_t id = 101U) {
  noleax::trace::StackDefinition definition;
  definition.stack_id = noleax::trace::StackId{id};
  definition.status = noleax::trace::StackCaptureStatus::kComplete;
  definition.frames.push_back({{}, 0U, 0x00007FF612341234ULL, 0U});
  return definition;
}

[[nodiscard]] std::vector<std::byte> stack_payload(
    const std::vector<noleax::trace::StackDefinition>& definitions) {
  std::vector<std::byte> payload;
  for (const auto& definition : definitions) {
    noleax::trace::append_stack_definition_record(payload, definition);
  }
  return payload;
}

[[nodiscard]] std::vector<std::byte> module_payload(
    const std::vector<noleax::trace::ModuleRecord>& records) {
  std::vector<std::byte> payload;
  for (const auto& record : records) {
    if (const auto* load = std::get_if<noleax::trace::ModuleLoad>(&record)) {
      noleax::trace::append_module_load_record(payload, *load);
    } else {
      noleax::trace::append_module_unload_record(payload,
                                                 std::get<noleax::trace::ModuleUnload>(record));
    }
  }
  return payload;
}

[[nodiscard]] std::vector<std::byte> statistics_payload(
    const noleax::trace::CaptureStatistics& statistics) {
  std::vector<std::byte> payload;
  noleax::trace::append_statistics_record(payload, statistics);
  return payload;
}

[[nodiscard]] std::vector<std::byte> end_payload(const noleax::trace::EndOfTrace& end) {
  std::vector<std::byte> payload;
  noleax::trace::append_end_of_trace_record(payload, end);
  return payload;
}

[[nodiscard]] noleax::analyzer::EventStreamResult analyze(
    const std::string& encoded, const noleax::analyzer::EventStreamCallbacks& callbacks = {}) {
  std::istringstream input{encoded, std::ios::binary};
  return noleax::analyzer::analyze_event_stream(input, callbacks);
}

[[nodiscard]] std::string complete_synthetic_trace() {
  const auto events = noleax::testing::make_all_memory_event_kinds();
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
  for (const auto& event : events) {
    builder.add_event(event);
  }
  builder.set_statistics(statistics_for_events(events)).finish_normally(17);
  return builder.build();
}

enum class CallbackKind : std::uint8_t {
  kFileHeader,
  kCaptureScope,
  kModuleLoad,
  kModuleUnload,
  kEvent,
  kLoss,
  kStatistics,
  kEnd,
};

}  // namespace

TEST_CASE("event stream preserves module generations across unload and base reuse",
          "[analyzer][events][module][stack]") {
  using namespace noleax::trace;
  ModuleLoad first;
  first.module_id = ModuleId{1U};
  first.monotonic_ticks = 1U;
  first.base_address = 0x100000U;
  first.image_size = 0x4000U;
  first.image_path = "C:/fixture/first.dll";
  const ModuleUnload unload{first.module_id, 3U};
  ModuleLoad second = first;
  second.module_id = ModuleId{2U};
  second.monotonic_ticks = 4U;
  second.image_path = "C:/fixture/second.dll";

  StackDefinition first_stack = stack_definition(201U);
  first_stack.frames[0] = {first.module_id, 0x123U, first.base_address + 0x123U, 0U};
  StackDefinition second_stack = stack_definition(202U);
  second_stack.frames[0] = {second.module_id, 0x123U, second.base_address + 0x123U, 0U};
  const auto encoded = write_trace({
      {descriptor(ChunkType::kMetadata), metadata_payload()},
      {descriptor(ChunkType::kModule), module_payload({ModuleRecord{first}})},
      {descriptor(ChunkType::kStack), stack_payload({first_stack})},
      {descriptor(ChunkType::kModule),
       module_payload({ModuleRecord{unload}, ModuleRecord{second}})},
      {descriptor(ChunkType::kStack), stack_payload({second_stack})},
      {descriptor(ChunkType::kEnd), end_payload(normal_end(0U, 4U))},
  });

  std::vector<ModuleLoad> loads;
  std::vector<ModuleUnload> unloads;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_module_load = [&loads](const ModuleLoad& load) { loads.push_back(load); };
  callbacks.on_module_unload = [&unloads](const ModuleUnload& value) { unloads.push_back(value); };
  const auto result = analyze(encoded, callbacks);
  CHECK(loads == std::vector{first, second});
  CHECK(unloads == std::vector{unload});
  CHECK(result.module_load_count == 2U);
  CHECK(result.module_unload_count == 1U);
  CHECK(result.stack_definition_count == 2U);
  CHECK(result.known_monotonic_end == 4U);
  CHECK_FALSE(result.partially_understood);

  first_stack.frames[0].module_offset = first.image_size;
  const auto invalid_stack = write_trace({
      {descriptor(ChunkType::kMetadata), metadata_payload()},
      {descriptor(ChunkType::kModule), module_payload({ModuleRecord{first}})},
      {descriptor(ChunkType::kStack), stack_payload({first_stack})},
  });
  CHECK_THROWS_AS(analyze(invalid_stack), noleax::analyzer::TraceAnalysisError);

  const auto duplicate_id = write_trace({
      {descriptor(ChunkType::kMetadata), metadata_payload()},
      {descriptor(ChunkType::kModule), module_payload({ModuleRecord{first}, ModuleRecord{first}})},
  });
  CHECK_THROWS_AS(analyze(duplicate_id), noleax::analyzer::TraceAnalysisError);
}

TEST_CASE("event stream decodes stack definitions before referenced events",
          "[analyzer][events][stack]") {
  using namespace noleax::trace;
  const StackDefinition expected = stack_definition();
  Event referenced_event = noleax::testing::make_all_memory_event_kinds().front();
  referenced_event.header.sequence = Sequence{1U};
  referenced_event.header.monotonic_ticks = 1U;
  referenced_event.header.stack_id = expected.stack_id;
  const auto encoded = write_trace({
      {descriptor(ChunkType::kMetadata), metadata_payload()},
      {descriptor(ChunkType::kStack), stack_payload({expected})},
      {descriptor(ChunkType::kEvent, 1U, 1U), event_payload({referenced_event})},
      {descriptor(ChunkType::kStatistics),
       statistics_payload(statistics_for_events({referenced_event}))},
      {descriptor(ChunkType::kEnd), end_payload(normal_end(1U, 1U))},
  });

  std::vector<StackDefinition> observed;
  bool event_observed_after_definition = false;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_stack_definition = [&observed](const StackDefinition& definition) {
    observed.push_back(definition);
  };
  callbacks.on_event = [&observed, &event_observed_after_definition](const Event& event) {
    event_observed_after_definition =
        observed.size() == 1U && event.header.stack_id == observed.front().stack_id;
  };
  const auto result = analyze(encoded, callbacks);
  CHECK(observed == std::vector<StackDefinition>{expected});
  CHECK(event_observed_after_definition);
  CHECK(result.event_count == 1U);
  CHECK(result.stack_definition_count == 1U);
  CHECK_FALSE(result.partially_understood);

  const auto duplicate = write_trace({
      {descriptor(ChunkType::kMetadata), metadata_payload()},
      {descriptor(ChunkType::kStack), stack_payload({expected, expected})},
  });
  CHECK_THROWS_AS(analyze(duplicate), noleax::analyzer::TraceAnalysisError);
}

TEST_CASE("event stream decodes every normalized event in trace order", "[analyzer][events]") {
  using namespace noleax::trace;
  const auto encoded = complete_synthetic_trace();
  const auto expected_events = noleax::testing::make_all_memory_event_kinds();
  std::vector<Event> actual_events;
  std::vector<CallbackKind> callback_order;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_file_header = [&callback_order](const FileHeader&) {
    callback_order.push_back(CallbackKind::kFileHeader);
  };
  callbacks.on_capture_scope = [&callback_order](const CaptureScope&) {
    callback_order.push_back(CallbackKind::kCaptureScope);
  };
  callbacks.on_event = [&actual_events, &callback_order](const Event& event) {
    actual_events.push_back(event);
    callback_order.push_back(CallbackKind::kEvent);
  };
  callbacks.on_statistics = [&callback_order](const CaptureStatistics&) {
    callback_order.push_back(CallbackKind::kStatistics);
  };
  callbacks.on_end_of_trace = [&callback_order](const EndOfTrace&) {
    callback_order.push_back(CallbackKind::kEnd);
  };

  const auto result = analyze(encoded, callbacks);
  CHECK(actual_events == expected_events);
  std::vector<CallbackKind> expected_order{CallbackKind::kFileHeader, CallbackKind::kCaptureScope};
  expected_order.insert(expected_order.end(), expected_events.size(), CallbackKind::kEvent);
  expected_order.push_back(CallbackKind::kStatistics);
  expected_order.push_back(CallbackKind::kEnd);
  CHECK(callback_order == expected_order);
  CHECK(result.file_header == file_header());
  CHECK(result.capture_scope == CaptureScope{true, false});
  REQUIRE(result.statistics.has_value());
  CHECK(*result.statistics == statistics_for_events(expected_events));
  REQUIRE(result.end_of_trace.has_value());
  CHECK(result.end_of_trace->target_exit_code == 17);
  CHECK(result.known_sequence_end == Sequence{9U});
  CHECK(result.known_monotonic_end == 90U);
  CHECK(result.event_count == expected_events.size());
  CHECK(result.loss_record_count == 0U);
  CHECK(result.bytes_read == encoded.size());
  CHECK_FALSE(result.truncated);
  CHECK_FALSE(result.partially_understood);
  CHECK(result.completeness.overall_state() == CompletenessState::kComplete);
  CHECK(result.completeness.recommended_exit_code() == 0);
}

TEST_CASE("event stream folds capture loss and termination into completeness",
          "[analyzer][events]") {
  using namespace noleax::trace;
  LossRecord event_loss;
  event_loss.reason = LossReason::kQueueFull;
  event_loss.location = LossLocation::kAgentQueue;
  event_loss.estimated_event_count = 2U;
  event_loss.sequence_range = SequenceRange{Sequence{4U}, Sequence{5U}};
  event_loss.tick_range = TickRange{40U, 50U};

  LossRecord stack_loss;
  stack_loss.reason = LossReason::kStackCaptureFailed;
  stack_loss.location = LossLocation::kAgentQueue;
  stack_loss.estimated_event_count = 1U;

  std::vector<LossRecord> observed_losses;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_loss = [&observed_losses](const LossRecord& loss) {
    observed_losses.push_back(loss);
  };
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {false, true}};
  const auto encoded = builder.add_loss(event_loss).add_loss(stack_loss).finish_normally().build();
  const auto result = analyze(encoded, callbacks);

  CHECK(observed_losses == std::vector{event_loss, stack_loss});
  CHECK(result.loss_record_count == 2U);
  CHECK(result.known_sequence_end == Sequence{5U});
  CHECK(result.known_monotonic_end == 50U);
  CHECK(result.completeness.has(CompletenessIssue::kCaptureDidNotStartAtProcessStart));
  CHECK(result.completeness.has(CompletenessIssue::kPreexistingAllocationsUnknown));
  CHECK(result.completeness.has(CompletenessIssue::kEventLoss));
  CHECK(result.completeness.has(CompletenessIssue::kStackDataLoss));
  CHECK_FALSE(result.completeness.has(CompletenessIssue::kMissingEndOfTrace));
  CHECK(result.completeness.recommended_exit_code() == 2);
}

TEST_CASE("event stream preserves complete chunks before a truncated tail", "[analyzer][events]") {
  using namespace noleax::trace;
  auto encoded = complete_synthetic_trace();
  encoded.pop_back();
  std::uint64_t callbacks = 0U;
  noleax::analyzer::EventStreamCallbacks stream_callbacks;
  stream_callbacks.on_event = [&callbacks](const Event&) { ++callbacks; };

  const auto result = analyze(encoded, stream_callbacks);
  CHECK(callbacks == 9U);
  CHECK(result.event_count == 9U);
  CHECK(result.truncated);
  CHECK(result.completeness.has(CompletenessIssue::kTraceTruncated));
  CHECK(result.completeness.has(CompletenessIssue::kMissingEndOfTrace));
  CHECK_FALSE(result.end_of_trace.has_value());
  CHECK(result.completeness.recommended_exit_code() == 2);
}

TEST_CASE("event stream marks skipped future records as partially understood",
          "[analyzer][events]") {
  using namespace noleax::trace;
  const auto events = noleax::testing::make_all_memory_event_kinds();
  auto events_payload = event_payload({events.front()});
  append_record(events_payload, 0x7FFFU, 1U, {}, kDefaultMaximumRecordSize);
  const std::vector chunks{
      ChunkInput{descriptor(ChunkType::kMetadata), metadata_payload()},
      ChunkInput{descriptor(ChunkType::kEvent, 1U, 1U), events_payload},
      ChunkInput{descriptor(ChunkType::kEnd), end_payload(normal_end(1U, 10U))},
  };

  const auto result = analyze(write_trace(chunks));
  CHECK(result.event_count == 1U);
  CHECK(result.partially_understood);
  CHECK(result.completeness.has(CompletenessIssue::kUnknownRecordSkipped));
  CHECK(result.completeness.understanding_state() == UnderstandingState::kPartial);
  CHECK(result.completeness.recommended_exit_code() == 2);
}

TEST_CASE("event stream propagates reader format uncertainty", "[analyzer][events]") {
  using namespace noleax::trace;
  const auto metadata = metadata_payload();
  const std::vector chunks{
      ChunkInput{descriptor(ChunkType::kMetadata), metadata},
      ChunkInput{descriptor(ChunkType::kModule), {}},
      ChunkInput{descriptor(ChunkType::kEnd), end_payload(normal_end(0U, 0U))},
  };
  std::string encoded = write_trace(chunks);
  const std::size_t module_header_offset = kFileHeaderSize + kChunkHeaderSize + metadata.size();
  encoded.at(module_header_offset) = static_cast<char>(0xFF);
  encoded.at(module_header_offset + 1U) = static_cast<char>(0x7F);

  const auto result = analyze(encoded);
  CHECK(result.partially_understood);
  CHECK(result.completeness.has(CompletenessIssue::kPartiallyUnderstoodFormat));
  CHECK(result.completeness.understanding_state() == UnderstandingState::kPartial);
  CHECK(result.completeness.recommended_exit_code() == 2);
}

TEST_CASE("event chunks are validated atomically before callbacks", "[analyzer][events]") {
  using namespace noleax::trace;
  auto events = noleax::testing::make_all_memory_event_kinds();
  events[1].header.sequence = events[0].header.sequence;
  const std::vector chunks{
      ChunkInput{descriptor(ChunkType::kMetadata), metadata_payload()},
      ChunkInput{descriptor(ChunkType::kEvent, 1U, 1U), event_payload({events[0], events[1]})},
  };
  std::uint64_t callbacks = 0U;
  noleax::analyzer::EventStreamCallbacks stream_callbacks;
  stream_callbacks.on_event = [&callbacks](const Event&) { ++callbacks; };

  std::istringstream input{write_trace(chunks), std::ios::binary};
  CHECK_THROWS_AS(noleax::analyzer::analyze_event_stream(input, stream_callbacks),
                  noleax::analyzer::TraceAnalysisError);
  CHECK(callbacks == 0U);
}

TEST_CASE("event stream rejects inconsistent chunk and terminal metadata", "[analyzer][events]") {
  using namespace noleax::trace;
  const auto events = noleax::testing::make_all_memory_event_kinds();
  const auto first_event_payload = event_payload({events.front()});

  SECTION("event descriptor range") {
    const std::vector chunks{
        ChunkInput{descriptor(ChunkType::kMetadata), metadata_payload()},
        ChunkInput{descriptor(ChunkType::kEvent, 1U, 2U), first_event_payload},
    };
    std::istringstream input{write_trace(chunks), std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_event_stream(input),
                    noleax::analyzer::TraceAnalysisError);
  }

  SECTION("statistics event count") {
    const std::vector chunks{
        ChunkInput{descriptor(ChunkType::kMetadata), metadata_payload()},
        ChunkInput{descriptor(ChunkType::kEvent, 1U, 1U), first_event_payload},
        ChunkInput{descriptor(ChunkType::kStatistics),
                   statistics_payload(statistics_for_count(2U))},
    };
    std::istringstream input{write_trace(chunks), std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_event_stream(input),
                    noleax::analyzer::TraceAnalysisError);
  }

  SECTION("statistics per-API count") {
    auto statistics = statistics_for_count(1U);
    statistics.per_api.front().api_id = 2U;
    const std::vector chunks{
        ChunkInput{descriptor(ChunkType::kMetadata), metadata_payload()},
        ChunkInput{descriptor(ChunkType::kEvent, 1U, 1U), first_event_payload},
        ChunkInput{descriptor(ChunkType::kStatistics), statistics_payload(statistics)},
    };
    std::istringstream input{write_trace(chunks), std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_event_stream(input),
                    noleax::analyzer::TraceAnalysisError);
  }

  SECTION("EndOfTrace bounds") {
    const std::vector chunks{
        ChunkInput{descriptor(ChunkType::kMetadata), metadata_payload()},
        ChunkInput{descriptor(ChunkType::kEvent, 1U, 1U), first_event_payload},
        ChunkInput{descriptor(ChunkType::kEnd), end_payload(normal_end(0U, 10U))},
    };
    std::istringstream input{write_trace(chunks), std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_event_stream(input),
                    noleax::analyzer::TraceAnalysisError);
  }

  SECTION("events after statistics") {
    const std::vector chunks{
        ChunkInput{descriptor(ChunkType::kMetadata), metadata_payload()},
        ChunkInput{descriptor(ChunkType::kStatistics),
                   statistics_payload(statistics_for_count(0U))},
        ChunkInput{descriptor(ChunkType::kEvent, 1U, 1U), first_event_payload},
    };
    std::istringstream input{write_trace(chunks), std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_event_stream(input),
                    noleax::analyzer::TraceAnalysisError);
  }

  SECTION("chunks after EndOfTrace") {
    const std::vector chunks{
        ChunkInput{descriptor(ChunkType::kMetadata), metadata_payload()},
        ChunkInput{descriptor(ChunkType::kEnd), end_payload(normal_end(0U, 0U))},
        ChunkInput{descriptor(ChunkType::kEvent, 1U, 1U), first_event_payload},
    };
    std::istringstream input{write_trace(chunks), std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_event_stream(input),
                    noleax::analyzer::TraceAnalysisError);
  }
}

TEST_CASE("event stream requires one CaptureScope before events", "[analyzer][events]") {
  using namespace noleax::trace;
  const auto events = noleax::testing::make_all_memory_event_kinds();

  SECTION("missing") {
    const std::vector chunks{
        ChunkInput{descriptor(ChunkType::kEvent, 1U, 1U), event_payload({events.front()})},
    };
    std::istringstream input{write_trace(chunks), std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_event_stream(input),
                    noleax::analyzer::TraceAnalysisError);
  }

  SECTION("duplicate") {
    auto payload = metadata_payload();
    append_capture_scope_record(payload, CaptureScope{true, false});
    const std::vector chunks{
        ChunkInput{descriptor(ChunkType::kMetadata), payload},
    };
    std::istringstream input{write_trace(chunks), std::ios::binary};
    CHECK_THROWS_AS(noleax::analyzer::analyze_event_stream(input),
                    noleax::analyzer::TraceAnalysisError);
  }
}
