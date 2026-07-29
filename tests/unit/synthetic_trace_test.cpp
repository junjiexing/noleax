#include "support/synthetic_trace.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/record_codec.hpp"
#include "noleax/trace/trace_reader.hpp"
#include "noleax/trace/trace_writer.hpp"
#include "noleax/trace/wire_format.hpp"

namespace {

[[nodiscard]] noleax::trace::FileHeader file_header() {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.flags = 0x10203040U;
  header.session_id[0] = std::byte{0xA5};
  header.file_index = 2U;
  header.monotonic_frequency = 10'000'000U;
  header.monotonic_origin = 0U;
  header.utc_origin_ns = -700;
  return header;
}

[[nodiscard]] noleax::trace::CaptureStatistics statistics_for_recorded_events(
    std::uint64_t event_count) {
  noleax::trace::CaptureStatistics statistics;
  statistics.observed_calls = event_count;
  statistics.successful_operations = event_count;
  statistics.unique_stacks = event_count;
  if (event_count != 0U) {
    noleax::trace::ApiStatistics api;
    api.api_id = 1U;
    api.observed_calls = event_count;
    api.successful_operations = event_count;
    statistics.per_api.push_back(api);
  }
  return statistics;
}

[[nodiscard]] noleax::trace::LossRecord loss_record() {
  noleax::trace::LossRecord loss;
  loss.reason = noleax::trace::LossReason::kQueueFull;
  loss.location = noleax::trace::LossLocation::kAgentQueue;
  loss.estimated_event_count = 3U;
  loss.sequence_range =
      noleax::trace::SequenceRange{noleax::trace::Sequence{10U}, noleax::trace::Sequence{12U}};
  loss.tick_range = noleax::trace::TickRange{100U, 120U};
  return loss;
}

struct DecodedTrace {
  noleax::trace::FileHeader header;
  std::vector<noleax::trace::ChunkType> chunk_types;
  std::vector<noleax::trace::CompressionCodec> codecs;
  std::optional<noleax::trace::CaptureScope> capture_scope;
  std::vector<noleax::trace::EventChunkRecord> event_records;
  std::optional<noleax::trace::CaptureStatistics> statistics;
  std::optional<noleax::trace::EndOfTrace> end;
};

template <typename Value>
void set_once(std::optional<Value>& destination, Value value, const char* duplicate_message) {
  if (destination.has_value()) {
    throw std::runtime_error{duplicate_message};
  }
  destination = std::move(value);
}

[[nodiscard]] DecodedTrace decode_trace(const std::string& encoded) {
  std::istringstream input{encoded, std::ios::binary};
  noleax::trace::TraceReader reader{input};
  DecodedTrace decoded;
  decoded.header = reader.file_header();

  while (true) {
    auto result = reader.read_next_chunk();
    if (result.status == noleax::trace::ChunkReadStatus::kEndOfFile) {
      break;
    }
    if (result.status != noleax::trace::ChunkReadStatus::kChunk || !result.chunk.has_value()) {
      throw std::runtime_error{"synthetic trace was unexpectedly truncated"};
    }

    auto& chunk = *result.chunk;
    decoded.chunk_types.push_back(chunk.header.descriptor.type);
    decoded.codecs.push_back(chunk.header.descriptor.codec);
    noleax::trace::RecordCursor cursor{chunk.payload};
    while (const auto record = cursor.next()) {
      switch (chunk.header.descriptor.type) {
        case noleax::trace::ChunkType::kMetadata: {
          auto scope = noleax::trace::decode_capture_scope_record(*record);
          if (!scope.has_value()) {
            throw std::runtime_error{"synthetic metadata contains an unknown record"};
          }
          set_once(decoded.capture_scope, *scope, "duplicate synthetic CaptureScope");
          break;
        }
        case noleax::trace::ChunkType::kEvent: {
          auto event = noleax::trace::decode_event_chunk_record(*record);
          if (!event.has_value()) {
            throw std::runtime_error{"synthetic event chunk contains an unknown record"};
          }
          decoded.event_records.push_back(*event);
          break;
        }
        case noleax::trace::ChunkType::kStatistics: {
          auto statistics = noleax::trace::decode_statistics_record(*record);
          if (!statistics.has_value()) {
            throw std::runtime_error{"synthetic statistics contains an unknown record"};
          }
          set_once(decoded.statistics, std::move(*statistics),
                   "duplicate synthetic CaptureStatistics");
          break;
        }
        case noleax::trace::ChunkType::kEnd: {
          auto end = noleax::trace::decode_end_of_trace_record(*record);
          if (!end.has_value()) {
            throw std::runtime_error{"synthetic end chunk contains an unknown record"};
          }
          set_once(decoded.end, *end, "duplicate synthetic EndOfTrace");
          break;
        }
        case noleax::trace::ChunkType::kModule:
        case noleax::trace::ChunkType::kStack:
          throw std::runtime_error{"unexpected synthetic chunk type"};
      }
    }
  }
  return decoded;
}

[[nodiscard]] std::string build_complete_trace(noleax::trace::CompressionCodec codec) {
  const auto events = noleax::testing::make_all_memory_event_kinds();
  noleax::testing::SyntheticTraceOptions options;
  options.codec = codec;
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}, options};
  for (const auto& event : events) {
    builder.add_event(event);
  }
  builder.add_loss(loss_record())
      .set_statistics(statistics_for_recorded_events(events.size()))
      .finish_normally(-7);
  return builder.build();
}

}  // namespace

TEST_CASE("synthetic traces round trip every event with all supported codecs",
          "[trace][synthetic]") {
  using namespace noleax::trace;
  const auto expected_events = noleax::testing::make_all_memory_event_kinds();
  const auto expected_loss = loss_record();
  const std::array codecs{
      CompressionCodec::kNone,
      CompressionCodec::kLz4,
      CompressionCodec::kZstd,
  };

  for (const auto codec : codecs) {
    CAPTURE(static_cast<unsigned int>(codec));
    const auto decoded = decode_trace(build_complete_trace(codec));
    CHECK(decoded.header == file_header());
    CHECK(decoded.chunk_types == std::vector{ChunkType::kMetadata, ChunkType::kEvent,
                                             ChunkType::kStatistics, ChunkType::kEnd});
    CHECK(decoded.codecs == std::vector(4U, codec));
    REQUIRE(decoded.capture_scope.has_value());
    CHECK(*decoded.capture_scope == CaptureScope{true, false});
    REQUIRE(decoded.event_records.size() == expected_events.size() + 1U);
    for (std::size_t index = 0; index < expected_events.size(); ++index) {
      REQUIRE(std::holds_alternative<Event>(decoded.event_records[index]));
      CHECK(std::get<Event>(decoded.event_records[index]) == expected_events[index]);
    }
    REQUIRE(std::holds_alternative<LossRecord>(decoded.event_records.back()));
    CHECK(std::get<LossRecord>(decoded.event_records.back()) == expected_loss);
    REQUIRE(decoded.statistics.has_value());
    CHECK(*decoded.statistics == statistics_for_recorded_events(expected_events.size()));
    REQUIRE(decoded.end.has_value());
    CHECK(decoded.end->final_sequence == Sequence{12U});
    CHECK(decoded.end->final_monotonic_ticks == 120U);
    CHECK(decoded.end->normal_stop);
    CHECK(decoded.end->target_exit_code == -7);
    CHECK(decoded.end->aggregate_completeness.has(CompletenessIssue::kEventLoss));
    CHECK_FALSE(decoded.end->aggregate_completeness.has(CompletenessIssue::kMissingEndOfTrace));
  }
}

TEST_CASE("synthetic trace generation is byte-for-byte deterministic", "[trace][synthetic]") {
  const std::array codecs{
      noleax::trace::CompressionCodec::kNone,
      noleax::trace::CompressionCodec::kLz4,
      noleax::trace::CompressionCodec::kZstd,
  };
  for (const auto codec : codecs) {
    CAPTURE(static_cast<unsigned int>(codec));
    CHECK(build_complete_trace(codec) == build_complete_trace(codec));
  }
}

TEST_CASE("synthetic trace rejects non-monotonic events", "[trace][synthetic]") {
  auto events = noleax::testing::make_all_memory_event_kinds();

  SECTION("sequence must strictly increase") {
    events[1].header.sequence = events[0].header.sequence;
    noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
    builder.add_event(events[0]).add_event(events[1]);
    CHECK_THROWS_AS(builder.build(), noleax::testing::SyntheticTraceError);
  }

  SECTION("ticks must not move backwards") {
    events[1].header.monotonic_ticks = events[0].header.monotonic_ticks - 1U;
    noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
    builder.add_event(events[0]).add_event(events[1]);
    CHECK_THROWS_AS(builder.build(), noleax::testing::SyntheticTraceError);
  }
}

TEST_CASE("synthetic trace cross-checks statistics against encoded events", "[trace][synthetic]") {
  const auto events = noleax::testing::make_all_memory_event_kinds();
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
  builder.add_event(events.front()).set_statistics(statistics_for_recorded_events(2U));
  CHECK_THROWS_AS(builder.build(), noleax::testing::SyntheticTraceError);
}

TEST_CASE("synthetic EndOfTrace must cover event and loss bounds", "[trace][synthetic]") {
  using namespace noleax::trace;
  const auto events = noleax::testing::make_all_memory_event_kinds();

  SECTION("event sequence") {
    EndOfTrace end;
    end.final_monotonic_ticks = events.front().header.monotonic_ticks;
    end.normal_stop = true;
    noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
    builder.add_event(events.front()).set_end_of_trace(end);
    CHECK_THROWS_AS(builder.build(), noleax::testing::SyntheticTraceError);
  }

  SECTION("event ticks") {
    EndOfTrace end;
    end.final_sequence = events.front().header.sequence;
    end.final_monotonic_ticks = events.front().header.monotonic_ticks - 1U;
    end.normal_stop = true;
    noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
    builder.add_event(events.front()).set_end_of_trace(end);
    CHECK_THROWS_AS(builder.build(), noleax::testing::SyntheticTraceError);
  }

  SECTION("loss ranges") {
    EndOfTrace end;
    end.final_sequence = Sequence{11U};
    end.final_monotonic_ticks = 119U;
    end.normal_stop = true;
    noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
    builder.add_loss(loss_record()).set_end_of_trace(end);
    CHECK_THROWS_AS(builder.build(), noleax::testing::SyntheticTraceError);
  }
}

TEST_CASE("synthetic trace reports a configured file limit", "[trace][synthetic]") {
  noleax::testing::SyntheticTraceOptions options;
  options.writer_options.max_file_size = noleax::trace::kFileHeaderSize;
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}, options};
  CHECK_THROWS_AS(builder.build(), noleax::testing::SyntheticTraceError);
}

TEST_CASE("synthetic trace may intentionally omit EndOfTrace", "[trace][synthetic]") {
  const auto events = noleax::testing::make_all_memory_event_kinds();
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
  const auto decoded = decode_trace(builder.add_event(events.front()).build());

  CHECK(decoded.chunk_types ==
        std::vector{noleax::trace::ChunkType::kMetadata, noleax::trace::ChunkType::kEvent});
  CHECK_FALSE(decoded.end.has_value());
  REQUIRE(decoded.capture_scope.has_value());
  noleax::trace::CompletenessTracker tracker{*decoded.capture_scope};
  CHECK(tracker.report().has(noleax::trace::CompletenessIssue::kMissingEndOfTrace));
  CHECK(tracker.report().recommended_exit_code() == 2);
}

TEST_CASE("finish normally derives capture and loss completeness", "[trace][synthetic]") {
  using namespace noleax::trace;
  LossRecord stack_loss;
  stack_loss.reason = LossReason::kStackCaptureFailed;
  stack_loss.location = LossLocation::kAgentQueue;
  stack_loss.estimated_event_count = 1U;

  noleax::testing::SyntheticTraceBuilder builder{file_header(), {false, true}};
  const auto decoded = decode_trace(builder.add_loss(stack_loss).finish_normally().build());
  REQUIRE(decoded.capture_scope.has_value());
  REQUIRE(decoded.end.has_value());
  CHECK(decoded.end->normal_stop);
  CHECK(decoded.end->target_exit_code == 0);
  CHECK(decoded.end->aggregate_completeness.has(
      CompletenessIssue::kCaptureDidNotStartAtProcessStart));
  CHECK(decoded.end->aggregate_completeness.has(CompletenessIssue::kPreexistingAllocationsUnknown));
  CHECK(decoded.end->aggregate_completeness.has(CompletenessIssue::kStackDataLoss));
  CHECK_FALSE(decoded.end->aggregate_completeness.has(CompletenessIssue::kEventLoss));
  CHECK_FALSE(decoded.end->aggregate_completeness.has(CompletenessIssue::kMissingEndOfTrace));

  CompletenessTracker tracker{*decoded.capture_scope};
  tracker.observe_loss(stack_loss);
  tracker.observe_end_of_trace(*decoded.end);
  CHECK(tracker.report() == decoded.end->aggregate_completeness);
}

TEST_CASE("synthetic trace timestamps are anchored at the monotonic origin", "[trace][synthetic]") {
  auto header = file_header();
  header.monotonic_origin = 500U;

  SECTION("empty normal trace ends at its origin") {
    noleax::testing::SyntheticTraceBuilder builder{header, {true, false}};
    const auto decoded = decode_trace(builder.finish_normally().build());
    REQUIRE(decoded.end.has_value());
    CHECK(decoded.end->final_monotonic_ticks == 500U);
  }

  SECTION("event before origin is rejected") {
    const auto events = noleax::testing::make_all_memory_event_kinds();
    noleax::testing::SyntheticTraceBuilder builder{header, {true, false}};
    builder.add_event(events.front());
    CHECK_THROWS_AS(builder.build(), noleax::testing::SyntheticTraceError);
  }
}
