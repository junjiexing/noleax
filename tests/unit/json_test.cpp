#include "noleax/analyzer/json.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
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
#include "support/json_dom.hpp"
#include "support/json_schema.hpp"
#include "support/synthetic_trace.hpp"

namespace {

[[nodiscard]] noleax::trace::FileHeader file_header() {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.flags = 3U;
  for (std::size_t index = 0U; index < header.session_id.size(); ++index) {
    header.session_id[index] = static_cast<std::byte>(index);
  }
  header.file_index = 2U;
  header.monotonic_frequency = 1'000'000'000U;
  header.monotonic_origin = 100U;
  header.utc_origin_ns = 1'000U;
  return header;
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

[[nodiscard]] noleax::analyzer::EventPresentation allocation_presentation() {
  noleax::analyzer::EventPresentation presentation;
  presentation.api_name = "RtlAllocateHeap";
  presentation.api_module = "ntdll.dll";
  presentation.stack_status = noleax::analyzer::StackCaptureStatus::kComplete;

  noleax::analyzer::ResolvedStackFrame frame;
  frame.absolute_address = 0x0000000140001234U;
  frame.module_name = "app.exe";
  frame.module_offset = 0x1234U;
  frame.symbol_name = "main";
  frame.symbol_offset = 4U;
  presentation.stack_frames.push_back(std::move(frame));
  return presentation;
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

[[nodiscard]] const noleax::testing::JsonValue& analysis_schema() {
  static const noleax::testing::JsonValue schema = [] {
    const auto path = std::filesystem::path{NOLEAX_TEST_SOURCE_DIR} / "docs" / "schema" /
                      "noleax-analysis-v1.schema.json";
    std::ifstream input{path, std::ios::binary};
    if (!input) {
      throw std::runtime_error{"cannot open analysis JSON schema"};
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    if (input.bad()) {
      throw std::runtime_error{"cannot read analysis JSON schema"};
    }
    return noleax::testing::parse_json(buffer.str());
  }();
  return schema;
}

[[nodiscard]] noleax::testing::JsonValue parse_and_validate(std::string_view output) {
  auto document = noleax::testing::parse_json(output);
  noleax::testing::validate_json_schema(document, analysis_schema());
  return document;
}

[[nodiscard]] std::string write_events(
    const noleax::trace::FileHeader& header, const std::vector<noleax::trace::Event>& events,
    const noleax::analyzer::EventPresentationResolver& resolver = {}) {
  std::ostringstream output;
  noleax::analyzer::JsonWriter writer{output};
  writer.begin_events(header, capture_scope(), noleax::analyzer::AnalysisFilter{});
  for (const auto& event : events) {
    writer.write_event(event, resolver ? resolver(event) : noleax::analyzer::EventPresentation{});
  }
  writer.finish_events(event_result(header, static_cast<std::uint64_t>(events.size())));
  return output.str();
}

}  // namespace

TEST_CASE("analysis JSON schema version is stable", "[analyzer][json]") {
  CHECK(noleax::analyzer::kAnalysisJsonSchemaVersion == 1U);
  CHECK(analysis_schema().at("properties").at("schema_version").at("const").unsigned_value() == 1U);
}

TEST_CASE("test JSON schema validator enforces refs and structural keywords",
          "[analyzer][json][schema]") {
  const auto schema = noleax::testing::parse_json(R"({
    "type":"object",
    "required":["kind","values"],
    "properties":{
      "kind":{"const":"sample"},
      "values":{"type":"array","items":{"$ref":"#/$defs/value"}}
    },
    "additionalProperties":false,
    "$defs":{"value":{"oneOf":[{"type":"integer"},{"enum":["unknown"]}]}}
  })");

  CHECK_NOTHROW(noleax::testing::validate_json_schema(
      noleax::testing::parse_json(R"({"kind":"sample","values":[1,"unknown"]})"), schema));
  CHECK_THROWS_AS(noleax::testing::validate_json_schema(
                      noleax::testing::parse_json(R"({"kind":"sample","values":[true]})"), schema),
                  noleax::testing::JsonSchemaValidationError);
  CHECK_THROWS_AS(
      noleax::testing::validate_json_schema(
          noleax::testing::parse_json(R"({"kind":"sample","values":[],"x":1})"), schema),
      noleax::testing::JsonSchemaValidationError);
}

TEST_CASE("events JSON pipeline streams schema-valid Event and Loss records", "[analyzer][json]") {
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

  noleax::analyzer::AnalysisFilterCriteria criteria;
  criteria.minimum_size = 32U;
  criteria.maximum_size = 128U;
  criteria.operations.push_back(noleax::trace::EventOperation::kAllocate);
  criteria.thread_ids.push_back(7U);
  criteria.api_names.emplace_back("RtlAllocateHeap");
  criteria.allocation_ids.push_back(10U);
  criteria.statuses.push_back(noleax::trace::EventStatus::kSuccess);
  const noleax::analyzer::AnalysisFilter filter{std::move(criteria)};

  const auto encoded = builder.build();
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  const auto result = noleax::analyzer::analyze_events_to_json(
      input, output, filter,
      [](const noleax::trace::Event&) {
        noleax::analyzer::EventMetadata metadata;
        metadata.api_name = "RtlAllocateHeap";
        return metadata;
      },
      [](const noleax::trace::Event&) { return allocation_presentation(); });

  CHECK(result.matched_event_count == 1U);
  CHECK(result.trace.loss_record_count == 1U);
  const auto document = parse_and_validate(output.str());
  CHECK(document.at("schema").scalar() == "noleax.analysis");
  CHECK(document.at("mode").scalar() == "events");
  CHECK(document.at("metadata").at("trace").at("session_id").scalar() ==
        "000102030405060708090a0b0c0d0e0f");
  CHECK(document.at("filters").at("minimum_size").unsigned_value() == 32U);

  const auto& records = document.at("events").array_items();
  REQUIRE(records.size() == 2U);
  CHECK(records[0].at("record_type").scalar() == "event");
  CHECK(records[0].at("api").at("name").scalar() == "RtlAllocateHeap");
  CHECK(records[0].at("stack").at("frames").array_items().size() == 1U);
  CHECK(records[0].at("payload").at("requested_size").unsigned_value() == 64U);
  CHECK(records[1].at("record_type").scalar() == "loss");
  CHECK(records[1].at("sequence_range").at("end").unsigned_value() == 3U);

  const auto& summary = document.at("summary");
  CHECK(summary.at("matched_events").unsigned_value() == 1U);
  CHECK(summary.at("capture_statistics").at("per_api").array_items().size() == 1U);
  CHECK(summary.at("completeness").at("overall").scalar() == "incomplete");
}

TEST_CASE("outstanding JSON pipeline emits its effective observation window", "[analyzer][json]") {
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
  const auto result = noleax::analyzer::analyze_outstanding_to_json(
      input, output, {10ns, 20ns, std::nullopt}, filter, {},
      [](const noleax::trace::Event&) { return allocation_presentation(); });

  REQUIRE(result.outstanding.size() == 1U);
  const auto document = parse_and_validate(output.str());
  CHECK(document.at("mode").scalar() == "outstanding");
  CHECK(document.at("window").at("requested_c_ns").type() == noleax::testing::JsonType::kNull);
  CHECK(document.at("window").at("effective_c_ns").signed_value() == 40);
  CHECK(document.at("window").at("observation_uses_trace_end").boolean_value());

  const auto& allocations = document.at("allocations").array_items();
  REQUIRE(allocations.size() == 1U);
  CHECK(allocations[0].at("generation_kind").scalar() == "heap_allocation");
  CHECK(allocations[0].at("allocation_id").unsigned_value() == 10U);
  CHECK(allocations[0].at("created_by").at("api").at("name").scalar() == "RtlAllocateHeap");
  CHECK(document.at("summary").at("outstanding").unsigned_value() == 1U);
}

TEST_CASE("events JSON has a strict schema for every normalized payload", "[analyzer][json]") {
  auto header = file_header();
  header.monotonic_origin = 0U;
  const auto events = noleax::testing::make_all_memory_event_kinds();
  const auto document = parse_and_validate(write_events(header, events));

  constexpr std::array<std::string_view, 9> expected_kinds{
      "heap_create",   "heap_destroy", "allocation", "reallocation", "free",
      "vm_allocation", "vm_free",      "map",        "unmap",
  };
  const auto& records = document.at("events").array_items();
  REQUIRE(records.size() == expected_kinds.size());
  for (std::size_t index = 0U; index < expected_kinds.size(); ++index) {
    CAPTURE(index);
    CHECK(records[index].at("payload").at("kind").scalar() == expected_kinds[index]);
  }
  CHECK(records[2].at("payload").at("result_address").scalar() == "0x0000000000002000");
  CHECK(records[5].at("payload").at("target").at("scope").scalar() == "current_process");
}

TEST_CASE("events JSON preserves UTF-8 and escapes all JSON control characters",
          "[analyzer][json]") {
  const std::string api_name = "内存\"\\\b\f\n\r\t\x01";
  const auto output =
      write_events(file_header(), {allocation_event()}, [&api_name](const noleax::trace::Event&) {
        auto presentation = allocation_presentation();
        presentation.api_name = api_name;
        presentation.api_module = "模块😀.dll";
        return presentation;
      });

  CHECK(output.find("\\\"") != std::string::npos);
  CHECK(output.find("\\\\") != std::string::npos);
  CHECK(output.find("\\b") != std::string::npos);
  CHECK(output.find("\\f") != std::string::npos);
  CHECK(output.find("\\n") != std::string::npos);
  CHECK(output.find("\\r") != std::string::npos);
  CHECK(output.find("\\t") != std::string::npos);
  CHECK(output.find("\\u0001") != std::string::npos);
  const auto document = parse_and_validate(output);
  const auto& record = document.at("events").array_items().front();
  CHECK(record.at("api").at("name").scalar() == api_name);
  CHECK(record.at("api").at("module").scalar() == "模块😀.dll");
}

TEST_CASE("events JSON rejects malformed UTF-8 supplied by presentation metadata",
          "[analyzer][json]") {
  const std::array invalid_strings{
      std::string{"\xC0\xAF", 2U},
      std::string{"\xE2", 1U},
      std::string{"\xED\xA0\x80", 3U},
      std::string{"\xF4\x90\x80\x80", 4U},
  };

  for (const auto& invalid : invalid_strings) {
    std::ostringstream output;
    noleax::analyzer::JsonWriter writer{output};
    writer.begin_events(file_header(), capture_scope(), noleax::analyzer::AnalysisFilter{});
    auto presentation = allocation_presentation();
    presentation.api_name = invalid;
    CAPTURE(invalid.size());
    CHECK_THROWS_AS(writer.write_event(allocation_event(), presentation),
                    noleax::analyzer::JsonFormatError);
  }
}

TEST_CASE("events JSON writes exact signed and unsigned integer boundaries", "[analyzer][json]") {
  auto header = file_header();
  header.utc_origin_ns = std::numeric_limits<std::int64_t>::min();
  auto event = allocation_event();
  event.header.sequence = noleax::trace::Sequence{std::numeric_limits<std::uint64_t>::max()};
  event.header.thread_id = std::numeric_limits<std::uint64_t>::max();
  event.header.system_error = {noleax::trace::SystemErrorDomain::kWin32,
                               std::numeric_limits<std::uint64_t>::max()};
  auto& allocation = std::get<noleax::trace::AllocationEvent>(event.payload);
  allocation.requested_size = std::numeric_limits<std::uint64_t>::max();
  allocation.allocation_id = noleax::trace::AllocationId{std::numeric_limits<std::uint64_t>::max()};

  auto result = event_result(header, 1U);
  result.trace.bytes_read = std::numeric_limits<std::uint64_t>::max();
  result.trace.known_monotonic_end = std::numeric_limits<std::uint64_t>::max();
  noleax::trace::EndOfTrace end;
  end.final_sequence = noleax::trace::Sequence{std::numeric_limits<std::uint64_t>::max()};
  end.final_monotonic_ticks = std::numeric_limits<std::uint64_t>::max();
  end.normal_stop = true;
  end.target_exit_code = std::numeric_limits<std::int32_t>::min();
  result.trace.end_of_trace = end;

  std::ostringstream output;
  noleax::analyzer::JsonWriter writer{output};
  writer.begin_events(header, capture_scope(), noleax::analyzer::AnalysisFilter{});
  writer.write_event(event);
  writer.finish_events(result);
  const auto document = parse_and_validate(output.str());
  const auto& record = document.at("events").array_items().front();
  CHECK(record.at("sequence").unsigned_value() == std::numeric_limits<std::uint64_t>::max());
  CHECK(record.at("thread_id").unsigned_value() == std::numeric_limits<std::uint64_t>::max());
  CHECK(record.at("payload").at("requested_size").unsigned_value() ==
        std::numeric_limits<std::uint64_t>::max());
  CHECK(record.at("system_error").at("code").scalar() == "0xffffffffffffffff");
  CHECK(document.at("metadata").at("trace").at("utc_origin_ns").signed_value() ==
        std::numeric_limits<std::int64_t>::min());
  CHECK(document.at("summary").at("bytes_read").unsigned_value() ==
        std::numeric_limits<std::uint64_t>::max());
  CHECK(document.at("summary").at("termination").at("target_exit_code").signed_value() ==
        std::numeric_limits<std::int32_t>::min());

  for (const auto signed_value :
       {std::numeric_limits<std::int64_t>::min(), std::numeric_limits<std::int64_t>::max()}) {
    auto signed_header = file_header();
    signed_header.utc_origin_ns = signed_value;
    std::ostringstream signed_output;
    noleax::analyzer::JsonWriter signed_writer{signed_output};
    signed_writer.begin_events(signed_header, capture_scope(), noleax::analyzer::AnalysisFilter{});
    signed_writer.finish_events(event_result(signed_header, 0U));
    const auto signed_document = parse_and_validate(signed_output.str());
    CAPTURE(signed_value);
    CHECK(signed_document.at("metadata").at("trace").at("utc_origin_ns").signed_value() ==
          signed_value);
  }
}

TEST_CASE("events JSON exposes stack resolution and rejects inconsistent presentation",
          "[analyzer][json]") {
  const auto document = parse_and_validate(
      write_events(file_header(), {allocation_event()},
                   [](const noleax::trace::Event&) { return allocation_presentation(); }));
  const auto& stack = document.at("events").array_items().front().at("stack");
  CHECK(stack.at("id").unsigned_value() == 11U);
  CHECK(stack.at("status").scalar() == "complete");
  CHECK(stack.at("definition_available").boolean_value());
  CHECK(stack.at("frames").array_items().front().at("symbol").scalar() == "main");

  SECTION("stack data without stack ID") {
    auto event = allocation_event();
    event.header.stack_id = {};
    std::ostringstream output;
    noleax::analyzer::JsonWriter writer{output};
    writer.begin_events(file_header(), capture_scope(), noleax::analyzer::AnalysisFilter{});
    CHECK_THROWS_AS(writer.write_event(event, allocation_presentation()),
                    noleax::analyzer::JsonFormatError);
  }

  SECTION("module offset without module") {
    auto presentation = allocation_presentation();
    presentation.stack_frames.front().module_name.reset();
    std::ostringstream output;
    noleax::analyzer::JsonWriter writer{output};
    writer.begin_events(file_header(), capture_scope(), noleax::analyzer::AnalysisFilter{});
    CHECK_THROWS_AS(writer.write_event(allocation_event(), presentation),
                    noleax::analyzer::JsonFormatError);
  }

  SECTION("symbol offset without symbol") {
    auto presentation = allocation_presentation();
    presentation.stack_frames.front().symbol_name.reset();
    std::ostringstream output;
    noleax::analyzer::JsonWriter writer{output};
    writer.begin_events(file_header(), capture_scope(), noleax::analyzer::AnalysisFilter{});
    CHECK_THROWS_AS(writer.write_event(allocation_event(), presentation),
                    noleax::analyzer::JsonFormatError);
  }
}

TEST_CASE("JSON writer rejects invalid state, inconsistent summaries, and failed streams",
          "[analyzer][json]") {
  SECTION("call order") {
    std::ostringstream output;
    noleax::analyzer::JsonWriter writer{output};
    CHECK_THROWS_AS(writer.write_event(allocation_event()), noleax::analyzer::JsonFormatError);
    writer.begin_events(file_header(), capture_scope(), noleax::analyzer::AnalysisFilter{});
    CHECK_THROWS_AS(
        writer.begin_events(file_header(), capture_scope(), noleax::analyzer::AnalysisFilter{}),
        noleax::analyzer::JsonFormatError);
    writer.write_event(allocation_event());
    writer.finish_events(event_result(file_header(), 1U));
    CHECK_THROWS_AS(writer.finish_events(event_result(file_header(), 1U)),
                    noleax::analyzer::JsonFormatError);
  }

  SECTION("record count") {
    std::ostringstream output;
    noleax::analyzer::JsonWriter writer{output};
    writer.begin_events(file_header(), capture_scope(), noleax::analyzer::AnalysisFilter{});
    writer.write_event(allocation_event());
    CHECK_THROWS_AS(writer.finish_events(event_result(file_header(), 2U)),
                    noleax::analyzer::JsonFormatError);
  }

  SECTION("output failure") {
    std::ostringstream output;
    output.setstate(std::ios::badbit);
    noleax::analyzer::JsonWriter writer{output};
    CHECK_THROWS_AS(
        writer.begin_events(file_header(), capture_scope(), noleax::analyzer::AnalysisFilter{}),
        noleax::analyzer::JsonFormatError);
  }

  SECTION("invalid outstanding creation event") {
    noleax::analyzer::OutstandingResult result;
    result.trace.file_header = file_header();
    result.trace.capture_scope = capture_scope();
    result.candidate_count = 1U;
    noleax::analyzer::MemoryGeneration generation;
    generation.kind = noleax::analyzer::GenerationKind::kHeapAllocation;
    generation.created_by = allocation_event();
    generation.created_by.header.sequence = {};
    result.outstanding.push_back(generation);

    std::ostringstream output;
    noleax::analyzer::JsonWriter writer{output};
    CHECK_THROWS_AS(writer.write_outstanding(result, noleax::analyzer::AnalysisFilter{}),
                    noleax::trace::EventValidationError);
    CHECK(output.str().empty());
  }
}
