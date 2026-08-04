#include "noleax/trace/custom_hook.hpp"

#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/stacks.hpp"
#include "noleax/analyzer/trace_metadata.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/record_codec.hpp"
#include "noleax/trace/trace_reader.hpp"
#include "noleax/trace/wire_format.hpp"
#include "support/synthetic_trace.hpp"

namespace {

[[nodiscard]] noleax::trace::FileHeader file_header() {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.monotonic_frequency = 1'000'000'000U;
  return header;
}

[[nodiscard]] noleax::trace::CustomHookDefinition hook_definition() {
  noleax::trace::CustomHookDefinition definition;
  definition.api_id = noleax::trace::kCustomHookApiIdBase;
  definition.module_name = "myalloc.dll";
  definition.label = "my_malloc";
  return definition;
}

[[nodiscard]] noleax::trace::Event custom_allocation_event() {
  noleax::trace::AllocationEvent allocation;
  allocation.requested_size = 64U;
  allocation.result_address = 0x2000U;
  allocation.allocation_id =
      noleax::trace::AllocationId{(std::uint64_t{noleax::trace::kCustomHookApiIdBase} << 40U) | 1U};
  noleax::trace::Event event;
  event.header.sequence = noleax::trace::Sequence{1U};
  event.header.monotonic_ticks = 10U;
  event.header.thread_id = 7U;
  event.header.api_id = noleax::trace::kCustomHookApiIdBase;
  event.header.status = noleax::trace::EventStatus::kSuccess;
  event.payload = allocation;
  return event;
}

}  // namespace

TEST_CASE("custom hook definition record round trips", "[trace][record-codec][custom-hook]") {
  const auto definition = hook_definition();
  std::vector<std::byte> payload;
  noleax::trace::append_custom_hook_definition_record(payload, definition);

  noleax::trace::RecordCursor cursor{payload};
  const auto record = cursor.next();
  REQUIRE(record.has_value());
  CHECK(record->type ==
        static_cast<std::uint16_t>(noleax::trace::MetadataRecordType::kCustomHookDefinition));
  const auto decoded = noleax::trace::decode_custom_hook_definition_record(*record);
  REQUIRE(decoded.has_value());
  CHECK(*decoded == definition);
}

TEST_CASE("custom hook definition validation rejects malformed declarations",
          "[trace][record-codec][custom-hook]") {
  auto definition = hook_definition();
  definition.api_id = 7U;
  CHECK_THROWS_AS(noleax::trace::validate_custom_hook_definition(definition),
                  noleax::trace::CustomHookValidationError);

  definition = hook_definition();
  definition.module_name.clear();
  CHECK_THROWS_AS(noleax::trace::validate_custom_hook_definition(definition),
                  noleax::trace::CustomHookValidationError);

  definition = hook_definition();
  definition.label.clear();
  CHECK_THROWS_AS(noleax::trace::validate_custom_hook_definition(definition),
                  noleax::trace::CustomHookValidationError);

  definition = hook_definition();
  definition.label = std::string{"bad\0name", 8U};
  CHECK_THROWS_AS(noleax::trace::validate_custom_hook_definition(definition),
                  noleax::trace::CustomHookValidationError);

  definition = hook_definition();
  definition.api_id = noleax::trace::kCustomHookApiIdBase - 1U;
  std::vector<std::byte> payload;
  CHECK_THROWS_AS(noleax::trace::append_custom_hook_definition_record(payload, definition),
                  noleax::trace::CustomHookValidationError);
}

TEST_CASE("custom hook definition decoder skips other records and rejects corruption",
          "[trace][record-codec][custom-hook]") {
  std::vector<std::byte> payload;
  noleax::trace::append_capture_scope_record(payload, {true, false});
  noleax::trace::RecordCursor cursor{payload};
  const auto record = cursor.next();
  REQUIRE(record.has_value());
  CHECK(noleax::trace::decode_custom_hook_definition_record(*record) == std::nullopt);

  std::vector<std::byte> truncated;
  noleax::trace::append_custom_hook_definition_record(truncated, hook_definition());
  truncated.resize(truncated.size() - 2U);
  noleax::trace::RecordCursor corrupted_cursor{truncated};
  CHECK_THROWS_AS(static_cast<void>(corrupted_cursor.next()), noleax::trace::TraceReadError);
}

TEST_CASE("event stream collects custom hook definitions and rejects duplicates",
          "[analyzer][event-stream][custom-hook]") {
  const std::string bytes = noleax::testing::SyntheticTraceBuilder{file_header(), {true, false}}
                                .add_custom_hook_definition(hook_definition())
                                .add_event(custom_allocation_event())
                                .finish_normally()
                                .build();
  std::istringstream input{bytes, std::ios::binary};
  const auto result = noleax::analyzer::analyze_event_stream(input);
  REQUIRE(result.custom_hooks.size() == 1U);
  CHECK(result.custom_hooks.front() == hook_definition());
  CHECK(result.event_count == 1U);
  CHECK_FALSE(result.partially_understood);

  noleax::trace::CustomHookDefinition duplicate = hook_definition();
  duplicate.label = "other_name";
  const std::string duplicate_bytes =
      noleax::testing::SyntheticTraceBuilder{file_header(), {true, false}}
          .add_custom_hook_definition(hook_definition())
          .add_custom_hook_definition(duplicate)
          .add_event(custom_allocation_event())
          .finish_normally()
          .build();
  std::istringstream duplicate_input{duplicate_bytes, std::ios::binary};
  CHECK_THROWS_AS(static_cast<void>(noleax::analyzer::analyze_event_stream(duplicate_input)),
                  noleax::analyzer::TraceAnalysisError);
}

TEST_CASE("trace metadata resolves custom hook API names with registry precedence",
          "[analyzer][metadata][custom-hook]") {
  const std::string bytes = noleax::testing::SyntheticTraceBuilder{file_header(), {true, false}}
                                .add_custom_hook_definition(hook_definition())
                                .add_event(custom_allocation_event())
                                .finish_normally()
                                .build();
  std::istringstream input{bytes, std::ios::binary};
  noleax::analyzer::TraceMetadata metadata;
  static_cast<void>(metadata.scan(input));

  const auto fields = metadata.metadata(custom_allocation_event());
  CHECK(fields.api_name == "my_malloc");
  CHECK(fields.api_module == "myalloc.dll");

  // A built-in ID still resolves through the registry even when custom definitions exist.
  auto builtin_event = custom_allocation_event();
  builtin_event.header.api_id = 1U;
  const auto builtin_fields = metadata.metadata(builtin_event);
  CHECK(builtin_fields.api_name == "RtlAllocateHeap");

  // Unknown IDs stay unnamed (presentations fall back to api-<id>).
  auto unknown_event = custom_allocation_event();
  unknown_event.header.api_id = noleax::trace::kCustomHookApiIdBase + 7U;
  CHECK_FALSE(metadata.metadata(unknown_event).api_name.has_value());
}

TEST_CASE("group_api_names resolves custom hook labels with api-<id> fallback",
          "[analyzer][stacks][custom-hook]") {
  const std::vector<noleax::trace::ApiId> api_ids{1U, noleax::trace::kCustomHookApiIdBase,
                                                  noleax::trace::kCustomHookApiIdBase + 3U};
  const std::vector<noleax::trace::CustomHookDefinition> definitions{hook_definition()};

  const auto resolved = noleax::analyzer::group_api_names(api_ids, definitions);
  REQUIRE(resolved.size() == 3U);
  CHECK(resolved.at(0U) == "RtlAllocateHeap");
  CHECK(resolved.at(1U) == "my_malloc");
  CHECK(resolved.at(2U) == "api-" + std::to_string(noleax::trace::kCustomHookApiIdBase + 3U));

  // The fallback path used by an analyzer without custom hook definitions.
  const auto fallback = noleax::analyzer::group_api_names(api_ids);
  REQUIRE(fallback.size() == 3U);
  CHECK(fallback.at(0U) == "RtlAllocateHeap");
  CHECK(fallback.at(1U) == "api-" + std::to_string(noleax::trace::kCustomHookApiIdBase));
}
