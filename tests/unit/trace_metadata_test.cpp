#include "noleax/analyzer/trace_metadata.hpp"

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <sstream>
#include <string>

#include "noleax/trace/event.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/stack.hpp"
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

[[nodiscard]] noleax::trace::Event allocation_event() {
  noleax::trace::Event event = noleax::testing::make_all_memory_event_kinds().at(2U);
  event.header.sequence = noleax::trace::Sequence{1U};
  event.header.monotonic_ticks = 10U;
  event.header.api_id = 1U;
  event.header.stack_id = noleax::trace::StackId{101U};
  return event;
}

[[nodiscard]] std::string trace_bytes() {
  noleax::trace::ModuleLoad module;
  module.module_id = noleax::trace::ModuleId{7U};
  module.base_address = 0x1000U;
  module.image_size = 0x1000U;
  module.image_path = "C:/missing/fixture.dll";

  noleax::trace::StackDefinition stack;
  stack.stack_id = noleax::trace::StackId{101U};
  stack.status = noleax::trace::StackCaptureStatus::kComplete;
  stack.frames.push_back({noleax::trace::ModuleId{7U}, 0x20U, 0x1020U, 0U});

  return noleax::testing::SyntheticTraceBuilder{file_header(), {true, false}}
      .add_module(module)
      .add_stack(stack)
      .add_event(allocation_event())
      .finish_normally()
      .build();
}

}  // namespace

TEST_CASE("trace metadata assembles API module and stack presentation",
          "[analyzer][metadata][stack]") {
  const std::string bytes = trace_bytes();
  std::istringstream input{bytes, std::ios::binary};
  noleax::analyzer::TraceMetadata metadata;
  const auto scan = metadata.scan(input);
  REQUIRE(scan.event_count == 1U);

  const auto event = allocation_event();
  const auto fields = metadata.metadata(event);
  CHECK(fields.api_name == "RtlAllocateHeap");
  CHECK(fields.api_module == "ntdll.dll");
  REQUIRE(fields.stack_modules.size() == 1U);
  CHECK(fields.stack_modules.front() == "C:/missing/fixture.dll");

  const auto presentation = metadata.presentation(event);
  CHECK(presentation.api_name == "RtlAllocateHeap");
  CHECK(presentation.stack_status == noleax::analyzer::StackCaptureStatus::kComplete);
  REQUIRE(presentation.stack_frames.size() == 1U);
  CHECK(presentation.stack_frames.front().module_name == "fixture.dll");
  CHECK(presentation.stack_frames.front().module_offset == 0x20U);
  CHECK(presentation.stack_frames.front().absolute_address == 0x1020U);

  auto event_without_stack = event;
  event_without_stack.header.stack_id = {};
  const auto presentation_without_stack = metadata.presentation(event_without_stack);
  CHECK_FALSE(presentation_without_stack.stack_status.has_value());
  CHECK(presentation_without_stack.stack_frames.empty());
}

TEST_CASE("trace metadata rejects resolution before scan and duplicate scans",
          "[analyzer][metadata]") {
  noleax::analyzer::TraceMetadata metadata;
  CHECK_THROWS_AS(metadata.metadata(allocation_event()), noleax::analyzer::TraceAnalysisError);

  const std::string bytes = trace_bytes();
  std::istringstream first{bytes, std::ios::binary};
  static_cast<void>(metadata.scan(first));
  std::istringstream second{bytes, std::ios::binary};
  CHECK_THROWS_AS(metadata.scan(second), noleax::analyzer::TraceAnalysisError);
}
