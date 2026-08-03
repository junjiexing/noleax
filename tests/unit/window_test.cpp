#include "noleax/analyzer/window.hpp"

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>

#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/wire_format.hpp"

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

[[nodiscard]] noleax::trace::Event event_at(std::uint64_t sequence, std::uint64_t ticks) {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{sequence};
  header.monotonic_ticks = ticks;
  header.thread_id = 7U;
  header.api_id = 1U;
  header.status = noleax::trace::EventStatus::kSuccess;
  header.stack_id = noleax::trace::StackId{11U};
  noleax::trace::AllocationEvent allocation;
  allocation.heap_handle = 0x1000U;
  allocation.heap_id = noleax::trace::HeapId{1U};
  allocation.requested_size = 64U;
  allocation.result_address = 0x2000U;
  allocation.allocation_id = noleax::trace::AllocationId{10U};
  return {header, allocation};
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

}  // namespace

TEST_CASE("empty window bounds match every event", "[analyzer][window]") {
  const noleax::analyzer::WindowBound bound;
  const auto event = event_at(1U, 110U);
  CHECK(noleax::analyzer::window_bound_empty(bound));
  CHECK(noleax::analyzer::window_at_or_after(bound, file_header(), event));
  CHECK(noleax::analyzer::window_before(bound, file_header(), event));
  CHECK(noleax::analyzer::window_at_or_before(bound, file_header(), event));
}

TEST_CASE("time window bounds use closed lower and open upper endpoints", "[analyzer][window]") {
  const auto header = file_header();
  const auto event = event_at(1U, 110U);  // 10ns after the origin
  CHECK(noleax::analyzer::window_at_or_after(at(10ns), header, event));
  CHECK_FALSE(noleax::analyzer::window_before(at(10ns), header, event));
  CHECK(noleax::analyzer::window_at_or_before(at(10ns), header, event));

  CHECK_FALSE(noleax::analyzer::window_at_or_after(at(11ns), header, event));
  CHECK(noleax::analyzer::window_before(at(11ns), header, event));
  CHECK_FALSE(noleax::analyzer::window_at_or_before(at(9ns), header, event));
  CHECK(noleax::analyzer::window_at_or_before(at(9ns), header, event_at(1U, 109U)));
}

TEST_CASE("sequence window bounds compare event sequences", "[analyzer][window]") {
  const auto header = file_header();
  const auto event = event_at(5U, 110U);
  CHECK(noleax::analyzer::window_at_or_after(seq(5U), header, event));
  CHECK_FALSE(noleax::analyzer::window_before(seq(5U), header, event));
  CHECK(noleax::analyzer::window_at_or_before(seq(5U), header, event));

  CHECK(noleax::analyzer::window_at_or_after(seq(4U), header, event));
  CHECK_FALSE(noleax::analyzer::window_at_or_after(seq(6U), header, event));
  CHECK(noleax::analyzer::window_before(seq(6U), header, event));
  CHECK_FALSE(noleax::analyzer::window_before(seq(4U), header, event));
  CHECK(noleax::analyzer::window_at_or_before(seq(6U), header, event));
  CHECK_FALSE(noleax::analyzer::window_at_or_before(seq(4U), header, event));
}

TEST_CASE("mixed window bounds require time and sequence together", "[analyzer][window]") {
  const auto header = file_header();
  noleax::analyzer::WindowBound bound = at(10ns);
  bound.sequence = 5U;
  CHECK(noleax::analyzer::window_at_or_after(bound, header, event_at(5U, 110U)));
  CHECK_FALSE(noleax::analyzer::window_at_or_after(bound, header, event_at(4U, 110U)));
  CHECK_FALSE(noleax::analyzer::window_at_or_after(bound, header, event_at(5U, 109U)));
  CHECK(noleax::analyzer::window_before(bound, header, event_at(4U, 109U)));
  CHECK_FALSE(noleax::analyzer::window_before(bound, header, event_at(6U, 109U)));
  CHECK_FALSE(noleax::analyzer::window_before(bound, header, event_at(4U, 111U)));
  CHECK_FALSE(noleax::analyzer::window_before(bound, header, event_at(5U, 109U)));
  CHECK(noleax::analyzer::window_at_or_before(bound, header, event_at(5U, 110U)));
  CHECK(noleax::analyzer::window_at_or_before(bound, header, event_at(4U, 109U)));
  CHECK_FALSE(noleax::analyzer::window_at_or_before(bound, header, event_at(5U, 111U)));
}

TEST_CASE("window bounds order only within the same kind", "[analyzer][window]") {
  CHECK(noleax::analyzer::window_bounds_in_order(at(10ns), at(10ns)));
  CHECK(noleax::analyzer::window_bounds_in_order(at(10ns), at(20ns)));
  CHECK_FALSE(noleax::analyzer::window_bounds_in_order(at(20ns), at(10ns)));

  CHECK(noleax::analyzer::window_bounds_in_order(seq(5U), seq(5U)));
  CHECK(noleax::analyzer::window_bounds_in_order(seq(5U), seq(6U)));
  CHECK_FALSE(noleax::analyzer::window_bounds_in_order(seq(6U), seq(5U)));

  // Different kinds have no defined order and pass validation.
  CHECK(noleax::analyzer::window_bounds_in_order(at(20ns), seq(1U)));
  CHECK(noleax::analyzer::window_bounds_in_order(seq(100U), at(1ns)));
  CHECK(noleax::analyzer::window_bounds_in_order({}, at(1ns)));
  CHECK(noleax::analyzer::window_bounds_in_order(seq(1U), {}));

  auto mixed_lower = at(10ns);
  mixed_lower.sequence = 5U;
  auto mixed_upper = at(20ns);
  mixed_upper.sequence = 6U;
  CHECK(noleax::analyzer::window_bounds_in_order(mixed_lower, mixed_upper));

  mixed_lower.sequence = 7U;
  CHECK_FALSE(noleax::analyzer::window_bounds_in_order(mixed_lower, mixed_upper));
  mixed_lower = at(30ns);
  mixed_lower.sequence = 5U;
  CHECK_FALSE(noleax::analyzer::window_bounds_in_order(mixed_lower, mixed_upper));
}
