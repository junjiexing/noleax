#include "noleax/analyzer/time.hpp"

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <compare>
#include <cstdint>
#include <limits>

#include "noleax/trace/wire_format.hpp"

namespace {

[[nodiscard]] noleax::trace::FileHeader clock_header(std::uint64_t frequency,
                                                     std::uint64_t origin) {
  noleax::trace::FileHeader header;
  header.monotonic_frequency = frequency;
  header.monotonic_origin = origin;
  return header;
}

}  // namespace

TEST_CASE("trace time comparison preserves exact fractional tick boundaries", "[analyzer][time]") {
  using namespace std::chrono_literals;
  using noleax::analyzer::compare_trace_time;

  const auto halves = clock_header(10U, 100U);
  CHECK(compare_trace_time(105U, halves, 500ms) == std::strong_ordering::equal);
  CHECK(compare_trace_time(104U, halves, 500ms) == std::strong_ordering::less);
  CHECK(compare_trace_time(106U, halves, 500ms) == std::strong_ordering::greater);

  const auto thirds = clock_header(3U, 10U);
  CHECK(compare_trace_time(11U, thirds, 333'333'333ns) == std::strong_ordering::greater);
  CHECK(compare_trace_time(11U, thirds, 333'333'334ns) == std::strong_ordering::less);
  CHECK(noleax::analyzer::trace_time_floor(11U, thirds) == 333'333'333ns);
}

TEST_CASE("trace time conversion handles uint64-scale counters without multiplication overflow",
          "[analyzer][time]") {
  using namespace std::chrono_literals;
  const auto maximum = std::numeric_limits<std::uint64_t>::max();
  const auto subsecond = clock_header(maximum, 0U);
  CHECK(noleax::analyzer::trace_time_floor(maximum - 1U, subsecond) == 999'999'999ns);

  const auto seconds = clock_header(1U, 0U);
  CHECK_THROWS_AS(noleax::analyzer::trace_time_floor(maximum, seconds),
                  noleax::analyzer::TraceTimeError);
}

TEST_CASE("trace time rejects invalid origins frequencies and durations", "[analyzer][time]") {
  using namespace std::chrono_literals;
  CHECK_THROWS_AS(noleax::analyzer::trace_time_floor(9U, clock_header(10U, 10U)),
                  noleax::analyzer::TraceTimeError);
  CHECK_THROWS_AS(noleax::analyzer::trace_time_floor(10U, clock_header(0U, 10U)),
                  noleax::analyzer::TraceTimeError);
  CHECK_THROWS_AS(noleax::analyzer::compare_trace_time(10U, clock_header(10U, 10U), -1ns),
                  noleax::analyzer::TraceTimeError);
}
