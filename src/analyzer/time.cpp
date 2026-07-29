#include "noleax/analyzer/time.hpp"

#include <chrono>
#include <compare>
#include <cstdint>
#include <limits>

#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {
namespace {

inline constexpr std::uint64_t kNanosecondsPerSecond = 1'000'000'000U;

[[nodiscard]] int compare_fractions(std::uint64_t left_numerator, std::uint64_t left_denominator,
                                    std::uint64_t right_numerator,
                                    std::uint64_t right_denominator) noexcept {
  bool reverse = false;
  while (true) {
    const std::uint64_t left_quotient = left_numerator / left_denominator;
    const std::uint64_t right_quotient = right_numerator / right_denominator;
    if (left_quotient != right_quotient) {
      const int result = left_quotient < right_quotient ? -1 : 1;
      return reverse ? -result : result;
    }

    const std::uint64_t left_remainder = left_numerator % left_denominator;
    const std::uint64_t right_remainder = right_numerator % right_denominator;
    if (left_remainder == 0U || right_remainder == 0U) {
      if (left_remainder == right_remainder) {
        return 0;
      }
      const int result = left_remainder == 0U ? -1 : 1;
      return reverse ? -result : result;
    }

    left_numerator = left_denominator;
    left_denominator = left_remainder;
    right_numerator = right_denominator;
    right_denominator = right_remainder;
    reverse = !reverse;
  }
}

[[nodiscard]] std::uint64_t add_fractional_value(std::uint64_t left, std::uint64_t right,
                                                 std::uint64_t denominator,
                                                 std::uint64_t& quotient) noexcept {
  if (left >= denominator - right) {
    ++quotient;
    return left - (denominator - right);
  }
  return left + right;
}

[[nodiscard]] std::uint64_t multiply_divide_floor(std::uint64_t value, std::uint64_t multiplier,
                                                  std::uint64_t denominator) noexcept {
  std::uint64_t result_quotient = 0U;
  std::uint64_t result_remainder = 0U;
  std::uint64_t part_quotient = value / denominator;
  std::uint64_t part_remainder = value % denominator;

  while (multiplier != 0U) {
    if ((multiplier & 1U) != 0U) {
      result_quotient += part_quotient;
      result_remainder =
          add_fractional_value(result_remainder, part_remainder, denominator, result_quotient);
    }
    multiplier >>= 1U;
    if (multiplier == 0U) {
      break;
    }
    part_quotient *= 2U;
    part_remainder =
        add_fractional_value(part_remainder, part_remainder, denominator, part_quotient);
  }
  return result_quotient;
}

[[nodiscard]] std::uint64_t relative_ticks(std::uint64_t monotonic_ticks,
                                           const noleax::trace::FileHeader& header) {
  if (header.monotonic_frequency == 0U) {
    throw TraceTimeError{"trace monotonic frequency must not be zero"};
  }
  if (monotonic_ticks < header.monotonic_origin) {
    throw TraceTimeError{"trace monotonic time precedes its origin"};
  }
  return monotonic_ticks - header.monotonic_origin;
}

}  // namespace

std::strong_ordering compare_trace_time(std::uint64_t monotonic_ticks,
                                        const noleax::trace::FileHeader& header,
                                        std::chrono::nanoseconds relative_time) {
  if (relative_time.count() < 0) {
    throw TraceTimeError{"relative trace time must not be negative"};
  }
  const std::uint64_t ticks = relative_ticks(monotonic_ticks, header);
  const std::uint64_t tick_seconds = ticks / header.monotonic_frequency;
  const auto nanoseconds_count = static_cast<std::uint64_t>(relative_time.count());
  const std::uint64_t time_seconds = nanoseconds_count / kNanosecondsPerSecond;
  if (tick_seconds < time_seconds) {
    return std::strong_ordering::less;
  }
  if (tick_seconds > time_seconds) {
    return std::strong_ordering::greater;
  }

  const int fractional_comparison =
      compare_fractions(ticks % header.monotonic_frequency, header.monotonic_frequency,
                        nanoseconds_count % kNanosecondsPerSecond, kNanosecondsPerSecond);
  if (fractional_comparison < 0) {
    return std::strong_ordering::less;
  }
  if (fractional_comparison > 0) {
    return std::strong_ordering::greater;
  }
  return std::strong_ordering::equal;
}

std::chrono::nanoseconds trace_time_floor(std::uint64_t monotonic_ticks,
                                          const noleax::trace::FileHeader& header) {
  const std::uint64_t ticks = relative_ticks(monotonic_ticks, header);
  const std::uint64_t whole_seconds = ticks / header.monotonic_frequency;
  const std::uint64_t fractional_nanoseconds = multiply_divide_floor(
      ticks % header.monotonic_frequency, kNanosecondsPerSecond, header.monotonic_frequency);
  const auto maximum = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  if (whole_seconds > (maximum - fractional_nanoseconds) / kNanosecondsPerSecond) {
    throw TraceTimeError{"relative trace time does not fit nanoseconds"};
  }
  const std::uint64_t nanoseconds = whole_seconds * kNanosecondsPerSecond + fractional_nanoseconds;
  return std::chrono::nanoseconds{static_cast<std::int64_t>(nanoseconds)};
}

}  // namespace noleax::analyzer
