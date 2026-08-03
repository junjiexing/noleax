#include "noleax/analyzer/window.hpp"

#include <chrono>
#include <compare>
#include <cstdint>

#include "noleax/analyzer/time.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {

bool window_bound_empty(const WindowBound& bound) noexcept {
  return !bound.time.has_value() && !bound.sequence.has_value();
}

bool window_at_or_after(const WindowBound& bound, const noleax::trace::FileHeader& header,
                        const noleax::trace::Event& event) {
  if (bound.time.has_value() && compare_trace_time(event.header.monotonic_ticks, header,
                                                   *bound.time) == std::strong_ordering::less) {
    return false;
  }
  if (bound.sequence.has_value() && event.header.sequence.value() < *bound.sequence) {
    return false;
  }
  return true;
}

bool window_before(const WindowBound& bound, const noleax::trace::FileHeader& header,
                   const noleax::trace::Event& event) {
  if (bound.time.has_value() && compare_trace_time(event.header.monotonic_ticks, header,
                                                   *bound.time) != std::strong_ordering::less) {
    return false;
  }
  if (bound.sequence.has_value() && event.header.sequence.value() >= *bound.sequence) {
    return false;
  }
  return true;
}

bool window_at_or_before(const WindowBound& bound, const noleax::trace::FileHeader& header,
                         const noleax::trace::Event& event) {
  if (bound.time.has_value() && compare_trace_time(event.header.monotonic_ticks, header,
                                                   *bound.time) == std::strong_ordering::greater) {
    return false;
  }
  if (bound.sequence.has_value() && event.header.sequence.value() > *bound.sequence) {
    return false;
  }
  return true;
}

bool window_bounds_in_order(const WindowBound& lower, const WindowBound& upper) noexcept {
  if (lower.time.has_value() && upper.time.has_value()) {
    return *lower.time <= *upper.time;
  }
  if (lower.sequence.has_value() && upper.sequence.has_value()) {
    return *lower.sequence <= *upper.sequence;
  }
  return true;
}

}  // namespace noleax::analyzer
