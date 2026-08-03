#pragma once

#include <chrono>
#include <cstdint>
#include <optional>

#include "noleax/trace/event.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {

// One analysis window endpoint: a relative trace time, an event sequence, or both. When both
// components are set an event must satisfy each of them (AND); an empty bound matches everything.
struct WindowBound {
  std::optional<std::chrono::nanoseconds> time;
  std::optional<std::uint64_t> sequence;

  bool operator==(const WindowBound&) const = default;
};

[[nodiscard]] bool window_bound_empty(const WindowBound& bound) noexcept;

// Lower-bound match (half-open interval, inclusive): time compares
// compare_trace_time(ticks, header, *time) >= 0, sequence compares event.header.sequence >=
// *sequence.
[[nodiscard]] bool window_at_or_after(const WindowBound& bound,
                                      const noleax::trace::FileHeader& header,
                                      const noleax::trace::Event& event);

// Upper-bound match (half-open interval, exclusive): time and sequence compare strictly below.
[[nodiscard]] bool window_before(const WindowBound& bound, const noleax::trace::FileHeader& header,
                                 const noleax::trace::Event& event);

// Inclusive upper-bound match (closed observation point): time and sequence compare at or below.
[[nodiscard]] bool window_at_or_before(const WindowBound& bound,
                                       const noleax::trace::FileHeader& header,
                                       const noleax::trace::Event& event);

// Ordering check for window validation: only bounds of the same kind are ordered (time against
// time, sequence against sequence); mixed or empty kinds have no defined order and pass.
[[nodiscard]] bool window_bounds_in_order(const WindowBound& lower,
                                          const WindowBound& upper) noexcept;

}  // namespace noleax::analyzer
