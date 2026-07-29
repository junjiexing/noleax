#pragma once

#include <chrono>
#include <compare>
#include <cstdint>
#include <stdexcept>

#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {

class TraceTimeError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

[[nodiscard]] std::strong_ordering compare_trace_time(std::uint64_t monotonic_ticks,
                                                      const noleax::trace::FileHeader& header,
                                                      std::chrono::nanoseconds relative_time);

[[nodiscard]] std::chrono::nanoseconds trace_time_floor(std::uint64_t monotonic_ticks,
                                                        const noleax::trace::FileHeader& header);

}  // namespace noleax::analyzer
