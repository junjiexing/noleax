#pragma once

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <stdexcept>
#include <vector>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/analyzer/window.hpp"

namespace noleax::analyzer {

struct OutstandingWindow {
  WindowBound a;
  std::optional<WindowBound> b;
  std::optional<WindowBound> c;
};

struct OutstandingResult {
  EventStreamResult trace;
  OutstandingWindow requested_window;
  WindowBound effective_b;
  WindowBound effective_c;
  std::uint64_t trace_end_monotonic_ticks{0};
  std::uint64_t candidate_count{0};
  std::uint64_t ended_by_c_count{0};
  std::uint64_t filtered_out_count{0};
  std::uint64_t orphaned_allocation_end_count{0};
  std::uint64_t orphaned_mapping_end_count{0};
  bool observation_uses_trace_end{false};
  std::vector<MemoryGeneration> outstanding;
};

class OutstandingAnalysisError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

[[nodiscard]] OutstandingResult analyze_outstanding(std::istream& input, OutstandingWindow window,
                                                    EventStreamOptions options = {});
[[nodiscard]] OutstandingResult analyze_filtered_outstanding(
    std::istream& input, OutstandingWindow window, const AnalysisFilter& filter,
    const EventMetadataResolver& resolver = {}, EventStreamOptions options = {});

}  // namespace noleax::analyzer
