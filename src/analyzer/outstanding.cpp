#include "noleax/analyzer/outstanding.hpp"

#include <algorithm>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <list>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/analyzer/time.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {
namespace {

void validate_window(const OutstandingWindow& window) {
  const auto negative_time = [](const std::optional<WindowBound>& bound) {
    return bound.has_value() && bound->time.has_value() && bound->time->count() < 0;
  };
  if ((window.a.time.has_value() && window.a.time->count() < 0) || negative_time(window.b) ||
      negative_time(window.c)) {
    throw OutstandingAnalysisError{"outstanding window times must not be negative"};
  }
  if (window.b.has_value() && !window_bounds_in_order(window.a, *window.b)) {
    throw OutstandingAnalysisError{"outstanding window requires a <= b"};
  }
  if (window.b.has_value() && window.c.has_value() &&
      !window_bounds_in_order(*window.b, *window.c)) {
    throw OutstandingAnalysisError{"outstanding window requires b <= c"};
  }
  if (!window.b.has_value() && window.c.has_value() &&
      !window_bounds_in_order(window.a, *window.c)) {
    throw OutstandingAnalysisError{"outstanding window requires a <= c"};
  }
}

// Bounds beyond the trace end clamp to the trace end instead of failing. A single-kind bound
// that exceeds collapses to the physical trace end point; a mixed bound clamps per component.
[[nodiscard]] bool window_bound_exceeds_trace_end(
    const WindowBound& bound, const noleax::trace::FileHeader& header, std::uint64_t trace_end,
    const std::optional<std::uint64_t>& trace_end_sequence) {
  if (bound.time.has_value() &&
      compare_trace_time(trace_end, header, *bound.time) == std::strong_ordering::less) {
    return true;
  }
  if (!bound.sequence.has_value()) {
    return false;
  }
  return trace_end_sequence.has_value() ? *bound.sequence > *trace_end_sequence
                                        : *bound.sequence > 0U;
}

// The observation point is inclusive. Round a fractional trace-end time up so comparing decoded
// events against the returned integral-nanosecond bound still includes the final event.
[[nodiscard]] WindowBound inclusive_trace_end_bound(
    const noleax::trace::FileHeader& header, std::uint64_t trace_end,
    const std::optional<std::uint64_t>& trace_end_sequence) {
  WindowBound result;
  const auto floor = trace_time_floor(trace_end, header);
  if (compare_trace_time(trace_end, header, floor) == std::strong_ordering::greater) {
    if (floor.count() < std::chrono::nanoseconds::max().count()) {
      result.time = floor + std::chrono::nanoseconds{1};
    }
  } else {
    result.time = floor;
  }
  result.sequence = trace_end_sequence;
  return result;
}

// The creation window has an exclusive upper endpoint. Represent physical trace end with the
// first integral-nanosecond/sequence fence strictly after every event, omitting a component when
// its representation cannot be incremented.
[[nodiscard]] WindowBound exclusive_trace_end_bound(
    const noleax::trace::FileHeader& header, std::uint64_t trace_end,
    const std::optional<std::uint64_t>& trace_end_sequence) {
  WindowBound result;
  const auto floor = trace_time_floor(trace_end, header);
  if (floor.count() < std::chrono::nanoseconds::max().count()) {
    result.time = floor + std::chrono::nanoseconds{1};
  }
  if (trace_end_sequence.has_value() &&
      *trace_end_sequence < (std::numeric_limits<std::uint64_t>::max)()) {
    result.sequence = *trace_end_sequence + 1U;
  }
  return result;
}

[[nodiscard]] WindowBound effective_upper_bound(
    const std::optional<WindowBound>& bound, const WindowBound& trace_end_bound,
    const noleax::trace::FileHeader& header, std::uint64_t trace_end,
    const std::optional<std::uint64_t>& trace_end_sequence) {
  if (!bound.has_value() || window_bound_empty(*bound)) {
    return trace_end_bound;
  }
  const bool mixed = bound->time.has_value() && bound->sequence.has_value();
  if (!mixed) {
    return window_bound_exceeds_trace_end(*bound, header, trace_end, trace_end_sequence)
               ? trace_end_bound
               : *bound;
  }
  WindowBound effective = *bound;
  if (effective.time.has_value() &&
      compare_trace_time(trace_end, header, *effective.time) == std::strong_ordering::less) {
    effective.time = trace_end_bound.time;
  }
  if (effective.sequence.has_value() &&
      (!trace_end_sequence.has_value() || *effective.sequence > *trace_end_sequence)) {
    effective.sequence = trace_end_sequence;
  }
  return effective;
}

void checked_increment(std::uint64_t& value, const char* message) {
  if (value == std::numeric_limits<std::uint64_t>::max()) {
    throw OutstandingAnalysisError{message};
  }
  ++value;
}

class OutstandingCollector {
 public:
  OutstandingCollector(OutstandingWindow window, const AnalysisFilter& filter,
                       const EventMetadataResolver& resolver)
      : window_{window}, filter_{filter}, resolver_{resolver} {
    GenerationCallbacks generation_callbacks;
    generation_callbacks.on_created = [this](const MemoryGeneration& generation) {
      observe_created(generation);
    };
    generation_callbacks.on_ended = [this](const MemoryGeneration& generation, GenerationEndReason,
                                           const noleax::trace::Event& event) {
      observe_ended(generation, event);
    };
    generation_callbacks.on_changed = [this](const MemoryGeneration& generation,
                                             const noleax::trace::Event& event) {
      observe_changed(generation, event);
    };
    tracker_ = GenerationTracker{std::move(generation_callbacks)};
  }

  [[nodiscard]] OutstandingResult analyze(std::istream& input, EventStreamOptions options) {
    EventStreamCallbacks callbacks;
    callbacks.on_file_header = [this](const noleax::trace::FileHeader& header) {
      file_header_ = header;
    };
    callbacks.on_event = [this](const noleax::trace::Event& event) { tracker_.observe(event); };

    OutstandingResult result;
    result.requested_window = window_;
    result.trace = analyze_event_stream(input, callbacks, options);
    const auto& header = result.trace.file_header;
    const std::uint64_t trace_end =
        result.trace.end_of_trace.has_value()
            ? result.trace.end_of_trace->final_monotonic_ticks
            : std::max(result.trace.known_monotonic_end, header.monotonic_origin);
    result.trace_end_monotonic_ticks = trace_end;
    std::optional<std::uint64_t> trace_end_sequence;
    if (result.trace.end_of_trace.has_value() &&
        result.trace.end_of_trace->final_sequence.is_valid()) {
      trace_end_sequence = result.trace.end_of_trace->final_sequence.value();
    } else if (result.trace.known_sequence_end.is_valid()) {
      trace_end_sequence = result.trace.known_sequence_end.value();
    }
    const WindowBound trace_end_bound =
        inclusive_trace_end_bound(header, trace_end, trace_end_sequence);
    const WindowBound trace_end_exclusive =
        exclusive_trace_end_bound(header, trace_end, trace_end_sequence);
    result.effective_b = effective_upper_bound(window_.b, trace_end_exclusive, header, trace_end,
                                               trace_end_sequence);

    const bool omitted_c = !window_.c.has_value() || window_bound_empty(*window_.c);
    const bool c_exceeds_trace =
        !omitted_c &&
        window_bound_exceeds_trace_end(*window_.c, header, trace_end, trace_end_sequence);
    result.observation_uses_trace_end = omitted_c || c_exceeds_trace;
    result.effective_c =
        effective_upper_bound(window_.c, trace_end_bound, header, trace_end, trace_end_sequence);
    result.candidate_count = candidate_count_;
    result.ended_by_c_count = ended_by_c_count_;

    // Candidates that provably ended at or before C were evicted when their end arrived, so
    // every survivor is outstanding at C; its size is the remaining (virtual) bytes at C.
    for (const auto& candidate : candidates_) {
      if (!filter_.matches_generation(candidate, resolver_)) {
        checked_increment(result.filtered_out_count, "filtered candidate count overflow");
        continue;
      }
      result.outstanding.push_back(candidate);
    }

    result.orphaned_allocation_end_count = tracker_.orphaned_allocation_end_count();
    result.orphaned_mapping_end_count = tracker_.orphaned_mapping_end_count();
    if (result.orphaned_allocation_end_count != 0U || result.orphaned_mapping_end_count != 0U) {
      result.trace.completeness.add(noleax::trace::CompletenessIssue::kEventLoss);
    }
    return result;
  }

 private:
  void observe_created(const MemoryGeneration& generation) {
    if (!file_header_.has_value()) {
      throw OutstandingAnalysisError{"generation appeared before FileHeader"};
    }
    if (!window_at_or_after(window_.a, *file_header_, generation.created_by) ||
        (window_.b.has_value() &&
         !window_before(*window_.b, *file_header_, generation.created_by))) {
      return;
    }

    checked_increment(candidate_count_, "candidate count overflow");
    candidates_.push_back(generation);
    const CandidateIterator candidate = std::prev(candidates_.end());
    if (generation.kind == GenerationKind::kHeapAllocation) {
      const bool inserted =
          allocation_candidates_.emplace(generation.allocation_id.value(), candidate).second;
      if (!inserted) {
        throw OutstandingAnalysisError{"allocation candidate ID is already present"};
      }
    } else {
      const bool inserted =
          mapping_candidates_.emplace(generation.mapping_id.value(), candidate).second;
      if (!inserted) {
        throw OutstandingAnalysisError{"mapping candidate ID is already present"};
      }
    }
  }

  void observe_ended(const MemoryGeneration& generation, const noleax::trace::Event& event) {
    if (!file_header_.has_value()) {
      throw OutstandingAnalysisError{"generation ended before FileHeader"};
    }
    auto& candidates = generation.kind == GenerationKind::kHeapAllocation ? allocation_candidates_
                                                                          : mapping_candidates_;
    const std::uint64_t id = generation.kind == GenerationKind::kHeapAllocation
                                 ? generation.allocation_id.value()
                                 : generation.mapping_id.value();
    const auto candidate = candidates.find(id);
    if (candidate == candidates.end()) {
      return;
    }

    // Early eviction: a generation that provably ends at or before C leaves the candidate
    // set when its end arrives; one that ends later (or never) stays outstanding at C.
    const bool observes_trace_end = !window_.c.has_value() || window_bound_empty(*window_.c);
    const bool ended_by_c =
        observes_trace_end || window_at_or_before(*window_.c, *file_header_, event);
    if (!ended_by_c) {
      return;
    }
    candidates_.erase(candidate->second);
    candidates.erase(candidate);
    checked_increment(ended_by_c_count_, "ended candidate count overflow");
  }

  void observe_changed(const MemoryGeneration& generation, const noleax::trace::Event& event) {
    if (!file_header_.has_value()) {
      throw OutstandingAnalysisError{"generation changed before FileHeader"};
    }
    // Only mapping generations change size; the reported size is the remaining virtual
    // bytes at C, so a change arriving after C does not apply.
    const auto candidate = mapping_candidates_.find(generation.mapping_id.value());
    if (candidate == mapping_candidates_.end()) {
      return;
    }
    const bool observes_trace_end = !window_.c.has_value() || window_bound_empty(*window_.c);
    if (observes_trace_end || window_at_or_before(*window_.c, *file_header_, event)) {
      candidate->second->size = generation.size;
    }
  }

  using CandidateIterator = std::list<MemoryGeneration>::iterator;

  OutstandingWindow window_;
  const AnalysisFilter& filter_;
  const EventMetadataResolver& resolver_;
  std::optional<noleax::trace::FileHeader> file_header_;
  GenerationTracker tracker_;
  std::list<MemoryGeneration> candidates_;
  std::unordered_map<std::uint64_t, CandidateIterator> allocation_candidates_;
  std::unordered_map<std::uint64_t, CandidateIterator> mapping_candidates_;
  std::uint64_t candidate_count_{0U};
  std::uint64_t ended_by_c_count_{0U};
};

}  // namespace

OutstandingResult analyze_outstanding(std::istream& input, OutstandingWindow window,
                                      EventStreamOptions options) {
  return analyze_filtered_outstanding(input, window, AnalysisFilter{}, {}, options);
}

OutstandingResult analyze_filtered_outstanding(std::istream& input, OutstandingWindow window,
                                               const AnalysisFilter& filter,
                                               const EventMetadataResolver& resolver,
                                               EventStreamOptions options) {
  validate_window(window);
  if (filter.requires_metadata() && !resolver) {
    throw AnalysisFilterError{"API and module filters require an event metadata resolver"};
  }
  return OutstandingCollector{window, filter, resolver}.analyze(input, options);
}

}  // namespace noleax::analyzer
