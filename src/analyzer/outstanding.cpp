#include "noleax/analyzer/outstanding.hpp"

#include <algorithm>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <limits>
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

struct CandidateState {
  MemoryGeneration generation;
  std::optional<std::uint64_t> ended_at;
};

void validate_window(const OutstandingWindow& window) {
  if (window.a.count() < 0 || window.b.count() < 0 ||
      (window.c.has_value() && window.c->count() < 0)) {
    throw OutstandingAnalysisError{"outstanding window times must not be negative"};
  }
  if (window.a > window.b) {
    throw OutstandingAnalysisError{"outstanding window requires a <= b"};
  }
  if (window.c.has_value() && window.b > *window.c) {
    throw OutstandingAnalysisError{"outstanding window requires b <= c"};
  }
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
    if (compare_trace_time(trace_end, header, window_.b) == std::strong_ordering::less) {
      throw OutstandingAnalysisError{"outstanding window b exceeds the trace end"};
    }

    const bool omitted_c = !window_.c.has_value();
    const bool c_exceeds_trace =
        window_.c.has_value() &&
        compare_trace_time(trace_end, header, *window_.c) == std::strong_ordering::less;
    result.observation_uses_trace_end = omitted_c || c_exceeds_trace;
    result.effective_c =
        result.observation_uses_trace_end ? trace_time_floor(trace_end, header) : *window_.c;
    result.candidate_count = static_cast<std::uint64_t>(candidates_.size());

    for (const auto& candidate : candidates_) {
      const bool ended_by_c =
          candidate.ended_at.has_value() &&
          (result.observation_uses_trace_end ||
           compare_trace_time(*candidate.ended_at, header, result.effective_c) !=
               std::strong_ordering::greater);
      if (ended_by_c) {
        checked_increment(result.ended_by_c_count, "ended candidate count overflow");
        continue;
      }

      if (!filter_.matches_generation(candidate.generation, resolver_)) {
        checked_increment(result.filtered_out_count, "filtered candidate count overflow");
        continue;
      }
      result.outstanding.push_back(candidate.generation);
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
    const auto ticks = generation.created_by.header.monotonic_ticks;
    if (compare_trace_time(ticks, *file_header_, window_.a) == std::strong_ordering::less ||
        compare_trace_time(ticks, *file_header_, window_.b) != std::strong_ordering::less) {
      return;
    }

    const std::size_t index = candidates_.size();
    candidates_.push_back(CandidateState{generation, std::nullopt});
    if (generation.kind == GenerationKind::kHeapAllocation) {
      allocation_candidates_.emplace(generation.allocation_id.value(), index);
    } else {
      mapping_candidates_.emplace(generation.mapping_id.value(), index);
    }
  }

  void observe_ended(const MemoryGeneration& generation, const noleax::trace::Event& event) {
    const auto& candidates = generation.kind == GenerationKind::kHeapAllocation
                                 ? allocation_candidates_
                                 : mapping_candidates_;
    const std::uint64_t id = generation.kind == GenerationKind::kHeapAllocation
                                 ? generation.allocation_id.value()
                                 : generation.mapping_id.value();
    const auto candidate = candidates.find(id);
    if (candidate == candidates.end()) {
      return;
    }
    auto& state = candidates_.at(candidate->second);
    if (state.ended_at.has_value()) {
      throw OutstandingAnalysisError{"candidate generation ended more than once"};
    }
    state.ended_at = event.header.monotonic_ticks;
  }

  OutstandingWindow window_;
  const AnalysisFilter& filter_;
  const EventMetadataResolver& resolver_;
  std::optional<noleax::trace::FileHeader> file_header_;
  GenerationTracker tracker_;
  std::vector<CandidateState> candidates_;
  std::unordered_map<std::uint64_t, std::size_t> allocation_candidates_;
  std::unordered_map<std::uint64_t, std::size_t> mapping_candidates_;
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
