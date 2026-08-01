#include "noleax/analyzer/stacks.hpp"

#include <algorithm>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/analyzer/time.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"

namespace noleax::analyzer {
namespace {

void validate_window(const StacksWindow& window) {
  if (window.from.count() < 0 || (window.to.has_value() && window.to->count() < 0)) {
    throw StacksAnalysisError{"stacks window times must not be negative"};
  }
  if (window.to.has_value() && window.from > *window.to) {
    throw StacksAnalysisError{"stacks window requires from <= to"};
  }
}

template <typename Group, typename Metric>
void sort_groups(std::vector<Group>& groups, Metric metric) {
  std::sort(groups.begin(), groups.end(), [&metric](const Group& left, const Group& right) {
    if (metric(left) != metric(right)) {
      return metric(left) > metric(right);
    }
    return left.stack_id.value() < right.stack_id.value();
  });
}

void sort_event_groups(std::vector<EventsStacksGroup>& groups, StacksSort sort) {
  switch (sort) {
    case StacksSort::kCalls:
      sort_groups(groups, [](const EventsStacksGroup& group) { return group.calls; });
      return;
    case StacksSort::kFreeBytes:
      sort_groups(groups, [](const EventsStacksGroup& group) { return group.free_bytes; });
      return;
    case StacksSort::kNetBytes:
      sort_groups(groups, [](const EventsStacksGroup& group) { return group.net_bytes(); });
      return;
    case StacksSort::kAllocBytes:
    case StacksSort::kBytes:
      sort_groups(groups, [](const EventsStacksGroup& group) { return group.alloc_bytes; });
      return;
  }
}

void sort_leak_groups(std::vector<LeaksStacksGroup>& groups, StacksSort sort) {
  switch (sort) {
    case StacksSort::kCalls:
      sort_groups(groups, [](const LeaksStacksGroup& group) { return group.calls; });
      return;
    case StacksSort::kAllocBytes:
    case StacksSort::kFreeBytes:
    case StacksSort::kNetBytes:
    case StacksSort::kBytes:
      sort_groups(groups, [](const LeaksStacksGroup& group) { return group.bytes; });
      return;
  }
}

class EventsStacksCollector {
 public:
  EventsStacksCollector(StacksWindow window, const AnalysisFilter& filter,
                        const EventMetadataResolver& resolver)
      : window_{window}, filter_{filter}, resolver_{resolver} {
    GenerationCallbacks callbacks;
    callbacks.on_ended = [this](const MemoryGeneration& generation, GenerationEndReason,
                                const noleax::trace::Event& event) {
      observe_generation_ended(generation, event);
    };
    tracker_ = GenerationTracker{std::move(callbacks)};
  }

  [[nodiscard]] EventsStacksResult analyze(std::istream& input, EventStreamOptions options) {
    EventStreamCallbacks callbacks;
    callbacks.on_file_header = [this](const noleax::trace::FileHeader& header) {
      file_header_ = header;
    };
    callbacks.on_event = [this](const noleax::trace::Event& event) { observe(event); };
    EventsStacksResult result;
    result.window = window_;
    result.trace = analyze_event_stream(input, callbacks, options);
    result.aggregated_event_count = aggregated_event_count_;
    result.unmatched_free_count = unmatched_free_count_;
    result.groups.reserve(groups_.size());
    for (auto& entry : groups_) {
      result.groups.push_back(entry.second);
    }
    return result;
  }

 private:
  [[nodiscard]] bool in_window(std::uint64_t ticks) const {
    if (compare_trace_time(ticks, *file_header_, window_.from) == std::strong_ordering::less) {
      return false;
    }
    if (window_.to.has_value() &&
        compare_trace_time(ticks, *file_header_, *window_.to) != std::strong_ordering::less) {
      return false;
    }
    return true;
  }

  [[nodiscard]] bool selected(const noleax::trace::Event& event) const {
    return noleax::trace::call_succeeded(event.header.status) &&
           in_window(event.header.monotonic_ticks) && filter_.matches_event(event, resolver_);
  }

  [[nodiscard]] EventsStacksGroup& group_for(const noleax::trace::Event& event) {
    EventsStacksGroup& group = groups_[event.header.stack_id.value()];
    if (group.calls == 0U) {
      group.stack_id = event.header.stack_id;
      group.sample_event = event;
    }
    return group;
  }

  void observe(const noleax::trace::Event& event) {
    if (!file_header_.has_value()) {
      throw StacksAnalysisError{"event appeared before FileHeader"};
    }
    const noleax::trace::EventOperation operation = noleax::trace::event_operation(event.payload);
    // The tracker consumes the generation on free, so check provenance first.
    const bool untracked_free =
        operation == noleax::trace::EventOperation::kFree &&
        noleax::trace::call_succeeded(event.header.status) &&
        tracker_.find_allocation(std::get<noleax::trace::FreeEvent>(event.payload).allocation_id) ==
            nullptr;
    tracker_.observe(event);

    if (untracked_free && selected(event)) {
      EventsStacksGroup& group = group_for(event);
      ++group.free_calls;
      ++group.calls;
      ++aggregated_event_count_;
      ++unmatched_free_count_;
      return;
    }
    if (operation == noleax::trace::EventOperation::kAllocate ||
        operation == noleax::trace::EventOperation::kReallocate) {
      if (!selected(event)) {
        return;
      }
      EventsStacksGroup& group = group_for(event);
      ++group.alloc_calls;
      ++group.calls;
      group.alloc_bytes +=
          operation == noleax::trace::EventOperation::kAllocate
              ? std::get<noleax::trace::AllocationEvent>(event.payload).requested_size
              : std::get<noleax::trace::ReallocationEvent>(event.payload).requested_size;
      ++aggregated_event_count_;
    }
  }

  void observe_generation_ended(const MemoryGeneration& generation,
                                const noleax::trace::Event& event) {
    if (generation.kind != GenerationKind::kHeapAllocation ||
        noleax::trace::event_operation(event.payload) != noleax::trace::EventOperation::kFree ||
        !selected(event)) {
      return;
    }
    EventsStacksGroup& group = group_for(event);
    ++group.free_calls;
    ++group.calls;
    group.free_bytes += generation.size;
    ++aggregated_event_count_;
  }

  StacksWindow window_;
  const AnalysisFilter& filter_;
  const EventMetadataResolver& resolver_;
  std::optional<noleax::trace::FileHeader> file_header_;
  GenerationTracker tracker_;
  std::unordered_map<std::uint64_t, EventsStacksGroup> groups_;
  std::uint64_t aggregated_event_count_{0U};
  std::uint64_t unmatched_free_count_{0U};
};

}  // namespace

EventsStacksResult analyze_event_stacks(std::istream& input, StacksWindow window, StacksSort sort,
                                        const AnalysisFilter& filter,
                                        const EventMetadataResolver& resolver,
                                        EventStreamOptions options) {
  validate_window(window);
  if (filter.requires_metadata() && !resolver) {
    throw AnalysisFilterError{"API and module filters require an event metadata resolver"};
  }
  EventsStacksResult result =
      EventsStacksCollector{window, filter, resolver}.analyze(input, options);
  sort_event_groups(result.groups, sort);
  return result;
}

LeaksStacksResult analyze_leak_stacks(std::istream& input, OutstandingWindow window,
                                      StacksSort sort, const AnalysisFilter& filter,
                                      const EventMetadataResolver& resolver,
                                      EventStreamOptions options) {
  LeaksStacksResult result;
  result.outstanding = analyze_filtered_outstanding(input, window, filter, resolver, options);
  std::unordered_map<std::uint64_t, LeaksStacksGroup> groups;
  for (const auto& generation : result.outstanding.outstanding) {
    if (generation.kind != GenerationKind::kHeapAllocation) {
      continue;
    }
    LeaksStacksGroup& group = groups[generation.created_by.header.stack_id.value()];
    if (group.calls == 0U) {
      group.stack_id = generation.created_by.header.stack_id;
      group.sample_event = generation.created_by;
    }
    ++group.calls;
    group.bytes += generation.size;
  }
  result.groups.reserve(groups.size());
  for (auto& entry : groups) {
    result.groups.push_back(entry.second);
  }
  sort_leak_groups(result.groups, sort);
  return result;
}

}  // namespace noleax::analyzer
