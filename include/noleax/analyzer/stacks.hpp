#pragma once

#include <chrono>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <stdexcept>
#include <vector>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/identifiers.hpp"

namespace noleax::analyzer {

enum class StacksSort : std::uint8_t {
  kCalls,
  kAllocBytes,
  kFreeBytes,
  kNetBytes,
  kBytes,
};

struct StacksWindow {
  std::chrono::nanoseconds from{0};
  std::optional<std::chrono::nanoseconds> to;
};

struct EventsStacksGroup {
  noleax::trace::StackId stack_id;
  noleax::trace::Event sample_event;
  std::uint64_t calls{0};
  std::uint64_t alloc_calls{0};
  std::uint64_t alloc_bytes{0};
  std::uint64_t free_calls{0};
  std::uint64_t free_bytes{0};

  [[nodiscard]] std::int64_t net_bytes() const noexcept {
    return static_cast<std::int64_t>(alloc_bytes) - static_cast<std::int64_t>(free_bytes);
  }
};

struct EventsStacksResult {
  EventStreamResult trace;
  StacksWindow window;
  std::vector<EventsStacksGroup> groups;
  std::uint64_t aggregated_event_count{0};
  std::uint64_t unmatched_free_count{0};
};

struct LeaksStacksGroup {
  noleax::trace::StackId stack_id;
  noleax::trace::Event sample_event;
  std::uint64_t calls{0};
  std::uint64_t bytes{0};
};

struct LeaksStacksResult {
  OutstandingResult outstanding;
  std::vector<LeaksStacksGroup> groups;
};

class StacksAnalysisError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

[[nodiscard]] EventsStacksResult analyze_event_stacks(std::istream& input, StacksWindow window,
                                                      StacksSort sort, const AnalysisFilter& filter,
                                                      const EventMetadataResolver& resolver = {},
                                                      EventStreamOptions options = {});

[[nodiscard]] LeaksStacksResult analyze_leak_stacks(std::istream& input, OutstandingWindow window,
                                                    StacksSort sort, const AnalysisFilter& filter,
                                                    const EventMetadataResolver& resolver = {},
                                                    EventStreamOptions options = {});

}  // namespace noleax::analyzer
