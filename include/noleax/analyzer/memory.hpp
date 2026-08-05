#pragma once

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <vector>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/window.hpp"
#include "noleax/trace/memory_snapshot.hpp"

namespace noleax::analyzer {

// The window of a memory analysis: time-only bounds (snapshots carry no event sequence, so
// configuration validation rejects #sequence endpoints for this mode).
struct MemoryWindow {
  WindowBound from;
  std::optional<WindowBound> to;

  bool operator==(const MemoryWindow&) const = default;
};

// One sampling tick: the counters and/or map records due at that tick. At least one of the two
// is always present.
struct MemorySnapshot {
  std::uint64_t monotonic_ticks{0U};
  std::optional<noleax::trace::MemoryCounters> counters;
  std::optional<noleax::trace::MemoryMap> map;
};

struct MemoryAnalysisResult {
  EventStreamResult trace;
  MemoryWindow window;
  std::vector<MemorySnapshot> snapshots;
};

// Reads the trace and collects the memory snapshots inside `window`, merged by sampling tick
// in ascending order.
[[nodiscard]] MemoryAnalysisResult analyze_memory(std::istream& input, MemoryWindow window = {},
                                                  EventStreamOptions stream_options = {});

}  // namespace noleax::analyzer
