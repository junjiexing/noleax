#include "noleax/analyzer/memory.hpp"

#include <compare>
#include <cstdint>
#include <istream>
#include <limits>
#include <utility>
#include <vector>

#include "noleax/analyzer/time.hpp"
#include "noleax/trace/memory_snapshot.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {
namespace {

[[nodiscard]] bool snapshot_at_or_after(const WindowBound& bound,
                                        const noleax::trace::FileHeader& header,
                                        std::uint64_t ticks) {
  return !bound.time.has_value() ||
         compare_trace_time(ticks, header, *bound.time) != std::strong_ordering::less;
}

[[nodiscard]] bool snapshot_before(const WindowBound& bound,
                                   const noleax::trace::FileHeader& header, std::uint64_t ticks) {
  return !bound.time.has_value() ||
         compare_trace_time(ticks, header, *bound.time) == std::strong_ordering::less;
}

[[nodiscard]] bool snapshot_in_window(const MemoryWindow& window,
                                      const noleax::trace::FileHeader& header,
                                      std::uint64_t ticks) {
  if (!snapshot_at_or_after(window.from, header, ticks)) {
    return false;
  }
  return !window.to.has_value() || snapshot_before(*window.to, header, ticks);
}

}  // namespace

MemoryAnalysisResult analyze_memory(std::istream& input, MemoryWindow window,
                                    EventStreamOptions stream_options) {
  std::vector<noleax::trace::MemoryCounters> counters_records;
  std::vector<noleax::trace::MemoryMap> map_records;
  EventStreamCallbacks callbacks;
  callbacks.on_memory_counters =
      [&counters_records](const noleax::trace::MemoryCounters& counters) {
        counters_records.push_back(counters);
      };
  callbacks.on_memory_map = [&map_records](const noleax::trace::MemoryMap& map) {
    map_records.push_back(map);
  };

  MemoryAnalysisResult result;
  result.window = window;
  result.trace = analyze_event_stream(input, callbacks, stream_options);
  const noleax::trace::FileHeader& header = result.trace.file_header;

  // Both record kinds arrive in non-decreasing tick order; merge them by sampling tick.
  auto counters_at = counters_records.begin();
  auto map_at = map_records.begin();
  while (counters_at != counters_records.end() || map_at != map_records.end()) {
    const std::uint64_t counters_ticks = counters_at != counters_records.end()
                                             ? counters_at->monotonic_ticks
                                             : std::numeric_limits<std::uint64_t>::max();
    const std::uint64_t map_ticks = map_at != map_records.end()
                                        ? map_at->monotonic_ticks
                                        : std::numeric_limits<std::uint64_t>::max();
    const std::uint64_t ticks = counters_ticks < map_ticks ? counters_ticks : map_ticks;
    if (snapshot_in_window(window, header, ticks)) {
      MemorySnapshot snapshot;
      snapshot.monotonic_ticks = ticks;
      if (counters_ticks == ticks) {
        snapshot.counters = *counters_at;
      }
      if (map_ticks == ticks) {
        snapshot.map = std::move(*map_at);
      }
      result.snapshots.push_back(std::move(snapshot));
    }
    if (counters_ticks == ticks) {
      ++counters_at;
    }
    if (map_ticks == ticks) {
      ++map_at;
    }
  }
  return result;
}

}  // namespace noleax::analyzer
