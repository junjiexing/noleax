#include "noleax/analyzer/memory.hpp"

#include <algorithm>
#include <compare>
#include <cstdint>
#include <istream>
#include <limits>
#include <string>
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
  std::vector<noleax::trace::AgentMemory> agent_records;
  EventStreamCallbacks callbacks;
  callbacks.on_memory_counters =
      [&counters_records](const noleax::trace::MemoryCounters& counters) {
        counters_records.push_back(counters);
      };
  callbacks.on_memory_map = [&map_records](const noleax::trace::MemoryMap& map) {
    map_records.push_back(map);
  };
  callbacks.on_agent_memory = [&agent_records](const noleax::trace::AgentMemory& agent) {
    agent_records.push_back(agent);
  };

  MemoryAnalysisResult result;
  result.window = window;
  result.trace = analyze_event_stream(input, callbacks, stream_options);
  const noleax::trace::FileHeader& header = result.trace.file_header;

  // All record kinds arrive in non-decreasing tick order; merge them by sampling tick.
  auto counters_at = counters_records.begin();
  auto map_at = map_records.begin();
  auto agent_at = agent_records.begin();
  const auto ticks_of = [](const auto& it, const auto& end) {
    return it != end ? it->monotonic_ticks : std::numeric_limits<std::uint64_t>::max();
  };
  while (counters_at != counters_records.end() || map_at != map_records.end() ||
         agent_at != agent_records.end()) {
    const std::uint64_t counters_ticks = ticks_of(counters_at, counters_records.end());
    const std::uint64_t map_ticks = ticks_of(map_at, map_records.end());
    const std::uint64_t agent_ticks = ticks_of(agent_at, agent_records.end());
    const std::uint64_t ticks = (std::min)(counters_ticks, (std::min)(map_ticks, agent_ticks));
    if (snapshot_in_window(window, header, ticks)) {
      MemorySnapshot snapshot;
      snapshot.monotonic_ticks = ticks;
      if (counters_ticks == ticks) {
        snapshot.counters = *counters_at;
      }
      if (map_ticks == ticks) {
        snapshot.map = std::move(*map_at);
      }
      if (agent_ticks == ticks) {
        snapshot.agent = std::move(*agent_at);
      }
      result.snapshots.push_back(std::move(snapshot));
    }
    if (counters_ticks == ticks) {
      ++counters_at;
    }
    if (map_ticks == ticks) {
      ++map_at;
    }
    if (agent_ticks == ticks) {
      ++agent_at;
    }
  }
  return result;
}

AgentMemoryTotals agent_memory_totals(const noleax::trace::AgentMemory& memory) {
  noleax::trace::validate_agent_memory(memory);
  AgentMemoryTotals totals;
  for (const noleax::trace::AgentMemoryCategorySample& category : memory.categories) {
    totals.reserved_bytes += category.reserved_bytes;
    totals.resident_bytes += category.resident_bytes;
    totals.exact =
        totals.exact && (category.flags & noleax::trace::kAgentMemoryCategoryFlagExact) != 0U;
  }
  return totals;
}

std::uint64_t application_memory_estimate(const MemorySnapshot& snapshot) {
  if (!snapshot.counters.has_value() || !snapshot.agent.has_value()) {
    return 0U;
  }
  const std::uint64_t agent_resident = agent_memory_totals(*snapshot.agent).resident_bytes;
  const std::uint64_t working_set = snapshot.counters->working_set_bytes;
  return agent_resident >= working_set ? 0U : working_set - agent_resident;
}

std::string agent_memory_category_name(noleax::trace::AgentMemoryCategory category) {
  switch (category) {
    case noleax::trace::AgentMemoryCategory::kEventQueue:
      return "event_queue";
    case noleax::trace::AgentMemoryCategory::kStackDictionary:
      return "stack_dictionary";
    case noleax::trace::AgentMemoryCategory::kTraceBuffers:
      return "trace_buffers";
    case noleax::trace::AgentMemoryCategory::kModuleTracker:
      return "module_tracker";
    case noleax::trace::AgentMemoryCategory::kHookBackend:
      return "hook_backend";
    case noleax::trace::AgentMemoryCategory::kAgentHeap:
      return "agent_heap";
  }
  return "unknown-" + std::to_string(static_cast<std::uint32_t>(category));
}

std::string_view agent_memory_sample_kind_name(noleax::trace::AgentMemorySampleKind kind) noexcept {
  switch (kind) {
    case noleax::trace::AgentMemorySampleKind::kPeriodic:
      return "periodic";
    case noleax::trace::AgentMemorySampleKind::kBaselinePreInit:
      return "baseline_pre_init";
    case noleax::trace::AgentMemorySampleKind::kBaselinePostInit:
      return "baseline_post_init";
  }
  return "unknown";
}

}  // namespace noleax::analyzer
