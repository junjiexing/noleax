#pragma once

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string_view>
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

// One sampling tick: the records due at that tick. At least one of the three is always
// present. agent (H4, format minor 4) carries the agent-owned memory breakdown; it is
// absent in older or non-Linux traces.
struct MemorySnapshot {
  std::uint64_t monotonic_ticks{0U};
  std::optional<noleax::trace::MemoryCounters> counters;
  std::optional<noleax::trace::MemoryMap> map;
  std::optional<noleax::trace::AgentMemory> agent;
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

// H4 (P0-1): derived per-snapshot figures shared by every output writer.
struct AgentMemoryTotals {
  std::uint64_t reserved_bytes{0U};
  std::uint64_t resident_bytes{0U};
  // Every category was measured exactly (dedicated mappings). When false the resident sum
  // includes heap estimates and the application figure derived from it is an estimate.
  bool exact{true};
};

[[nodiscard]] AgentMemoryTotals agent_memory_totals(
    const noleax::trace::AgentMemory& memory) noexcept;

// Process working set minus the agent-owned resident sum (saturating at zero). Only
// meaningful when the snapshot carries both counters and agent records; the result is an
// estimate unless agent_memory_totals(snapshot.agent).exact holds.
[[nodiscard]] std::uint64_t application_memory_estimate(const MemorySnapshot& snapshot) noexcept;

// Stable snake_case name for a category ("event_queue", ...); "unknown-<id>" for ids this
// analyzer build does not know.
[[nodiscard]] std::string agent_memory_category_name(noleax::trace::AgentMemoryCategory category);

// Snake_case sample kind name for output ("periodic", "baseline_pre_init", ...).
[[nodiscard]] std::string_view agent_memory_sample_kind_name(
    noleax::trace::AgentMemorySampleKind kind) noexcept;

}  // namespace noleax::analyzer
