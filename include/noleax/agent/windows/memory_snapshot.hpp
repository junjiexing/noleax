#pragma once

#include "noleax/trace/memory_snapshot.hpp"

namespace noleax::agent::windows {

// Samples the process-wide memory counters through K32GetProcessMemoryInfo. Returns false when
// the operating system call fails; the caller skips the sample. `monotonic_ticks` stays
// untouched so the caller stamps the sample with its own clock read.
[[nodiscard]] bool capture_memory_counters(noleax::trace::MemoryCounters& counters) noexcept;

// Walks the process address space with VirtualQuery and records every committed or reserved
// region (ascending base order) plus full-walk aggregates that include MEM_FREE ranges. The
// region list is truncated at noleax::trace::kMaximumMemoryMapRegions with `map.truncated` set;
// the aggregates always describe the complete walk. Returns false when the walk cannot start.
// `monotonic_ticks` stays untouched so the caller stamps the sample with its own clock read.
[[nodiscard]] bool capture_memory_map(noleax::trace::MemoryMap& map);

}  // namespace noleax::agent::windows
