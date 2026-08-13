#pragma once

#include <cstdint>
#include <vector>

#include "noleax/trace/memory_snapshot.hpp"

namespace noleax::agent::linux {

// Linux counterparts of the Windows process memory samplers
// (docs/LINUX_PORT_PLAN.md M4): counters from /proc/self/status, the full map walk from
// /proc/self/maps. Both run on the writer thread at the configured intervals; failures
// skip the sample silently and never abort the capture.
//
// Field mapping for the counters (the wire model keeps the Windows field names):
//   working_set_bytes       <- VmRSS
//   peak_working_set_bytes  <- VmHWM
//   private_bytes           <- RssAnon (resident anonymous; the closest Linux analog of
//                            Windows PrivateUsage)
//   commit_bytes            <- VmSize (total mapped virtual size)
[[nodiscard]] bool capture_memory_counters(noleax::trace::MemoryCounters& counters) noexcept;

// Maps /proc/self/maps regions onto the wire model: a region with no permission bits
// (---p, PROT_NONE) reports kReserve, everything else kCommit; a named path reports
// kImage when executable, kMapped otherwise; anonymous and special regions ([heap],
// [stack], vDSO, ...) report kPrivate. protect carries the POSIX PROT_* bits.
//
// Aggregate domain: committed/reserved/free only cover the platform's user canonical
// range (x86-64 4-level paging ends at 0x0000'7fff'ffff'ffff; 5-level la57 systems are
// detected via /proc/cpuinfo and extend it to 0x00ff'ffff'ffff'ffff). Kernel-only
// mappings above it ([vsyscall]) are still listed in `regions` but excluded from every
// aggregate, so the free-space totals can never wrap toward UINT64_MAX. Note that
// committed/reserved are inferred from maps permissions — they are not a Linux commit
// charge and do not compare to the Windows semantics beyond the field names.
[[nodiscard]] bool capture_memory_map(noleax::trace::MemoryMap& map);

namespace detail {

// Test seam: the aggregation half of the map walk, split from /proc parsing so fixtures
// can drive it with synthetic layouts. `canonical_user_end` is the inclusive last user
// address; pass kCanonicalUserEnd4Level/kCanonicalUserEnd5Level explicitly in tests.
inline constexpr std::uint64_t kCanonicalUserEnd4Level = 0x00007FFFFFFFFFFFULL;
inline constexpr std::uint64_t kCanonicalUserEnd5Level = 0x00FFFFFFFFFFFFFFULL;

struct MapsSummaryRegion {
  std::uint64_t begin{0U};
  std::uint64_t end{0U};
  bool committed{false};
};

struct MapsSummary {
  std::uint64_t committed_bytes{0U};
  std::uint64_t reserved_bytes{0U};
  std::uint64_t free_bytes{0U};
  std::uint64_t largest_free_bytes{0U};
};

[[nodiscard]] MapsSummary summarize_maps_regions(const std::vector<MapsSummaryRegion>& regions,
                                                 std::uint64_t canonical_user_end) noexcept;

// The running kernel's canonical user-space end (la57-aware, probed once per process).
[[nodiscard]] std::uint64_t canonical_user_end() noexcept;

}  // namespace detail

}  // namespace noleax::agent::linux
