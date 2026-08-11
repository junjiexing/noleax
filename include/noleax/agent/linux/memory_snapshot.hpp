#pragma once

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
// [stack], vDSO, ...) report kPrivate. protect carries the POSIX PROT_* bits. Aggregates
// cover the whole address space: gaps between regions account as free space.
[[nodiscard]] bool capture_memory_map(noleax::trace::MemoryMap& map);

}  // namespace noleax::agent::linux
