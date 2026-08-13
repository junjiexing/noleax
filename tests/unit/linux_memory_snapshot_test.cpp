#include <sys/mman.h>

#include <catch2/catch_test_macros.hpp>

#include "noleax/agent/linux/memory_snapshot.hpp"

namespace {

using noleax::agent::linux::capture_memory_counters;
using noleax::agent::linux::capture_memory_map;

}  // namespace

TEST_CASE("linux memory counters come from /proc/self/status", "[agent][memory][linux]") {
  noleax::trace::MemoryCounters counters;
  REQUIRE(capture_memory_counters(counters));

  CHECK(counters.working_set_bytes > 0U);
  CHECK(counters.peak_working_set_bytes >= counters.working_set_bytes);
  CHECK(counters.commit_bytes >= counters.working_set_bytes);
  CHECK(counters.private_bytes > 0U);
  CHECK(counters.private_bytes <= counters.working_set_bytes);
}

TEST_CASE("linux memory map walks regions and accounts free gaps", "[agent][memory][linux]") {
  // A PROT_NONE reservation gives the walk a reserve-state region to classify.
  void* const reserved =
      ::mmap(nullptr, 2U * 1024U * 1024U, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(reserved != MAP_FAILED);

  noleax::trace::MemoryMap map;
  REQUIRE(capture_memory_map(map));

  REQUIRE_FALSE(map.regions.empty());
  CHECK(map.committed_bytes > 0U);
  CHECK(map.reserved_bytes >= 2U * 1024U * 1024U);
  CHECK(map.free_bytes > 0U);
  CHECK(map.largest_free_bytes <= map.free_bytes);

  bool saw_reserved_region = false;
  bool saw_image = false;
  std::uint64_t previous_base = 0U;
  for (const auto& region : map.regions) {
    CHECK(region.base >= previous_base);
    previous_base = region.base;
    CHECK(region.size > 0U);
    if (region.base == reinterpret_cast<std::uintptr_t>(reserved)) {
      saw_reserved_region = true;
      CHECK(region.state == noleax::trace::MemoryRegionState::kReserve);
      CHECK(region.protect == 0U);
    }
    if (region.type == noleax::trace::MemoryRegionType::kImage) {
      saw_image = true;
    }
  }
  CHECK(saw_reserved_region);
  CHECK(saw_image);  // the test binary and libc map executable file-backed pages

  ::munmap(reserved, 2U * 1024U * 1024U);
}

namespace {

using noleax::agent::linux::detail::kCanonicalUserEnd4Level;
using noleax::agent::linux::detail::kCanonicalUserEnd5Level;
using noleax::agent::linux::detail::MapsSummaryRegion;
using noleax::agent::linux::detail::summarize_maps_regions;

// Inclusive canonical end -> exclusive bound used by the aggregation.
constexpr std::uint64_t kUser4Limit = kCanonicalUserEnd4Level + 1ULL;
constexpr std::uint64_t kUser5Limit = kCanonicalUserEnd5Level + 1ULL;
constexpr std::uint64_t kVsyscallBegin = 0xFFFFFFFFFF600000ULL;
constexpr std::uint64_t kVsyscallEnd = 0xFFFFFFFFFF601000ULL;

}  // namespace

TEST_CASE("linux memory map aggregates ignore the vsyscall gap", "[agent][memory][linux]") {
  // The SCL field failure: an ordinary user layout followed by [vsyscall]. The gap beyond
  // the last user mapping must clamp at the canonical end instead of wrapping the totals
  // toward UINT64_MAX.
  constexpr std::uint64_t r1b = 0x0000555555554000ULL, r1e = 0x0000555555556000ULL;
  constexpr std::uint64_t r2b = 0x00007FFFF7DD0000ULL, r2e = 0x00007FFFF7FC0000ULL;
  constexpr std::uint64_t r3b = 0x00007FFFF7FC0000ULL, r3e = 0x00007FFFF7FC4000ULL;
  const std::vector<MapsSummaryRegion> regions = {
      {r1b, r1e, true},
      {r2b, r2e, true},
      {r3b, r3e, false},
      {kVsyscallBegin, kVsyscallEnd, true},
  };
  const auto summary = summarize_maps_regions(regions, kCanonicalUserEnd4Level);
  CHECK(summary.committed_bytes == (r1e - r1b) + (r2e - r2b));
  CHECK(summary.reserved_bytes == r3e - r3b);
  // Only the inter-region gap counts (the walk's long-standing semantics); the [vsyscall]
  // region contributes nothing in either direction.
  CHECK(summary.free_bytes == r2b - r1e);
  CHECK(summary.largest_free_bytes == r2b - r1e);
  CHECK(summary.free_bytes < (1ULL << 48U));
}

TEST_CASE("linux memory map aggregates cover the five-level canonical range",
          "[agent][memory][linux]") {
  // la57 user mappings above the 4-level end are ordinary user space on 5-level systems:
  // they count, and the totals still cannot wrap.
  constexpr std::uint64_t r1b = 0x0000555555554000ULL, r1e = 0x0000555555556000ULL;
  constexpr std::uint64_t r2b = 0x00F00000000000ULL, r2e = r2b + 0x100000ULL;
  const std::vector<MapsSummaryRegion> regions = {
      {r1b, r1e, true},
      {r2b, r2e, true},
      {kVsyscallBegin, kVsyscallEnd, true},
  };
  const auto summary = summarize_maps_regions(regions, kCanonicalUserEnd5Level);
  CHECK(summary.committed_bytes == (r1e - r1b) + (r2e - r2b));
  CHECK(summary.free_bytes == r2b - r1e);
  CHECK(summary.largest_free_bytes == r2b - r1e);
  CHECK(summary.free_bytes < (1ULL << 57U));

  // The same layout read on a 4-level system: the la57 region is above the user range,
  // so it joins [vsyscall] in the exclusion set rather than inflating the totals.
  const auto four_level = summarize_maps_regions(regions, kCanonicalUserEnd4Level);
  CHECK(four_level.committed_bytes == r1e - r1b);
  CHECK(four_level.free_bytes == 0U);
  CHECK(four_level.free_bytes < (1ULL << 48U));
}

TEST_CASE("linux memory map aggregates handle unsorted and straddling regions",
          "[agent][memory][linux]") {
  constexpr std::uint64_t r1b = 0x00007FFFF7DD0000ULL, r1e = 0x00007FFFF7DE0000ULL;
  constexpr std::uint64_t r2b = 0x0000555555554000ULL, r2e = 0x0000555555556000ULL;
  constexpr std::uint64_t r3b = kCanonicalUserEnd4Level - 0x1000ULL;
  const std::vector<MapsSummaryRegion> regions = {
      {r1b, r1e, true},
      {r2b, r2e, true},             // out of order: must not produce a negative gap
      {r3b, kVsyscallBegin, true},  // straddles the canonical boundary: clamped
  };
  const auto summary = summarize_maps_regions(regions, kCanonicalUserEnd4Level);
  CHECK(summary.committed_bytes == (r1e - r1b) + (r2e - r2b) + (kUser4Limit - r3b));
  CHECK(summary.free_bytes == r3b - r1e);
  CHECK(summary.largest_free_bytes == r3b - r1e);
}
