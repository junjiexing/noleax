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
