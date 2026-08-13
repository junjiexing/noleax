#include "noleax/trace/interval_set.hpp"

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <vector>

namespace {

using noleax::trace::IntervalSet;

using Set = IntervalSet<std::uint32_t>;
using Fragment = Set::Fragment;

[[nodiscard]] std::vector<Fragment> subtract(Set& set, std::uint64_t begin, std::uint64_t end) {
  return set.subtract(begin, end);
}

}  // namespace

TEST_CASE("interval set query and iteration over disjoint inserts", "[trace][interval-set]") {
  Set set;
  CHECK(set.empty());
  CHECK(set.insert(0x1000U, 0x2000U, 1U).empty());
  CHECK(set.insert(0x3000U, 0x5000U, 2U).empty());
  CHECK(set.insert(0x8000U, 0x9000U, 3U).empty());

  CHECK(set.size() == 3U);
  CHECK(set.total_bytes() == 0x1000U + 0x2000U + 0x1000U);
  CHECK_FALSE(set.find(0x0800U).has_value());
  CHECK_FALSE(set.find(0x2000U).has_value());
  const auto point = set.find(0x4100U);
  REQUIRE(point.has_value());
  CHECK(*point == Fragment{0x3000U, 0x5000U, 2U});
  CHECK(set.fragments() == std::vector<Fragment>{{0x1000U, 0x2000U, 1U},
                                                 {0x3000U, 0x5000U, 2U},
                                                 {0x8000U, 0x9000U, 3U}});

  SECTION("point query at boundaries") {
    CHECK(set.find(0x1000U).has_value());
    CHECK_FALSE(set.find(0x1FFFU + 1U).has_value());
    CHECK(set.find(0x8FFFU).has_value());
  }

  SECTION("range query clips to the requested bounds") {
    CHECK(set.intersections(0x1800U, 0x4000U) ==
          std::vector<Fragment>{{0x1800U, 0x2000U, 1U}, {0x3000U, 0x4000U, 2U}});
    CHECK(set.intersections(0x0000U, 0xFFFFU) == set.fragments());
    CHECK(set.intersections(0x2000U, 0x3000U).empty());
    CHECK(set.intersections(0x5000U, 0x5000U).empty());
    CHECK(set.intersections(0x9000U, 0x1000U).empty());
  }
}

TEST_CASE("interval set subtract covers the full range of one interval", "[trace][interval-set]") {
  Set set;
  static_cast<void>(set.insert(0x1000U, 0x5000U, 7U));

  SECTION("full cover erases the interval") {
    CHECK(subtract(set, 0x1000U, 0x5000U) == std::vector<Fragment>{{0x1000U, 0x5000U, 7U}});
    CHECK(set.empty());
  }

  SECTION("a wider range clips to the interval") {
    CHECK(subtract(set, 0x0000U, 0x8000U) == std::vector<Fragment>{{0x1000U, 0x5000U, 7U}});
    CHECK(set.empty());
  }

  SECTION("prefix removal shrinks the begin") {
    CHECK(subtract(set, 0x1000U, 0x3000U) == std::vector<Fragment>{{0x1000U, 0x3000U, 7U}});
    CHECK(set.fragments() == std::vector<Fragment>{{0x3000U, 0x5000U, 7U}});
  }

  SECTION("suffix removal shrinks the end") {
    CHECK(subtract(set, 0x2000U, 0x5000U) == std::vector<Fragment>{{0x2000U, 0x5000U, 7U}});
    CHECK(set.fragments() == std::vector<Fragment>{{0x1000U, 0x2000U, 7U}});
  }

  SECTION("middle removal splits the interval in two") {
    CHECK(subtract(set, 0x2000U, 0x4000U) == std::vector<Fragment>{{0x2000U, 0x4000U, 7U}});
    CHECK(set.fragments() == std::vector<Fragment>{{0x1000U, 0x2000U, 7U}, {0x4000U, 0x5000U, 7U}});
    CHECK(set.total_bytes() == 0x2000U);
  }

  SECTION("an interior miss removes nothing") {
    CHECK(subtract(set, 0x5000U, 0x6000U).empty());
    CHECK(subtract(set, 0x0000U, 0x1000U).empty());
    CHECK(set.fragments() == std::vector<Fragment>{{0x1000U, 0x5000U, 7U}});
  }
}

TEST_CASE("interval set subtract spans several intervals and repeats safely",
          "[trace][interval-set]") {
  Set set;
  static_cast<void>(set.insert(0x1000U, 0x2000U, 1U));
  static_cast<void>(set.insert(0x3000U, 0x4000U, 2U));
  static_cast<void>(set.insert(0x5000U, 0x6000U, 3U));

  SECTION("cross-entry removal trims the ends and erases the middle") {
    CHECK(subtract(set, 0x1800U, 0x5200U) == std::vector<Fragment>{{0x1800U, 0x2000U, 1U},
                                                                   {0x3000U, 0x4000U, 2U},
                                                                   {0x5000U, 0x5200U, 3U}});
    CHECK(set.fragments() == std::vector<Fragment>{{0x1000U, 0x1800U, 1U}, {0x5200U, 0x6000U, 3U}});
  }

  SECTION("repeating the same subtract is a no-op the second time") {
    static_cast<void>(set.subtract(0x1800U, 0x5200U));
    CHECK(set.subtract(0x1800U, 0x5200U).empty());
    CHECK(set.fragments() == std::vector<Fragment>{{0x1000U, 0x1800U, 1U}, {0x5200U, 0x6000U, 3U}});
  }

  SECTION("subtracting a hole between intervals removes nothing") {
    CHECK(set.subtract(0x2000U, 0x3000U).empty());
    CHECK(set.size() == 3U);
  }

  SECTION("erasing everything one piece at a time empties the set") {
    static_cast<void>(set.subtract(0x1000U, 0x2000U));
    static_cast<void>(set.subtract(0x3000U, 0x4000U));
    static_cast<void>(set.subtract(0x5000U, 0x6000U));
    CHECK(set.empty());
  }
}

TEST_CASE("interval set insert evicts overlaps and coalesces equal neighbours",
          "[trace][interval-set]") {
  Set set;
  static_cast<void>(set.insert(0x1000U, 0x2000U, 1U));
  static_cast<void>(set.insert(0x3000U, 0x4000U, 2U));

  SECTION("insert over a hole fills it") {
    CHECK(set.insert(0x2000U, 0x3000U, 9U).empty());
    CHECK(set.fragments() == std::vector<Fragment>{{0x1000U, 0x2000U, 1U},
                                                   {0x2000U, 0x3000U, 9U},
                                                   {0x3000U, 0x4000U, 2U}});
  }

  SECTION("insert evicts partial and full overlaps in one call") {
    CHECK(set.insert(0x1800U, 0x3400U, 5U) ==
          std::vector<Fragment>{{0x1800U, 0x2000U, 1U}, {0x3000U, 0x3400U, 2U}});
    CHECK(set.fragments() == std::vector<Fragment>{{0x1000U, 0x1800U, 1U},
                                                   {0x1800U, 0x3400U, 5U},
                                                   {0x3400U, 0x4000U, 2U}});
  }

  SECTION("insert over the whole set evicts everything") {
    CHECK(set.insert(0x0000U, 0x8000U, 4U).size() == 2U);
    CHECK(set.fragments() == std::vector<Fragment>{{0x0000U, 0x8000U, 4U}});
  }

  SECTION("adjacent inserts with equal values stay distinct fragments") {
    // No coalescing: fragment boundaries survive so the writer and the analyzer, fed the
    // same operation stream, keep identical fragmentation.
    static_cast<void>(set.insert(0x2000U, 0x2800U, 1U));
    static_cast<void>(set.insert(0x0800U, 0x1000U, 1U));
    CHECK(set.fragments() == std::vector<Fragment>{{0x0800U, 0x1000U, 1U},
                                                   {0x1000U, 0x2000U, 1U},
                                                   {0x2000U, 0x2800U, 1U},
                                                   {0x3000U, 0x4000U, 2U}});
  }

  SECTION("insert bridging two intervals keeps all three fragments") {
    static_cast<void>(set.insert(0x2000U, 0x3000U, 2U));
    CHECK(set.fragments() == std::vector<Fragment>{{0x1000U, 0x2000U, 1U},
                                                   {0x2000U, 0x3000U, 2U},
                                                   {0x3000U, 0x4000U, 2U}});
  }
}

TEST_CASE("interval set subtract from an empty range is a no-op", "[trace][interval-set]") {
  Set set;
  static_cast<void>(set.insert(0x1000U, 0x2000U, 1U));
  CHECK(set.subtract(0x3000U, 0x3000U).empty());
  CHECK(set.subtract(0x3000U, 0x1000U).empty());
  CHECK(set.insert(0x4000U, 0x4000U, 2U).empty());
  CHECK(set.fragments() == std::vector<Fragment>{{0x1000U, 0x2000U, 1U}});
}
