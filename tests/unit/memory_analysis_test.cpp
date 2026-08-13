#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <vector>

#include "noleax/analyzer/console.hpp"
#include "noleax/analyzer/csv.hpp"
#include "noleax/analyzer/json.hpp"
#include "noleax/analyzer/memory.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/memory_snapshot.hpp"
#include "noleax/trace/wire_format.hpp"
#include "support/csv_table.hpp"
#include "support/json_dom.hpp"
#include "support/json_schema.hpp"
#include "support/synthetic_trace.hpp"

namespace {

[[nodiscard]] noleax::trace::FileHeader file_header() {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.monotonic_frequency = 1'000'000'000U;
  header.monotonic_origin = 100U;
  header.utc_origin_ns = 1'000U;
  return header;
}

[[nodiscard]] noleax::trace::MemoryCounters counters(std::uint64_t ticks, std::uint64_t working_set,
                                                     std::uint64_t private_bytes,
                                                     std::uint64_t commit_bytes) {
  noleax::trace::MemoryCounters result;
  result.monotonic_ticks = ticks;
  result.working_set_bytes = working_set;
  result.peak_working_set_bytes = 3'000U;
  result.private_bytes = private_bytes;
  result.commit_bytes = commit_bytes;
  return result;
}

[[nodiscard]] noleax::trace::MemoryMap map(std::uint64_t ticks, std::uint64_t committed) {
  noleax::trace::MemoryMap result;
  result.monotonic_ticks = ticks;
  result.committed_bytes = committed;
  result.reserved_bytes = 20'000U;
  result.free_bytes = 1'000'000U;
  result.largest_free_bytes = 500'000U;
  result.regions = {
      noleax::trace::MemoryMapRegion{0x10000U, 0x2000U, noleax::trace::MemoryRegionState::kCommit,
                                     noleax::trace::MemoryRegionType::kPrivate, 0x04U},
      noleax::trace::MemoryMapRegion{0x40000000U, 0x100000U,
                                     noleax::trace::MemoryRegionState::kReserve,
                                     noleax::trace::MemoryRegionType::kMapped, 0x02U},
  };
  return result;
}

[[nodiscard]] std::string memory_trace() {
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
  builder.add_memory_counters(counters(100U, 1'000U, 500U, 600U));
  builder.add_memory_map(map(100U, 10'000U));
  builder.add_memory_counters(counters(200U, 2'000U, 600U, 700U));
  builder.add_memory_counters(counters(300U, 3'000U, 700U, 800U));
  builder.add_memory_map(map(300U, 11'000U));
  builder.finish_normally(0);
  return builder.build();
}

[[nodiscard]] noleax::analyzer::MemoryWindow full_window() {
  noleax::analyzer::MemoryWindow window;
  window.from.time = std::chrono::nanoseconds{0};
  return window;
}

}  // namespace

TEST_CASE("memory analysis merges snapshots by sampling tick", "[analyzer][memory]") {
  const auto encoded = memory_trace();
  std::istringstream input{encoded, std::ios::binary};
  const auto result = noleax::analyzer::analyze_memory(input);

  REQUIRE(result.snapshots.size() == 3U);
  CHECK(result.snapshots[0].monotonic_ticks == 100U);
  REQUIRE(result.snapshots[0].counters.has_value());
  REQUIRE(result.snapshots[0].map.has_value());
  CHECK(result.snapshots[0].counters->working_set_bytes == 1'000U);
  CHECK(result.snapshots[0].map->committed_bytes == 10'000U);
  CHECK(result.snapshots[1].monotonic_ticks == 200U);
  CHECK(result.snapshots[1].counters.has_value());
  CHECK_FALSE(result.snapshots[1].map.has_value());
  CHECK(result.snapshots[2].monotonic_ticks == 300U);
  CHECK(result.snapshots[2].counters.has_value());
  CHECK(result.snapshots[2].map.has_value());
  CHECK(result.trace.memory_counters_count == 3U);
  CHECK(result.trace.memory_map_count == 2U);
  CHECK_FALSE(result.trace.partially_understood);
}

TEST_CASE("memory analysis applies the time window", "[analyzer][memory]") {
  const auto encoded = memory_trace();
  noleax::analyzer::MemoryWindow window;
  window.from.time = std::chrono::nanoseconds{100};
  window.to = noleax::analyzer::WindowBound{};
  window.to->time = std::chrono::nanoseconds{200};

  std::istringstream input{encoded, std::ios::binary};
  const auto result = noleax::analyzer::analyze_memory(input, window);
  REQUIRE(result.snapshots.size() == 1U);
  CHECK(result.snapshots[0].monotonic_ticks == 200U);
  CHECK(result.snapshots[0].counters.has_value());
  CHECK_FALSE(result.snapshots[0].map.has_value());
}

TEST_CASE("memory console output lists the time series and peaks", "[analyzer][memory][console]") {
  using Catch::Matchers::ContainsSubstring;
  const auto encoded = memory_trace();
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  const auto result = noleax::analyzer::analyze_memory_to_console(input, output, full_window(), {});
  const std::string text = output.str();

  CHECK_THAT(text, ContainsSubstring("noleax memory\n"));
  CHECK_THAT(text, ContainsSubstring("window: [0ns, trace-end)\n"));
  CHECK_THAT(text, ContainsSubstring("+0ns working-set=1000B peak-working-set=3000B private=500B "
                                     "commit=600B committed=10000B reserved=20000B free=1000000B "
                                     "largest-free=500000B regions=2\n"));
  CHECK_THAT(text, ContainsSubstring("+100ns working-set=2000B peak-working-set=3000B private=600B "
                                     "commit=700B\n"));
  CHECK_THAT(text, ContainsSubstring("peaks:\n"));
  CHECK_THAT(text, ContainsSubstring("working-set: 3000B at +200ns\n"));
  CHECK_THAT(text, ContainsSubstring("private: 700B at +200ns\n"));
  CHECK_THAT(text, ContainsSubstring("commit: 800B at +200ns\n"));
  CHECK_THAT(text, ContainsSubstring("committed: 11000B at +200ns\n"));
  CHECK_THAT(text, ContainsSubstring("reserved: 20000B at +0ns\n"));
  CHECK_THAT(text, ContainsSubstring("  snapshots: 3\n"));
  CHECK_THAT(text, ContainsSubstring("  counter-snapshots: 3\n"));
  CHECK_THAT(text, ContainsSubstring("  map-snapshots: 2\n"));
  CHECK(result.trace.completeness.overall_state() == noleax::trace::CompletenessState::kComplete);
}

TEST_CASE("memory JSON output follows the v4 schema", "[analyzer][memory][json]") {
  const auto encoded = memory_trace();
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  static_cast<void>(noleax::analyzer::analyze_memory_to_json(input, output, full_window()));

  const auto schema_path = std::filesystem::path{NOLEAX_TEST_SOURCE_DIR} / "docs" / "schema" /
                           "noleax-analysis-v5.schema.json";
  std::ifstream schema_input{schema_path, std::ios::binary};
  REQUIRE(schema_input);
  std::ostringstream schema_text;
  schema_text << schema_input.rdbuf();
  const auto schema = noleax::testing::parse_json(schema_text.str());
  const auto document = noleax::testing::parse_json(output.str());
  noleax::testing::validate_json_schema(document, schema);

  CHECK(document.at("mode").scalar() == "memory");
  CHECK(document.at("schema_version").unsigned_value() == 5U);
  const auto& snapshots = document.at("snapshots").array_items();
  REQUIRE(snapshots.size() == 3U);
  CHECK(snapshots[0].at("monotonic_ticks").unsigned_value() == 100U);
  CHECK(snapshots[0].at("relative_time_ns").signed_value() == 0);
  CHECK(snapshots[0].at("counters").at("working_set_bytes").unsigned_value() == 1'000U);
  CHECK(snapshots[0].at("map").at("region_count").unsigned_value() == 2U);
  const auto& regions = snapshots[0].at("map").at("regions").array_items();
  REQUIRE(regions.size() == 2U);
  CHECK(regions[0].at("base").scalar() == "0x0000000000010000");
  CHECK(regions[0].at("state").scalar() == "commit");
  CHECK(regions[0].at("type").scalar() == "private");
  CHECK(regions[1].at("state").scalar() == "reserve");
  CHECK(regions[1].at("type").scalar() == "mapped");
  CHECK_FALSE(snapshots[1].contains("map"));
  CHECK(snapshots[1].at("counters").at("working_set_bytes").unsigned_value() == 2'000U);
  CHECK(document.at("summary").at("snapshots").unsigned_value() == 3U);
  CHECK(document.at("summary").at("counter_snapshots").unsigned_value() == 3U);
  CHECK(document.at("summary").at("map_snapshots").unsigned_value() == 2U);
}

TEST_CASE("memory CSV output emits one row per sampling tick", "[analyzer][memory][csv]") {
  const auto encoded = memory_trace();
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  static_cast<void>(noleax::analyzer::analyze_memory_to_csv(input, output, full_window()));

  const auto table = noleax::testing::parse_csv(output.str());
  const std::vector<std::string> expected_header{
      "time_ns",        "working_set_bytes", "peak_working_set_bytes",
      "private_bytes",  "commit_bytes",      "committed_bytes",
      "reserved_bytes", "free_bytes",        "largest_free_bytes",
      "region_count",   "truncated",
  };
  CHECK(table.header == expected_header);
  REQUIRE(table.rows.size() == 3U);
  CHECK(table.at(0U, "time_ns") == "0");
  CHECK(table.at(0U, "working_set_bytes") == "1000");
  CHECK(table.at(0U, "committed_bytes") == "10000");
  CHECK(table.at(0U, "region_count") == "2");
  CHECK(table.at(0U, "truncated") == "false");
  CHECK(table.at(1U, "time_ns") == "100");
  CHECK(table.at(1U, "working_set_bytes") == "2000");
  CHECK(table.at(1U, "committed_bytes").empty());
  CHECK(table.at(1U, "region_count").empty());
  CHECK(table.at(1U, "truncated").empty());
  CHECK(table.at(2U, "working_set_bytes") == "3000");
  CHECK(table.at(2U, "committed_bytes") == "11000");
}
