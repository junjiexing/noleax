#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <limits>
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
                                                     std::uint64_t commit_bytes,
                                                     std::uint64_t peak_working_set = 3'000U) {
  noleax::trace::MemoryCounters result;
  result.monotonic_ticks = ticks;
  result.working_set_bytes = working_set;
  result.peak_working_set_bytes = peak_working_set;
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

[[nodiscard]] noleax::trace::AgentMemory baseline_agent_memory(
    std::uint64_t ticks, noleax::trace::AgentMemorySampleKind kind) {
  noleax::trace::AgentMemory result;
  result.monotonic_ticks = ticks;
  result.kind = kind;
  return result;
}

[[nodiscard]] noleax::trace::AgentMemory periodic_agent_memory(std::uint64_t ticks,
                                                               std::uint32_t heap_flags) {
  noleax::trace::AgentMemory result;
  result.monotonic_ticks = ticks;
  result.kind = noleax::trace::AgentMemorySampleKind::kPeriodic;
  result.categories = {
      noleax::trace::AgentMemoryCategorySample{noleax::trace::AgentMemoryCategory::kEventQueue,
                                               noleax::trace::kAgentMemoryCategoryFlagExact, 4'096U,
                                               2'048U},
      noleax::trace::AgentMemoryCategorySample{noleax::trace::AgentMemoryCategory::kAgentHeap,
                                               heap_flags, 8'192U, 1'024U},
  };
  return result;
}

[[nodiscard]] noleax::trace::BufferConfiguration buffer_configuration() {
  noleax::trace::BufferConfiguration result;
  result.requested_bytes = 1'048'576U;
  result.effective_slots = 1'024U;
  result.event_size = 648U;
  result.slot_size = 1'024U;
  result.reserved_bytes = 1'048'576U;
  result.resident_after_init_bytes = 65'536U;
  result.flags = noleax::trace::kBufferConfigurationFlagAdjusted;
  return result;
}

[[nodiscard]] std::string agent_memory_trace() {
  noleax::testing::SyntheticTraceBuilder builder{file_header(), {true, false}};
  builder.set_buffer_configuration(buffer_configuration());
  builder.add_agent_memory(
      baseline_agent_memory(100U, noleax::trace::AgentMemorySampleKind::kBaselinePreInit));
  builder.add_agent_memory(
      baseline_agent_memory(150U, noleax::trace::AgentMemorySampleKind::kBaselinePostInit));
  builder.add_memory_counters(counters(200U, 8'192U, 500U, 600U, 16'384U));
  builder.add_agent_memory(periodic_agent_memory(200U, 0U));
  builder.add_memory_counters(counters(300U, 16'384U, 600U, 700U, 32'768U));
  builder.add_agent_memory(
      periodic_agent_memory(300U, noleax::trace::kAgentMemoryCategoryFlagExact));
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

TEST_CASE("agent memory totals reject overflowing samples", "[analyzer][memory]") {
  noleax::trace::AgentMemory memory;
  memory.categories = {
      noleax::trace::AgentMemoryCategorySample{
          noleax::trace::AgentMemoryCategory::kEventQueue, 0U,
          std::numeric_limits<std::uint64_t>::max(), 0U},
      noleax::trace::AgentMemoryCategorySample{noleax::trace::AgentMemoryCategory::kAgentHeap, 0U,
                                               1U, 0U},
  };
  CHECK_THROWS_AS(noleax::analyzer::agent_memory_totals(memory),
                  noleax::trace::MemorySnapshotValidationError);
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

TEST_CASE("memory JSON output follows the v6 schema", "[analyzer][memory][json]") {
  const auto encoded = memory_trace();
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  static_cast<void>(noleax::analyzer::analyze_memory_to_json(input, output, full_window()));

  const auto schema_path = std::filesystem::path{NOLEAX_TEST_SOURCE_DIR} / "docs" / "schema" /
                           "noleax-analysis-v6.schema.json";
  std::ifstream schema_input{schema_path, std::ios::binary};
  REQUIRE(schema_input);
  std::ostringstream schema_text;
  schema_text << schema_input.rdbuf();
  const auto schema = noleax::testing::parse_json(schema_text.str());
  const auto document = noleax::testing::parse_json(output.str());
  noleax::testing::validate_json_schema(document, schema);

  CHECK(document.at("mode").scalar() == "memory");
  CHECK(document.at("schema_version").unsigned_value() == 6U);
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
  CHECK(document.at("summary").at("agent_snapshots").unsigned_value() == 0U);
  CHECK_FALSE(snapshots[0].contains("agent"));
  CHECK_FALSE(document.contains("buffer_configuration"));
}

TEST_CASE("memory CSV output emits one row per sampling tick", "[analyzer][memory][csv]") {
  const auto encoded = memory_trace();
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  static_cast<void>(noleax::analyzer::analyze_memory_to_csv(input, output, full_window()));

  const auto table = noleax::testing::parse_csv(output.str());
  const std::vector<std::string> expected_header{
      "time_ns",
      "working_set_bytes",
      "peak_working_set_bytes",
      "private_bytes",
      "commit_bytes",
      "committed_bytes",
      "reserved_bytes",
      "free_bytes",
      "largest_free_bytes",
      "region_count",
      "truncated",
      "agent_reserved_bytes",
      "agent_resident_bytes",
      "application_estimate_bytes",
  };
  CHECK(table.header == expected_header);
  REQUIRE(table.rows.size() == 3U);
  CHECK(table.at(0U, "time_ns") == "0");
  CHECK(table.at(0U, "working_set_bytes") == "1000");
  CHECK(table.at(0U, "committed_bytes") == "10000");
  CHECK(table.at(0U, "region_count") == "2");
  CHECK(table.at(0U, "truncated") == "false");
  CHECK(table.at(0U, "agent_reserved_bytes").empty());
  CHECK(table.at(0U, "agent_resident_bytes").empty());
  CHECK(table.at(0U, "application_estimate_bytes").empty());
  CHECK(table.at(1U, "time_ns") == "100");
  CHECK(table.at(1U, "working_set_bytes") == "2000");
  CHECK(table.at(1U, "committed_bytes").empty());
  CHECK(table.at(1U, "region_count").empty());
  CHECK(table.at(1U, "truncated").empty());
  CHECK(table.at(2U, "working_set_bytes") == "3000");
  CHECK(table.at(2U, "committed_bytes") == "11000");
}

TEST_CASE("memory JSON output splits agent and application memory", "[analyzer][memory][json]") {
  const auto encoded = agent_memory_trace();
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  static_cast<void>(noleax::analyzer::analyze_memory_to_json(input, output, full_window()));

  const auto schema_path = std::filesystem::path{NOLEAX_TEST_SOURCE_DIR} / "docs" / "schema" /
                           "noleax-analysis-v6.schema.json";
  std::ifstream schema_input{schema_path, std::ios::binary};
  REQUIRE(schema_input);
  std::ostringstream schema_text;
  schema_text << schema_input.rdbuf();
  const auto schema = noleax::testing::parse_json(schema_text.str());
  const auto document = noleax::testing::parse_json(output.str());
  noleax::testing::validate_json_schema(document, schema);

  CHECK(document.at("mode").scalar() == "memory");
  CHECK(document.at("schema_version").unsigned_value() == 6U);
  const auto& snapshots = document.at("snapshots").array_items();
  REQUIRE(snapshots.size() == 4U);

  const auto& pre_init = snapshots[0].at("agent");
  CHECK(pre_init.at("sample_kind").scalar() == "baseline_pre_init");
  CHECK(pre_init.at("reserved_bytes").unsigned_value() == 0U);
  CHECK(pre_init.at("resident_bytes").unsigned_value() == 0U);
  CHECK(pre_init.at("exact").boolean_value());
  CHECK(pre_init.at("categories").array_items().empty());
  CHECK_FALSE(snapshots[0].contains("counters"));
  CHECK_FALSE(snapshots[0].contains("application_estimate_bytes"));

  CHECK(snapshots[1].at("agent").at("sample_kind").scalar() == "baseline_post_init");
  CHECK_FALSE(snapshots[1].contains("application_estimate_bytes"));

  const auto& periodic = snapshots[2].at("agent");
  CHECK(periodic.at("sample_kind").scalar() == "periodic");
  CHECK(periodic.at("reserved_bytes").unsigned_value() == 12'288U);
  CHECK(periodic.at("resident_bytes").unsigned_value() == 3'072U);
  CHECK_FALSE(periodic.at("exact").boolean_value());
  const auto& categories = periodic.at("categories").array_items();
  REQUIRE(categories.size() == 2U);
  CHECK(categories[0].at("category").scalar() == "event_queue");
  CHECK(categories[0].at("reserved_bytes").unsigned_value() == 4'096U);
  CHECK(categories[0].at("resident_bytes").unsigned_value() == 2'048U);
  CHECK(categories[0].at("exact").boolean_value());
  CHECK(categories[1].at("category").scalar() == "agent_heap");
  CHECK(categories[1].at("reserved_bytes").unsigned_value() == 8'192U);
  CHECK(categories[1].at("resident_bytes").unsigned_value() == 1'024U);
  CHECK_FALSE(categories[1].at("exact").boolean_value());
  CHECK(snapshots[2].at("application_estimate_bytes").unsigned_value() == 5'120U);
  CHECK_FALSE(snapshots[2].at("application_estimate_exact").boolean_value());

  CHECK(snapshots[3].at("agent").at("exact").boolean_value());
  CHECK(snapshots[3].at("application_estimate_bytes").unsigned_value() == 13'312U);
  CHECK(snapshots[3].at("application_estimate_exact").boolean_value());

  const auto& buffer = document.at("buffer_configuration");
  CHECK(buffer.at("requested_bytes").unsigned_value() == 1'048'576U);
  CHECK(buffer.at("effective_slots").unsigned_value() == 1'024U);
  CHECK(buffer.at("event_size").unsigned_value() == 648U);
  CHECK(buffer.at("slot_size").unsigned_value() == 1'024U);
  CHECK(buffer.at("reserved_bytes").unsigned_value() == 1'048'576U);
  CHECK(buffer.at("resident_after_init_bytes").unsigned_value() == 65'536U);
  CHECK(buffer.at("adjusted").boolean_value());

  CHECK(document.at("summary").at("snapshots").unsigned_value() == 4U);
  CHECK(document.at("summary").at("counter_snapshots").unsigned_value() == 2U);
  CHECK(document.at("summary").at("agent_snapshots").unsigned_value() == 4U);
}

TEST_CASE("memory console output splits agent and application memory",
          "[analyzer][memory][console]") {
  using Catch::Matchers::ContainsSubstring;
  const auto encoded = agent_memory_trace();
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  static_cast<void>(noleax::analyzer::analyze_memory_to_console(input, output, full_window(), {}));
  const std::string text = output.str();

  CHECK_THAT(text,
             ContainsSubstring("+0ns agent-resident=0B agent-reserved=0B baseline=pre-init\n"));
  CHECK_THAT(text,
             ContainsSubstring("+50ns agent-resident=0B agent-reserved=0B baseline=post-init\n"));
  CHECK_THAT(text,
             ContainsSubstring("+100ns working-set=8192B peak-working-set=16384B private=500B "
                               "commit=600B agent-resident=3072B agent-reserved=12288B "
                               "application=5120B (estimate)\n"));
  CHECK_THAT(text,
             ContainsSubstring("+200ns working-set=16384B peak-working-set=32768B private=600B "
                               "commit=700B agent-resident=3072B agent-reserved=12288B "
                               "application=13312B (exact)\n"));
  CHECK_THAT(text, ContainsSubstring("  buffer: requested=1048576B slots=1024 slot=1024B "
                                     "event=648B reserved=1048576B resident-after-init=65536B "
                                     "adjusted=true\n"));
  CHECK_THAT(text, ContainsSubstring("  snapshots: 4\n"));
  CHECK_THAT(text, ContainsSubstring("  counter-snapshots: 2\n"));
  CHECK_THAT(text, ContainsSubstring("  agent-snapshots: 4\n"));
}

TEST_CASE("memory CSV output includes the agent memory columns", "[analyzer][memory][csv]") {
  const auto encoded = agent_memory_trace();
  std::istringstream input{encoded, std::ios::binary};
  std::ostringstream output;
  static_cast<void>(noleax::analyzer::analyze_memory_to_csv(input, output, full_window()));

  const auto table = noleax::testing::parse_csv(output.str());
  REQUIRE(table.rows.size() == 4U);
  CHECK(table.at(0U, "agent_reserved_bytes") == "0");
  CHECK(table.at(0U, "agent_resident_bytes") == "0");
  CHECK(table.at(0U, "application_estimate_bytes").empty());
  CHECK(table.at(1U, "agent_reserved_bytes") == "0");
  CHECK(table.at(1U, "application_estimate_bytes").empty());
  CHECK(table.at(2U, "working_set_bytes") == "8192");
  CHECK(table.at(2U, "agent_reserved_bytes") == "12288");
  CHECK(table.at(2U, "agent_resident_bytes") == "3072");
  CHECK(table.at(2U, "application_estimate_bytes") == "5120");
  CHECK(table.at(3U, "agent_reserved_bytes") == "12288");
  CHECK(table.at(3U, "agent_resident_bytes") == "3072");
  CHECK(table.at(3U, "application_estimate_bytes") == "13312");
}
