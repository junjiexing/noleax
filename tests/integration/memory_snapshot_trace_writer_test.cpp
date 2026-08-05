#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_trace_writer.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/trace/memory_snapshot.hpp"
#include "noleax/trace/wire_format.hpp"

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID address);

struct ParsedSnapshots {
  noleax::analyzer::EventStreamResult result;
  std::vector<noleax::trace::MemoryCounters> counters;
  std::vector<noleax::trace::MemoryMap> maps;
};

[[nodiscard]] noleax::trace::FileHeader make_file_header() {
  LARGE_INTEGER frequency{};
  LARGE_INTEGER origin{};
  if (QueryPerformanceFrequency(&frequency) == FALSE || QueryPerformanceCounter(&origin) == FALSE) {
    throw std::runtime_error{"QueryPerformanceCounter is unavailable"};
  }
  noleax::trace::FileHeader header;
  header.pointer_width = sizeof(void*);
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.session_id[0] = std::byte{0x5A};
  header.monotonic_frequency = static_cast<std::uint64_t>(frequency.QuadPart);
  header.monotonic_origin = static_cast<std::uint64_t>(origin.QuadPart);
  return header;
}

[[nodiscard]] bool finish_uninstall(noleax::agent::windows::RtlAllocateHeapHook& hook) noexcept {
  auto status = hook.uninstall();
  if (status == noleax::agent::HookUninstallStatus::kTeardownPending && hook.flush()) {
    status = noleax::agent::HookUninstallStatus::kUninstalled;
  }
  return status == noleax::agent::HookUninstallStatus::kUninstalled;
}

[[nodiscard]] ParsedSnapshots parse_trace(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  if (!input) {
    throw std::runtime_error{"cannot reopen trace output"};
  }
  ParsedSnapshots parsed;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_memory_counters = [&parsed](const noleax::trace::MemoryCounters& counters) {
    parsed.counters.push_back(counters);
  };
  callbacks.on_memory_map = [&parsed](const noleax::trace::MemoryMap& map) {
    parsed.maps.push_back(map);
  };
  parsed.result = noleax::analyzer::analyze_event_stream(input, callbacks);
  return parsed;
}

[[nodiscard]] bool counters_consistent(const noleax::trace::MemoryCounters& counters) {
  return counters.working_set_bytes != 0U && counters.peak_working_set_bytes != 0U &&
         counters.working_set_bytes <= counters.peak_working_set_bytes &&
         counters.private_bytes != 0U;
}

[[nodiscard]] bool map_consistent(const noleax::trace::MemoryMap& map) {
  return map.committed_bytes != 0U && map.free_bytes != 0U &&
         map.largest_free_bytes <= map.free_bytes && !map.regions.empty();
}

[[nodiscard]] int run_test(std::uint64_t counters_interval_ms, std::uint64_t map_interval_ms,
                           const char* mode_name, const std::filesystem::path& output_path) {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const HANDLE heap = GetProcessHeap();
  if (ntdll == nullptr || heap == nullptr) {
    return 10;
  }
  const auto allocate =
      reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  const auto free_heap =
      reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  if (allocate == nullptr || free_heap == nullptr) {
    return 11;
  }

  std::ofstream output{output_path, std::ios::binary | std::ios::trunc};
  if (!output) {
    return 12;
  }
  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlAllocateHeapHook hook{backend, 16U, 16U};
  noleax::agent::windows::RtlAllocateHeapTraceWriterOptions options;
  options.flush_interval = std::chrono::milliseconds{5};
  options.memory_counters_interval = std::chrono::milliseconds{counters_interval_ms};
  options.memory_map_interval = std::chrono::milliseconds{map_interval_ms};
  noleax::agent::windows::RtlAllocateHeapTraceWriter writer{hook, output, make_file_header(),
                                                            options};
  const auto install = hook.install();
  if (!install.installed()) {
    return 13;
  }
  writer.begin_capture();

  // Keep the process busy for long enough that several intervals elapse.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{900};
  while (std::chrono::steady_clock::now() < deadline) {
    for (std::uint32_t iteration = 0U; iteration < 100U; ++iteration) {
      void* const allocation = allocate(heap, 0U, 64U + iteration);
      if (allocation == nullptr || free_heap(heap, 0U, allocation) == FALSE) {
        return 14;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  if (!finish_uninstall(hook)) {
    return 15;
  }
  const auto writer_result = writer.finish();
  if (!backend.shutdown()) {
    return 16;
  }
  output.close();
  if (!output) {
    return 17;
  }
  if (writer_result.status != noleax::agent::windows::RtlAllocateHeapTraceWriterStatus::kComplete) {
    return 18;
  }

  const ParsedSnapshots parsed = parse_trace(output_path);
  const auto counters_count = parsed.result.memory_counters_count;
  const auto map_count = parsed.result.memory_map_count;
  if (counters_count != parsed.counters.size() || map_count != parsed.maps.size()) {
    return 18;
  }
  // The analyzer already rejects non-monotonic ticks; double-check the decoded order here.
  for (std::size_t index = 1U; index < parsed.counters.size(); ++index) {
    if (parsed.counters[index].monotonic_ticks < parsed.counters[index - 1U].monotonic_ticks) {
      return 19;
    }
  }
  for (const auto& counters : parsed.counters) {
    if (!counters_consistent(counters)) {
      return 20;
    }
  }
  for (const auto& map : parsed.maps) {
    if (!map_consistent(map)) {
      return 21;
    }
  }
  // The end-of-trace boundary covers the final snapshot, which is sampled after the last
  // event drain.
  if (parsed.result.end_of_trace.has_value()) {
    const std::uint64_t final_ticks = parsed.result.end_of_trace->final_monotonic_ticks;
    if (!parsed.counters.empty() && final_ticks < parsed.counters.back().monotonic_ticks) {
      return 28;
    }
    if (!parsed.maps.empty() && final_ticks < parsed.maps.back().monotonic_ticks) {
      return 29;
    }
  }

  const std::string_view mode{mode_name};
  if (mode == "both") {
    // Baseline + final + roughly one periodic sample per 100 ms over ~900 ms.
    if (counters_count < 4U || map_count < 4U) {
      return 22;
    }
  } else if (mode == "counters-only") {
    if (counters_count < 4U || map_count != 0U) {
      return 23;
    }
  } else if (mode == "map-only") {
    if (counters_count != 0U || map_count < 4U) {
      return 24;
    }
  } else if (mode == "disabled") {
    if (counters_count != 0U || map_count != 0U) {
      return 25;
    }
  } else if (mode == "mixed") {
    // 100 ms counters versus 300 ms maps: counters must clearly outnumber maps.
    if (counters_count < 2U * map_count || map_count < 2U) {
      return 26;
    }
  } else {
    return 27;
  }

  std::printf("status=ok mode=%s counters=%llu maps=%llu\n", mode_name,
              static_cast<unsigned long long>(counters_count),
              static_cast<unsigned long long>(map_count));
  return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::fprintf(stderr,
                 "usage: memory-snapshot-trace-writer-test "
                 "<both|counters-only|map-only|disabled|mixed> <output>\n");
    return 2;
  }
  const std::string_view mode{argv[1]};
  std::uint64_t counters_interval_ms = 100U;
  std::uint64_t map_interval_ms = 100U;
  if (mode == "counters-only") {
    map_interval_ms = 0U;
  } else if (mode == "map-only") {
    counters_interval_ms = 0U;
  } else if (mode == "disabled") {
    counters_interval_ms = 0U;
    map_interval_ms = 0U;
  } else if (mode == "mixed") {
    counters_interval_ms = 100U;
    map_interval_ms = 300U;
  } else if (mode != "both") {
    return 3;
  }
  try {
    return run_test(counters_interval_ms, map_interval_ms, argv[1], std::filesystem::path{argv[2]});
  } catch (const std::exception& error) {
    std::fprintf(stderr, "memory snapshot writer test failed: %s\n", error.what());
    return 4;
  }
}
