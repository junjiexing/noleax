// Probe for the Linux in-process trace writer (docs/LINUX_PORT_PLAN.md M3/M4/M7): synthesizes
// a scripted glibc heap + virtual memory event set through LinuxTraceWriter and validates
// the resulting .nlx trace by reading it back with the platform-neutral trace reader plus
// the analyzer's event-stream invariants and generation tracker. Standalone main, exit 0/1.
//
// Seven phases:
//   1. clean launch-scope capture: allocation/reallocation/free generation pairing,
//      unmatched and failed calls, multi-chunk flushing, completeness mask 0;
//   2. lossy capture: a failed stack capture (inline LossRecord), a backwards
//      timestamp (clamp), and a disabled stack (no loss, no stack_id);
//   3. file-limit capture: trace-full drop accounting and the terminal reserve;
//   4. queue-full capture: a pre-begin queue overflow surfaces as a finalize-time
//      queue-full Loss record plus the event-loss completeness bit;
//   5. virtual memory events: anonymous mmap/munmap, file-backed map/unmap, mremap
//      in-place growth, an mremap move (free + allocate pair), a failed mmap, and an
//      unmatched munmap, with generation pairing through the analyzer;
//   6. memory samplers: tiny snapshot intervals produce kMemory chunks with plausible
//      counters and a non-empty region map;
//   7. custom hooks: two declared points emit CustomHookDefinition records, one noted
//      install failure emits a CustomHookFailure record and sets completeness bit 10, and
//      the points' events decode with namespaced allocation ids.
//   8. writer failure injection (H2): open/write/flush/close/disk-full fault points, the
//      .partial protocol, the best-effort error tail (Loss + Statistics + abnormal
//      EndOfTrace), and the dual-error result when the tail itself fails;
//   9. statistics conservation property: randomized per-API producer counters (including
//      zero-activity APIs and custom points) must reconcile per API and in aggregate.
//  10. VM interval model (H3): prefix/suffix/middle partial unmaps, a munmap spanning a
//      hole into a second mapping, double unmap and hole unmap (unmatched), with the
//      analyzer's outstanding view equal to the scripted ground truth;
//  11. overlap eviction and completion-sequence ordering: MAP_FIXED-style eviction, a stale
//      create trimmed to zero, a stale munmap skipping the newer generation, one spanning
//      munmap ending three generations;
//  12. mremap matrix: in-place grow/shrink, a move pair, a MREMAP_FIXED eviction move, a
//      shrink that releases a neighbour in the generation's hole, and a file-backed view's
//      partial free (VmFree pieces) plus final whole-view Unmap;
//  13. agent memory attribution (H4): dedicated-queue baselines, BufferConfiguration
//      metadata, the agent/application split under a unique-stack storm, and the startup
//      RSS step attribution.
//
// With an argument, phases 5, 6, and 13 also copy their traces into that directory (for
// manual CLI cross-checks).

#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/linux/agent_memory.hpp"
#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/agent/linux/hook_registry.hpp"
#include "noleax/agent/linux/memory_snapshot.hpp"
#include "noleax/agent/linux/module_tracker.hpp"
#include "noleax/agent/linux/stack_capture.hpp"
#include "noleax/agent/linux/trace_writer.hpp"
#include "noleax/agent/windows/stack_dictionary.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/custom_hook.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/memory_snapshot.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/wire_format.hpp"

namespace {

using noleax::agent::linux::CapturedStack;
using noleax::agent::linux::LinuxHeapEvent;
using noleax::agent::linux::LinuxHeapEventOperation;
using noleax::agent::linux::LinuxHeapEventQueue;
using noleax::agent::linux::LinuxHeapEventStatus;
using noleax::agent::linux::LinuxModuleTracker;
using noleax::agent::linux::LinuxTraceWriter;
using noleax::agent::linux::LinuxTraceWriterOptions;
using noleax::agent::linux::LinuxTraceWriterResult;
using noleax::agent::linux::LinuxTraceWriterStatus;

unsigned g_failures = 0U;

void check(bool condition, const char* message) {
  if (!condition) {
    std::printf("FAIL: %s\n", message);
    ++g_failures;
  }
}

void check(bool condition, const std::string& message) { check(condition, message.c_str()); }

[[nodiscard]] std::uint64_t monotonic_now_ns() noexcept {
  timespec value{};
  clock_gettime(CLOCK_MONOTONIC, &value);
  return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
         static_cast<std::uint64_t>(value.tv_nsec);
}

[[nodiscard]] std::uint64_t this_thread_id() noexcept {
  return static_cast<std::uint64_t>(::syscall(SYS_gettid));
}

// Real unwinder frames: the captured PCs land in the probe executable and libc, so the
// writer's module-relative normalization is exercised for real.
__attribute__((noinline)) CapturedStack capture_probe_stack() {
  CapturedStack stack;
  noleax::agent::linux::capture_current_stack(stack, 32U);
  return stack;
}

[[nodiscard]] bool push_event(LinuxHeapEventQueue& queue, LinuxHeapEvent event) {
  return queue.try_emplace([&event](LinuxHeapEvent& slot, std::uint64_t sequence) noexcept {
    event.queue_sequence = sequence;
    slot = event;
  });
}

struct EventSpec {
  noleax::trace::ApiId api_id;
  LinuxHeapEventOperation operation;
  LinuxHeapEventStatus status{LinuxHeapEventStatus::kSuccess};
  std::uint64_t requested_size{0U};
  std::uint64_t count{0U};
  std::uint64_t alignment{0U};
  std::uint64_t address{0U};
  std::uint64_t result_address{0U};
  std::uint32_t operation_result{0U};
  // Virtual memory arguments (mmap/munmap/mremap); zero for the heap family.
  std::uint64_t requested_address{0U};
  std::uint64_t protection{0U};
  std::uint64_t map_flags{0U};
  std::uint64_t section_handle{0U};
  std::uint64_t section_offset{0U};
  // Completion ordering token for VM events; zero auto-assigns the next value (fine for
  // in-order scripts). Interval-model phases set it explicitly to reorder completion
  // against queue arrival.
  std::uint64_t completion_sequence{0U};
};

std::uint64_t g_next_completion_sequence = 1U;

[[nodiscard]] LinuxHeapEvent make_event(const EventSpec& spec, std::uint64_t ticks,
                                        std::uint64_t thread_id) {
  LinuxHeapEvent event;
  event.monotonic_ticks = ticks;
  event.thread_id = thread_id;
  event.requested_size = spec.requested_size;
  event.count = spec.count;
  event.alignment = spec.alignment;
  event.result_address = spec.result_address;
  event.address = spec.address;
  event.operation_result = spec.operation_result;
  event.api_id = spec.api_id;
  event.operation = spec.operation;
  event.status = spec.status;
  event.requested_address = spec.requested_address;
  event.protection = spec.protection;
  event.map_flags = spec.map_flags;
  event.section_handle = spec.section_handle;
  event.section_offset = spec.section_offset;
  if (spec.completion_sequence != 0U) {
    event.completion_sequence = spec.completion_sequence;
  } else if (spec.operation == LinuxHeapEventOperation::kVmAllocate ||
             spec.operation == LinuxHeapEventOperation::kVmUnmap ||
             spec.operation == LinuxHeapEventOperation::kVmRemap) {
    event.completion_sequence = g_next_completion_sequence++;
  }
  event.stack = capture_probe_stack();
  return event;
}

struct GenerationNote {
  noleax::analyzer::GenerationKind kind;
  std::uint64_t address;
  std::uint64_t size;
};

struct EndedGenerationNote {
  noleax::analyzer::GenerationKind kind;
  noleax::analyzer::GenerationEndReason reason;
  std::uint64_t address;
  std::uint64_t size;
};

struct Readback {
  noleax::analyzer::EventStreamResult stream;
  std::vector<noleax::trace::Event> events;
  std::vector<noleax::trace::LossRecord> losses;
  std::vector<noleax::trace::ModuleLoad> module_loads;
  std::vector<noleax::trace::StackDefinition> stacks;
  std::vector<noleax::trace::MemoryCounters> memory_counters;
  std::vector<noleax::trace::MemoryMap> memory_maps;
  std::vector<noleax::trace::AgentMemory> memory_agents;
  std::vector<GenerationNote> generations_created_log;
  std::vector<EndedGenerationNote> generations_ended_log;
  std::uint64_t generations_created{0U};
  std::uint64_t generations_ended{0U};
  std::uint64_t generations_live{0U};
  std::uint64_t orphaned_ends{0U};
  std::uint64_t orphaned_mapping_ends{0U};
};

[[nodiscard]] Readback read_trace(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  if (!input) {
    throw std::runtime_error{"cannot open the trace for reading"};
  }
  Readback readback;
  noleax::analyzer::GenerationCallbacks generation_callbacks;
  generation_callbacks.on_created =
      [&readback](const noleax::analyzer::MemoryGeneration& generation) {
        readback.generations_created_log.push_back(
            GenerationNote{generation.kind, generation.address, generation.size});
      };
  generation_callbacks.on_ended = [&readback](const noleax::analyzer::MemoryGeneration& generation,
                                              noleax::analyzer::GenerationEndReason reason,
                                              const noleax::trace::Event&) {
    readback.generations_ended_log.push_back(
        EndedGenerationNote{generation.kind, reason, generation.address, generation.size});
  };
  noleax::analyzer::GenerationTracker generations{generation_callbacks};
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_module_load = [&readback](const noleax::trace::ModuleLoad& load) {
    readback.module_loads.push_back(load);
  };
  callbacks.on_stack_definition = [&readback](const noleax::trace::StackDefinition& definition) {
    readback.stacks.push_back(definition);
  };
  callbacks.on_event = [&readback, &generations](const noleax::trace::Event& event) {
    generations.observe(event);
    readback.events.push_back(event);
  };
  callbacks.on_loss = [&readback](const noleax::trace::LossRecord& loss) {
    readback.losses.push_back(loss);
  };
  callbacks.on_memory_counters = [&readback](const noleax::trace::MemoryCounters& counters) {
    readback.memory_counters.push_back(counters);
  };
  callbacks.on_memory_map = [&readback](const noleax::trace::MemoryMap& map) {
    readback.memory_maps.push_back(map);
  };
  callbacks.on_agent_memory = [&readback](const noleax::trace::AgentMemory& agent) {
    readback.memory_agents.push_back(agent);
  };
  readback.stream = noleax::analyzer::analyze_event_stream(input, callbacks);
  readback.generations_created = generations.created_count();
  readback.generations_ended = generations.ended_count();
  readback.generations_live = generations.live_count();
  readback.orphaned_ends = generations.orphaned_allocation_end_count();
  readback.orphaned_mapping_ends = generations.orphaned_mapping_end_count();
  return readback;
}

[[nodiscard]] std::filesystem::path probe_path(const char* phase) {
  return std::filesystem::temp_directory_path() /
         ("noleax-linux-trace-writer-probe-" + std::to_string(::getpid()) + "-" + phase + ".nlx");
}

[[nodiscard]] std::filesystem::path partial_probe_path(const std::filesystem::path& path) {
  std::filesystem::path partial = path;
  partial += ".partial";
  return partial;
}

[[nodiscard]] bool path_exists(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::is_regular_file(path, error) && !error;
}

// Phases 5 and 6 leave a copy of their trace behind when the probe is given a directory,
// so the traces can be cross-checked with the real CLI.
void keep_trace(const std::filesystem::path& path, const std::filesystem::path& keep_dir,
                const char* name) {
  if (keep_dir.empty()) {
    return;
  }
  std::error_code error;
  std::filesystem::create_directories(keep_dir, error);
  std::filesystem::copy_file(path, keep_dir / name,
                             std::filesystem::copy_options::overwrite_existing, error);
  if (error) {
    std::printf("FAIL: cannot keep trace %s\n", name);
    ++g_failures;
  }
}

[[nodiscard]] LinuxTraceWriterOptions launch_options(std::uint64_t monotonic_origin) {
  LinuxTraceWriterOptions options;
  options.capture_scope = noleax::trace::CaptureScope{true, false};
  options.flush_interval = std::chrono::milliseconds{10};
  options.monotonic_origin = monotonic_origin;
  for (std::size_t index = 0U; index < options.session_id.size(); ++index) {
    options.session_id[index] = static_cast<std::byte>(0xA0U + index);
  }
  return options;
}

void check_common_result(const LinuxTraceWriterResult& result, const std::filesystem::path& path,
                         std::uint64_t expected_queue_drops = 0U) {
  check(result.statistics_written, "statistics chunk was written");
  check(result.end_of_trace_written, "EndOfTrace chunk was written");
  check(result.error_message.empty(),
        "writer error message is empty (got: " + result.error_message + ")");
  check(result.queue_dropped_events == expected_queue_drops, "queue drops match the phase");
  check(result.module_notification_drops == 0U, "no module notification drops");
  std::error_code error;
  const std::uint64_t file_size = std::filesystem::file_size(path, error);
  check(!error && file_size == result.bytes_written, "bytes_written matches the file size");
}

void check_common_readback(const Readback& readback, std::uint64_t monotonic_origin) {
  const noleax::trace::FileHeader& header = readback.stream.file_header;
  check(header.platform == noleax::trace::Platform::kLinux, "file header platform is Linux");
  check(header.architecture == noleax::trace::Architecture::kX64, "file header arch is x64");
  check(header.pointer_width == sizeof(void*), "file header pointer width");
  check(header.monotonic_frequency == 1'000'000'000ULL, "monotonic frequency is 1e9");
  check(header.monotonic_origin == monotonic_origin, "monotonic origin round-trips");
  bool session_id_matches = true;
  for (std::size_t index = 0U; index < header.session_id.size(); ++index) {
    session_id_matches =
        session_id_matches && header.session_id[index] == static_cast<std::byte>(0xA0U + index);
  }
  check(session_id_matches, "session id round-trips");
  check(readback.stream.capture_scope.started_at_process_start, "capture scope: launch");
  check(!readback.stream.capture_scope.preexisting_allocations_unknown,
        "capture scope: preexisting allocations known");
  check(readback.stream.statistics.has_value(), "statistics record decoded");
  check(readback.stream.end_of_trace.has_value(), "EndOfTrace record decoded");
  if (readback.stream.end_of_trace.has_value()) {
    check(readback.stream.end_of_trace->normal_stop, "EndOfTrace reports a normal stop");
  }
  check(readback.stream.module_load_count >= 2U, "at least two module loads");
  bool saw_exe = false;
  bool saw_libc = false;
  for (const noleax::trace::ModuleLoad& load : readback.module_loads) {
    // The main executable records its real path (readlink of /proc/self/exe at capture
    // time), so the analyzer opens the target image rather than its own.
    saw_exe = saw_exe || (!load.image_path.empty() && load.image_path[0] == '/' &&
                          load.image_path.find("/proc/") != 0U);
    saw_libc = saw_libc || load.image_path.find("libc") != std::string::npos;
  }
  check(saw_exe, "main executable module record is present");
  check(saw_libc, "libc module record is present");
  // Per-API statistics reconcile with the decoded events (the analyzer already enforces
  // the exact equality; double-check the arithmetic explicitly here).
  if (readback.stream.statistics.has_value()) {
    const noleax::trace::CaptureStatistics& statistics = *readback.stream.statistics;
    std::unordered_map<noleax::trace::ApiId, std::uint64_t> decoded_per_api;
    for (const noleax::trace::Event& event : readback.events) {
      ++decoded_per_api[event.header.api_id];
    }
    for (const noleax::trace::ApiStatistics& api : statistics.per_api) {
      check(api.observed_calls == api.successful_operations + api.failed_operations,
            "per-API observed == successful + failed");
      const std::uint64_t recorded =
          api.observed_calls - api.filtered_before_queue - api.dropped_events;
      check(recorded == decoded_per_api[api.api_id], "per-API recorded == decoded events");
    }
    check(statistics.observed_calls ==
              statistics.successful_operations + statistics.failed_operations,
          "aggregate observed == successful + failed");
    check(
        statistics.observed_calls - statistics.filtered_before_queue - statistics.dropped_events ==
            readback.stream.event_count,
        "aggregate recorded == decoded events");
  }
}

// Phase 1: clean launch-scope capture with the full generation-pairing script.
bool phase1() {
  std::printf("phase 1: clean capture\n");
  const std::filesystem::path path = probe_path("p1");
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();

  constexpr std::uint64_t kA1 = 0x5000'0000'1000ULL;
  constexpr std::uint64_t kA2 = 0x5000'0000'2000ULL;
  constexpr std::uint64_t kA3 = 0x5000'0000'3000ULL;
  constexpr std::uint64_t kA4 = 0x5000'0000'4000ULL;
  constexpr std::uint64_t kA5 = 0x5000'0000'5000ULL;
  constexpr std::uint64_t kA6 = 0x5000'0000'6000ULL;
  constexpr std::uint64_t kA7 = 0x5000'0000'7000ULL;
  constexpr std::uint64_t kStray = 0x5000'DEAD'0000ULL;

  using noleax::agent::linux::kCallocApiId;
  using noleax::agent::linux::kFreeApiId;
  using noleax::agent::linux::kMallocApiId;
  using noleax::agent::linux::kMemalignApiId;
  using noleax::agent::linux::kPosixMemalignApiId;
  using noleax::agent::linux::kReallocApiId;
  using noleax::agent::linux::kReallocarrayApiId;
  constexpr auto kAllocate = LinuxHeapEventOperation::kAllocate;
  constexpr auto kReallocate = LinuxHeapEventOperation::kReallocate;
  constexpr auto kFree = LinuxHeapEventOperation::kFree;
  constexpr auto kSuccess = LinuxHeapEventStatus::kSuccess;
  constexpr auto kFailure = LinuxHeapEventStatus::kFailure;

  const EventSpec script[] = {
      {kMallocApiId, kAllocate, kSuccess, 0x100U, 0U, 0U, 0U, kA1, 0U},
      {kCallocApiId, kAllocate, kSuccess, 0x100U, 4U, 0U, 0U, kA2, 0U},
      {kReallocApiId, kReallocate, kSuccess, 0x200U, 0U, 0U, kA1, kA3, 0U},
      {kReallocApiId, kReallocate, kSuccess, 0x80U, 0U, 0U, 0U, kA4, 0U},
      {kReallocApiId, kReallocate, kSuccess, 0U, 0U, 0U, kA2, 0U, 0U},
      {kFreeApiId, kFree, kSuccess, 0U, 0U, 0U, kA3, 0U, 0U},
      {kFreeApiId, kFree, kSuccess, 0U, 0U, 0U, kStray, 0U, 0U},
      {kMallocApiId, kAllocate, kFailure, 1ULL << 40U, 0U, 0U, 0U, 0U, ENOMEM},
      {kPosixMemalignApiId, kAllocate, kSuccess, 0x80U, 0U, 64U, 0U, kA5, 0U},
      {kReallocarrayApiId, kReallocate, kSuccess, 0x80U, 2U, 0U, kA4, kA6, 0U},
      {kFreeApiId, kFree, kSuccess, 0U, 0U, 0U, 0U, 0U, 0U},
      {kMemalignApiId, kAllocate, kSuccess, 0x200U, 0U, 128U, 0U, kA7, 0U},
      {kFreeApiId, kFree, kSuccess, 0U, 0U, 0U, kA6, 0U, 0U},
  };
  constexpr std::size_t kEventCount = sizeof(script) / sizeof(script[0]);

  LinuxTraceWriterResult result;
  {
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriter writer{queue, tracker, path, launch_options(origin)};
    writer.begin_capture();

    const std::uint64_t base = monotonic_now_ns();
    for (std::size_t index = 0U; index < kEventCount; ++index) {
      const std::uint64_t ticks = base + (index + 1U) * 1'000U;
      if (!push_event(queue, make_event(script[index], ticks, thread_id))) {
        std::printf("FAIL: event queue push %zu\n", index);
        return false;
      }
      if (index == 4U) {
        // Let the periodic flush split the capture across several event chunks.
        std::this_thread::sleep_for(std::chrono::milliseconds{35});
      }
    }
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kComplete, "phase 1 status is complete");
  check_common_result(result, path);
  check(result.trace_dropped_events == 0U, "phase 1 has no trace drops");
  check(result.stack_capture_failures == 0U, "phase 1 has no stack capture failures");
  check(result.timestamp_adjustments == 0U, "phase 1 has no timestamp adjustments");
  check(result.module_load_records >= 2U, "phase 1 wrote module loads");
  check(result.stack_dictionary_segments == 1U, "phase 1 stack dictionary has one segment");
  check(result.completeness_mask == 0U, "phase 1 completeness mask is zero");
  check(result.per_api.size() == noleax::agent::linux::kLinuxHookRegistry.size(),
        "phase 1 per-API result covers the registry");

  const Readback readback = read_trace(path);
  check_common_readback(readback, origin);
  check(readback.stream.event_count == kEventCount, "phase 1 decoded every event");
  check(readback.stream.loss_record_count == 0U, "phase 1 has no Loss records");
  check(readback.stream.completeness.mask() == 0U, "phase 1 decoded completeness is complete");
  check(readback.stream.end_of_trace.has_value() &&
            readback.stream.end_of_trace->final_sequence == noleax::trace::Sequence{kEventCount},
        "phase 1 EndOfTrace final sequence");
  check(readback.stacks.size() >= 1U, "phase 1 stack definitions were written");

  std::unordered_set<std::uint64_t> defined_stacks;
  bool saw_module_relative_frame = false;
  for (const noleax::trace::StackDefinition& definition : readback.stacks) {
    defined_stacks.insert(definition.stack_id.value());
    for (const noleax::trace::StackFrame& frame : definition.frames) {
      saw_module_relative_frame = saw_module_relative_frame || frame.module_id.is_valid();
    }
  }
  check(saw_module_relative_frame, "phase 1 stacks resolve against module records");
  for (const noleax::trace::Event& event : readback.events) {
    check(event.header.stack_id.is_valid(), "phase 1 every event carries a stack");
    check(event.header.thread_id == thread_id, "phase 1 thread id round-trips");
    if (event.header.stack_id.is_valid()) {
      check(defined_stacks.contains(event.header.stack_id.value()),
            "phase 1 event stacks have definitions");
    }
  }
  if (readback.stream.statistics.has_value()) {
    const noleax::trace::CaptureStatistics& statistics = *readback.stream.statistics;
    check(statistics.observed_calls == kEventCount, "phase 1 observed calls");
    check(statistics.successful_operations == kEventCount - 1U, "phase 1 successful calls");
    check(statistics.failed_operations == 1U, "phase 1 failed calls");
    check(statistics.dropped_events == 0U, "phase 1 dropped events");
    check(statistics.unique_stacks >= 1U, "phase 1 unique stacks");
    check(statistics.unique_stacks + statistics.reused_stacks == kEventCount,
          "phase 1 stack statistics cover every event");
    for (const noleax::trace::ApiStatistics& api : statistics.per_api) {
      std::uint64_t expected = 0U;
      for (const EventSpec& spec : script) {
        expected += spec.api_id == api.api_id ? 1U : 0U;
      }
      check(api.observed_calls == expected, "phase 1 per-API observed matches the script");
    }
  }

  // Generation pairing: 7 created (kA1..kA7), 5 ended, kA5 and kA7 stay live.
  check(readback.generations_created == 7U, "phase 1 created generations");
  check(readback.generations_ended == 5U, "phase 1 ended generations");
  check(readback.generations_live == 2U, "phase 1 live generations");
  check(readback.orphaned_ends == 0U, "phase 1 orphaned generation ends");

  using noleax::trace::EventStatus;
  using noleax::trace::ReallocationEffect;
  const auto& events = readback.events;
  const auto realloc_migration =
      events.size() > 2U ? std::get_if<noleax::trace::ReallocationEvent>(&events[2].payload)
                         : nullptr;
  check(realloc_migration != nullptr && events[2].header.status == EventStatus::kSuccess &&
            realloc_migration->old_address == kA1 &&
            realloc_migration->old_allocation_id.is_valid() &&
            realloc_migration->new_allocation_id.is_valid() &&
            realloc_migration->old_allocation_id != realloc_migration->new_allocation_id &&
            realloc_migration->effect == ReallocationEffect::kNewGeneration &&
            realloc_migration->result_address == kA3,
        "phase 1 realloc migration ends the old generation and starts a new one");
  const auto realloc_fresh = events.size() > 3U
                                 ? std::get_if<noleax::trace::ReallocationEvent>(&events[3].payload)
                                 : nullptr;
  check(realloc_fresh != nullptr && events[3].header.status == EventStatus::kUnmatched &&
            realloc_fresh->old_address == 0U && !realloc_fresh->old_allocation_id.is_valid() &&
            realloc_fresh->new_allocation_id.is_valid() &&
            realloc_fresh->effect == ReallocationEffect::kNewGeneration &&
            realloc_fresh->result_address == kA4,
        "phase 1 realloc(NULL) allocates a fresh unmatched generation");
  const auto realloc_freed = events.size() > 4U
                                 ? std::get_if<noleax::trace::ReallocationEvent>(&events[4].payload)
                                 : nullptr;
  check(realloc_freed != nullptr && events[4].header.status == EventStatus::kSuccess &&
            realloc_freed->old_allocation_id.is_valid() &&
            !realloc_freed->new_allocation_id.is_valid() &&
            realloc_freed->effect == ReallocationEffect::kFreed &&
            realloc_freed->result_address == 0U,
        "phase 1 realloc(p, 0) frees the old generation");
  const auto stray_free =
      events.size() > 6U ? std::get_if<noleax::trace::FreeEvent>(&events[6].payload) : nullptr;
  check(stray_free != nullptr && events[6].header.status == EventStatus::kUnmatched &&
            stray_free->address == kStray && !stray_free->allocation_id.is_valid(),
        "phase 1 unmatched free carries no allocation id");
  const auto failed_malloc = events.size() > 7U
                                 ? std::get_if<noleax::trace::AllocationEvent>(&events[7].payload)
                                 : nullptr;
  check(failed_malloc != nullptr && events[7].header.status == EventStatus::kFailure &&
            events[7].header.system_error.domain == noleax::trace::SystemErrorDomain::kPosix &&
            events[7].header.system_error.code == static_cast<std::uint64_t>(ENOMEM) &&
            failed_malloc->result_address == 0U && !failed_malloc->allocation_id.is_valid(),
        "phase 1 failed malloc carries the posix error and no generation");
  const auto null_free =
      events.size() > 10U ? std::get_if<noleax::trace::FreeEvent>(&events[10].payload) : nullptr;
  check(null_free != nullptr && events[10].header.status == EventStatus::kUnmatched &&
            null_free->address == 0U && !null_free->allocation_id.is_valid(),
        "phase 1 free(NULL) is unmatched");
  for (const noleax::trace::Event& event : events) {
    if (const auto* allocation = std::get_if<noleax::trace::AllocationEvent>(&event.payload)) {
      check(allocation->heap_handle == 0U && !allocation->heap_id.is_valid(),
            "phase 1 allocation records carry no heap identity");
    }
  }

  std::error_code error;
  std::filesystem::remove(path, error);
  return true;
}

// Phase 2: a failed stack capture (inline LossRecord + stack data loss), a backwards
// timestamp (clamped, counted), and a disabled stack (no loss, no stack_id).
bool phase2() {
  std::printf("phase 2: lossy capture\n");
  const std::filesystem::path path = probe_path("p2");
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();
  constexpr std::uint64_t kB1 = 0x5000'0000'1000ULL;
  constexpr std::uint64_t kB2 = 0x5000'0000'2000ULL;

  LinuxTraceWriterResult result;
  {
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriter writer{queue, tracker, path, launch_options(origin)};
    writer.begin_capture();

    const std::uint64_t base = monotonic_now_ns();
    EventSpec spec{noleax::agent::linux::kMallocApiId,
                   LinuxHeapEventOperation::kAllocate,
                   LinuxHeapEventStatus::kSuccess,
                   0x40U,
                   0U,
                   0U,
                   0U,
                   kB1,
                   0U};

    LinuxHeapEvent failed_stack = make_event(spec, base + 1'000U, thread_id);
    failed_stack.stack = CapturedStack{};
    failed_stack.stack.status = noleax::agent::linux::StackCaptureStatus::kFailed;
    failed_stack.stack.requested_depth = 32U;
    check(noleax::agent::linux::stack_capture_succeeded(capture_probe_stack()),
          "phase 2 stack capture works");
    if (!push_event(queue, failed_stack)) {
      std::printf("FAIL: phase 2 push 1\n");
      return false;
    }

    spec.result_address = kB2;
    LinuxHeapEvent backwards = make_event(spec, base + 1'000U, thread_id);
    backwards.monotonic_ticks = base + 500U;  // moves backwards: the writer must clamp
    if (!push_event(queue, backwards)) {
      std::printf("FAIL: phase 2 push 2\n");
      return false;
    }

    LinuxHeapEvent disabled_stack;
    disabled_stack.monotonic_ticks = base + 2'000U;
    disabled_stack.thread_id = thread_id;
    disabled_stack.address = kB1;
    disabled_stack.api_id = noleax::agent::linux::kFreeApiId;
    disabled_stack.operation = LinuxHeapEventOperation::kFree;
    disabled_stack.status = LinuxHeapEventStatus::kSuccess;
    disabled_stack.stack = CapturedStack{};  // kDisabled
    if (!push_event(queue, disabled_stack)) {
      std::printf("FAIL: phase 2 push 3\n");
      return false;
    }

    LinuxHeapEvent last;
    last.monotonic_ticks = base + 3'000U;
    last.thread_id = thread_id;
    last.address = kB2;
    last.api_id = noleax::agent::linux::kFreeApiId;
    last.operation = LinuxHeapEventOperation::kFree;
    last.status = LinuxHeapEventStatus::kSuccess;
    last.stack = capture_probe_stack();
    if (!push_event(queue, last)) {
      std::printf("FAIL: phase 2 push 4\n");
      return false;
    }
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kComplete, "phase 2 status is complete");
  check_common_result(result, path);
  check(result.stack_capture_failures == 1U, "phase 2 counts the stack capture failure");
  check(result.timestamp_adjustments == 1U, "phase 2 counts the timestamp adjustment");
  check(result.trace_dropped_events == 0U, "phase 2 has no trace drops");
  check(result.completeness_mask ==
            static_cast<std::uint32_t>(noleax::trace::CompletenessIssue::kStackDataLoss),
        "phase 2 completeness carries only stack data loss");

  const Readback readback = read_trace(path);
  check_common_readback(readback, origin);
  check(readback.stream.event_count == 4U, "phase 2 decoded every event");
  check(readback.losses.size() == 1U, "phase 2 wrote one Loss record");
  if (!readback.losses.empty()) {
    const noleax::trace::LossRecord& loss = readback.losses.front();
    check(loss.reason == noleax::trace::LossReason::kStackCaptureFailed,
          "phase 2 Loss reason is stack capture failure");
    check(loss.location == noleax::trace::LossLocation::kAgentQueue,
          "phase 2 Loss location is the agent queue");
    check(loss.estimated_event_count.has_value() && *loss.estimated_event_count == 1U,
          "phase 2 Loss estimates one event");
    check(loss.sequence_range.has_value() &&
              loss.sequence_range->begin == noleax::trace::Sequence{1U} &&
              loss.sequence_range->end == noleax::trace::Sequence{1U},
          "phase 2 Loss sequence range covers the failed-stack event");
  }
  if (readback.events.size() == 4U) {
    check(!readback.events[0].header.stack_id.is_valid(),
          "phase 2 failed-stack event has no stack id");
    check(readback.events[1].header.stack_id.is_valid(), "phase 2 clamped event keeps its stack");
    check(!readback.events[2].header.stack_id.is_valid(),
          "phase 2 disabled-stack event has no stack id");
    check(readback.events[3].header.stack_id.is_valid(), "phase 2 final event has a stack");
    check(readback.events[1].header.monotonic_ticks == readback.events[0].header.monotonic_ticks,
          "phase 2 backwards timestamp was clamped");
  }
  check(readback.generations_created == 2U && readback.generations_ended == 2U &&
            readback.generations_live == 0U,
        "phase 2 generations pair up");
  if (readback.stream.statistics.has_value()) {
    check(
        readback.stream.statistics->unique_stacks + readback.stream.statistics->reused_stacks == 2U,
        "phase 2 stack statistics cover the stacked events");
  }

  std::error_code error;
  std::filesystem::remove(path, error);
  return true;
}

// Phase 3: a tiny file limit forces trace-full drops; the terminal reserve must still
// hold the loss, statistics, and EndOfTrace records.
bool phase3() {
  std::printf("phase 3: file-limit capture\n");
  const std::filesystem::path path = probe_path("p3");
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();
  constexpr std::size_t kEventCount = 4'000U;

  LinuxTraceWriterResult result;
  {
    LinuxHeapEventQueue queue{4096U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriterOptions options = launch_options(origin);
    options.compression = noleax::trace::CompressionCodec::kNone;
    options.trace.max_file_size = 256U * 1024U;
    options.flush_interval = std::chrono::milliseconds{5};
    LinuxTraceWriter writer{queue, tracker, path, options};
    writer.begin_capture();

    EventSpec spec{noleax::agent::linux::kMallocApiId,
                   LinuxHeapEventOperation::kAllocate,
                   LinuxHeapEventStatus::kSuccess,
                   0x20U,
                   0U,
                   0U,
                   0U,
                   0U,
                   0U};
    const std::uint64_t base = monotonic_now_ns();
    for (std::size_t index = 0U; index < kEventCount; ++index) {
      spec.address = 0U;
      spec.result_address = 0x6000'0000'0000ULL + index * 0x1000ULL;
      if (!push_event(queue, make_event(spec, base + (index + 1U) * 100U, thread_id))) {
        std::printf("FAIL: phase 3 push %zu\n", index);
        return false;
      }
    }
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kFileLimit, "phase 3 status is file limit");
  check_common_result(result, path);
  check(result.trace_dropped_events > 0U, "phase 3 dropped events at the file limit");
  // The file limit is a normal stop: the reserve held the terminal records, and the
  // completed trace was promoted off the .partial path.
  check(result.final_path == path, "phase 3 renamed the completed trace");
  check(result.partial_path == partial_probe_path(path), "phase 3 reports the partial path");
  check(!path_exists(partial_probe_path(path)), "phase 3 left no partial behind");
  check(result.statistics.observed_calls == kEventCount, "phase 3 observed every call");
  check(result.statistics.successful_operations == kEventCount, "phase 3 all calls succeeded");
  check(result.statistics.dropped_events == result.trace_dropped_events,
        "phase 3 statistics drops match the result");
  const std::uint64_t written = result.statistics.observed_calls -
                                result.statistics.filtered_before_queue -
                                result.statistics.dropped_events;
  check(written > 0U && written < kEventCount, "phase 3 wrote a strict prefix of the events");

  const Readback readback = read_trace(path);
  check_common_readback(readback, origin);
  check(readback.stream.event_count == written, "phase 3 decoded events match the statistics");
  check(readback.stream.completeness.has(noleax::trace::CompletenessIssue::kEventLoss),
        "phase 3 completeness reports event loss");
  bool saw_trace_full = false;
  for (const noleax::trace::LossRecord& loss : readback.losses) {
    saw_trace_full = saw_trace_full || loss.reason == noleax::trace::LossReason::kTraceFull;
  }
  check(saw_trace_full, "phase 3 wrote a trace-full Loss record");
  check(readback.orphaned_ends == 0U, "phase 3 has no orphaned generation ends");
  check(readback.generations_live == readback.stream.event_count,
        "phase 3 decoded allocations stay live");

  std::error_code error;
  std::filesystem::remove(path, error);
  return true;
}

// Phase 4: a queue-full drop before capture begins surfaces as a finalize-time Loss
// record (kQueueFull) and the event-loss completeness bit; the two queued events still
// reconcile exactly with the statistics.
bool phase4() {
  std::printf("phase 4: queue-drop capture\n");
  const std::filesystem::path path = probe_path("p4");
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();

  LinuxTraceWriterResult result;
  {
    LinuxHeapEventQueue queue{2U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriter writer{queue, tracker, path, launch_options(origin)};

    // The worker is parked until begin_capture(), so the capacity-2 queue overflows
    // deterministically on the third push.
    EventSpec spec{noleax::agent::linux::kMallocApiId,
                   LinuxHeapEventOperation::kAllocate,
                   LinuxHeapEventStatus::kSuccess,
                   0x40U,
                   0U,
                   0U,
                   0U,
                   0U,
                   0U};
    const std::uint64_t base = monotonic_now_ns();
    spec.result_address = 0x5000'0000'1000ULL;
    check(push_event(queue, make_event(spec, base + 1'000U, thread_id)), "phase 4 first push fits");
    spec.result_address = 0x5000'0000'2000ULL;
    check(push_event(queue, make_event(spec, base + 2'000U, thread_id)),
          "phase 4 second push fits");
    spec.result_address = 0x5000'0000'3000ULL;
    check(!push_event(queue, make_event(spec, base + 3'000U, thread_id)),
          "phase 4 third push drops at the full queue");

    writer.begin_capture();
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kComplete, "phase 4 status is complete");
  check_common_result(result, path, 1U);
  check(result.trace_dropped_events == 0U, "phase 4 has no trace drops");
  check(result.completeness_mask ==
            static_cast<std::uint32_t>(noleax::trace::CompletenessIssue::kEventLoss),
        "phase 4 completeness carries only event loss");

  const Readback readback = read_trace(path);
  check_common_readback(readback, origin);
  check(readback.stream.event_count == 2U, "phase 4 decoded the two queued events");
  bool saw_queue_full = false;
  for (const noleax::trace::LossRecord& loss : readback.losses) {
    if (loss.reason == noleax::trace::LossReason::kQueueFull &&
        loss.location == noleax::trace::LossLocation::kAgentQueue) {
      saw_queue_full = true;
      check(loss.estimated_event_count.has_value() && *loss.estimated_event_count == 1U,
            "phase 4 queue-full Loss estimates one event");
    }
  }
  check(saw_queue_full, "phase 4 wrote a queue-full Loss record");
  check(readback.stream.completeness.has(noleax::trace::CompletenessIssue::kEventLoss),
        "phase 4 decoded completeness reports event loss");
  check(readback.generations_created == 2U && readback.generations_live == 2U,
        "phase 4 generations match the queued events");

  std::error_code error;
  std::filesystem::remove(path, error);
  return true;
}

// Phase 5: virtual memory events. The script exercises an anonymous mmap/munmap pair, a
// file-backed map/unmap pair, mremap in-place growth (same mapping_id, grown generation),
// an mremap move (a VmFree + VmAllocate record pair from one raw event), a failed mmap,
// and an unmatched munmap; generation kinds and end reasons are asserted through the
// analyzer's GenerationTracker.
bool phase5(const std::filesystem::path& keep_dir) {
  std::printf("phase 5: virtual memory events\n");
  const std::filesystem::path path = probe_path("p5");
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();

  constexpr std::uint64_t kV1 = 0x7000'0001'0000ULL;
  constexpr std::uint64_t kS1 = 0x7000'0002'0000ULL;
  constexpr std::uint64_t kV2 = 0x7000'0003'0000ULL;
  constexpr std::uint64_t kStray = 0x7000'DEAD'0000ULL;
  constexpr std::uint64_t kAnonymous = std::numeric_limits<std::uint64_t>::max();
  constexpr std::uint32_t kRelease = 0x8000U;

  using noleax::agent::linux::kMmapApiId;
  using noleax::agent::linux::kMremapApiId;
  using noleax::agent::linux::kMunmapApiId;
  constexpr auto kVmAllocate = LinuxHeapEventOperation::kVmAllocate;
  constexpr auto kVmUnmap = LinuxHeapEventOperation::kVmUnmap;
  constexpr auto kVmRemap = LinuxHeapEventOperation::kVmRemap;
  constexpr auto kFailure = LinuxHeapEventStatus::kFailure;

  EventSpec mmap_anon{kMmapApiId, kVmAllocate};
  mmap_anon.requested_size = 0x4000U;
  mmap_anon.protection = 0x3U;  // PROT_READ | PROT_WRITE
  mmap_anon.map_flags = 0x22U;  // MAP_PRIVATE | MAP_ANONYMOUS
  mmap_anon.section_handle = kAnonymous;
  mmap_anon.result_address = kV1;

  EventSpec mmap_file{kMmapApiId, kVmAllocate};
  mmap_file.requested_size = 0x2000U;
  mmap_file.protection = 0x1U;    // PROT_READ
  mmap_file.map_flags = 0x2U;     // MAP_PRIVATE
  mmap_file.section_handle = 7U;  // a real fd
  mmap_file.section_offset = 0x1000U;
  mmap_file.result_address = kS1;

  EventSpec remap_grow{kMremapApiId, kVmRemap};
  remap_grow.address = kV1;
  remap_grow.requested_size = 0x4000U;  // old size
  remap_grow.count = 0x8000U;           // new size
  remap_grow.map_flags = 0x1U;          // MREMAP_MAYMOVE
  remap_grow.result_address = kV1;      // grew in place

  EventSpec remap_move{kMremapApiId, kVmRemap};
  remap_move.address = kV1;
  remap_move.requested_size = 0x8000U;
  remap_move.count = 0x10000U;
  remap_move.map_flags = 0x1U;
  remap_move.result_address = kV2;  // moved

  EventSpec mmap_fail{kMmapApiId, kVmAllocate, kFailure};
  mmap_fail.requested_size = 1ULL << 40U;
  mmap_fail.protection = 0x3U;
  mmap_fail.map_flags = 0x22U;
  mmap_fail.section_handle = kAnonymous;
  mmap_fail.operation_result = ENOMEM;

  EventSpec munmap_v2{kMunmapApiId, kVmUnmap};
  munmap_v2.address = kV2;
  munmap_v2.requested_size = 0x10000U;

  EventSpec munmap_s1{kMunmapApiId, kVmUnmap};
  munmap_s1.address = kS1;
  munmap_s1.requested_size = 0x2000U;

  EventSpec munmap_stray{kMunmapApiId, kVmUnmap};
  munmap_stray.address = kStray;
  munmap_stray.requested_size = 0x1000U;

  const EventSpec script[] = {mmap_anon, mmap_file, remap_grow, remap_move,
                              mmap_fail, munmap_v2, munmap_s1,  munmap_stray};
  constexpr std::size_t kRawCount = sizeof(script) / sizeof(script[0]);
  constexpr std::size_t kEventCount = kRawCount + 1U;  // the moved mremap emits a pair

  LinuxTraceWriterResult result;
  {
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriter writer{queue, tracker, path, launch_options(origin)};
    writer.begin_capture();

    const std::uint64_t base = monotonic_now_ns();
    for (std::size_t index = 0U; index < kRawCount; ++index) {
      const std::uint64_t ticks = base + (index + 1U) * 1'000U;
      if (!push_event(queue, make_event(script[index], ticks, thread_id))) {
        std::printf("FAIL: phase 5 event queue push %zu\n", index);
        return false;
      }
    }
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kComplete, "phase 5 status is complete");
  check_common_result(result, path);
  check(result.trace_dropped_events == 0U, "phase 5 has no trace drops");
  check(result.timestamp_adjustments == 0U, "phase 5 has no timestamp adjustments");
  check(result.completeness_mask == 0U, "phase 5 completeness mask is zero");
  check(result.statistics.observed_calls == kEventCount,
        "phase 5 observed calls count the mremap pair as two records");

  const Readback readback = read_trace(path);
  check_common_readback(readback, origin);
  check(readback.stream.event_count == kEventCount, "phase 5 decoded every wire event");
  check(readback.stream.loss_record_count == 0U, "phase 5 has no Loss records");
  check(readback.stream.completeness.mask() == 0U, "phase 5 decoded completeness is complete");
  check(readback.stream.end_of_trace.has_value() &&
            readback.stream.end_of_trace->final_sequence == noleax::trace::Sequence{kEventCount},
        "phase 5 EndOfTrace final sequence covers the pair");

  using noleax::trace::EventStatus;
  using noleax::trace::SystemErrorDomain;
  const auto& events = readback.events;
  if (events.size() == kEventCount) {
    for (std::size_t index = 0U; index < kEventCount; ++index) {
      check(events[index].header.sequence == noleax::trace::Sequence{index + 1U},
            "phase 5 wire sequences are contiguous");
    }
    const auto pid = static_cast<std::uint64_t>(::getpid());

    const auto* anon_mmap = std::get_if<noleax::trace::VmAllocateEvent>(&events[0].payload);
    check(anon_mmap != nullptr && events[0].header.api_id == kMmapApiId &&
              events[0].header.status == EventStatus::kSuccess &&
              anon_mmap->target.scope == noleax::trace::ProcessMemoryScope::kCurrentProcess &&
              anon_mmap->target.process_id == pid && anon_mmap->requested_base == 0U &&
              anon_mmap->result_base == kV1 && anon_mmap->requested_size == 0x4000U &&
              anon_mmap->result_size == 0x4000U && anon_mmap->mapping_base == kV1 &&
              anon_mmap->mapping_size == 0x4000U && anon_mmap->allocation_type == 0x22U &&
              anon_mmap->protection == 0x3U && anon_mmap->mapping_id.is_valid(),
          "phase 5 anonymous mmap is a VmAllocate generation");

    const auto* file_map = std::get_if<noleax::trace::MapEvent>(&events[1].payload);
    check(file_map != nullptr && events[1].header.api_id == kMmapApiId &&
              events[1].header.status == EventStatus::kSuccess && file_map->section_handle == 7U &&
              file_map->section_offset == 0x1000U && file_map->result_base == kS1 &&
              file_map->view_size == 0x2000U && file_map->protection == 0x1U &&
              file_map->mapping_id.is_valid() && anon_mmap != nullptr &&
              file_map->mapping_id != anon_mmap->mapping_id,
          "phase 5 file-backed mmap is a Map generation");

    const auto* grow = std::get_if<noleax::trace::VmAllocateEvent>(&events[2].payload);
    check(grow != nullptr && events[2].header.api_id == kMremapApiId &&
              events[2].header.status == EventStatus::kSuccess && anon_mmap != nullptr &&
              grow->mapping_id == anon_mmap->mapping_id && grow->result_base == kV1 &&
              grow->mapping_base == kV1 && grow->mapping_size == 0x8000U &&
              grow->requested_size == 0x8000U && grow->result_size == 0x8000U,
          "phase 5 in-place mremap keeps the mapping id and grows the generation");

    const auto* move_free = std::get_if<noleax::trace::VmFreeEvent>(&events[3].payload);
    const auto* move_alloc = std::get_if<noleax::trace::VmAllocateEvent>(&events[4].payload);
    check(move_free != nullptr && move_alloc != nullptr &&
              events[3].header.api_id == kMremapApiId && events[4].header.api_id == kMremapApiId &&
              events[3].header.status == EventStatus::kSuccess &&
              events[4].header.status == EventStatus::kSuccess && anon_mmap != nullptr &&
              move_free->mapping_id == anon_mmap->mapping_id && move_free->base == kV1 &&
              move_free->region_size == 0x8000U && move_free->free_type == kRelease &&
              move_alloc->mapping_id.is_valid() &&
              move_alloc->mapping_id != anon_mmap->mapping_id && move_alloc->result_base == kV2 &&
              move_alloc->mapping_base == kV2 && move_alloc->mapping_size == 0x10000U &&
              move_alloc->requested_size == 0x10000U && move_alloc->result_size == 0x10000U &&
              events[3].header.stack_id == events[4].header.stack_id &&
              events[3].header.stack_id.is_valid(),
          "phase 5 moved mremap is a release-free + allocate pair");

    const auto* failed_mmap = std::get_if<noleax::trace::VmAllocateEvent>(&events[5].payload);
    check(failed_mmap != nullptr && events[5].header.api_id == kMmapApiId &&
              events[5].header.status == EventStatus::kFailure &&
              events[5].header.system_error.domain == SystemErrorDomain::kPosix &&
              events[5].header.system_error.code == static_cast<std::uint64_t>(ENOMEM) &&
              failed_mmap->result_base == 0U && !failed_mmap->mapping_id.is_valid(),
          "phase 5 failed mmap carries the posix error and no generation");

    const auto* free_v2 = std::get_if<noleax::trace::VmFreeEvent>(&events[6].payload);
    check(free_v2 != nullptr && events[6].header.api_id == kMunmapApiId &&
              events[6].header.status == EventStatus::kSuccess && move_alloc != nullptr &&
              free_v2->mapping_id == move_alloc->mapping_id && free_v2->base == kV2 &&
              free_v2->region_size == 0x10000U && free_v2->free_type == kRelease,
          "phase 5 munmap of an anonymous mapping is a release VmFree");

    const auto* unmap_s1 = std::get_if<noleax::trace::UnmapEvent>(&events[7].payload);
    check(unmap_s1 != nullptr && events[7].header.api_id == kMunmapApiId &&
              events[7].header.status == EventStatus::kSuccess && file_map != nullptr &&
              unmap_s1->mapping_id == file_map->mapping_id && unmap_s1->base == kS1,
          "phase 5 munmap of a file-backed view is an Unmap");

    const auto* stray = std::get_if<noleax::trace::VmFreeEvent>(&events[8].payload);
    check(stray != nullptr && events[8].header.status == EventStatus::kUnmatched &&
              !stray->mapping_id.is_valid() && stray->base == kStray &&
              stray->free_type == kRelease,
          "phase 5 unmatched munmap carries no mapping id");
  }

  if (readback.stream.statistics.has_value()) {
    const noleax::trace::CaptureStatistics& statistics = *readback.stream.statistics;
    check(statistics.observed_calls == kEventCount, "phase 5 statistics observed");
    check(statistics.successful_operations == kEventCount - 1U, "phase 5 statistics successful");
    check(statistics.failed_operations == 1U, "phase 5 statistics failed");
    for (const noleax::trace::ApiStatistics& api : statistics.per_api) {
      if (api.api_id == kMmapApiId) {
        check(api.observed_calls == 3U && api.successful_operations == 2U &&
                  api.failed_operations == 1U,
              "phase 5 mmap statistics");
      }
      if (api.api_id == kMunmapApiId) {
        check(api.observed_calls == 3U && api.successful_operations == 3U,
              "phase 5 munmap statistics");
      }
      if (api.api_id == kMremapApiId) {
        // Two raw mremap calls; the moved one wrote two records.
        check(api.observed_calls == 3U && api.successful_operations == 3U,
              "phase 5 mremap statistics count the pair");
      }
    }
  }

  // Generation pairing through the analyzer: two virtual allocations and one mapped view
  // created, all three ended, nothing live, nothing orphaned.
  using noleax::analyzer::GenerationEndReason;
  using noleax::analyzer::GenerationKind;
  check(readback.generations_created == 3U && readback.generations_ended == 3U &&
            readback.generations_live == 0U,
        "phase 5 mapping generations pair up");
  check(readback.orphaned_ends == 0U && readback.orphaned_mapping_ends == 0U,
        "phase 5 has no orphaned generation ends");
  const auto& created = readback.generations_created_log;
  check(created.size() == 3U && created[0].kind == GenerationKind::kVirtualAllocation &&
            created[0].address == kV1 && created[0].size == 0x4000U &&
            created[1].kind == GenerationKind::kMappedView && created[1].address == kS1 &&
            created[1].size == 0x2000U && created[2].kind == GenerationKind::kVirtualAllocation &&
            created[2].address == kV2 && created[2].size == 0x10000U,
        "phase 5 created generations carry the expected kinds and ranges");
  const auto& ended = readback.generations_ended_log;
  check(ended.size() == 3U && ended[0].kind == GenerationKind::kVirtualAllocation &&
            ended[0].reason == GenerationEndReason::kVirtualFreed && ended[0].address == kV1 &&
            ended[0].size == 0x8000U,
        "phase 5 the moved mremap ends the in-place-grown generation");
  check(ended.size() == 3U && ended[1].kind == GenerationKind::kVirtualAllocation &&
            ended[1].reason == GenerationEndReason::kVirtualFreed && ended[1].address == kV2 &&
            ended[1].size == 0x10000U,
        "phase 5 munmap ends the moved generation");
  check(ended.size() == 3U && ended[2].kind == GenerationKind::kMappedView &&
            ended[2].reason == GenerationEndReason::kUnmapped && ended[2].address == kS1,
        "phase 5 munmap ends the mapped view");

  keep_trace(path, keep_dir, "phase5-vm.nlx");
  std::error_code error;
  std::filesystem::remove(path, error);
  return true;
}

// Phase 6: the memory samplers. One-millisecond intervals produce a baseline sample at
// capture start, periodic samples while the capture idles, and a final sample at
// finalize; the decoded counters must be plausible and the region map non-empty.
bool phase6(const std::filesystem::path& keep_dir) {
  std::printf("phase 6: memory samplers\n");
  const std::filesystem::path path = probe_path("p6");
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();
  constexpr std::uint64_t kC1 = 0x5000'00C1'0000ULL;

  LinuxTraceWriterResult result;
  {
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriterOptions options = launch_options(origin);
    options.memory_counters_interval = std::chrono::milliseconds{1};
    options.memory_map_interval = std::chrono::milliseconds{1};
    LinuxTraceWriter writer{queue, tracker, path, options};
    writer.begin_capture();

    const std::uint64_t base = monotonic_now_ns();
    EventSpec spec{noleax::agent::linux::kMallocApiId,
                   LinuxHeapEventOperation::kAllocate,
                   LinuxHeapEventStatus::kSuccess,
                   0x40U,
                   0U,
                   0U,
                   0U,
                   kC1,
                   0U};
    if (!push_event(queue, make_event(spec, base + 1'000U, thread_id))) {
      std::printf("FAIL: phase 6 push 1\n");
      return false;
    }
    EventSpec free_spec{noleax::agent::linux::kFreeApiId,
                        LinuxHeapEventOperation::kFree,
                        LinuxHeapEventStatus::kSuccess,
                        0U,
                        0U,
                        0U,
                        kC1,
                        0U,
                        0U};
    if (!push_event(queue, make_event(free_spec, base + 2'000U, thread_id))) {
      std::printf("FAIL: phase 6 push 2\n");
      return false;
    }
    // Let a few sampler ticks elapse beyond the baseline and final samples.
    std::this_thread::sleep_for(std::chrono::milliseconds{30});
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kComplete, "phase 6 status is complete");
  check_common_result(result, path);
  check(result.completeness_mask == 0U, "phase 6 completeness mask is zero");
  check(result.memory_chunks >= 2U, "phase 6 wrote at least the baseline and final memory chunks");
  check(result.memory_counters_records >= 2U, "phase 6 wrote memory counters records");
  check(result.memory_map_records >= 2U, "phase 6 wrote memory map records");
  check(result.memory_counters_records == result.memory_map_records,
        "phase 6 both samplers tick together");

  const Readback readback = read_trace(path);
  check_common_readback(readback, origin);
  check(readback.stream.event_count == 2U, "phase 6 decoded the two events");
  check(readback.stream.memory_counters_count == result.memory_counters_records,
        "phase 6 counters records round-trip");
  check(readback.stream.memory_map_count == result.memory_map_records,
        "phase 6 map records round-trip");
  check(readback.memory_counters.size() >= 2U, "phase 6 decoded counters records");
  check(readback.memory_maps.size() >= 2U, "phase 6 decoded map records");

  bool counters_plausible = !readback.memory_counters.empty();
  std::uint64_t previous_ticks = 0U;
  for (const noleax::trace::MemoryCounters& counters : readback.memory_counters) {
    counters_plausible = counters_plausible && counters.monotonic_ticks >= origin &&
                         counters.monotonic_ticks >= previous_ticks &&
                         counters.working_set_bytes > 0U &&
                         counters.peak_working_set_bytes >= counters.working_set_bytes &&
                         counters.private_bytes > 0U && counters.commit_bytes > 0U;
    previous_ticks = counters.monotonic_ticks;
  }
  check(counters_plausible, "phase 6 counters are plausible and ordered");

  bool maps_plausible = !readback.memory_maps.empty();
  previous_ticks = 0U;
  const std::uint64_t canonical_end = noleax::agent::linux::detail::canonical_user_end();
  for (const noleax::trace::MemoryMap& map : readback.memory_maps) {
    std::uint64_t listed_committed = 0U;
    for (const noleax::trace::MemoryMapRegion& region : map.regions) {
      // Aggregates only cover the user canonical range; special kernel mappings above it
      // (e.g. [vsyscall]) are listed but never counted.
      if (region.state == noleax::trace::MemoryRegionState::kCommit &&
          region.base < canonical_end) {
        const std::uint64_t clamped_end = (std::min)(region.base + region.size, canonical_end + 1U);
        listed_committed += clamped_end - region.base;
      }
    }
    maps_plausible = maps_plausible && map.monotonic_ticks >= origin &&
                     map.monotonic_ticks >= previous_ticks && map.regions.size() >= 2U &&
                     map.committed_bytes > 0U && map.committed_bytes >= listed_committed &&
                     map.largest_free_bytes <= map.free_bytes;
    previous_ticks = map.monotonic_ticks;
  }
  check(maps_plausible, "phase 6 memory maps are plausible and ordered");

  check(readback.generations_created == 1U && readback.generations_ended == 1U &&
            readback.generations_live == 0U,
        "phase 6 heap generations pair up");

  keep_trace(path, keep_dir, "phase6-memory.nlx");
  std::error_code error;
  std::filesystem::remove(path, error);
  return true;
}

// Phase 7: custom hooks (M7). Two declared points produce CustomHookDefinition records in
// the metadata chunk; one install failure noted before begin_capture produces a
// CustomHookFailure record right after them and sets completeness bit 10
// (custom_hook_install_failed). The points' queued events decode as AllocationEvent/
// FreeEvent with per-point namespaced allocation ids ((api_id << 40) | counter) that pass
// through the live map into the matching free.
bool phase7() {
  std::printf("phase 7: custom hooks\n");
  const std::filesystem::path path = probe_path("p7");
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();

  constexpr noleax::trace::ApiId kHookA = noleax::trace::kCustomHookApiIdBase;
  constexpr noleax::trace::ApiId kHookB = noleax::trace::kCustomHookApiIdBase + 1U;
  constexpr std::uint64_t kP1 = 0x5000'1000'1000ULL;
  constexpr std::uint64_t kP2 = 0x5000'1000'2000ULL;
  constexpr auto kAllocate = LinuxHeapEventOperation::kAllocate;
  constexpr auto kFree = LinuxHeapEventOperation::kFree;
  constexpr auto kSuccess = LinuxHeapEventStatus::kSuccess;
  constexpr auto kFailure = LinuxHeapEventStatus::kFailure;

  LinuxTraceWriterResult result;
  {
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriterOptions options = launch_options(origin);
    noleax::ipc::CustomHookSpec hook_a;
    hook_a.module = "liba.so";
    hook_a.alloc.locator = noleax::ipc::CustomHookLocator::kExport;
    hook_a.alloc.export_name = "a_malloc";
    hook_a.free.locator = noleax::ipc::CustomHookLocator::kExport;
    hook_a.free.export_name = "a_free";
    hook_a.label = "a_malloc";
    noleax::ipc::CustomHookSpec hook_b;
    hook_b.module = "libb.so";
    hook_b.alloc.locator = noleax::ipc::CustomHookLocator::kRva;
    hook_b.alloc.rva = 0x12340U;
    hook_b.free.locator = noleax::ipc::CustomHookLocator::kRva;
    hook_b.free.rva = 0x12580U;
    hook_b.label = "libb.so+0x12340";
    options.custom_hooks = {hook_a, hook_b};
    LinuxTraceWriter writer{queue, tracker, path, options};

    noleax::trace::CustomHookFailure failure;
    failure.module = "libmissing.so";
    failure.role = noleax::trace::CustomHookFailureRole::kPoint;
    failure.reason = noleax::trace::CustomHookFailureReason::kModuleNotLoaded;
    failure.detail = "module never loaded";
    writer.note_custom_hook_failures({failure});
    writer.begin_capture();

    const EventSpec script[] = {
        {kHookA, kAllocate, kSuccess, 0x80U, 0U, 0U, 0U, kP1, 0U},
        {kHookA, kFree, kSuccess, 0U, 0U, 0U, kP1, 0U, 0U},
        {kHookB, kAllocate, kSuccess, 0x40U, 0U, 0U, 0U, kP2, 0U},
        {kHookA, kAllocate, kFailure, 1ULL << 40U, 0U, 0U, 0U, 0U, ENOMEM},
    };
    constexpr std::size_t kEventCount = sizeof(script) / sizeof(script[0]);

    const std::uint64_t base = monotonic_now_ns();
    for (std::size_t index = 0U; index < kEventCount; ++index) {
      const std::uint64_t ticks = base + (index + 1U) * 1'000U;
      if (!push_event(queue, make_event(script[index], ticks, thread_id))) {
        std::printf("FAIL: phase 7 event queue push %zu\n", index);
        return false;
      }
    }
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kComplete, "phase 7 status is complete");
  check_common_result(result, path);
  check(result.trace_dropped_events == 0U, "phase 7 has no trace drops");
  check(result.completeness_mask ==
            static_cast<std::uint32_t>(noleax::trace::CompletenessIssue::kCustomHookInstallFailed),
        "phase 7 completeness carries only custom hook install failure");

  const Readback readback = read_trace(path);
  check_common_readback(readback, origin);
  check(readback.stream.event_count == 4U, "phase 7 decoded every event");
  check(readback.stream.loss_record_count == 0U, "phase 7 has no Loss records");
  check(
      readback.stream.completeness.has(noleax::trace::CompletenessIssue::kCustomHookInstallFailed),
      "phase 7 decoded completeness reports the install failure");

  const auto& definitions = readback.stream.custom_hooks;
  check(definitions.size() == 2U, "phase 7 wrote two CustomHookDefinition records");
  if (definitions.size() == 2U) {
    check(definitions[0].api_id == kHookA && definitions[0].module_name == "liba.so" &&
              definitions[0].label == "a_malloc",
          "phase 7 first definition is the export-located point");
    check(definitions[1].api_id == kHookB && definitions[1].module_name == "libb.so" &&
              definitions[1].label == "libb.so+0x12340",
          "phase 7 second definition is the rva-located point");
  }
  const auto& failures = readback.stream.custom_hook_failures;
  check(failures.size() == 1U, "phase 7 wrote one CustomHookFailure record");
  if (failures.size() == 1U) {
    check(failures[0].module == "libmissing.so" &&
              failures[0].role == noleax::trace::CustomHookFailureRole::kPoint &&
              failures[0].reason == noleax::trace::CustomHookFailureReason::kModuleNotLoaded &&
              failures[0].detail == "module never loaded",
          "phase 7 failure record round-trips");
  }

  constexpr std::uint64_t kIdA1 = (std::uint64_t{kHookA} << 40U) | 1U;
  constexpr std::uint64_t kIdB1 = (std::uint64_t{kHookB} << 40U) | 1U;
  using noleax::trace::EventStatus;
  const auto& events = readback.events;
  if (events.size() == 4U) {
    const auto* alloc_a = std::get_if<noleax::trace::AllocationEvent>(&events[0].payload);
    check(alloc_a != nullptr && events[0].header.api_id == kHookA &&
              events[0].header.status == EventStatus::kSuccess &&
              alloc_a->requested_size == 0x80U && alloc_a->result_address == kP1 &&
              alloc_a->heap_handle == 0U && !alloc_a->heap_id.is_valid() &&
              alloc_a->allocation_id.is_valid() && alloc_a->allocation_id.value() == kIdA1,
          "phase 7 custom allocation carries the namespaced allocation id");
    const auto* free_a = std::get_if<noleax::trace::FreeEvent>(&events[1].payload);
    check(free_a != nullptr && events[1].header.api_id == kHookA &&
              events[1].header.status == EventStatus::kSuccess && free_a->address == kP1 &&
              free_a->allocation_id.is_valid() && free_a->allocation_id.value() == kIdA1,
          "phase 7 custom free passes the stamped allocation id through");
    const auto* alloc_b = std::get_if<noleax::trace::AllocationEvent>(&events[2].payload);
    check(alloc_b != nullptr && events[2].header.api_id == kHookB &&
              alloc_b->allocation_id.is_valid() && alloc_b->allocation_id.value() == kIdB1 &&
              alloc_a != nullptr && alloc_b->allocation_id != alloc_a->allocation_id,
          "phase 7 the second point stamps its own id namespace");
    const auto* failed = std::get_if<noleax::trace::AllocationEvent>(&events[3].payload);
    check(failed != nullptr && events[3].header.api_id == kHookA &&
              events[3].header.status == EventStatus::kFailure &&
              events[3].header.system_error.domain == noleax::trace::SystemErrorDomain::kPosix &&
              events[3].header.system_error.code == static_cast<std::uint64_t>(ENOMEM) &&
              !failed->allocation_id.is_valid(),
          "phase 7 failed custom allocation carries the posix error and no generation");
  }

  // Generation pairing: two custom allocations created, one freed, one left live.
  check(readback.generations_created == 2U && readback.generations_ended == 1U &&
            readback.generations_live == 1U && readback.orphaned_ends == 0U,
        "phase 7 custom generations pair up");

  if (readback.stream.statistics.has_value()) {
    const noleax::trace::CaptureStatistics& statistics = *readback.stream.statistics;
    check(statistics.observed_calls == 4U && statistics.successful_operations == 3U &&
              statistics.failed_operations == 1U,
          "phase 7 statistics cover the custom events");
    bool saw_hook_a = false;
    bool saw_hook_b = false;
    for (const noleax::trace::ApiStatistics& api : statistics.per_api) {
      if (api.api_id == kHookA) {
        saw_hook_a = true;
        check(api.observed_calls == 3U && api.successful_operations == 2U &&
                  api.failed_operations == 1U,
              "phase 7 per-API statistics for the first point");
      }
      if (api.api_id == kHookB) {
        saw_hook_b = true;
        check(api.observed_calls == 1U && api.successful_operations == 1U,
              "phase 7 per-API statistics for the second point");
      }
    }
    check(saw_hook_a && saw_hook_b, "phase 7 statistics list both custom points");
  }
  check(result.per_api.size() == noleax::agent::linux::kLinuxHookRegistry.size() + 2U,
        "phase 7 per-API result covers the registry plus the custom points");

  std::error_code error;
  std::filesystem::remove(path, error);
  return true;
}

// ---------------------------------------------------------------------------
// Phase 8: writer failure injection (docs/HARDENING_PLAN.md H2)
// ---------------------------------------------------------------------------

struct WriterFaultGuard {
  ~WriterFaultGuard() { noleax::agent::linux::detail::disarm_writer_fault(); }
};

// Pushes count simple successful malloc events with distinct result addresses.
[[nodiscard]] bool push_alloc_events(LinuxHeapEventQueue& queue, std::size_t count,
                                     std::uint64_t base_ticks, std::uint64_t thread_id) {
  EventSpec spec{noleax::agent::linux::kMallocApiId,
                 LinuxHeapEventOperation::kAllocate,
                 LinuxHeapEventStatus::kSuccess,
                 0x40U,
                 0U,
                 0U,
                 0U,
                 0U,
                 0U};
  for (std::size_t index = 0U; index < count; ++index) {
    spec.result_address = 0x5000'4000'0000ULL + index * 0x1000ULL;
    if (!push_event(queue, make_event(spec, base_ticks + (index + 1U) * 100U, thread_id))) {
      return false;
    }
  }
  return true;
}

// The error-tail invariants shared by every tail-writable failure: kWriterError +
// kAbnormalStop and no missing-EndOfTrace, one writer-error Loss record, and exact
// statistics conservation.
void check_error_tail_readback(const Readback& readback, std::uint64_t expected_written,
                               std::uint64_t expected_dropped, const char* scenario) {
  const auto at = [scenario](const char* what) { return std::string{scenario} + ": " + what; };
  check(readback.stream.statistics.has_value(), at("statistics record decoded"));
  check(readback.stream.end_of_trace.has_value(), at("EndOfTrace record decoded"));
  if (readback.stream.end_of_trace.has_value()) {
    check(!readback.stream.end_of_trace->normal_stop, at("EndOfTrace is abnormal"));
  }
  check(readback.stream.completeness.has(noleax::trace::CompletenessIssue::kWriterError),
        at("completeness reports the writer error"));
  check(readback.stream.completeness.has(noleax::trace::CompletenessIssue::kAbnormalStop),
        at("completeness reports the abnormal stop"));
  check(!readback.stream.completeness.has(noleax::trace::CompletenessIssue::kMissingEndOfTrace),
        at("completeness clears the missing EndOfTrace"));
  bool saw_writer_loss = false;
  for (const noleax::trace::LossRecord& loss : readback.losses) {
    if (loss.reason == noleax::trace::LossReason::kWriterError) {
      saw_writer_loss = true;
      check(loss.location == noleax::trace::LossLocation::kWriter, at("writer loss location"));
      if (expected_dropped != 0U) {
        check(loss.estimated_event_count.has_value() &&
                  *loss.estimated_event_count == expected_dropped,
              at("writer loss estimates the in-flight events"));
      }
    }
  }
  check(saw_writer_loss, at("writer-error Loss record present"));
  check(readback.stream.event_count == expected_written, at("decoded events == written"));
  if (readback.stream.statistics.has_value()) {
    const noleax::trace::CaptureStatistics& statistics = *readback.stream.statistics;
    check(statistics.observed_calls ==
              statistics.successful_operations + statistics.failed_operations,
          at("observed == successful + failed"));
    check(
        statistics.observed_calls - statistics.filtered_before_queue - statistics.dropped_events ==
            expected_written,
        at("written + filtered + dropped == observed"));
    check(statistics.dropped_events == expected_dropped, at("dropped matches the result"));
    for (const noleax::trace::ApiStatistics& api : statistics.per_api) {
      check(api.observed_calls == api.successful_operations + api.failed_operations,
            at("per-API conservation"));
    }
  }
}

// 8a: open failures — a real bad path (ENOENT) and the injected fault on a good path.
bool phase8_open_failure() {
  std::printf("phase 8a: open failure\n");
  const std::uint64_t origin = monotonic_now_ns();
  const std::filesystem::path bad_dir_trace =
      std::filesystem::temp_directory_path() / "noleax-h2-no-such-dir" / "trace.nlx";
  {
    LinuxHeapEventQueue queue{16U};
    LinuxModuleTracker tracker{origin};
    try {
      LinuxTraceWriter writer{queue, tracker, bad_dir_trace, launch_options(origin)};
      check(false, "8a: a bad output path must fail construction");
    } catch (const noleax::trace::TraceWriteError& error) {
      check(error.phase() == noleax::trace::TraceWritePhase::kOpen, "8a: real open failure phase");
      check(error.system_error() == static_cast<std::uint32_t>(ENOENT),
            "8a: real open failure errno");
      check(!error.file_offset().has_value() && !error.chunk_type().has_value(),
            "8a: open failure carries no file context");
    }
  }
  check(!path_exists(bad_dir_trace) && !path_exists(partial_probe_path(bad_dir_trace)),
        "8a: a failed open creates no file");

  const std::filesystem::path path = probe_path("p8open");
  WriterFaultGuard guard;
  noleax::agent::linux::detail::arm_writer_fault(
      {noleax::agent::linux::detail::kWriterFaultOpen, 0U, false, 0U});
  {
    LinuxHeapEventQueue queue{16U};
    LinuxModuleTracker tracker{origin};
    try {
      LinuxTraceWriter writer{queue, tracker, path, launch_options(origin)};
      check(false, "8a: the injected open fault must fail construction");
    } catch (const noleax::trace::TraceWriteError& error) {
      check(error.phase() == noleax::trace::TraceWritePhase::kOpen,
            "8a: injected open failure phase");
      check(error.system_error() == static_cast<std::uint32_t>(EIO),
            "8a: injected open failure defaults to EIO");
    }
  }
  check(!path_exists(path) && !path_exists(partial_probe_path(path)),
        "8a: the injected open failure creates no file");
  return true;
}

// 8b: a mid-stream write failure with a writable tail: the first two chunk writes
// (metadata, initial modules) succeed, the third (stack chunk at the first flush tick)
// fails. The .partial must carry the two chunks, the error tail, and nothing else.
bool phase8_write_failure() {
  std::printf("phase 8b: mid-stream write failure\n");
  const std::filesystem::path path = probe_path("p8write");
  const std::filesystem::path partial = partial_probe_path(path);
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();
  constexpr std::size_t kEventCount = 8U;

  LinuxTraceWriterResult result;
  {
    WriterFaultGuard guard;
    noleax::agent::linux::detail::arm_writer_fault(
        {noleax::agent::linux::detail::kWriterFaultWrite, 2U, false, 0U});
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriter writer{queue, tracker, path, launch_options(origin)};
    writer.begin_capture();
    if (!push_alloc_events(queue, kEventCount, monotonic_now_ns(), thread_id)) {
      std::printf("FAIL: phase 8b pushes\n");
      return false;
    }
    // Cross at least one flush tick (10 ms) so the failure hits mid-capture.
    std::this_thread::sleep_for(std::chrono::milliseconds{60});
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kWriterError, "8b: status is writer error");
  check(!result.error_message.empty(), "8b: error message recorded");
  check(result.error_phase == noleax::trace::TraceWritePhase::kWrite, "8b: error phase");
  check(result.error_system_error == static_cast<std::uint32_t>(EIO), "8b: error errno");
  check(result.error_file_offset.has_value() && *result.error_file_offset > 0U,
        "8b: error offset recorded");
  check(result.error_chunk_type.has_value(), "8b: error chunk type recorded");
  check(result.tail_error_message.empty(), "8b: the tail itself wrote cleanly");
  check(result.statistics_written && result.end_of_trace_written, "8b: tail records written");
  check(!path_exists(path) && path_exists(partial), "8b: only the .partial exists");
  check(result.partial_path == partial && result.final_path.empty(), "8b: result paths");
  check(result.statistics.observed_calls == kEventCount, "8b: every consumed event observed");
  check(result.statistics.dropped_events == kEventCount,
        "8b: consumed-but-unwritten events are drops");

  const Readback readback = read_trace(partial);
  check_error_tail_readback(readback, 0U, kEventCount, "8b: error tail readback");

  // The analyzer CLI must accept the .partial path explicitly and report incompleteness.
  const std::string command =
      "\"" NOLEAX_CLI_PATH "\" analyze --mode events \"" + partial.string() + "\" > /dev/null 2>&1";
  const int cli_result = std::system(command.c_str());
  check(WIFEXITED(cli_result) && WEXITSTATUS(cli_result) == 2,
        "8b: noleax analyze accepts the .partial and exits 2");

  std::error_code error;
  std::filesystem::remove(partial, error);
  return true;
}

// 8c: a one-shot flush failure at the first flush tick: the event chunks are already on
// disk, so the tail adds the Loss + Statistics + abnormal EndOfTrace and nothing is
// counted as dropped.
bool phase8_flush_failure() {
  std::printf("phase 8c: flush failure\n");
  const std::filesystem::path path = probe_path("p8flush");
  const std::filesystem::path partial = partial_probe_path(path);
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();
  constexpr std::size_t kEventCount = 8U;

  LinuxTraceWriterResult result;
  {
    WriterFaultGuard guard;
    // Flush #1 is the begin_capture metadata flush; #2 is the first flush tick.
    noleax::agent::linux::detail::arm_writer_fault(
        {noleax::agent::linux::detail::kWriterFaultFlush, 1U, false, 0U});
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriter writer{queue, tracker, path, launch_options(origin)};
    writer.begin_capture();
    if (!push_alloc_events(queue, kEventCount, monotonic_now_ns(), thread_id)) {
      std::printf("FAIL: phase 8c pushes\n");
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{60});
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kWriterError, "8c: status is writer error");
  check(result.error_phase == noleax::trace::TraceWritePhase::kFlush, "8c: error phase");
  check(result.tail_error_message.empty(), "8c: the tail retry flush succeeded");
  check(result.statistics_written && result.end_of_trace_written, "8c: tail records written");
  check(!path_exists(path) && path_exists(partial), "8c: only the .partial exists");
  check(result.statistics.observed_calls == kEventCount && result.statistics.dropped_events == 0U,
        "8c: every event was written before the flush failed");

  const Readback readback = read_trace(partial);
  check_error_tail_readback(readback, kEventCount, 0U, "8c: error tail readback");

  std::error_code error;
  std::filesystem::remove(partial, error);
  return true;
}

// 8d: the close at commit time fails. The file content is complete — EndOfTrace, normal
// stop — but the writer refuses to vouch for it: no rename, writer error in the result.
bool phase8_close_failure() {
  std::printf("phase 8d: close failure\n");
  const std::filesystem::path path = probe_path("p8close");
  const std::filesystem::path partial = partial_probe_path(path);
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();
  constexpr std::size_t kEventCount = 8U;

  LinuxTraceWriterResult result;
  {
    WriterFaultGuard guard;
    noleax::agent::linux::detail::arm_writer_fault(
        {noleax::agent::linux::detail::kWriterFaultClose, 0U, false, 0U});
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriter writer{queue, tracker, path, launch_options(origin)};
    writer.begin_capture();
    if (!push_alloc_events(queue, kEventCount, monotonic_now_ns(), thread_id)) {
      std::printf("FAIL: phase 8d pushes\n");
      return false;
    }
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kWriterError, "8d: status is writer error");
  check(result.error_phase == noleax::trace::TraceWritePhase::kClose, "8d: error phase");
  check(result.error_system_error == static_cast<std::uint32_t>(EIO), "8d: error errno");
  check(result.tail_error_message.empty(), "8d: the close failure is the first failure");
  check(result.statistics_written && result.end_of_trace_written,
        "8d: terminal records were written before the close");
  check(!path_exists(path) && path_exists(partial), "8d: no rename after a close failure");
  check(result.final_path.empty(), "8d: no final path in the result");
  std::error_code size_error;
  check(std::filesystem::file_size(partial, size_error) == result.bytes_written && !size_error,
        "8d: bytes_written matches the partial file");

  const Readback readback = read_trace(partial);
  check(readback.stream.end_of_trace.has_value() && readback.stream.end_of_trace->normal_stop,
        "8d: the preserved partial is a complete normal-stop trace");
  check(readback.stream.event_count == kEventCount, "8d: every event survived the close failure");
  check(readback.stream.completeness.mask() == 0U, "8d: the preserved partial is complete");

  std::error_code error;
  std::filesystem::remove(partial, error);
  return true;
}

// 8e: a disk-full-flavoured write failure late in a longer stream (ENOSPC after 40 chunk
// writes). Everything up to the failure survives; the tail accounts the in-flight events.
bool phase8_late_disk_full() {
  std::printf("phase 8e: late disk-full write failure\n");
  const std::filesystem::path path = probe_path("p8full");
  const std::filesystem::path partial = partial_probe_path(path);
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();
  constexpr std::size_t kEventCount = 2'000U;

  LinuxTraceWriterResult result;
  {
    WriterFaultGuard guard;
    noleax::agent::linux::detail::arm_writer_fault({noleax::agent::linux::detail::kWriterFaultWrite,
                                                    40U, false,
                                                    static_cast<std::uint32_t>(ENOSPC)});
    LinuxHeapEventQueue queue{4096U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriterOptions options = launch_options(origin);
    options.compression = noleax::trace::CompressionCodec::kNone;
    options.flush_interval = std::chrono::milliseconds{5};
    options.chunk_target_size = 4U * 1024U;
    LinuxTraceWriter writer{queue, tracker, path, options};
    writer.begin_capture();
    if (!push_alloc_events(queue, kEventCount, monotonic_now_ns(), thread_id)) {
      std::printf("FAIL: phase 8e pushes\n");
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{300});
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kWriterError, "8e: status is writer error");
  check(result.error_phase == noleax::trace::TraceWritePhase::kWrite, "8e: error phase");
  check(result.error_system_error == static_cast<std::uint32_t>(ENOSPC), "8e: error is ENOSPC");
  check(result.tail_error_message.empty(), "8e: the tail wrote cleanly");
  check(result.end_of_trace_written, "8e: abnormal EndOfTrace written");
  check(!path_exists(path) && path_exists(partial), "8e: only the .partial exists");

  const noleax::trace::CaptureStatistics& statistics = result.statistics;
  const std::uint64_t written =
      statistics.observed_calls - statistics.filtered_before_queue - statistics.dropped_events;
  check(statistics.observed_calls > 0U && statistics.observed_calls <= kEventCount,
        "8e: observed is the consumed prefix");
  check(written > 0U && written < statistics.observed_calls,
        "8e: a strict prefix of the consumed events survived");
  check(statistics.dropped_events == statistics.observed_calls - written,
        "8e: the rest is accounted as dropped");

  const Readback readback = read_trace(partial);
  check_error_tail_readback(readback, written, statistics.dropped_events, "8e: tail readback");
  check(readback.orphaned_ends == 0U, "8e: no orphaned generation ends");

  std::error_code error;
  std::filesystem::remove(partial, error);
  return true;
}

// 8f: a sticky write failure — the disk stays full — so the error tail itself cannot
// write. The result must carry BOTH errors, and the .partial (metadata + modules only)
// must still decode, now with a missing EndOfTrace.
bool phase8_tail_unwritable() {
  std::printf("phase 8f: tail-unwritable write failure\n");
  const std::filesystem::path path = probe_path("p8sticky");
  const std::filesystem::path partial = partial_probe_path(path);
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();
  constexpr std::size_t kEventCount = 8U;

  LinuxTraceWriterResult result;
  {
    WriterFaultGuard guard;
    noleax::agent::linux::detail::arm_writer_fault(
        {noleax::agent::linux::detail::kWriterFaultWrite, 2U, true, 0U});
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriter writer{queue, tracker, path, launch_options(origin)};
    writer.begin_capture();
    if (!push_alloc_events(queue, kEventCount, monotonic_now_ns(), thread_id)) {
      std::printf("FAIL: phase 8f pushes\n");
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{60});
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kWriterError, "8f: status is writer error");
  check(!result.error_message.empty(), "8f: the original error is recorded");
  check(result.error_phase == noleax::trace::TraceWritePhase::kWrite, "8f: error phase");
  check(!result.tail_error_message.empty(), "8f: the tail failure is recorded separately");
  check(!result.statistics_written && !result.end_of_trace_written,
        "8f: no tail record reached the disk");
  check(!path_exists(path) && path_exists(partial), "8f: only the .partial exists");
  // The in-memory statistics still account every consumed event, even unwritten.
  check(result.statistics.observed_calls == kEventCount &&
            result.statistics.dropped_events == kEventCount,
        "8f: in-memory statistics still conserve");

  const Readback readback = read_trace(partial);
  check(!readback.stream.end_of_trace.has_value(), "8f: the partial has no EndOfTrace");
  check(readback.stream.completeness.has(noleax::trace::CompletenessIssue::kMissingEndOfTrace),
        "8f: the reader reports the missing EndOfTrace");
  check(readback.stream.event_count == 0U, "8f: no event chunk survived");

  std::error_code error;
  std::filesystem::remove(partial, error);
  return true;
}

bool phase8() {
  bool ok = phase8_open_failure();
  ok = phase8_write_failure() && ok;
  ok = phase8_flush_failure() && ok;
  ok = phase8_close_failure() && ok;
  ok = phase8_late_disk_full() && ok;
  ok = phase8_tail_unwritable() && ok;
  return ok;
}

// ---------------------------------------------------------------------------
// Phase 9: statistics conservation property (H2). Randomized producer counter snapshots
// — including zero-activity APIs and custom hook points — drive counter_source while the
// matching events are drained for real; the finalize-time reconciliation must hold per
// API and in aggregate, in the result and in the decoded trace.
// ---------------------------------------------------------------------------

struct PropertyApiPlan {
  noleax::trace::ApiId api_id{0U};
  std::uint64_t successful{0U};  // includes the filtered calls, like the hook counters
  std::uint64_t failed{0U};
  std::uint64_t filtered{0U};  // allocate-family only
};

class PropertyRandom final {
 public:
  explicit PropertyRandom(std::uint64_t seed) : state_{seed == 0U ? 1U : seed} {}
  [[nodiscard]] std::uint64_t next(std::uint64_t bound) {
    state_ ^= state_ << 13U;
    state_ ^= state_ >> 7U;
    state_ ^= state_ << 17U;
    return bound == 0U ? 0U : state_ % bound;
  }

 private:
  std::uint64_t state_;
};

[[nodiscard]] bool allocate_family_api(noleax::trace::ApiId api_id) {
  return api_id == noleax::agent::linux::kMallocApiId ||
         api_id == noleax::agent::linux::kCallocApiId ||
         api_id == noleax::agent::linux::kPosixMemalignApiId ||
         api_id == noleax::agent::linux::kAlignedAllocApiId ||
         api_id == noleax::agent::linux::kMemalignApiId ||
         api_id >= noleax::trace::kCustomHookApiIdBase;
}

// One valid raw event for the API: heap allocate/reallocate/free shapes for the heap
// family, VM shapes for mmap/munmap/mremap, allocate-only for custom points.
[[nodiscard]] EventSpec property_event_spec(noleax::trace::ApiId api_id, bool failure,
                                            std::uint64_t unique_address) {
  using noleax::agent::linux::kAlignedAllocApiId;
  using noleax::agent::linux::kCallocApiId;
  using noleax::agent::linux::kFreeApiId;
  using noleax::agent::linux::kMallocApiId;
  using noleax::agent::linux::kMemalignApiId;
  using noleax::agent::linux::kMmapApiId;
  using noleax::agent::linux::kMremapApiId;
  using noleax::agent::linux::kMunmapApiId;
  using noleax::agent::linux::kPosixMemalignApiId;
  using noleax::agent::linux::kReallocApiId;
  using noleax::agent::linux::kReallocarrayApiId;
  constexpr std::uint64_t kAnonymous = std::numeric_limits<std::uint64_t>::max();
  const auto status = failure ? LinuxHeapEventStatus::kFailure : LinuxHeapEventStatus::kSuccess;
  EventSpec spec{api_id, LinuxHeapEventOperation::kAllocate, status};
  spec.operation_result = failure ? static_cast<std::uint32_t>(ENOMEM) : 0U;
  if (api_id == kMallocApiId || api_id == kCallocApiId || api_id == kPosixMemalignApiId ||
      api_id == kAlignedAllocApiId || api_id == kMemalignApiId ||
      api_id >= noleax::trace::kCustomHookApiIdBase) {
    spec.operation = LinuxHeapEventOperation::kAllocate;
    spec.requested_size = failure ? (1ULL << 40U) : 0x40U;
    spec.result_address = failure ? 0U : unique_address;
    return spec;
  }
  if (api_id == kReallocApiId || api_id == kReallocarrayApiId) {
    spec.operation = LinuxHeapEventOperation::kReallocate;
    spec.requested_size = 0x40U;
    spec.address = failure ? unique_address : 0U;
    spec.result_address = failure ? 0U : unique_address;
    return spec;
  }
  if (api_id == kFreeApiId) {
    spec.operation = LinuxHeapEventOperation::kFree;  // free(NULL): unmatched
    spec.operation_result = 0U;
    return spec;
  }
  if (api_id == kMmapApiId) {
    spec.operation = LinuxHeapEventOperation::kVmAllocate;
    spec.requested_size = failure ? (1ULL << 40U) : 0x1000U;
    spec.protection = 0x3U;
    spec.map_flags = 0x22U;
    spec.section_handle = kAnonymous;
    spec.result_address = failure ? 0U : unique_address;
    return spec;
  }
  if (api_id == kMunmapApiId) {
    spec.operation = LinuxHeapEventOperation::kVmUnmap;
    spec.address = unique_address;
    spec.requested_size = 0x1000U;
    spec.operation_result = failure ? static_cast<std::uint32_t>(EINVAL) : 0U;
    return spec;
  }
  // mremap: an in-place resize of an untracked range (one wire record).
  spec.operation = LinuxHeapEventOperation::kVmRemap;
  spec.address = unique_address;
  spec.requested_size = 0x1000U;
  spec.count = 0x2000U;
  spec.map_flags = 0x1U;
  spec.result_address = failure ? 0U : unique_address;
  return spec;
}

bool phase9_property_run(std::uint64_t seed) {
  const std::filesystem::path path = probe_path(("p9-" + std::to_string(seed)).c_str());
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();
  PropertyRandom random{seed};

  noleax::ipc::CustomHookSpec custom_hook;
  custom_hook.module = "libprop.so";
  custom_hook.alloc.locator = noleax::ipc::CustomHookLocator::kExport;
  custom_hook.alloc.export_name = "prop_malloc";
  custom_hook.free.locator = noleax::ipc::CustomHookLocator::kExport;
  custom_hook.free.export_name = "prop_free";
  custom_hook.label = "prop_malloc";

  std::vector<PropertyApiPlan> plans;
  for (const auto& entry : noleax::agent::linux::kLinuxHookRegistry) {
    PropertyApiPlan plan;
    plan.api_id = entry.api_id;
    plan.successful = random.next(8U);
    plan.failed = entry.api_id == noleax::agent::linux::kFreeApiId ? 0U : random.next(4U);
    plan.filtered = allocate_family_api(plan.api_id) ? random.next(plan.successful + 1U) : 0U;
    plans.push_back(plan);
  }
  PropertyApiPlan custom_plan;
  custom_plan.api_id = noleax::trace::kCustomHookApiIdBase;
  custom_plan.successful = random.next(8U);
  custom_plan.failed = random.next(4U);
  custom_plan.filtered = random.next(custom_plan.successful + 1U);
  plans.push_back(custom_plan);

  std::vector<noleax::agent::linux::LinuxTraceWriterApiCounterSnapshot> snapshots;
  for (const PropertyApiPlan& plan : plans) {
    snapshots.push_back(noleax::agent::linux::LinuxTraceWriterApiCounterSnapshot{
        plan.api_id, plan.successful + plan.failed, plan.successful, plan.failed, plan.filtered,
        0U});
  }

  LinuxTraceWriterResult result;
  {
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriterOptions options = launch_options(origin);
    options.custom_hooks = {custom_hook};
    options.counter_source = [&snapshots] { return snapshots; };
    LinuxTraceWriter writer{queue, tracker, path, options};
    writer.begin_capture();

    const std::uint64_t base = monotonic_now_ns();
    std::uint64_t produced = 0U;
    std::uint64_t next_address = 0x5000'9000'0000ULL;
    for (const PropertyApiPlan& plan : plans) {
      // The producer never queues filtered calls: consumed = successful - filtered +
      // failed events.
      // The 0x4000 stride keeps the synthesized ranges disjoint (VM specs span up to
      // 0x2000): the interval model turns an overlap into eviction records, which would
      // break this phase's one-record-per-call premise.
      for (std::uint64_t index = 0U; index < plan.successful - plan.filtered; ++index) {
        const EventSpec spec = property_event_spec(plan.api_id, false, next_address += 0x4000ULL);
        if (!push_event(queue, make_event(spec, base + ++produced * 100U, thread_id))) {
          std::printf("FAIL: phase 9 push\n");
          return false;
        }
      }
      for (std::uint64_t index = 0U; index < plan.failed; ++index) {
        const EventSpec spec = property_event_spec(plan.api_id, true, next_address += 0x4000ULL);
        if (!push_event(queue, make_event(spec, base + ++produced * 100U, thread_id))) {
          std::printf("FAIL: phase 9 push\n");
          return false;
        }
      }
    }
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kComplete, "phase 9 status is complete");
  check_common_result(result, path);
  check(result.trace_dropped_events == 0U && result.queue_dropped_events == 0U,
        "phase 9 has no drops");

  std::uint64_t expected_observed = 0U;
  std::uint64_t expected_successful = 0U;
  std::uint64_t expected_failed = 0U;
  std::uint64_t expected_filtered = 0U;
  for (const PropertyApiPlan& plan : plans) {
    expected_observed += plan.successful + plan.failed;
    expected_successful += plan.successful;
    expected_failed += plan.failed;
    expected_filtered += plan.filtered;
  }

  const noleax::trace::CaptureStatistics& statistics = result.statistics;
  check(statistics.observed_calls == expected_observed &&
            statistics.successful_operations == expected_successful &&
            statistics.failed_operations == expected_failed &&
            statistics.filtered_before_queue == expected_filtered &&
            statistics.dropped_events == 0U,
        "phase 9 aggregate counters match the synthesized plan");
  check(
      statistics.observed_calls == statistics.successful_operations + statistics.failed_operations,
      "phase 9 aggregate observed == successful + failed");
  check(statistics.observed_calls - statistics.filtered_before_queue - statistics.dropped_events ==
            expected_observed - expected_filtered,
        "phase 9 aggregate written + filtered + dropped == observed");
  for (const noleax::trace::ApiStatistics& api : statistics.per_api) {
    check(api.observed_calls == api.successful_operations + api.failed_operations,
          "phase 9 per-API observed == successful + failed");
    check(api.dropped_events == 0U, "phase 9 per-API drops are zero");
  }
  std::uint64_t per_api_filtered_sum = 0U;
  for (const noleax::trace::ApiStatistics& api : statistics.per_api) {
    per_api_filtered_sum += api.filtered_before_queue;
  }
  check(per_api_filtered_sum == statistics.filtered_before_queue,
        "phase 9 aggregate filtered == sum of per-API filtered");

  const Readback readback = read_trace(path);
  check_common_readback(readback, origin);
  check(readback.stream.event_count == expected_observed - expected_filtered,
        "phase 9 decoded events == written");

  std::error_code error;
  std::filesystem::remove(path, error);
  return true;
}

bool phase9() {
  std::printf("phase 9: statistics conservation property\n");
  bool ok = true;
  for (std::uint64_t seed = 1U; seed <= 8U; ++seed) {
    ok = phase9_property_run(seed * 0x9E3779B97F4A7C15ULL) && ok;
  }
  return ok;
}

struct VmScriptResult {
  LinuxTraceWriterResult result;
  Readback readback;
  std::filesystem::path path;
};

// Drives a scripted VM event set through the writer and reads the trace back; every spec
// carries an explicit completion sequence so completion order can differ from queue order.
// The trace file stays on disk (out.path) for further analyzer passes; the caller removes it.
[[nodiscard]] bool run_vm_script(const char* phase_name, const EventSpec* script, std::size_t count,
                                 VmScriptResult& out, bool with_counter_source = false) {
  const std::filesystem::path path = probe_path(phase_name);
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();

  LinuxTraceWriterResult result;
  {
    LinuxHeapEventQueue queue{1024U};
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriterOptions options = launch_options(origin);
    if (with_counter_source) {
      // Call-space producer snapshots for the three VM channels, with the mremap move pairs
      // folded in exactly like the runtime folds paired_records: the finalize reconciliation
      // must add the writer-side extra records on top of these.
      std::uint64_t mmap_calls = 0U;
      std::uint64_t munmap_calls = 0U;
      std::uint64_t mremap_calls = 0U;
      std::uint64_t mremap_pairs = 0U;
      for (std::size_t index = 0U; index < count; ++index) {
        if (script[index].api_id == noleax::agent::linux::kMmapApiId) {
          ++mmap_calls;
        } else if (script[index].api_id == noleax::agent::linux::kMunmapApiId) {
          ++munmap_calls;
        } else if (script[index].api_id == noleax::agent::linux::kMremapApiId) {
          ++mremap_calls;
          if (script[index].status == LinuxHeapEventStatus::kSuccess &&
              script[index].result_address != script[index].address) {
            ++mremap_pairs;
          }
        }
      }
      options.counter_source = [mmap_calls, munmap_calls, mremap_calls, mremap_pairs] {
        return std::vector<noleax::agent::linux::LinuxTraceWriterApiCounterSnapshot>{
            {noleax::agent::linux::kMmapApiId, mmap_calls, mmap_calls, 0U, 0U, 0U},
            {noleax::agent::linux::kMunmapApiId, munmap_calls, munmap_calls, 0U, 0U, 0U},
            {noleax::agent::linux::kMremapApiId, mremap_calls + mremap_pairs,
             mremap_calls + mremap_pairs, 0U, 0U, 0U}};
      };
    }
    LinuxTraceWriter writer{queue, tracker, path, options};
    writer.begin_capture();
    const std::uint64_t base = monotonic_now_ns();
    for (std::size_t index = 0U; index < count; ++index) {
      if (!push_event(queue, make_event(script[index], base + (index + 1U) * 1'000U, thread_id))) {
        std::printf("FAIL: %s event queue push %zu\n", phase_name, index);
        return false;
      }
    }
    result = writer.finish();
  }
  out.result = result;
  out.readback = read_trace(path);
  out.path = path;
  return true;
}

void remove_vm_script_trace(VmScriptResult& result) {
  std::error_code error;
  std::filesystem::remove(result.path, error);
}

[[nodiscard]] EventSpec vm_mmap(std::uint64_t base, std::uint64_t size,
                                std::uint64_t completion_sequence) {
  EventSpec spec{noleax::agent::linux::kMmapApiId, LinuxHeapEventOperation::kVmAllocate,
                 LinuxHeapEventStatus::kSuccess};
  spec.requested_size = size;
  spec.protection = 0x3U;  // PROT_READ | PROT_WRITE
  spec.map_flags = 0x22U;  // MAP_PRIVATE | MAP_ANONYMOUS
  spec.section_handle = std::numeric_limits<std::uint64_t>::max();
  spec.result_address = base;
  spec.completion_sequence = completion_sequence;
  return spec;
}

[[nodiscard]] EventSpec vm_mmap_file(std::uint64_t base, std::uint64_t size,
                                     std::uint64_t completion_sequence) {
  EventSpec spec = vm_mmap(base, size, completion_sequence);
  spec.protection = 0x1U;  // PROT_READ
  spec.map_flags = 0x2U;   // MAP_PRIVATE
  spec.section_handle = 9U;
  return spec;
}

[[nodiscard]] EventSpec vm_munmap(std::uint64_t base, std::uint64_t size,
                                  std::uint64_t completion_sequence) {
  EventSpec spec{noleax::agent::linux::kMunmapApiId, LinuxHeapEventOperation::kVmUnmap,
                 LinuxHeapEventStatus::kSuccess};
  spec.address = base;
  spec.requested_size = size;
  spec.completion_sequence = completion_sequence;
  return spec;
}

[[nodiscard]] EventSpec vm_mremap(std::uint64_t old_base, std::uint64_t old_size,
                                  std::uint64_t new_size, std::uint64_t new_base,
                                  std::uint64_t completion_sequence,
                                  std::uint64_t fixed_new_address = 0U) {
  EventSpec spec{noleax::agent::linux::kMremapApiId, LinuxHeapEventOperation::kVmRemap,
                 LinuxHeapEventStatus::kSuccess};
  spec.address = old_base;
  spec.requested_size = old_size;
  spec.count = new_size;
  spec.result_address = new_base;
  spec.completion_sequence = completion_sequence;
  if (fixed_new_address != 0U) {
    spec.map_flags = 0x3U;  // MREMAP_MAYMOVE | MREMAP_FIXED (0x1 | 0x2)
    spec.alignment = fixed_new_address;
  } else {
    spec.map_flags = 0x1U;  // MREMAP_MAYMOVE
  }
  return spec;
}

[[nodiscard]] const noleax::trace::VmFreeEvent* vm_free_at(const Readback& readback,
                                                           std::size_t index) {
  if (index >= readback.events.size()) {
    return nullptr;
  }
  return std::get_if<noleax::trace::VmFreeEvent>(&readback.events[index].payload);
}

// Phase 10: deterministic partial-unmap fixture (single-threaded ground truth): a 1 MiB
// mapping loses its prefix, suffix, and middle in turn, a munmap spans a hole into a second
// mapping, a double unmap and an unmap of a hole keep the unmatched shape, and the final
// outstanding state must equal the ground truth the script computes — through the analyzer's
// generation tracker AND the outstanding analysis over the written trace.
bool phase10() {
  std::printf("phase 10: partial unmap interval fixture\n");
  constexpr std::uint64_t kA = 0x7000'1000'0000ULL;
  constexpr std::uint64_t kB = 0x7000'2000'0000ULL;
  constexpr std::uint64_t kMiB = 1ULL << 20U;
  constexpr std::uint64_t kKiB = 1ULL << 10U;

  const EventSpec script[] = {
      vm_mmap(kA, kMiB, 1U),                                                     // create A
      vm_munmap(kA, 64U * kKiB, 2U),                                             // prefix
      vm_munmap(kA + 768U * kKiB, 256U * kKiB, 3U),                              // suffix
      vm_munmap(kA + 256U * kKiB, 128U * kKiB, 4U),                              // middle split
      vm_mmap(kB, 512U * kKiB, 5U),                                              // create B
      vm_munmap(kA + 896U * kKiB, (kB + 128U * kKiB) - (kA + 896U * kKiB), 6U),  // spans B
      vm_munmap(kB, 128U * kKiB, 7U),               // double unmap of B's freed head
      vm_munmap(kA + 896U * kKiB, 64U * kKiB, 8U),  // unmap of a hole
  };
  constexpr std::size_t kRawCount = sizeof(script) / sizeof(script[0]);

  VmScriptResult run;
  if (!run_vm_script("p10", script, kRawCount, run)) {
    return false;
  }
  check(run.result.status == LinuxTraceWriterStatus::kComplete, "phase 10 status is complete");
  check(run.result.error_message.empty(),
        "phase 10 writer error is empty (got: " + run.result.error_message + ")");
  check(run.result.trace_dropped_events == 0U, "phase 10 has no trace drops");

  const Readback& readback = run.readback;
  check(readback.stream.event_count == kRawCount, "phase 10 one wire record per syscall here");
  check(readback.stream.completeness.mask() == 0U, "phase 10 decoded completeness is complete");

  // Ground truth: A keeps [A+64K, A+256K) and [A+384K, A+768K) = 576 KiB; B keeps
  // [B+128K, B+512K) = 384 KiB.
  constexpr std::uint64_t kARemaining = 192U * kKiB + 384U * kKiB;
  constexpr std::uint64_t kBRemaining = 384U * kKiB;
  check(readback.generations_created == 2U && readback.generations_ended == 0U &&
            readback.generations_live == 2U,
        "phase 10 both generations survive partially");
  check(readback.orphaned_ends == 0U && readback.orphaned_mapping_ends == 0U,
        "phase 10 has no orphaned ends");

  const auto& events = readback.events;
  if (events.size() == kRawCount) {
    const auto* create_a = std::get_if<noleax::trace::VmAllocateEvent>(&events[0].payload);
    const auto* create_b = std::get_if<noleax::trace::VmAllocateEvent>(&events[4].payload);
    check(
        create_a != nullptr && create_b != nullptr && create_a->mapping_id != create_b->mapping_id,
        "phase 10 the two creates carry distinct mapping ids");
    if (create_a != nullptr && create_b != nullptr) {
      const auto check_free = [&](std::size_t index, noleax::trace::MappingId id,
                                  std::uint64_t base, std::uint64_t size, const char* what) {
        const auto* free_event = vm_free_at(readback, index);
        check(free_event != nullptr && free_event->mapping_id == id && free_event->base == base &&
                  free_event->region_size == size && free_event->free_type == 0x8000U &&
                  events[index].header.status == noleax::trace::EventStatus::kSuccess,
              what);
      };
      check_free(1U, create_a->mapping_id, kA, 64U * kKiB, "phase 10 prefix free is interior");
      check_free(2U, create_a->mapping_id, kA + 768U * kKiB, 256U * kKiB,
                 "phase 10 suffix free is interior");
      check_free(3U, create_a->mapping_id, kA + 256U * kKiB, 128U * kKiB,
                 "phase 10 middle free is interior");
      check_free(5U, create_b->mapping_id, kB, 128U * kKiB,
                 "phase 10 the spanning unmap releases only B's covered head");
      const auto* double_unmap = vm_free_at(readback, 6U);
      check(double_unmap != nullptr && !double_unmap->mapping_id.is_valid() &&
                events[6].header.status == noleax::trace::EventStatus::kUnmatched,
            "phase 10 double unmap is unmatched");
      const auto* hole_unmap = vm_free_at(readback, 7U);
      check(hole_unmap != nullptr && !hole_unmap->mapping_id.is_valid() &&
                events[7].header.status == noleax::trace::EventStatus::kUnmatched,
            "phase 10 hole unmap is unmatched");
    }
  }

  // The analyzer's outstanding view over the finished trace must equal the ground truth:
  // two generations with exactly the remaining virtual bytes.
  {
    std::ifstream input{run.path, std::ios::binary};
    if (!input) {
      std::printf("FAIL: phase 10 cannot reopen the trace\n");
      return false;
    }
    const auto outstanding = noleax::analyzer::analyze_outstanding(input, {});
    check(outstanding.outstanding.size() == 2U,
          "phase 10 outstanding holds both partial generations");
    std::uint64_t virtual_bytes = 0U;
    bool saw_a = false;
    bool saw_b = false;
    for (const auto& generation : outstanding.outstanding) {
      if (generation.kind != noleax::analyzer::GenerationKind::kVirtualAllocation) {
        continue;
      }
      virtual_bytes += generation.size;
      saw_a = saw_a || (generation.address == kA && generation.size == kARemaining);
      saw_b = saw_b || (generation.address == kB && generation.size == kBRemaining);
    }
    check(saw_a && saw_b, "phase 10 outstanding sizes match the scripted ground truth");
    check(virtual_bytes == kARemaining + kBRemaining,
          "phase 10 outstanding virtual bytes equal the remaining sum");
    check(outstanding.ended_by_c_count == 0U, "phase 10 nothing ended before trace end");
  }
  remove_vm_script_trace(run);
  return true;
}

// Phase 11: overlap eviction and completion-sequence ordering. Three mmaps increasingly
// overlap the same range (the later ones evict the earlier tails, MAP_FIXED-style); a stale
// mmap whose completion predates the incumbents records its create but owns nothing (trim
// records zero it out); a stale munmap skips the newer generation and reports unmatched; a
// final spanning munmap ends every generation with one record per fragment.
bool phase11() {
  std::printf("phase 11: overlap eviction and completion ordering\n");
  constexpr std::uint64_t kY = 0x7000'3000'0000ULL;
  constexpr std::uint64_t kKiB = 1ULL << 10U;

  const EventSpec script[] = {
      vm_mmap(kY, 64U * kKiB, 10U),                // D owns [0, 64K)
      vm_mmap(kY + 16U * kKiB, 64U * kKiB, 15U),   // F evicts D's [16K, 64K), owns [16K, 80K)
      vm_mmap(kY + 32U * kKiB, 64U * kKiB, 20U),   // E evicts F's [32K, 80K), owns [32K, 96K)
      vm_mmap(kY + 40U * kKiB, 16U * kKiB, 12U),   // G is stale (12 < 15 < 20): owns nothing
      vm_munmap(kY + 88U * kKiB, 8U * kKiB, 18U),  // stale vs E (20): unmatched
      vm_munmap(kY, 96U * kKiB, 30U),              // ends D, F, E with one record each
  };
  constexpr std::size_t kRawCount = sizeof(script) / sizeof(script[0]);
  constexpr std::size_t kRecordCount = 11U;  // 1 + 2 + 2 + 2 + 1 + 3

  VmScriptResult run;
  if (!run_vm_script("p11", script, kRawCount, run, /*with_counter_source=*/true)) {
    return false;
  }
  check(run.result.status == LinuxTraceWriterStatus::kComplete, "phase 11 status is complete");
  check(run.result.error_message.empty(),
        "phase 11 writer error is empty (got: " + run.result.error_message + ")");

  const Readback& readback = run.readback;
  check(readback.stream.event_count == kRecordCount, "phase 11 wire record count");
  check(readback.stream.completeness.mask() == 0U, "phase 11 decoded completeness is complete");
  check(readback.generations_created == 4U && readback.generations_ended == 4U &&
            readback.generations_live == 0U,
        "phase 11 every generation pairs off (the stale one ends on its trim)");
  check(readback.orphaned_mapping_ends == 0U, "phase 11 has no orphaned mapping ends");

  if (run.result.statistics.per_api.size() >= 3U) {
    for (const noleax::trace::ApiStatistics& api : run.result.statistics.per_api) {
      if (api.api_id == noleax::agent::linux::kMmapApiId) {
        check(api.observed_calls == 7U && api.successful_operations == 7U,
              "phase 11 mmap observed counts the eviction and trim records");
      }
      if (api.api_id == noleax::agent::linux::kMunmapApiId) {
        check(api.observed_calls == 4U && api.successful_operations == 4U,
              "phase 11 munmap observed counts the spanning fragment records");
      }
    }
    check(run.result.statistics.observed_calls == kRecordCount,
          "phase 11 aggregate observed covers every wire record");
  }

  const auto& events = readback.events;
  if (events.size() == kRecordCount) {
    const auto* create_d = std::get_if<noleax::trace::VmAllocateEvent>(&events[0].payload);
    const auto* create_f = std::get_if<noleax::trace::VmAllocateEvent>(&events[2].payload);
    const auto* create_e = std::get_if<noleax::trace::VmAllocateEvent>(&events[4].payload);
    const auto* create_g = std::get_if<noleax::trace::VmAllocateEvent>(&events[5].payload);
    check(create_d != nullptr && create_f != nullptr && create_e != nullptr && create_g != nullptr,
          "phase 11 four creates in wire order");
    if (create_d != nullptr && create_f != nullptr && create_e != nullptr && create_g != nullptr) {
      const auto eviction_f = vm_free_at(readback, 1U);
      check(eviction_f != nullptr && eviction_f->mapping_id == create_d->mapping_id &&
                eviction_f->base == kY + 16U * kKiB && eviction_f->region_size == 48U * kKiB,
            "phase 11 F's placement evicts D's tail");
      const auto eviction_e = vm_free_at(readback, 3U);
      check(eviction_e != nullptr && eviction_e->mapping_id == create_f->mapping_id &&
                eviction_e->base == kY + 32U * kKiB && eviction_e->region_size == 48U * kKiB,
            "phase 11 E's placement evicts F's tail");
      const auto trim_g = vm_free_at(readback, 6U);
      check(trim_g != nullptr && trim_g->mapping_id == create_g->mapping_id &&
                trim_g->base == kY + 40U * kKiB && trim_g->region_size == 16U * kKiB &&
                events[6].header.status == noleax::trace::EventStatus::kSuccess,
            "phase 11 the stale create is trimmed back to zero");
      const auto stale_unmap = vm_free_at(readback, 7U);
      check(stale_unmap != nullptr && !stale_unmap->mapping_id.is_valid() &&
                events[7].header.status == noleax::trace::EventStatus::kUnmatched,
            "phase 11 the stale munmap skips the newer generation and is unmatched");
      const auto end_d = vm_free_at(readback, 8U);
      const auto end_f = vm_free_at(readback, 9U);
      const auto end_e = vm_free_at(readback, 10U);
      check(end_d != nullptr && end_f != nullptr && end_e != nullptr &&
                end_d->mapping_id == create_d->mapping_id && end_d->base == kY &&
                end_d->region_size == 16U * kKiB && end_f->mapping_id == create_f->mapping_id &&
                end_f->base == kY + 16U * kKiB && end_f->region_size == 16U * kKiB &&
                end_e->mapping_id == create_e->mapping_id && end_e->base == kY + 32U * kKiB &&
                end_e->region_size == 64U * kKiB,
            "phase 11 the spanning munmap ends every generation with one record each");
    }
  }
  remove_vm_script_trace(run);
  return true;
}

// Phase 12: the mremap matrix through the interval model — in-place grow, in-place shrink,
// a move, a MREMAP_FIXED move onto an occupied mapping, a shrink that evicts a neighbour
// living in the generation's hole — plus a partial unmap of a file-backed view (VmFree
// pieces, not Unmap) and its final whole-view Unmap.
bool phase12() {
  std::printf("phase 12: mremap matrix and section partial unmap\n");
  constexpr std::uint64_t kM = 0x7000'4000'0000ULL;
  constexpr std::uint64_t kN = 0x7000'5000'0000ULL;
  constexpr std::uint64_t kP = 0x7000'6000'0000ULL;
  constexpr std::uint64_t kQ = 0x7000'7000'0000ULL;
  constexpr std::uint64_t kS = 0x7000'8000'0000ULL;
  constexpr std::uint64_t kKiB = 1ULL << 10U;

  const EventSpec script[] = {
      vm_mmap(kM, 64U * kKiB, 1U),
      vm_mremap(kM, 64U * kKiB, 128U * kKiB, kM, 2U),  // grow in place
      vm_mremap(kM, 128U * kKiB, 32U * kKiB, kM, 3U),  // shrink in place
      vm_mremap(kM, 32U * kKiB, 64U * kKiB, kN, 4U),   // move M -> N
      vm_mmap(kP, 64U * kKiB, 5U),
      vm_mremap(kN, 64U * kKiB, 64U * kKiB, kP, 6U, kP),  // FIXED move onto P
      vm_mmap(kQ, 128U * kKiB, 7U),
      vm_munmap(kQ + 64U * kKiB, 32U * kKiB, 8U),       // hole in Q
      vm_mmap(kQ + 64U * kKiB, 32U * kKiB, 9U),         // neighbour fills the hole
      vm_mremap(kQ, 128U * kKiB, 32U * kKiB, kQ, 10U),  // shrink evicts the neighbour
      vm_mmap_file(kS, 128U * kKiB, 11U),
      vm_munmap(kS, 64U * kKiB, 12U),               // partial view free (VmFree)
      vm_munmap(kS + 64U * kKiB, 64U * kKiB, 13U),  // remainder: whole-view Unmap
  };
  constexpr std::size_t kRawCount = sizeof(script) / sizeof(script[0]);
  // Records: 1,1,1,2,1,3,1,1,1,3,1,1,1 = 18 from 13 raw events. A shrink whose event old
  // size spans past the resized VMA run releases the outer pieces with explicit frees (the
  // resize record itself covers only the run's own tail).
  constexpr std::size_t kRecordCount = 18U;

  VmScriptResult run;
  if (!run_vm_script("p12", script, kRawCount, run, /*with_counter_source=*/true)) {
    return false;
  }
  check(run.result.status == LinuxTraceWriterStatus::kComplete, "phase 12 status is complete");
  check(run.result.error_message.empty(),
        "phase 12 writer error is empty (got: " + run.result.error_message + ")");

  const Readback& readback = run.readback;
  check(readback.stream.event_count == kRecordCount, "phase 12 wire record count");
  check(readback.stream.completeness.mask() == 0U, "phase 12 decoded completeness is complete");
  check(readback.generations_created == 7U, "phase 12 seven generations were created");
  check(readback.generations_ended == 5U && readback.generations_live == 2U,
        "phase 12 five generations ended, the FIXED-move result and the shrunk Q survive");
  check(readback.orphaned_mapping_ends == 0U, "phase 12 has no orphaned mapping ends");

  for (const noleax::trace::ApiStatistics& api : run.result.statistics.per_api) {
    if (api.api_id == noleax::agent::linux::kMremapApiId) {
      check(api.observed_calls == 10U && api.successful_operations == 10U,
            "phase 12 mremap observed counts pairs and eviction extras");
    }
  }

  const auto& events = readback.events;
  if (events.size() == kRecordCount) {
    const auto* create_m = std::get_if<noleax::trace::VmAllocateEvent>(&events[0].payload);
    const auto* grow = std::get_if<noleax::trace::VmAllocateEvent>(&events[1].payload);
    const auto* shrink = std::get_if<noleax::trace::VmAllocateEvent>(&events[2].payload);
    check(create_m != nullptr && grow != nullptr && shrink != nullptr &&
              grow->mapping_id == create_m->mapping_id &&
              shrink->mapping_id == create_m->mapping_id && grow->mapping_size == 128U * kKiB &&
              shrink->mapping_size == 32U * kKiB,
          "phase 12 in-place grow and shrink keep the mapping id and adjust the size");
    const auto* move_free = vm_free_at(readback, 3U);
    const auto* move_create = std::get_if<noleax::trace::VmAllocateEvent>(&events[4].payload);
    check(move_free != nullptr && move_create != nullptr &&
              move_free->mapping_id == create_m->mapping_id &&
              move_free->region_size == 32U * kKiB && move_create->result_base == kN &&
              move_create->mapping_size == 64U * kKiB,
          "phase 12 the move is a release-free plus create pair");
    // The FIXED move: free half for the N generation, eviction for the P generation, then
    // the create at P.
    const auto* fixed_free = vm_free_at(readback, 6U);
    const auto* fixed_evict = vm_free_at(readback, 7U);
    const auto* fixed_create = std::get_if<noleax::trace::VmAllocateEvent>(&events[8].payload);
    check(fixed_free != nullptr && fixed_evict != nullptr && fixed_create != nullptr &&
              move_create != nullptr && fixed_free->mapping_id == move_create->mapping_id &&
              fixed_free->base == kN && fixed_evict->base == kP &&
              fixed_evict->region_size == 64U * kKiB && fixed_create->result_base == kP &&
              fixed_evict->mapping_id != fixed_create->mapping_id,
          "phase 12 the FIXED move evicts the destination generation first");
    // The shrink of Q evicts the neighbour in Q's hole and releases Q's own far fragment,
    // then the resize record adjusts the size.
    const auto* neighbour_evict = vm_free_at(readback, 12U);
    const auto* own_far_piece = vm_free_at(readback, 13U);
    const auto* q_resize = std::get_if<noleax::trace::VmAllocateEvent>(&events[14].payload);
    const auto* create_q = std::get_if<noleax::trace::VmAllocateEvent>(&events[9].payload);
    check(neighbour_evict != nullptr && own_far_piece != nullptr && q_resize != nullptr &&
              create_q != nullptr && neighbour_evict->base == kQ + 64U * kKiB &&
              neighbour_evict->region_size == 32U * kKiB &&
              neighbour_evict->mapping_id != create_q->mapping_id &&
              own_far_piece->mapping_id == create_q->mapping_id &&
              own_far_piece->base == kQ + 96U * kKiB && own_far_piece->region_size == 32U * kKiB &&
              q_resize->mapping_id == create_q->mapping_id && q_resize->mapping_size == 32U * kKiB,
          "phase 12 the shrink evicts the neighbour and keeps the mapping id");
    // Section partial free: a VmFree piece (not an Unmap), then the remainder's Unmap.
    const auto* view_partial = vm_free_at(readback, 16U);
    const auto* view_end = std::get_if<noleax::trace::UnmapEvent>(&events[17].payload);
    const auto* view_create = std::get_if<noleax::trace::MapEvent>(&events[15].payload);
    check(view_partial != nullptr && view_end != nullptr && view_create != nullptr &&
              view_partial->mapping_id == view_create->mapping_id && view_partial->base == kS &&
              view_partial->region_size == 64U * kKiB &&
              view_end->mapping_id == view_create->mapping_id && view_end->base == kS,
          "phase 12 the view partial free is a VmFree piece and the remainder an Unmap");
  }
  remove_vm_script_trace(run);
  return true;
}

// Phase 13 (H4, P0-1): agent-owned memory attribution. The queue lives in its dedicated
// mapping (production path), the two startup baselines bracket its creation, and a storm
// of unique-stack live allocations grows the agent bookkeeping while the application
// does nothing — the decoded agent/application split must show exactly that.
bool phase13(const std::filesystem::path& keep_dir) {
  std::printf("phase 13: agent memory attribution (H4)\n");
  const std::filesystem::path path = probe_path("p13");
  const std::uint64_t origin = monotonic_now_ns();
  const std::uint64_t thread_id = this_thread_id();
  constexpr std::uint64_t kAllocBase = 0x6000'0000'0000ULL;
  constexpr std::uint64_t kEventCount = 8'192U;

  LinuxTraceWriterResult result;
  noleax::trace::BufferConfiguration buffer_configuration;
  std::uint64_t rss_pre = 0U;
  std::uint64_t rss_post = 0U;
  {
    noleax::agent::linux::AgentMemoryRegistry& registry =
        noleax::agent::linux::AgentMemoryRegistry::instance();
    // Baseline 1/2 in production order (agent_runtime start): before any capture
    // component exists.
    noleax::agent::linux::LinuxTraceWriterBaseline baseline_pre;
    baseline_pre.monotonic_ticks = monotonic_now_ns();
    baseline_pre.has_counters =
        noleax::agent::linux::capture_memory_counters(baseline_pre.counters);
    registry.snapshot(baseline_pre.categories);
    rss_pre = baseline_pre.counters.working_set_bytes;

    auto queue = noleax::agent::linux::make_linux_heap_event_queue(16'384U);
    LinuxModuleTracker tracker{origin};
    LinuxTraceWriterOptions options = launch_options(origin);
    options.memory_counters_interval = std::chrono::milliseconds{1};
    options.memory_map_interval = std::chrono::milliseconds{0};
    LinuxTraceWriter writer{*queue, tracker, path, options};

    buffer_configuration =
        noleax::agent::linux::plan_event_queue(16U * 1024U * 1024U).configuration;
    // The runtime-side estimate categories, mimicking agent_runtime start().
    registry.set_estimate(noleax::trace::AgentMemoryCategory::kHookBackend,
                          noleax::agent::linux::kHookBackendBaseEstimateBytes,
                          noleax::agent::linux::kHookBackendBaseEstimateBytes);
    registry.set_estimate(noleax::trace::AgentMemoryCategory::kAgentHeap,
                          noleax::agent::linux::kAgentHeapReservedEstimateBytes,
                          noleax::agent::linux::kAgentHeapResidentEstimateBytes);
    noleax::agent::linux::LinuxTraceWriterBaseline baseline_post;
    baseline_post.monotonic_ticks = monotonic_now_ns();
    baseline_post.has_counters =
        noleax::agent::linux::capture_memory_counters(baseline_post.counters);
    registry.snapshot(baseline_post.categories);
    rss_post = baseline_post.counters.working_set_bytes;
    for (const noleax::trace::AgentMemoryCategorySample& category : baseline_post.categories) {
      if (category.category == noleax::trace::AgentMemoryCategory::kEventQueue) {
        buffer_configuration.resident_after_init_bytes = category.resident_bytes;
      }
    }
    writer.note_startup_memory(buffer_configuration, baseline_pre, baseline_post);
    writer.begin_capture();

    // Unique stacks (innermost frame nudged per event) plus never-freed allocations:
    // every event grows the writer's live bookkeeping and half of the queue ring.
    const std::uint64_t base = monotonic_now_ns();
    for (std::uint64_t index = 0U; index < kEventCount; ++index) {
      EventSpec spec{noleax::agent::linux::kMallocApiId,
                     LinuxHeapEventOperation::kAllocate,
                     LinuxHeapEventStatus::kSuccess,
                     0x40U,
                     0U,
                     0U,
                     0U,
                     kAllocBase + index * 0x40U,
                     0U};
      LinuxHeapEvent event = make_event(spec, base + 1'000U + index, thread_id);
      if (event.stack.frame_count != 0U) {
        event.stack.frames[0] += index * 16U;
      }
      if (!push_event(*queue, event)) {
        std::printf("FAIL: phase 13 push %llu\n", static_cast<unsigned long long>(index));
        return false;
      }
      if (index % 2'048U == 0U) {
        std::this_thread::sleep_for(std::chrono::milliseconds{4});
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
    result = writer.finish();
  }

  check(result.status == LinuxTraceWriterStatus::kComplete, "phase 13 status is complete");
  check_common_result(result, path);
  check(result.completeness_mask == 0U, "phase 13 completeness mask is zero");
  check(result.memory_agent_records >= 4U,
        "phase 13 wrote the two baselines plus periodic agent records");

  const Readback readback = read_trace(path);
  check_common_readback(readback, origin);
  check(readback.stream.buffer_configuration.has_value(),
        "phase 13 trace carries the buffer configuration");
  if (readback.stream.buffer_configuration.has_value()) {
    const noleax::trace::BufferConfiguration& decoded = *readback.stream.buffer_configuration;
    check(decoded == buffer_configuration,
          "phase 13 buffer configuration record round-trips exactly");
    check((decoded.flags & noleax::trace::kBufferConfigurationFlagAdjusted) != 0U &&
              decoded.requested_bytes == 16U * 1024U * 1024U &&
              decoded.effective_slots == 16'384U && decoded.event_size == 648U &&
              decoded.slot_size == 656U && decoded.reserved_bytes == 16'384ULL * 656U &&
              decoded.resident_after_init_bytes == 0U,
          "phase 13 buffer configuration carries the exact slot math");
  }
  check(readback.stream.memory_agent_count == result.memory_agent_records,
        "phase 13 agent records round-trip");
  check(readback.memory_agents.size() >= 4U, "phase 13 decoded the agent records");
  if (readback.memory_agents.size() >= 2U) {
    const noleax::trace::AgentMemory& pre = readback.memory_agents[0];
    const noleax::trace::AgentMemory& post = readback.memory_agents[1];
    check(pre.kind == noleax::trace::AgentMemorySampleKind::kBaselinePreInit &&
              post.kind == noleax::trace::AgentMemorySampleKind::kBaselinePostInit,
          "phase 13 the first two agent records are the startup baselines");
    check(pre.categories.empty(), "phase 13 the pre-init baseline has no agent memory yet");
    bool saw_exact_queue = false;
    for (const noleax::trace::AgentMemoryCategorySample& category : post.categories) {
      if (category.category == noleax::trace::AgentMemoryCategory::kEventQueue) {
        saw_exact_queue = true;
        check(category.reserved_bytes == 16'384ULL * 656U && category.resident_bytes == 0U &&
                  (category.flags & noleax::trace::kAgentMemoryCategoryFlagExact) != 0U,
              "phase 13 the post-init queue is reserved but not resident");
      }
      if (category.category == noleax::trace::AgentMemoryCategory::kStackDictionary) {
        check(category.reserved_bytes >= 8U * 1024U * 1024U &&
                  (category.flags & noleax::trace::kAgentMemoryCategoryFlagExact) == 0U,
              "phase 13 the stack dictionary is a labeled estimate");
      }
    }
    check(saw_exact_queue, "phase 13 the post-init baseline lists the event queue");
    check(pre.monotonic_ticks <= post.monotonic_ticks, "phase 13 baseline ticks are ordered");
  }

  // Every periodic agent record pairs with a counters record at the same tick.
  std::map<std::uint64_t, std::uint64_t> working_set_at;
  for (const noleax::trace::MemoryCounters& counters : readback.memory_counters) {
    working_set_at[counters.monotonic_ticks] = counters.working_set_bytes;
  }
  std::uint64_t agent_min = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t agent_max = 0U;
  std::uint64_t application_min = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t application_max = 0U;
  bool all_paired = true;
  for (const noleax::trace::AgentMemory& agent : readback.memory_agents) {
    if (agent.kind != noleax::trace::AgentMemorySampleKind::kPeriodic) {
      continue;
    }
    const auto working_set = working_set_at.find(agent.monotonic_ticks);
    all_paired = all_paired && working_set != working_set_at.end();
    std::uint64_t resident = 0U;
    for (const noleax::trace::AgentMemoryCategorySample& category : agent.categories) {
      resident += category.resident_bytes;
    }
    agent_min = (std::min)(agent_min, resident);
    agent_max = (std::max)(agent_max, resident);
    if (working_set != working_set_at.end()) {
      const std::uint64_t application =
          resident >= working_set->second ? 0U : working_set->second - resident;
      application_min = (std::min)(application_min, application);
      application_max = (std::max)(application_max, application);
    }
  }
  check(all_paired, "phase 13 every periodic agent record pairs with process counters");
  // Acceptance 3: the agent bookkeeping grew (live allocation map + touched queue
  // pages) while the application estimate stayed flat.
  check(agent_max >= agent_min + 256U * 1024U, "phase 13 agent-owned memory grows measurably");
  check(application_max <= application_min + 1536U * 1024U,
        "phase 13 the application estimate stays flat (no fake growth)");

  // Acceptance 2: the startup RSS step is explained by the post-init agent-owned total.
  std::uint64_t agent_post_resident = 0U;
  if (readback.memory_agents.size() >= 2U) {
    for (const noleax::trace::AgentMemoryCategorySample& category :
         readback.memory_agents[1].categories) {
      agent_post_resident += category.resident_bytes;
    }
  }
  const std::uint64_t rss_step = rss_post - rss_pre;
  const std::uint64_t tolerance = 2U * 1024U * 1024U + rss_step / 20U;
  check(agent_post_resident + tolerance >= rss_step && rss_post >= rss_pre,
        "phase 13 the startup RSS step is agent-owned (within 5% + 2 MiB)");

  keep_trace(path, keep_dir, "phase13-agent-memory.nlx");
  std::error_code error;
  std::filesystem::remove(path, error);
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  if (!noleax::agent::acquire_hook_guard_runtime()) {
    std::printf("FAIL: hook guard runtime is unavailable\n");
    return 1;
  }
  const std::filesystem::path keep_dir =
      argc > 1 ? std::filesystem::path{argv[1]} : std::filesystem::path{};
  bool ok = true;
  try {
    ok = phase1() && ok;
    ok = phase2() && ok;
    ok = phase3() && ok;
    ok = phase4() && ok;
    ok = phase5(keep_dir) && ok;
    ok = phase6(keep_dir) && ok;
    ok = phase7() && ok;
    ok = phase8() && ok;
    ok = phase9() && ok;
    ok = phase10() && ok;
    ok = phase11() && ok;
    ok = phase12() && ok;
    ok = phase13(keep_dir) && ok;
  } catch (const std::exception& error) {
    std::printf("FAIL: unexpected exception: %s\n", error.what());
    ok = false;
  }
  noleax::agent::release_hook_guard_runtime();
  if (!ok || g_failures != 0U) {
    std::printf("FAIL: %u check(s) failed\n", g_failures + (ok ? 0U : 1U));
    return 1;
  }
  std::printf("OK\n");
  return 0;
}
