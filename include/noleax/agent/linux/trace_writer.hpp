#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/agent/linux/module_tracker.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/custom_hook.hpp"
#include "noleax/trace/identifiers.hpp"
#include "noleax/trace/memory_snapshot.hpp"
#include "noleax/trace/trace_reader.hpp"
#include "noleax/trace/trace_writer.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::agent::linux {

// Producer-side hot-path counters, consulted at finalize when
// LinuxTraceWriterOptions::counter_source is set. dropped_events is the
// producer-attributed queue drop count (the queue's own counter is global; per-API
// attribution lives with the producers).
struct LinuxTraceWriterApiCounterSnapshot {
  noleax::trace::ApiId api_id{0U};
  std::uint64_t recordable_calls{0U};
  std::uint64_t successful_calls{0U};
  std::uint64_t failed_calls{0U};
  std::uint64_t filtered_calls{0U};
  std::uint64_t dropped_events{0U};
};

// H4 (P0-1): one capture-start baseline sample, taken by the runtime before (pre-init)
// or after (post-init) queue/hook/writer creation. Recorded into the trace as the first
// kMemory records so the startup RSS step is attributable.
struct LinuxTraceWriterBaseline {
  std::uint64_t monotonic_ticks{0U};
  bool has_counters{false};
  noleax::trace::MemoryCounters counters{};
  std::vector<noleax::trace::AgentMemoryCategorySample> categories;
};

// Linux counterpart of RtlAllocateHeapTraceWriterOptions (docs/LINUX_PORT_PLAN.md M3/M4),
// covering the glibc heap and virtual memory (mmap/munmap/mremap) event families plus the
// periodic memory samplers and the M7 custom hook points; the glibc heap has no
// heap-lifecycle family.
struct LinuxTraceWriterOptions {
  noleax::trace::TraceWriterOptions trace;
  noleax::trace::CompressionCodec compression{noleax::trace::CompressionCodec::kLz4};
  // Launch capture passes {true, false}; the conservative default is attach-shaped.
  noleax::trace::CaptureScope capture_scope{false, true};
  std::chrono::nanoseconds flush_interval{250'000'000};
  // Periodic memory snapshots (M4): sampled on the writer thread from /proc/self and
  // written as kMemory chunks. A zero interval disables that sampler.
  std::chrono::nanoseconds memory_counters_interval{0};
  std::chrono::nanoseconds memory_map_interval{0};
  std::size_t chunk_target_size{64U * 1024U};
  std::size_t stack_dictionary_capacity{16'384U};
  std::uint32_t maximum_record_size{noleax::trace::kDefaultMaximumRecordSize};
  // Session token copied into the file header; zero when the caller has none.
  std::array<std::byte, 16U> session_id{};
  // CLOCK_MONOTONIC nanosecond origin stamped into the file header. The caller must
  // construct the module tracker with the same origin; zero samples the clock at
  // writer construction (valid only when the tracker used a not-later origin).
  std::uint64_t monotonic_origin{0U};
  // CLOCK_REALTIME nanosecond origin; zero samples the clock at writer construction.
  std::int64_t utc_origin_ns{0};
  // Authoritative producer counters per API, consulted once at finalize. Events the
  // producer filters out before the queue (capture.min_size) never reach the writer,
  // so an honest filtered_before_queue and the observed side of the reconciliation
  // come from this snapshot. Unset: statistics derive from drained events only.
  std::function<std::vector<LinuxTraceWriterApiCounterSnapshot>()> counter_source;
  // Declared custom hook points (M7), in declaration order: point i owns api_id
  // noleax::trace::kCustomHookApiIdBase + i. The writer emits one CustomHookDefinition
  // record per point in the metadata chunk and drains the points' queued events;
  // install failures are reported separately through note_custom_hook_failures().
  std::vector<noleax::ipc::CustomHookSpec> custom_hooks;
};

enum class LinuxTraceWriterStatus : std::uint8_t {
  kComplete,
  kFileLimit,
  kWriterError,
};

struct LinuxTraceWriterApiResult {
  noleax::trace::ApiId api_id{0U};
  std::uint64_t observed_calls{0U};
  std::uint64_t written_events{0U};
  std::uint64_t filtered_before_queue{0U};
  // Writer-side (trace-full) drops only. The event queue's drop counter is global, so
  // queue-full loss cannot be attributed per API; it is reported through the finalize
  // Loss record, the completeness mask, and LinuxTraceWriterResult::queue_dropped_events.
  std::uint64_t dropped_events{0U};
};

struct LinuxTraceWriterResult {
  LinuxTraceWriterStatus status{LinuxTraceWriterStatus::kWriterError};
  noleax::trace::CaptureStatistics statistics;
  std::vector<LinuxTraceWriterApiResult> per_api;
  std::uint64_t stack_capture_failures{0U};
  std::uint64_t queue_dropped_events{0U};
  std::uint64_t trace_dropped_events{0U};
  std::uint64_t timestamp_adjustments{0U};
  std::uint64_t stack_dictionary_segments{0U};
  std::uint64_t module_load_records{0U};
  std::uint64_t module_unload_records{0U};
  std::uint64_t module_notification_drops{0U};
  std::uint64_t bytes_written{0U};
  std::uint32_t completeness_mask{0U};
  // kMemory chunks written by the periodic samplers and the records they carried.
  std::uint64_t memory_chunks{0U};
  std::uint64_t memory_counters_records{0U};
  std::uint64_t memory_map_records{0U};
  // H4 (P0-1): AgentMemory records written (baselines + periodic).
  std::uint64_t memory_agent_records{0U};
  bool statistics_written{false};
  bool end_of_trace_written{false};
  std::string error_message;
  // Structured context of the first writer failure (error_message): the phase the writer
  // was in, the errno where the stream provided one (0 = none), the byte offset in the
  // output file, and the chunk type being written. kNone/empty mark failures without
  // that context (internal validation, option errors).
  noleax::trace::TraceWritePhase error_phase{noleax::trace::TraceWritePhase::kNone};
  std::uint32_t error_system_error{0U};
  std::optional<std::uint64_t> error_file_offset;
  std::optional<noleax::trace::ChunkType> error_chunk_type;
  // The best-effort error tail (Loss + Statistics + EndOfTrace) can itself fail — the
  // disk stays full, the stream stays broken. That failure lands here and never
  // overwrites error_message, so a doubly-failed finish reports both.
  std::string tail_error_message;
  // Atomic output protocol: the writer streams into partial_path from the start and
  // renames it to the requested path only after a successful EndOfTrace + flush + close.
  // final_path stays empty on any failure; the .partial file then holds everything up to
  // the failure point and remains analyzable (docs/TRACE_RECOVERY.md).
  std::filesystem::path partial_path;
  std::filesystem::path final_path;
};

// Live writer telemetry for CaptureStatus (QueryStatus while the capture runs). Both
// values are zero before the first chunk write / stream flush.
struct LinuxTraceWriterLiveStatus {
  std::uint64_t bytes_written{0U};
  // CLOCK_MONOTONIC nanoseconds of the last successful stream flush; 0 = never flushed.
  std::uint64_t last_flush_monotonic_ns{0U};
  // H4 (P0-1): agent-owned totals and the event-queue resident bytes at the last memory
  // snapshot; zero before the first one.
  std::uint64_t agent_reserved_bytes{0U};
  std::uint64_t agent_resident_bytes{0U};
  std::uint64_t event_queue_resident_bytes{0U};
};

namespace detail {

// Test-only fault injection for the writer failure paths (docs/HARDENING_PLAN.md H2).
// Inert by default: a zero point mask never fails. Arm before constructing the writer
// under test and disarm right after finish; the state is process-global, so tests must
// not arm it concurrently.
inline constexpr std::uint32_t kWriterFaultOpen = 1U << 0U;
inline constexpr std::uint32_t kWriterFaultWrite = 1U << 1U;
inline constexpr std::uint32_t kWriterFaultFlush = 1U << 2U;
inline constexpr std::uint32_t kWriterFaultClose = 1U << 3U;

struct WriterFault {
  std::uint32_t points{0U};
  // Armed operations to let through before the first injected failure (0 = fail the
  // first one).
  std::uint64_t operations_until_failure{0U};
  // Once triggered, keep failing every armed operation (a full disk does not recover).
  bool sticky{false};
  // errno the injected failure reports; 0 maps to EIO.
  std::uint32_t error_number{0U};
};

void arm_writer_fault(const WriterFault& fault) noexcept;
void disarm_writer_fault() noexcept;

}  // namespace detail

// Drains the shared glibc heap + virtual memory event queue and the poll-based module
// tracker on an internal worker thread and writes a bounded .nlx trace through the
// platform-neutral noleax::trace library. Construction requires an initialized hook guard
// runtime and a not-yet-recording producer side, exactly like the Windows writer; the
// caller stops the hooks (logical stop plus in-flight barrier) before
// finish()/finish_after_worker_exit().
class LinuxTraceWriter final {
 public:
  LinuxTraceWriter(LinuxHeapEventQueue& event_queue, LinuxModuleTracker& module_tracker,
                   const std::filesystem::path& output_path, LinuxTraceWriterOptions options = {});
  ~LinuxTraceWriter();

  LinuxTraceWriter(const LinuxTraceWriter&) = delete;
  LinuxTraceWriter& operator=(const LinuxTraceWriter&) = delete;
  LinuxTraceWriter(LinuxTraceWriter&&) = delete;
  LinuxTraceWriter& operator=(LinuxTraceWriter&&) = delete;

  void begin_capture();
  // Records custom hook points that failed to install. The failures land in the metadata
  // chunk (next to the CustomHookDefinition records) and mark the trace completeness issue;
  // the capture itself continues with the hooks that did install. Call after hook
  // installation, before begin_capture().
  void note_custom_hook_failures(std::vector<noleax::trace::CustomHookFailure> failures);
  // H4 (P0-1): records the buffer conversion math (metadata chunk) and the two startup
  // baselines (first kMemory records). Call after hook installation — the post-init
  // baseline must already include this writer's own estimates — before begin_capture().
  void note_startup_memory(noleax::trace::BufferConfiguration configuration,
                           LinuxTraceWriterBaseline baseline_pre_init,
                           LinuxTraceWriterBaseline baseline_post_init);
  [[nodiscard]] LinuxTraceWriterResult finish();
  // Finalizes the trace on the calling thread when the worker can no longer run
  // (process teardown). Runs the final drain inline without joining or waking the
  // worker and without touching locks the dead worker may have held.
  [[nodiscard]] LinuxTraceWriterResult finish_after_worker_exit();
  [[nodiscard]] bool is_running() const noexcept;
  // Atomic snapshot of the live writer telemetry; safe to call from the session thread
  // while the writer thread runs.
  [[nodiscard]] LinuxTraceWriterLiveStatus live_status() const noexcept;

 private:
  class Implementation;
  std::unique_ptr<Implementation> implementation_;
};

}  // namespace noleax::agent::linux
