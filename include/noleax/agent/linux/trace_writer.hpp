#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/agent/linux/module_tracker.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/identifiers.hpp"
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

// Linux counterpart of RtlAllocateHeapTraceWriterOptions (docs/LINUX_PORT_PLAN.md M3/M4),
// covering the glibc heap and virtual memory (mmap/munmap/mremap) event families plus the
// periodic memory samplers; custom-hook knobs arrive with M7 and the glibc heap has no
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
  bool statistics_written{false};
  bool end_of_trace_written{false};
  std::string error_message;
};

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
  [[nodiscard]] LinuxTraceWriterResult finish();
  // Finalizes the trace on the calling thread when the worker can no longer run
  // (process teardown). Runs the final drain inline without joining or waking the
  // worker and without touching locks the dead worker may have held.
  [[nodiscard]] LinuxTraceWriterResult finish_after_worker_exit();
  [[nodiscard]] bool is_running() const noexcept;

 private:
  class Implementation;
  std::unique_ptr<Implementation> implementation_;
};

}  // namespace noleax::agent::linux
