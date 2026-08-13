// Linux in-process trace writer (docs/LINUX_PORT_PLAN.md M3/M4/M7): drains the shared glibc
// heap + virtual memory event queue plus the poll-based module tracker on an internal
// worker thread and writes a bounded .nlx trace through the platform-neutral noleax::trace
// library. Mirrors the Windows RtlAllocateHeapTraceWriter architecture and invariants,
// scoped to the two built-in event families, the /proc memory samplers, and the custom
// hook points declared in LinuxTraceWriterOptions::custom_hooks (M7; the glibc heap has no
// heap-lifecycle family). heap_handle is always 0 and heap_id stays invalid in allocation
// records (the wire model only requires heap_id for HeapCreate).

#include "noleax/agent/linux/trace_writer.hpp"

#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/linux/hook_registry.hpp"
#include "noleax/agent/linux/memory_snapshot.hpp"
#include "noleax/agent/linux/stack_capture.hpp"
#include "noleax/agent/windows/stack_dictionary.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/custom_hook.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/record_codec.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/trace_writer.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::agent::linux {

namespace detail {
namespace {

std::atomic<std::uint32_t> g_writer_fault_points{0U};
std::atomic<std::uint64_t> g_writer_fault_countdown{0U};
std::atomic<std::uint32_t> g_writer_fault_fired{0U};
std::atomic<bool> g_writer_fault_sticky{false};
std::atomic<std::uint32_t> g_writer_fault_errno_value{0U};

}  // namespace

void arm_writer_fault(const WriterFault& fault) noexcept {
  g_writer_fault_errno_value.store(fault.error_number, std::memory_order_relaxed);
  g_writer_fault_sticky.store(fault.sticky, std::memory_order_relaxed);
  g_writer_fault_fired.store(0U, std::memory_order_relaxed);
  g_writer_fault_countdown.store(fault.operations_until_failure, std::memory_order_relaxed);
  g_writer_fault_points.store(fault.points, std::memory_order_release);
}

void disarm_writer_fault() noexcept { g_writer_fault_points.store(0U, std::memory_order_release); }

// Returns the errno the armed fault reports for point, or 0 to let the operation through.
// The countdown is shared by every armed point: N means "let N armed operations pass".
[[nodiscard]] std::uint32_t writer_fault_errno(std::uint32_t point) noexcept {
  if ((g_writer_fault_points.load(std::memory_order_acquire) & point) == 0U) {
    return 0U;
  }
  const std::uint32_t configured = g_writer_fault_errno_value.load(std::memory_order_relaxed);
  const std::uint32_t error_number =
      configured != 0U ? configured : static_cast<std::uint32_t>(EIO);
  if ((g_writer_fault_fired.load(std::memory_order_relaxed) & point) != 0U) {
    return g_writer_fault_sticky.load(std::memory_order_relaxed) ? error_number : 0U;
  }
  std::uint64_t remaining = g_writer_fault_countdown.load(std::memory_order_relaxed);
  while (remaining != 0U) {
    if (g_writer_fault_countdown.compare_exchange_weak(
            remaining, remaining - 1U, std::memory_order_relaxed, std::memory_order_relaxed)) {
      return 0U;
    }
  }
  g_writer_fault_fired.fetch_or(point, std::memory_order_relaxed);
  return error_number;
}

}  // namespace detail

namespace {

// The normalized stack dictionary is platform-neutral code that still lives under
// agent/windows; hoisting it to the shared agent namespace waits for Windows CI
// validation, so the Linux writer uses it in place. Do not move the file.
using noleax::agent::windows::hash_normalized_stack;
using noleax::agent::windows::NormalizedStack;
using noleax::agent::windows::NormalizedStackDictionary;
using noleax::agent::windows::RawStackInternResult;

constexpr std::size_t kMaximumStackDefinitionRecordSize =
    noleax::trace::kRecordHeaderSize + 16U +
    static_cast<std::size_t>(kMaximumCapturedStackDepth) * 32U;
constexpr std::size_t kMaximumModuleLoadRecordSize = 8U * 1024U;
constexpr std::size_t kMaximumEventAdditionSize = 152U + 56U;
// Terminal record sizes (src/trace/record_codec.cpp): a Loss record is the 8-byte record
// header plus a fixed 48-byte payload; CaptureStatistics adds an 80-byte fixed payload
// plus 48 bytes per API; EndOfTrace carries a 40-byte payload. Every append validates
// against the configured maximum_record_size, which these fixed sizes never approach.
constexpr std::uint64_t kLossRecordSize = noleax::trace::kRecordHeaderSize + 48U;
constexpr std::uint64_t kStatisticsRecordSize =
    noleax::trace::kRecordHeaderSize + 80U + kLinuxHookRegistry.size() * 48U;
constexpr std::uint64_t kEndOfTraceRecordSize = noleax::trace::kRecordHeaderSize + 40U;
// Sized-on-purpose file reserve for the terminal records (the spec for
// TraceWriterOptions::reserved_tail_size): the orderly finalize writes up to three Loss
// records (module drops, queue overflow, trace-full), the writer-error tail writes a
// fourth (the writer error itself); both then write one Statistics and one EndOfTrace
// record, each family in its own chunk.
constexpr std::uint64_t kTerminalReserveBaseSize =
    (noleax::trace::kChunkHeaderSize + 4U * kLossRecordSize) +
    (noleax::trace::kChunkHeaderSize + kStatisticsRecordSize) +
    (noleax::trace::kChunkHeaderSize + kEndOfTraceRecordSize);
// Each declared custom hook point adds one more 48-byte per-API statistics record;
// validate_options extends the reserve by exactly that amount.
constexpr std::uint64_t kTerminalReservePerCustomHook = 48U;
constexpr auto kEmptyPollInterval = std::chrono::milliseconds{1};

[[nodiscard]] LinuxHeapEventQueue& validate_event_queue(LinuxHeapEventQueue& event_queue) {
  if (!hook_guard_runtime_is_ready()) {
    throw std::invalid_argument{"trace writer requires an initialized hook guard runtime"};
  }
  return event_queue;
}

[[nodiscard]] std::uint64_t monotonic_now_ns() noexcept {
  timespec value{};
  clock_gettime(CLOCK_MONOTONIC, &value);
  return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
         static_cast<std::uint64_t>(value.tv_nsec);
}

[[nodiscard]] std::int64_t utc_now_ns() noexcept {
  timespec value{};
  clock_gettime(CLOCK_REALTIME, &value);
  return static_cast<std::int64_t>(value.tv_sec) * 1'000'000'000LL +
         static_cast<std::int64_t>(value.tv_nsec);
}

[[nodiscard]] std::filesystem::path partial_output_path(const std::filesystem::path& final_path) {
  std::filesystem::path partial = final_path;
  partial += ".partial";
  return partial;
}

[[nodiscard]] std::ofstream open_trace_output(const std::filesystem::path& path) {
  if (const std::uint32_t injected = detail::writer_fault_errno(detail::kWriterFaultOpen)) {
    throw noleax::trace::TraceWriteError{"cannot create the trace output file",
                                         noleax::trace::TraceWritePhase::kOpen, injected};
  }
  errno = 0;
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  if (!output) {
    throw noleax::trace::TraceWriteError{"cannot create the trace output file",
                                         noleax::trace::TraceWritePhase::kOpen,
                                         static_cast<std::uint32_t>(errno)};
  }
  return output;
}

[[nodiscard]] noleax::trace::FileHeader make_file_header(const LinuxTraceWriterOptions& options,
                                                         std::uint64_t monotonic_origin) noexcept {
  noleax::trace::FileHeader header;
  header.pointer_width = static_cast<std::uint8_t>(sizeof(void*));
  header.platform = noleax::trace::Platform::kLinux;
  header.architecture = noleax::trace::Architecture::kX64;
  header.session_id = options.session_id;
  // The event queue and the module tracker both stamp CLOCK_MONOTONIC nanoseconds.
  header.monotonic_frequency = 1'000'000'000ULL;
  header.monotonic_origin = monotonic_origin;
  header.utc_origin_ns = options.utc_origin_ns != 0 ? options.utc_origin_ns : utc_now_ns();
  return header;
}

[[nodiscard]] bool known_codec(noleax::trace::CompressionCodec codec) noexcept {
  switch (codec) {
    case noleax::trace::CompressionCodec::kNone:
    case noleax::trace::CompressionCodec::kLz4:
    case noleax::trace::CompressionCodec::kZstd:
      return true;
  }
  return false;
}

[[nodiscard]] LinuxTraceWriterOptions validate_options(LinuxTraceWriterOptions options) {
  noleax::trace::validate_capture_scope(options.capture_scope);
  if (!known_codec(options.compression)) {
    throw std::invalid_argument{"trace writer compression codec is not supported"};
  }
  if (options.flush_interval <= std::chrono::nanoseconds::zero()) {
    throw std::invalid_argument{"trace writer flush interval must be positive"};
  }
  if (options.memory_counters_interval < std::chrono::nanoseconds::zero() ||
      options.memory_map_interval < std::chrono::nanoseconds::zero()) {
    throw std::invalid_argument{"trace writer memory snapshot intervals must not be negative"};
  }
  if (options.custom_hooks.size() > noleax::ipc::kMaximumCustomHooks) {
    throw std::invalid_argument{"trace writer declares too many custom hook points"};
  }
  if (options.chunk_target_size == 0U ||
      options.chunk_target_size > options.trace.max_uncompressed_chunk_size) {
    throw std::invalid_argument{"trace writer chunk target is out of range"};
  }
  if (options.stack_dictionary_capacity == 0U) {
    throw std::invalid_argument{"trace writer stack dictionary must not be empty"};
  }
  if (options.maximum_record_size < kMaximumStackDefinitionRecordSize ||
      options.maximum_record_size < kMaximumModuleLoadRecordSize ||
      options.trace.max_uncompressed_chunk_size < kMaximumStackDefinitionRecordSize ||
      options.trace.max_uncompressed_chunk_size < kMaximumModuleLoadRecordSize ||
      options.trace.max_uncompressed_chunk_size < kMaximumEventAdditionSize) {
    throw std::invalid_argument{"trace writer limits cannot hold the largest raw stack event"};
  }
  // Worst-case stored size of a full uncompressed chunk must fit, or an incompressible
  // chunk would kill the capture with a writer error mid-run (LZ4: n + n/255 + 16; the
  // +64 margin also covers zstd's small-chunk bound).
  const std::uint64_t worst_stored = options.trace.max_uncompressed_chunk_size +
                                     options.trace.max_uncompressed_chunk_size / 255U + 64U;
  if (options.trace.max_stored_chunk_size < worst_stored) {
    throw std::invalid_argument{
        "trace writer stored chunk size cannot hold the largest compressed chunk"};
  }
  options.trace.reserved_tail_size = (std::max)(
      options.trace.reserved_tail_size,
      kTerminalReserveBaseSize + options.custom_hooks.size() * kTerminalReservePerCustomHook);
  return options;
}

// The writer derives the CustomHookDefinition records from the declared specs: point i owns
// api_id kCustomHookApiIdBase + i, exactly like the Windows CustomSymbolHooks constructor.
[[nodiscard]] std::vector<noleax::trace::CustomHookDefinition> make_custom_hook_definitions(
    const std::vector<noleax::ipc::CustomHookSpec>& specs) {
  std::vector<noleax::trace::CustomHookDefinition> definitions;
  definitions.reserve(specs.size());
  for (std::size_t index = 0U; index < specs.size(); ++index) {
    noleax::trace::CustomHookDefinition definition;
    definition.api_id =
        noleax::trace::kCustomHookApiIdBase + static_cast<noleax::trace::ApiId>(index);
    definition.module_name = specs[index].module;
    definition.label = specs[index].label;
    noleax::trace::validate_custom_hook_definition(definition);
    definitions.push_back(std::move(definition));
  }
  return definitions;
}

void checked_add(std::uint64_t& value, std::uint64_t addition, const char* subject) {
  if (addition > std::numeric_limits<std::uint64_t>::max() - value) {
    throw std::overflow_error{subject};
  }
  value += addition;
}

[[nodiscard]] noleax::trace::StackCaptureStatus trace_stack_status(StackCaptureStatus status) {
  switch (status) {
    case StackCaptureStatus::kCaptured:
      return noleax::trace::StackCaptureStatus::kComplete;
    case StackCaptureStatus::kTruncated:
      return noleax::trace::StackCaptureStatus::kTruncatedByDepth;
    case StackCaptureStatus::kFailed:
      return noleax::trace::StackCaptureStatus::kUnwindFailed;
    case StackCaptureStatus::kDisabled:
      return noleax::trace::StackCaptureStatus::kUnavailable;
  }
  throw std::invalid_argument{"captured stack status is not supported"};
}

[[nodiscard]] LinuxHeapEventOperation expected_operation(LinuxLogicalHookApi api) {
  switch (api) {
    case LinuxLogicalHookApi::kMalloc:
    case LinuxLogicalHookApi::kCalloc:
    case LinuxLogicalHookApi::kPosixMemalign:
    case LinuxLogicalHookApi::kAlignedAlloc:
    case LinuxLogicalHookApi::kMemalign:
      return LinuxHeapEventOperation::kAllocate;
    case LinuxLogicalHookApi::kRealloc:
    case LinuxLogicalHookApi::kReallocarray:
      return LinuxHeapEventOperation::kReallocate;
    case LinuxLogicalHookApi::kFree:
      return LinuxHeapEventOperation::kFree;
    case LinuxLogicalHookApi::kMmap:
      return LinuxHeapEventOperation::kVmAllocate;
    case LinuxLogicalHookApi::kMunmap:
      return LinuxHeapEventOperation::kVmUnmap;
    case LinuxLogicalHookApi::kMremap:
      return LinuxHeapEventOperation::kVmRemap;
  }
  throw std::invalid_argument{"Linux hook API is not supported"};
}

[[nodiscard]] bool has_raw_module_flag(const RawModuleEvent& event,
                                       RawModuleEventFlag flag) noexcept {
  return (event.flags & static_cast<std::uint32_t>(flag)) != 0U;
}

[[nodiscard]] std::string unknown_module_path(std::uint64_t base_address) {
  std::string result{"<unknown-module-0x"};
  char digits[16]{};
  const auto conversion = std::to_chars(std::begin(digits), std::end(digits), base_address, 16);
  if (conversion.ec != std::errc{}) {
    throw std::runtime_error{"cannot format an unknown module address"};
  }
  result.append(digits, conversion.ptr);
  result.push_back('>');
  return result;
}

[[nodiscard]] const char* chunk_type_name(noleax::trace::ChunkType type) noexcept {
  switch (type) {
    case noleax::trace::ChunkType::kMetadata:
      return "metadata";
    case noleax::trace::ChunkType::kModule:
      return "module";
    case noleax::trace::ChunkType::kStack:
      return "stack";
    case noleax::trace::ChunkType::kEvent:
      return "event";
    case noleax::trace::ChunkType::kStatistics:
      return "statistics";
    case noleax::trace::ChunkType::kEnd:
      return "end";
    case noleax::trace::ChunkType::kMemory:
      return "memory";
  }
  return "unknown";
}

struct LiveModule {
  noleax::trace::ModuleId module_id;
  std::uint64_t base{0U};
  std::uint64_t size{0U};
};

// A live mapping generation: anonymous mappings live in live_vm_mappings_ (wire
// VmAllocate/VmFree), file-backed ones in live_section_mappings_ (wire Map/Unmap), keyed
// by base address exactly like the Windows writer's two maps.
struct LiveMapping {
  noleax::trace::MappingId mapping_id;
  std::uint64_t base{0U};
  std::uint64_t size{0U};
};

// munmap always releases its range, so the wire VmFreeEvent carries the same release bit
// the Windows MEM_RELEASE uses (0x8000): the analyzer's generation tracker keys a full
// mapping release on exactly this bit.
constexpr std::uint32_t kVmFreeTypeRelease = 0x00008000U;

// The in-process hooks only ever observe the current process, so every Linux VM event
// targets it (there is no handle concept for self; the pid identifies the process).
[[nodiscard]] noleax::trace::ProcessTarget current_process_target() noexcept {
  noleax::trace::ProcessTarget target;
  target.scope = noleax::trace::ProcessMemoryScope::kCurrentProcess;
  target.process_id = static_cast<std::uint64_t>(::getpid());
  return target;
}

}  // namespace

class LinuxTraceWriter::Implementation final {
 public:
  Implementation(LinuxHeapEventQueue& event_queue, LinuxModuleTracker& module_tracker,
                 const std::filesystem::path& output_path, LinuxTraceWriterOptions options)
      : event_queue_{validate_event_queue(event_queue)},
        module_tracker_{module_tracker},
        options_{validate_options(options)},
        custom_definitions_{make_custom_hook_definitions(options_.custom_hooks)},
        final_path_{output_path},
        partial_path_{partial_output_path(output_path)},
        output_{open_trace_output(partial_path_)},
        monotonic_origin_{options_.monotonic_origin != 0U ? options_.monotonic_origin
                                                          : monotonic_now_ns()},
        dictionary_{options_.stack_dictionary_capacity},
        writer_{output_, make_file_header(options_, monotonic_origin_), options_.trace},
        completeness_{options_.capture_scope},
        api_counters_{kLinuxHookRegistry.size() + custom_definitions_.size()} {
    module_payload_.reserve(options_.chunk_target_size);
    stack_payload_.reserve(options_.chunk_target_size);
    event_payload_.reserve(options_.chunk_target_size);
    status_bytes_written_.store(writer_.bytes_written(), std::memory_order_relaxed);
    worker_ = std::thread{[this] { thread_main(); }};
    std::unique_lock lock{state_mutex_};
    state_changed_.wait(lock, [this] { return thread_ready_; });
  }

  ~Implementation() {
    request_stop();
    if (worker_.joinable()) {
      worker_.join();
    }
    // Destruction without finish() still honors the atomic output protocol: promote a
    // cleanly finalized trace, keep a failed one as .partial.
    commit_output();
  }

  void begin_capture() {
    std::scoped_lock lock{state_mutex_};
    if (capture_begun_) {
      throw std::logic_error{"trace writer capture has already begun"};
    }
    if (stop_requested_.load(std::memory_order_acquire)) {
      throw std::logic_error{"trace writer is already stopping"};
    }
    write_metadata();
    // Durability floor: header + scope must reach the disk before the capture starts, so
    // a .partial left by a kill is always a decodable trace.
    flush_stream();
    capture_begun_ = true;
    state_changed_.notify_all();
  }

  // Records custom hook points that failed to install. The failures land in the metadata
  // chunk (next to the CustomHookDefinition records) and mark the trace completeness issue;
  // the capture itself continues with the hooks that did install. Call after hook
  // installation, before begin_capture().
  void note_custom_hook_failures(std::vector<noleax::trace::CustomHookFailure> failures) {
    std::scoped_lock lock{state_mutex_};
    if (capture_begun_) {
      throw std::logic_error{"custom hook failures must be noted before capture begins"};
    }
    if (failures.empty()) {
      return;
    }
    for (const auto& failure : failures) {
      noleax::trace::validate_custom_hook_failure(failure);
    }
    completeness_.mark_custom_hook_install_failed();
    custom_hook_failures_ = std::move(failures);
  }

  void request_stop() noexcept {
    stop_requested_.store(true, std::memory_order_release);
    state_changed_.notify_all();
  }

  [[nodiscard]] LinuxTraceWriterResult finish() {
    request_stop();
    if (worker_.joinable()) {
      worker_.join();
    }
    commit_output();
    finalized_ = true;
    return result_;
  }

  // Inline finalization for process teardown: the worker can no longer run, so the
  // final drain boundary of capture_loop() runs on this thread. state_mutex_ is never
  // touched here because the worker may have died while holding it.
  [[nodiscard]] LinuxTraceWriterResult finish_after_worker_exit() {
    if (finalized_ || inline_finalize_done_) {
      return result_;
    }
    inline_finalize_done_ = true;
    try {
      if (capture_begun_) {
        finalize_capture_inline();
      } else {
        finalize_empty_trace();
      }
    } catch (const noleax::trace::TraceWriteError& error) {
      record_writer_error(error);
    } catch (const std::exception& error) {
      record_writer_error(error.what());
    } catch (...) {
      record_writer_error("unknown trace writer failure");
    }
    commit_output();
    return result_;
  }

  [[nodiscard]] bool is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
  }

  [[nodiscard]] LinuxTraceWriterLiveStatus live_status() const noexcept {
    LinuxTraceWriterLiveStatus status;
    status.bytes_written = status_bytes_written_.load(std::memory_order_relaxed);
    status.last_flush_monotonic_ns = last_flush_monotonic_ns_.load(std::memory_order_relaxed);
    return status;
  }

 private:
  // Runs the final drain boundary of capture_loop() on the calling thread. Used when
  // the worker can no longer run (process teardown).
  void finalize_capture_inline() {
    if (!initial_modules_processed_) {
      initial_modules_processed_ = true;
      for (const RawModuleEvent& initial : module_tracker_.initial_modules()) {
        process_module_event(initial);
      }
      collect_module_drops();
    }
    module_tracker_.poll();
    LinuxHeapEvent raw_event;
    while (event_queue_.try_pop(raw_event)) {
      drain_modules_through(raw_event.monotonic_ticks);
      process_event(raw_event);
    }
    drain_modules_through(std::numeric_limits<std::uint64_t>::max());
    collect_queue_drops();
    collect_module_drops();
    flush_pending();
    finalize_trace();
  }

  // First writer failure wins: the enriched error (phase/errno/offset/chunk type plus the
  // human-readable message) lands in the result, one line goes to stderr — the only
  // always-available channel inside a target (game) process — and the best-effort error
  // tail runs once. Later failures never overwrite the first error, and a tail failure is
  // reported separately in tail_error_message. No exception ever escapes: the writer
  // thread shares the process with the target.
  void record_writer_error(const noleax::trace::TraceWriteError& error) noexcept {
    try {
      record_writer_error_impl(std::string{error.what()}, error.phase(), error.system_error(),
                               error.file_offset(), error.chunk_type());
    } catch (...) {
      result_.status = LinuxTraceWriterStatus::kWriterError;
    }
  }

  void record_writer_error(const char* message) noexcept {
    try {
      record_writer_error_impl(std::string{message}, noleax::trace::TraceWritePhase::kNone, 0U,
                               std::nullopt, std::nullopt);
    } catch (...) {
      result_.status = LinuxTraceWriterStatus::kWriterError;
    }
  }

  void record_writer_error_impl(std::string message, noleax::trace::TraceWritePhase phase,
                                std::uint32_t system_error,
                                std::optional<std::uint64_t> file_offset,
                                std::optional<noleax::trace::ChunkType> chunk_type) {
    if (!error_recorded_) {
      error_recorded_ = true;
      result_.status = LinuxTraceWriterStatus::kWriterError;
      result_.error_message = std::move(message);
      result_.error_phase = phase;
      result_.error_system_error = system_error;
      result_.error_file_offset = file_offset;
      result_.error_chunk_type = chunk_type;
      report_writer_error_to_stderr();
    }
    try {
      write_error_tail();
      // One last durability attempt; if this fails the tail records may not have reached
      // the disk either, which is a tail failure.
      flush_stream();
    } catch (const std::exception& tail_error) {
      if (result_.tail_error_message.empty()) {
        result_.tail_error_message = tail_error.what();
      }
    } catch (...) {
      if (result_.tail_error_message.empty()) {
        result_.tail_error_message = "unknown trace tail failure";
      }
    }
    fill_result_counters();
  }

  void report_writer_error_to_stderr() const noexcept {
    try {
      std::string line{"noleax-agent: trace writer failed: "};
      line.append(result_.error_message);
      line.append(" (phase=");
      line.append(noleax::trace::trace_write_phase_name(result_.error_phase));
      if (result_.error_system_error != 0U) {
        line.append(" errno=");
        line.append(std::to_string(result_.error_system_error));
      }
      if (result_.error_file_offset.has_value()) {
        line.append(" offset=");
        line.append(std::to_string(*result_.error_file_offset));
      }
      if (result_.error_chunk_type.has_value()) {
        line.append(" chunk=");
        line.append(chunk_type_name(*result_.error_chunk_type));
      }
      line.push_back(')');
      std::fprintf(stderr, "%s\n", line.c_str());
      std::fflush(stderr);
    } catch (...) {
    }
  }

  // Events the writer consumed but never wrote: the discarded pending buffer plus an
  // event that was mid-processing when the failure hit, excluding the trace-full drops
  // (they carry their own Loss record). Zero means "nothing was in flight".
  [[nodiscard]] std::uint64_t consumed_but_unwritten_events() const {
    std::uint64_t consumed = 0U;
    std::uint64_t written = 0U;
    for (const ApiCounters& counters : api_counters_) {
      checked_add(consumed, counters.successful, "error-tail consumed count overflow");
      checked_add(consumed, counters.failed, "error-tail consumed count overflow");
      checked_add(written, counters.written, "error-tail written count overflow");
    }
    if (consumed < written + trace_dropped_events_) {
      return 0U;  // accounting disagreement: report no estimate rather than a wrong one
    }
    return consumed - written - trace_dropped_events_;
  }

  // Preserve a parseable, explicitly incomplete trace when the writer fails. Buffered
  // payload is deliberately discarded because an exception may have interrupted a record
  // mid-write; the tail Statistics accounts every consumed-but-unwritten event as
  // dropped, so observed = successful + failed and written + filtered + dropped =
  // observed hold exactly like an orderly finalize. Every stage is best-effort: a stage
  // failure is remembered and the remaining stages still run (an EndOfTrace attempt
  // matters even when the statistics could not be computed).
  void write_error_tail() {
    if (error_tail_attempted_ || result_.end_of_trace_written) {
      return;
    }
    error_tail_attempted_ = true;
    writer_.release_file_reserve();
    std::string first_failure;
    const auto note_failure = [&first_failure](const char* what) {
      if (first_failure.empty()) {
        first_failure = what;
      }
    };

    try {
      std::vector<std::byte> loss_payload;
      append_collected_loss_records(loss_payload);
      noleax::trace::LossRecord writer_loss;
      writer_loss.reason = noleax::trace::LossReason::kWriterError;
      writer_loss.location = noleax::trace::LossLocation::kWriter;
      // A known count of zero is not encodable (validate_loss_record), so absence of the
      // estimate means "nothing was in flight".
      if (const std::uint64_t unwritten = consumed_but_unwritten_events()) {
        writer_loss.estimated_event_count = unwritten;
      }
      completeness_.observe_loss(writer_loss);
      noleax::trace::append_loss_record(loss_payload, writer_loss, options_.maximum_record_size);
      static_cast<void>(write_terminal_chunk(noleax::trace::ChunkType::kEvent, loss_payload));
    } catch (const std::exception& error) {
      note_failure(error.what());
    } catch (...) {
      note_failure("unknown writer-error loss failure");
    }

    if (!result_.statistics_written) {
      try {
        const noleax::trace::CaptureStatistics statistics = make_error_statistics();
        noleax::trace::validate_statistics(statistics);
        result_.statistics = statistics;
        result_.per_api.clear();
        for (std::size_t index = 0U; index < statistics.per_api.size(); ++index) {
          const noleax::trace::ApiStatistics& api = statistics.per_api[index];
          result_.per_api.push_back(LinuxTraceWriterApiResult{
              api.api_id, api.observed_calls, api_counters_[index].written,
              api.filtered_before_queue, api.dropped_events});
        }
        std::vector<std::byte> statistics_payload;
        noleax::trace::append_statistics_record(statistics_payload, statistics,
                                                options_.maximum_record_size);
        result_.statistics_written =
            write_terminal_chunk(noleax::trace::ChunkType::kStatistics, statistics_payload);
      } catch (const std::exception& error) {
        note_failure(error.what());
      } catch (...) {
        note_failure("unknown writer-error statistics failure");
      }
    }

    try {
      noleax::trace::EndOfTrace end;
      end.final_sequence = noleax::trace::Sequence{last_wire_sequence_};
      end.final_monotonic_ticks =
          (std::max)((std::max)((std::max)(last_ticks_, last_module_ticks_), last_memory_ticks_),
                     monotonic_origin_);
      end.normal_stop = false;
      end.aggregate_completeness = completeness_.report();
      end.aggregate_completeness.add(noleax::trace::CompletenessIssue::kAbnormalStop);
      end.aggregate_completeness.remove(noleax::trace::CompletenessIssue::kMissingEndOfTrace);
      std::vector<std::byte> end_payload;
      noleax::trace::append_end_of_trace_record(end_payload, end, options_.maximum_record_size);
      result_.end_of_trace_written =
          write_terminal_chunk(noleax::trace::ChunkType::kEnd, end_payload);
      result_.completeness_mask = result_.end_of_trace_written ? end.aggregate_completeness.mask()
                                                               : completeness_.report().mask();
    } catch (const std::exception& error) {
      note_failure(error.what());
      result_.completeness_mask = completeness_.report().mask();
    } catch (...) {
      note_failure("unknown writer-error EndOfTrace failure");
      result_.completeness_mask = completeness_.report().mask();
    }

    if (!first_failure.empty()) {
      throw std::runtime_error{first_failure};
    }
  }

  // Statistics at the failure point. With an authoritative producer snapshot every
  // observed-but-unwritten event is a drop (queue drops, trace-full drops, the discarded
  // pending buffer, and events still queued when the writer died); without one the
  // drained counters bound the same accounting. Both branches keep the per-API and
  // aggregate conservations exact.
  [[nodiscard]] noleax::trace::CaptureStatistics make_error_statistics() const {
    std::vector<LinuxTraceWriterApiCounterSnapshot> counter_snapshots;
    if (options_.counter_source) {
      counter_snapshots = options_.counter_source();
    }
    noleax::trace::CaptureStatistics statistics;
    for (std::size_t index = 0U; index < api_counters_.size(); ++index) {
      const ApiCounters& counters = api_counters_[index];
      const noleax::trace::ApiId api_id =
          index < kLinuxHookRegistry.size()
              ? kLinuxHookRegistry[index].api_id
              : custom_definitions_[index - kLinuxHookRegistry.size()].api_id;
      const LinuxTraceWriterApiCounterSnapshot* snapshot = nullptr;
      for (const auto& candidate : counter_snapshots) {
        if (candidate.api_id == api_id) {
          snapshot = &candidate;
          break;
        }
      }
      noleax::trace::ApiStatistics api;
      api.api_id = api_id;
      if (snapshot != nullptr) {
        if (snapshot->recordable_calls != snapshot->successful_calls + snapshot->failed_calls) {
          throw std::runtime_error{
              "glibc heap hook counters do not reconcile (recordable "
              "!= successful + failed)"};
        }
        api.observed_calls = snapshot->recordable_calls;
        api.successful_operations = snapshot->successful_calls;
        api.failed_operations = snapshot->failed_calls;
        api.filtered_before_queue = snapshot->filtered_calls;
        if (counters.written > api.observed_calls ||
            api.filtered_before_queue > api.observed_calls - counters.written) {
          throw std::runtime_error{
              "glibc heap hook counters do not reconcile with drained trace events"};
        }
        api.dropped_events = api.observed_calls - counters.written - api.filtered_before_queue;
      } else {
        api.observed_calls = counters.successful;
        checked_add(api.observed_calls, counters.failed,
                    "error-tail observed operation count overflow");
        api.successful_operations = counters.successful;
        api.failed_operations = counters.failed;
        api.filtered_before_queue = 0U;
        if (counters.written > api.observed_calls) {
          throw std::runtime_error{"error-tail written event count exceeds observed operations"};
        }
        api.dropped_events = api.observed_calls - counters.written;
      }
      statistics.per_api.push_back(api);
      checked_add(statistics.observed_calls, api.observed_calls,
                  "error-tail aggregate observed count overflow");
      checked_add(statistics.successful_operations, api.successful_operations,
                  "error-tail aggregate success count overflow");
      checked_add(statistics.failed_operations, api.failed_operations,
                  "error-tail aggregate failure count overflow");
      checked_add(statistics.filtered_before_queue, api.filtered_before_queue,
                  "error-tail aggregate filtered count overflow");
      checked_add(statistics.dropped_events, api.dropped_events,
                  "error-tail aggregate drop count overflow");
    }
    statistics.unique_stacks = unique_stacks_;
    statistics.reused_stacks = reused_stacks_;
    statistics.written_uncompressed_bytes = writer_.uncompressed_payload_bytes_written();
    statistics.written_stored_bytes = writer_.stored_payload_bytes_written();
    return statistics;
  }

  // Atomically promotes the partial trace after a successful finalize: close the stream
  // first (a close failure means the last flush never reached the disk), then rename.
  // Any failure leaves the .partial file in place for the analyzer.
  void commit_output() noexcept {
    if (output_committed_) {
      return;
    }
    output_committed_ = true;
    try {
      result_.partial_path = partial_path_;
      if (output_.is_open()) {
        const std::uint32_t injected = detail::writer_fault_errno(detail::kWriterFaultClose);
        errno = 0;
        output_.close();
        const std::uint32_t close_error =
            injected != 0U ? injected : static_cast<std::uint32_t>(errno);
        if (injected != 0U) {
          output_.setstate(std::ios_base::failbit);  // the injected close failure
        }
        if (!output_) {
          record_commit_failure("trace output stream close failed",
                                noleax::trace::TraceWritePhase::kClose, close_error);
          return;
        }
      }
      if (result_.status == LinuxTraceWriterStatus::kWriterError) {
        return;  // a failed capture's trace stays .partial on purpose
      }
      std::error_code error;
      std::filesystem::rename(partial_path_, final_path_, error);
      if (error) {
        record_commit_failure("cannot promote the completed partial trace to its final path",
                              noleax::trace::TraceWritePhase::kClose,
                              static_cast<std::uint32_t>(error.value()));
        return;
      }
      result_.final_path = final_path_;
    } catch (...) {
    }
  }

  void record_commit_failure(const char* message, noleax::trace::TraceWritePhase phase,
                             std::uint32_t system_error) {
    if (!error_recorded_) {
      error_recorded_ = true;
      result_.status = LinuxTraceWriterStatus::kWriterError;
      result_.error_message = message;
      result_.error_phase = phase;
      result_.error_system_error = system_error;
      result_.error_file_offset = writer_.bytes_written();
      result_.error_chunk_type = std::nullopt;
      report_writer_error_to_stderr();
    } else if (result_.tail_error_message.empty()) {
      // Finishing the failed trace failed too; the first error still stands.
      result_.tail_error_message = message;
    }
  }

  void write_metadata() {
    if (metadata_written_) {
      return;
    }
    metadata_written_ = true;
    std::vector<std::byte> payload;
    noleax::trace::append_capture_scope_record(payload, options_.capture_scope,
                                               options_.maximum_record_size);
    for (const noleax::trace::CustomHookDefinition& definition : custom_definitions_) {
      noleax::trace::append_custom_hook_definition_record(payload, definition,
                                                          options_.maximum_record_size);
    }
    for (const noleax::trace::CustomHookFailure& failure : custom_hook_failures_) {
      noleax::trace::append_custom_hook_failure_record(payload, failure,
                                                       options_.maximum_record_size);
    }
    noleax::trace::ChunkDescriptor descriptor;
    descriptor.type = noleax::trace::ChunkType::kMetadata;
    descriptor.codec = options_.compression;
    if (writer_.write_chunk(descriptor, payload) != noleax::trace::ChunkWriteResult::kWritten) {
      throw noleax::trace::TraceWriteError{"trace file limit cannot hold CaptureScope metadata"};
    }
  }

  void thread_main() noexcept {
    const InternalThreadScope internal_thread;
    {
      std::scoped_lock lock{state_mutex_};
      thread_ready_ = true;
      state_changed_.notify_all();
    }

    try {
      bool capture_begun = false;
      {
        std::unique_lock lock{state_mutex_};
        // Polling like capture_loop does: an unbounded wait here could miss a stop that
        // lands between predicate evaluation and blocking (request_stop notifies without
        // holding state_mutex_), deadlocking finish()/the destructor on join().
        while (!capture_begun_ && !stop_requested_.load(std::memory_order_acquire)) {
          state_changed_.wait_for(lock, kEmptyPollInterval, [this] {
            return capture_begun_ || stop_requested_.load(std::memory_order_acquire);
          });
        }
        capture_begun = capture_begun_;
      }
      if (capture_begun) {
        capture_loop();
      } else {
        finalize_empty_trace();
      }
    } catch (const noleax::trace::TraceWriteError& error) {
      record_writer_error(error);
    } catch (const std::exception& error) {
      record_writer_error(error.what());
    } catch (...) {
      record_writer_error("unknown trace writer failure");
    }
    running_.store(false, std::memory_order_release);
  }

  void capture_loop() {
    initial_modules_processed_ = true;
    for (const RawModuleEvent& initial : module_tracker_.initial_modules()) {
      process_module_event(initial);
    }
    collect_module_drops();
    auto next_flush = std::chrono::steady_clock::now() + options_.flush_interval;
    // Both samplers are due immediately: every enabled sampler takes a baseline sample at
    // capture start.
    auto next_counters = std::chrono::steady_clock::now();
    auto next_map = next_counters;
    for (;;) {
      bool drained_event = false;
      // Linux has no in-process loader notification: poll for module changes first so
      // fresh load records precede the events whose stacks may reference them.
      module_tracker_.poll();
      LinuxHeapEvent raw_event;
      while (event_queue_.try_pop(raw_event)) {
        drained_event = true;
        drain_modules_through(raw_event.monotonic_ticks);
        process_event(raw_event);
      }
      drain_modules_through(std::numeric_limits<std::uint64_t>::max());
      collect_queue_drops();
      collect_module_drops();

      if (stop_requested_.load(std::memory_order_acquire)) {
        break;
      }
      const auto now = std::chrono::steady_clock::now();
      if (now >= next_flush) {
        flush_pending();
        // Durability tick: after a kill, the .partial stays analyzable up to the last
        // successful stream flush.
        flush_stream();
        next_flush = now + options_.flush_interval;
      }
      const bool counters_due =
          options_.memory_counters_interval.count() > 0 && now >= next_counters;
      const bool map_due = options_.memory_map_interval.count() > 0 && now >= next_map;
      if (counters_due || map_due) {
        capture_memory_snapshot(counters_due, map_due);
        if (counters_due) {
          next_counters = now + options_.memory_counters_interval;
        }
        if (map_due) {
          next_map = now + options_.memory_map_interval;
        }
      }
      if (!drained_event) {
        std::unique_lock lock{state_mutex_};
        state_changed_.wait_for(lock, kEmptyPollInterval,
                                [this] { return stop_requested_.load(std::memory_order_acquire); });
      }
    }

    // The caller stops producers before requesting writer shutdown, so this final drain
    // boundary observes every queued event.
    module_tracker_.poll();
    LinuxHeapEvent raw_event;
    while (event_queue_.try_pop(raw_event)) {
      drain_modules_through(raw_event.monotonic_ticks);
      process_event(raw_event);
    }
    drain_modules_through(std::numeric_limits<std::uint64_t>::max());
    collect_queue_drops();
    collect_module_drops();
    flush_pending();
    // Take one final sample of every enabled sampler on the orderly stop path. The
    // finish_after_worker_exit() (process teardown) path skips this on purpose: the last
    // periodic snapshot stands.
    if (options_.memory_counters_interval.count() > 0 || options_.memory_map_interval.count() > 0) {
      capture_memory_snapshot(options_.memory_counters_interval.count() > 0,
                              options_.memory_map_interval.count() > 0);
    }
    finalize_trace();
  }

  // Samples the due memory record kinds and writes them as one kMemory chunk (counters
  // first). Sampling runs on the writer thread (an internal thread), so its own allocations
  // and API calls are never recorded. A failed or throwing sampler skips its record; a
  // failed chunk write degrades to the usual file-limit handling. Sampling never aborts
  // the capture — but a TraceWriteError is a writer failure, not a sampler failure, and
  // must reach the error tail.
  void capture_memory_snapshot(bool want_counters, bool want_map) {
    if (file_limit_reached_) {
      return;
    }
    try {
      memory_payload_.clear();
      const std::uint64_t ticks =
          (std::max)(monotonic_now_ns(), (std::max)(last_memory_ticks_, monotonic_origin_));
      last_memory_ticks_ = ticks;
      std::uint64_t counters_records = 0U;
      std::uint64_t map_records = 0U;
      if (want_counters) {
        noleax::trace::MemoryCounters counters;
        if (capture_memory_counters(counters)) {
          counters.monotonic_ticks = ticks;
          noleax::trace::append_memory_counters_record(memory_payload_, counters,
                                                       options_.maximum_record_size);
          counters_records = 1U;
        }
      }
      if (want_map) {
        noleax::trace::MemoryMap map;
        if (capture_memory_map(map)) {
          map.monotonic_ticks = ticks;
          noleax::trace::append_memory_map_record(memory_payload_, map,
                                                  options_.maximum_record_size);
          map_records = 1U;
        }
      }
      if (!memory_payload_.empty()) {
        if (write_data_chunk(noleax::trace::ChunkType::kMemory, memory_payload_)) {
          checked_add(memory_chunks_, 1U, "memory chunk count overflow");
          checked_add(memory_counters_records_, counters_records,
                      "memory counters record count overflow");
          checked_add(memory_map_records_, map_records, "memory map record count overflow");
        }
        memory_payload_.clear();
      }
    } catch (const noleax::trace::TraceWriteError&) {
      memory_payload_.clear();
      throw;
    } catch (...) {
      memory_payload_.clear();
    }
  }

  void drain_modules_through(std::uint64_t maximum_ticks) {
    for (;;) {
      if (!pending_module_event_.has_value()) {
        RawModuleEvent event;
        if (!module_tracker_.try_dequeue(event)) {
          return;
        }
        pending_module_event_ = event;
      }
      if (pending_module_event_->monotonic_ticks > maximum_ticks) {
        return;
      }
      process_module_event(*pending_module_event_);
      pending_module_event_.reset();
    }
  }

  void collect_module_drops() {
    checked_add(module_notification_drops_, module_tracker_.take_dropped_event_count(),
                "module notification drop count overflow");
  }

  void collect_queue_drops() {
    checked_add(queue_dropped_events_, event_queue_.take_dropped_count(),
                "queue drop count overflow");
  }

  void process_module_event(const RawModuleEvent& raw_event) {
    if (raw_event.base_address == 0U || raw_event.path_length > raw_event.path.size()) {
      throw std::invalid_argument{"raw module event is invalid"};
    }
    std::uint64_t ticks = raw_event.monotonic_ticks;
    if (has_raw_module_flag(raw_event, RawModuleEventFlag::kInitialSnapshot)) {
      // The construction-time snapshot is stamped with the tracker's origin, which may
      // precede the file header origin by a few nanoseconds; pin it to the origin.
      ticks = (std::max)(ticks, monotonic_origin_);
    } else if (ticks < monotonic_origin_) {
      throw std::invalid_argument{"raw module event precedes the trace origin"};
    }
    if (ticks < last_module_ticks_) {
      ticks = last_module_ticks_;
    }

    if (raw_event.type == RawModuleEventType::kLoad) {
      if (raw_event.image_size == 0U) {
        throw std::invalid_argument{"raw module load has an empty image range"};
      }
      if (live_modules_.contains(raw_event.base_address)) {
        throw std::runtime_error{"module load overlaps a live module generation"};
      }
      if (next_module_id_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error{"module ID space is exhausted"};
      }
      if (pending_event_count_ != 0U) {
        flush_pending();
      }

      noleax::trace::ModuleLoad load;
      load.module_id = noleax::trace::ModuleId{next_module_id_++};
      load.monotonic_ticks = ticks;
      load.base_address = raw_event.base_address;
      load.image_size = raw_event.image_size;
      load.image_path.assign(raw_event.path.data(),
                             static_cast<std::size_t>(raw_event.path_length));
      if (load.image_path.empty()) {
        load.image_path = unknown_module_path(raw_event.base_address);
        load.flags |= static_cast<std::uint32_t>(noleax::trace::ModuleLoadFlag::kPathTruncated);
      } else if (has_raw_module_flag(raw_event, RawModuleEventFlag::kPathTruncated)) {
        load.flags |= static_cast<std::uint32_t>(noleax::trace::ModuleLoadFlag::kPathTruncated);
      }
      noleax::trace::append_module_load_record(module_payload_, load, options_.maximum_record_size);
      live_modules_.emplace(
          raw_event.base_address,
          LiveModule{load.module_id, raw_event.base_address, raw_event.image_size});
      checked_add(pending_module_loads_, 1U, "pending module load count overflow");
    } else if (raw_event.type == RawModuleEventType::kUnload) {
      const auto existing = live_modules_.find(raw_event.base_address);
      if (existing == live_modules_.end()) {
        last_module_ticks_ = ticks;
        return;
      }
      if (pending_event_count_ != 0U) {
        flush_pending();
      }
      noleax::trace::append_module_unload_record(
          module_payload_, noleax::trace::ModuleUnload{existing->second.module_id, ticks},
          options_.maximum_record_size);
      live_modules_.erase(existing);
      checked_add(pending_module_unloads_, 1U, "pending module unload count overflow");
    } else {
      throw std::invalid_argument{"raw module event type is not supported"};
    }
    last_module_ticks_ = ticks;
    if (module_payload_.size() >= options_.chunk_target_size) {
      flush_module_payload();
    }
  }

  [[nodiscard]] NormalizedStack normalize_stack(const CapturedStack& raw_stack) const {
    NormalizedStack normalized;
    normalized.status = trace_stack_status(raw_stack.status);
    normalized.frame_count = raw_stack.frame_count;
    for (std::uint16_t index = 0U; index < raw_stack.frame_count; ++index) {
      const std::uint64_t address = raw_stack.frames[index];
      noleax::trace::StackFrame frame{{}, 0U, address, 0U};
      auto module = live_modules_.upper_bound(address);
      if (module != live_modules_.begin()) {
        --module;
        const LiveModule& candidate = module->second;
        if (address >= candidate.base && address - candidate.base < candidate.size) {
          frame.module_id = candidate.module_id;
          frame.module_offset = address - candidate.base;
        }
      }
      normalized.frames[index] = frame;
    }
    return normalized;
  }

  void validate_raw_event(const LinuxHeapEvent& raw_event) const {
    if (raw_event.queue_sequence == 0U || raw_event.thread_id == 0U ||
        raw_event.monotonic_ticks < monotonic_origin_) {
      throw std::invalid_argument{"raw Linux heap event header is invalid"};
    }
    const bool succeeded = raw_event.status == LinuxHeapEventStatus::kSuccess;
    if (!succeeded && raw_event.status != LinuxHeapEventStatus::kFailure) {
      throw std::invalid_argument{"raw Linux heap event result is inconsistent"};
    }
    if (succeeded != (raw_event.operation_result == 0U)) {
      throw std::invalid_argument{"raw Linux heap event result is inconsistent"};
    }
    const LinuxHookRegistryEntry* const hook = find_linux_hook(raw_event.api_id);
    const bool custom_event = hook == nullptr;
    if (custom_event && !is_declared_custom_api(raw_event.api_id)) {
      throw std::invalid_argument{"raw Linux heap event carries an unknown API ID"};
    }
    if (custom_event) {
      // Custom hook points produce only the three heap operations; the per-operation
      // invariants below are shared with the built-in heap events.
      if (raw_event.operation != LinuxHeapEventOperation::kAllocate &&
          raw_event.operation != LinuxHeapEventOperation::kReallocate &&
          raw_event.operation != LinuxHeapEventOperation::kFree) {
        throw std::invalid_argument{"raw custom hook event operation is not supported"};
      }
    } else if (expected_operation(hook->logical_api) != raw_event.operation) {
      throw std::invalid_argument{"raw Linux heap event operation does not match its API"};
    }
    switch (raw_event.operation) {
      case LinuxHeapEventOperation::kAllocate:
        if (raw_event.address != 0U || succeeded != (raw_event.result_address != 0U)) {
          throw std::invalid_argument{"raw malloc-family event result is inconsistent"};
        }
        break;
      case LinuxHeapEventOperation::kReallocate:
        if (!succeeded && raw_event.result_address != 0U) {
          throw std::invalid_argument{"raw realloc-family event result is inconsistent"};
        }
        if (succeeded && raw_event.result_address == 0U && raw_event.address == 0U) {
          // realloc(NULL, 0) returning NULL is indistinguishable from a failure.
          throw std::invalid_argument{"raw realloc-family event result is inconsistent"};
        }
        break;
      case LinuxHeapEventOperation::kFree:
        if (raw_event.requested_size != 0U || raw_event.result_address != 0U ||
            raw_event.count != 0U || raw_event.alignment != 0U) {
          throw std::invalid_argument{"raw free event is inconsistent"};
        }
        break;
      case LinuxHeapEventOperation::kVmAllocate:
        // mmap: requested_address/protection/map_flags/section_handle/section_offset are
        // free-form arguments; only the size and the result carry invariants.
        if (raw_event.address != 0U || raw_event.count != 0U || raw_event.alignment != 0U ||
            (succeeded && raw_event.requested_size == 0U) ||
            succeeded != (raw_event.result_address != 0U)) {
          throw std::invalid_argument{"raw mmap event result is inconsistent"};
        }
        break;
      case LinuxHeapEventOperation::kVmUnmap:
        if (raw_event.requested_address != 0U || raw_event.count != 0U ||
            raw_event.alignment != 0U || raw_event.result_address != 0U ||
            raw_event.protection != 0U || raw_event.map_flags != 0U ||
            raw_event.section_handle != 0U || raw_event.section_offset != 0U ||
            (succeeded && (raw_event.address == 0U || raw_event.requested_size == 0U))) {
          throw std::invalid_argument{"raw munmap event result is inconsistent"};
        }
        break;
      case LinuxHeapEventOperation::kVmRemap:
        // mremap: requested_size is the old size, count the new size; the result base is
        // nonzero exactly on success. alignment carries the requested new address, which
        // is defined only when MREMAP_FIXED (0x10) is present in map_flags.
        if (raw_event.requested_address != 0U || raw_event.protection != 0U ||
            raw_event.section_handle != 0U || raw_event.section_offset != 0U ||
            (raw_event.alignment != 0U && (raw_event.map_flags & 0x10U) == 0U) ||
            (succeeded && (raw_event.address == 0U || raw_event.count == 0U)) ||
            succeeded != (raw_event.result_address != 0U)) {
          throw std::invalid_argument{"raw mremap event result is inconsistent"};
        }
        break;
    }
    if (last_sequence_ == std::numeric_limits<std::uint64_t>::max() ||
        raw_event.queue_sequence != last_sequence_ + 1U) {
      throw std::invalid_argument{"raw Linux heap event sequence is not contiguous"};
    }
  }

  void validate_raw_stack(const CapturedStack& stack) const {
    if (stack.requested_depth > kMaximumCapturedStackDepth ||
        stack.frame_count > kMaximumCapturedStackDepth) {
      throw std::invalid_argument{"raw captured stack depth exceeds its fixed capacity"};
    }
    if (stack_capture_succeeded(stack)) {
      for (std::uint16_t index = 0U; index < stack.frame_count; ++index) {
        if (stack.frames[index] == 0U) {
          throw std::invalid_argument{"raw captured stack contains a zero frame"};
        }
      }
      return;
    }
    if (stack.status == StackCaptureStatus::kFailed && stack.frame_count == 0U) {
      return;
    }
    if (stack.status == StackCaptureStatus::kDisabled && stack.frame_count == 0U &&
        stack.requested_depth == 0U) {
      return;
    }
    throw std::invalid_argument{"raw captured stack encoding is invalid"};
  }

  [[nodiscard]] bool is_declared_custom_api(noleax::trace::ApiId api_id) const noexcept {
    if (api_id < noleax::trace::kCustomHookApiIdBase) {
      return false;
    }
    return static_cast<std::size_t>(api_id - noleax::trace::kCustomHookApiIdBase) <
           custom_definitions_.size();
  }

  [[nodiscard]] noleax::trace::AllocationId make_allocation_id(noleax::trace::ApiId api_id) {
    if (api_id < noleax::trace::kCustomHookApiIdBase) {
      if (next_allocation_id_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error{"allocation ID space is exhausted"};
      }
      return noleax::trace::AllocationId{next_allocation_id_++};
    }
    // Custom hook allocations live in their own ID space: (api_id << 40) | counter, with
    // the counter per hook point starting at one (mirrors the Windows writer); matching
    // frees and reallocations pass the stamped id through the live map unchanged.
    std::uint64_t& counter = custom_allocation_counters_[api_id];
    if (counter >= (std::uint64_t{1U} << 40U)) {
      throw std::overflow_error{"custom hook allocation ID space is exhausted"};
    }
    ++counter;
    return noleax::trace::AllocationId{(static_cast<std::uint64_t>(api_id) << 40U) | counter};
  }

  [[nodiscard]] noleax::trace::MappingId create_virtual_mapping(std::uint64_t base,
                                                                std::uint64_t size) {
    if (next_mapping_id_ == std::numeric_limits<std::uint64_t>::max()) {
      throw std::overflow_error{"mapping ID space is exhausted"};
    }
    if (base == 0U || size == 0U || live_vm_mappings_.contains(base)) {
      throw std::runtime_error{"virtual mapping creation is inconsistent"};
    }
    const noleax::trace::MappingId id{next_mapping_id_++};
    live_vm_mappings_.emplace(base, LiveMapping{id, base, size});
    return id;
  }

  [[nodiscard]] noleax::trace::MappingId create_section_mapping(std::uint64_t base,
                                                                std::uint64_t size) {
    if (next_mapping_id_ == std::numeric_limits<std::uint64_t>::max()) {
      throw std::overflow_error{"mapping ID space is exhausted"};
    }
    if (base == 0U || size == 0U || live_section_mappings_.contains(base)) {
      throw std::runtime_error{"section mapping creation is inconsistent"};
    }
    const noleax::trace::MappingId id{next_mapping_id_++};
    live_section_mappings_.emplace(base, LiveMapping{id, base, size});
    return id;
  }

  // Contains-lookup over the file-backed views (munmap may name any address inside the
  // view), mirroring the Windows writer's find_section_mapping.
  [[nodiscard]] auto find_section_mapping(std::uint64_t address) {
    if (address == 0U) {
      return live_section_mappings_.end();
    }
    auto candidate = live_section_mappings_.upper_bound(address);
    if (candidate == live_section_mappings_.begin()) {
      return live_section_mappings_.end();
    }
    --candidate;
    const LiveMapping& mapping = candidate->second;
    if (address < mapping.base || address - mapping.base >= mapping.size) {
      return live_section_mappings_.end();
    }
    return candidate;
  }

  [[nodiscard]] noleax::trace::EventStatus unmatched_status(std::uint64_t address) const noexcept {
    return address != 0U && options_.capture_scope.preexisting_allocations_unknown
               ? noleax::trace::EventStatus::kPreexisting
               : noleax::trace::EventStatus::kUnmatched;
  }

  void process_event(const LinuxHeapEvent& raw_event) {
    validate_raw_event(raw_event);
    validate_raw_stack(raw_event.stack);
    last_sequence_ = raw_event.queue_sequence;
    std::uint64_t normalized_ticks = raw_event.monotonic_ticks;
    if (normalized_ticks < last_ticks_) {
      normalized_ticks = last_ticks_;
      checked_add(timestamp_adjustments_, 1U, "timestamp adjustment count overflow");
    }
    last_ticks_ = normalized_ticks;

    const std::size_t api_index = hook_api_index(raw_event.api_id);
    ApiCounters& counters = api_counters_[api_index];
    const bool succeeded = raw_event.status == LinuxHeapEventStatus::kSuccess;
    // Wire records per raw event: a successful mremap that moves (or remaps a file-backed
    // view) decomposes into a free + create record pair; every other event is one record.
    const std::uint64_t event_records = raw_event.operation == LinuxHeapEventOperation::kVmRemap
                                            ? remap_event_records(raw_event)
                                            : 1U;
    if (succeeded) {
      checked_add(counters.successful, event_records, "successful operation count overflow");
    } else {
      checked_add(counters.failed, 1U, "failed operation count overflow");
    }

    // Wire sequences: one raw event occupies event_records consecutive values, so the
    // mremap pair keeps the stream strictly increasing while the queue sequence check
    // above keeps raw contiguity. Until the first pair, wire sequences equal queue ones.
    if (event_records - 1U > std::numeric_limits<std::uint64_t>::max() - next_wire_sequence_) {
      throw std::overflow_error{"event sequence space is exhausted"};
    }
    const std::uint64_t wire_begin = next_wire_sequence_;
    next_wire_sequence_ += event_records;
    last_wire_sequence_ = next_wire_sequence_ - 1U;

    std::optional<noleax::trace::LossRecord> stack_capture_loss;
    if (raw_event.stack.status == StackCaptureStatus::kFailed) {
      stack_capture_loss = make_stack_capture_loss(wire_begin, event_records, normalized_ticks);
      checked_add(stack_capture_failures_, 1U, "stack capture failure count overflow");
      completeness_.observe_loss(*stack_capture_loss);
    }
    if (file_limit_reached_) {
      note_event_trace_drop(raw_event, normalized_ticks, wire_begin, event_records);
      return;
    }

    ensure_pending_capacity(event_records);
    if (file_limit_reached_) {
      note_event_trace_drop(raw_event, normalized_ticks, wire_begin, event_records);
      return;
    }

    noleax::trace::Event event;
    event.header.sequence = noleax::trace::Sequence{wire_begin};
    event.header.monotonic_ticks = normalized_ticks;
    event.header.thread_id = raw_event.thread_id;
    event.header.api_id = raw_event.api_id;
    event.header.status =
        succeeded ? noleax::trace::EventStatus::kSuccess : noleax::trace::EventStatus::kFailure;
    if (!succeeded) {
      event.header.system_error = {noleax::trace::SystemErrorDomain::kPosix,
                                   raw_event.operation_result};
    }

    std::uint64_t event_unique_stacks = 0U;
    std::uint64_t event_reused_stacks = 0U;
    if (stack_capture_succeeded(raw_event.stack)) {
      const NormalizedStack normalized_stack = normalize_stack(raw_event.stack);
      const RawStackInternResult interned =
          dictionary_.intern(normalized_stack, hash_normalized_stack(normalized_stack));
      event.header.stack_id = interned.stack_id;
      if (interned.inserted) {
        append_stack_definition(interned.stack_id, normalized_stack);
        event_unique_stacks = 1U;
      } else {
        event_reused_stacks = 1U;
      }
    } else if (stack_capture_loss.has_value()) {
      noleax::trace::append_loss_record(event_payload_, *stack_capture_loss,
                                        options_.maximum_record_size);
    }

    if (raw_event.operation == LinuxHeapEventOperation::kAllocate) {
      noleax::trace::AllocationEvent allocation;
      allocation.requested_size = raw_event.requested_size;
      allocation.result_address = raw_event.result_address;
      if (succeeded) {
        allocation.allocation_id = make_allocation_id(raw_event.api_id);
        live_allocations_.insert_or_assign(raw_event.result_address, allocation.allocation_id);
      }
      event.payload = allocation;
    } else if (raw_event.operation == LinuxHeapEventOperation::kReallocate) {
      noleax::trace::ReallocationEvent reallocation;
      reallocation.old_address = raw_event.address;
      reallocation.requested_size = raw_event.requested_size;
      reallocation.result_address = raw_event.result_address;
      auto old_allocation = live_allocations_.end();
      if (raw_event.address != 0U) {
        old_allocation = live_allocations_.find(raw_event.address);
      }
      if (old_allocation != live_allocations_.end()) {
        reallocation.old_allocation_id = old_allocation->second;
      }
      if (succeeded) {
        if (old_allocation != live_allocations_.end()) {
          live_allocations_.erase(old_allocation);
          if (raw_event.result_address == 0U) {
            // realloc(p, 0) frees the old generation and returns NULL.
            reallocation.effect = noleax::trace::ReallocationEffect::kFreed;
          } else {
            reallocation.new_allocation_id = make_allocation_id(raw_event.api_id);
            reallocation.effect = noleax::trace::ReallocationEffect::kNewGeneration;
            live_allocations_.insert_or_assign(raw_event.result_address,
                                               reallocation.new_allocation_id);
          }
        } else {
          event.header.status = unmatched_status(raw_event.address);
          if (raw_event.result_address != 0U) {
            // realloc(NULL, n) allocates a fresh generation with no old one.
            reallocation.new_allocation_id = make_allocation_id(raw_event.api_id);
            reallocation.effect = noleax::trace::ReallocationEffect::kNewGeneration;
            live_allocations_.insert_or_assign(raw_event.result_address,
                                               reallocation.new_allocation_id);
          }
        }
      }
      event.payload = reallocation;
    } else if (raw_event.operation == LinuxHeapEventOperation::kFree) {
      noleax::trace::FreeEvent free_event;
      free_event.address = raw_event.address;
      if (succeeded) {
        const auto allocation = live_allocations_.find(raw_event.address);
        if (allocation != live_allocations_.end()) {
          free_event.allocation_id = allocation->second;
          live_allocations_.erase(allocation);
        } else {
          event.header.status = unmatched_status(raw_event.address);
        }
      }
      event.payload = free_event;
    } else if (raw_event.operation == LinuxHeapEventOperation::kVmAllocate) {
      if (raw_event.section_handle == std::numeric_limits<std::uint64_t>::max()) {
        // Anonymous mmap: one fresh mapping generation per successful call.
        noleax::trace::VmAllocateEvent allocation;
        allocation.target = current_process_target();
        allocation.requested_base = raw_event.requested_address;
        allocation.result_base = raw_event.result_address;
        allocation.requested_size = raw_event.requested_size;
        allocation.allocation_type = static_cast<std::uint32_t>(raw_event.map_flags);
        allocation.protection = static_cast<std::uint32_t>(raw_event.protection);
        if (succeeded) {
          allocation.result_size = raw_event.requested_size;
          allocation.mapping_id =
              create_virtual_mapping(raw_event.result_address, raw_event.requested_size);
          allocation.mapping_base = raw_event.result_address;
          allocation.mapping_size = raw_event.requested_size;
        }
        event.payload = allocation;
      } else {
        // File-backed mmap: a section view keyed by its fd and offset.
        noleax::trace::MapEvent mapping_event;
        mapping_event.section_handle = raw_event.section_handle;
        mapping_event.target = current_process_target();
        mapping_event.result_base = raw_event.result_address;
        mapping_event.section_offset = raw_event.section_offset;
        mapping_event.protection = static_cast<std::uint32_t>(raw_event.protection);
        if (succeeded) {
          mapping_event.view_size = raw_event.requested_size;
          mapping_event.mapping_id =
              create_section_mapping(raw_event.result_address, raw_event.requested_size);
        }
        event.payload = mapping_event;
      }
    } else if (raw_event.operation == LinuxHeapEventOperation::kVmUnmap) {
      const auto vm_mapping = live_vm_mappings_.find(raw_event.address);
      const auto section_mapping = vm_mapping == live_vm_mappings_.end()
                                       ? find_section_mapping(raw_event.address)
                                       : live_section_mappings_.end();
      if (section_mapping != live_section_mappings_.end()) {
        // File-backed view: a successful munmap unmaps the whole view generation (the
        // wire model has no partial unmap; the record carries the view base).
        noleax::trace::UnmapEvent unmap_event;
        unmap_event.target = current_process_target();
        unmap_event.base = section_mapping->second.base;
        if (succeeded) {
          unmap_event.mapping_id = section_mapping->second.mapping_id;
          live_section_mappings_.erase(section_mapping);
        }
        event.payload = unmap_event;
      } else {
        noleax::trace::VmFreeEvent free_event;
        free_event.target = current_process_target();
        free_event.base = raw_event.address;
        free_event.region_size = raw_event.requested_size;
        free_event.free_type = kVmFreeTypeRelease;
        if (succeeded) {
          if (vm_mapping != live_vm_mappings_.end()) {
            free_event.mapping_id = vm_mapping->second.mapping_id;
            live_vm_mappings_.erase(vm_mapping);
          } else {
            // munmap of a range the capture never saw: no generation change.
            event.header.status = unmatched_status(raw_event.address);
          }
        }
        event.payload = free_event;
      }
    } else if (!succeeded) {
      // Failed mremap: no generation change; record the attempt as a failed allocation.
      noleax::trace::VmAllocateEvent allocation;
      allocation.target = current_process_target();
      allocation.requested_base = raw_event.address;
      allocation.requested_size = raw_event.count;
      allocation.allocation_type = static_cast<std::uint32_t>(raw_event.map_flags);
      event.payload = allocation;
    }
    if (raw_event.operation != LinuxHeapEventOperation::kVmRemap || !succeeded) {
      noleax::trace::append_event_record(event_payload_, event, options_.maximum_record_size);
    } else {
      append_vm_remap_records(raw_event, event);
    }

    if (pending_event_count_ == 0U) {
      pending_sequence_begin_ = wire_begin;
      pending_tick_begin_ = normalized_ticks;
    }
    pending_sequence_end_ = last_wire_sequence_;
    pending_tick_end_ = normalized_ticks;
    checked_add(pending_event_count_, event_records, "pending event count overflow");
    checked_add(counters.pending, event_records, "pending per-API event count overflow");
    checked_add(pending_unique_stacks_, event_unique_stacks, "pending unique stack count overflow");
    checked_add(pending_reused_stacks_, event_reused_stacks, "pending reused stack count overflow");

    if (stack_payload_.size() >= options_.chunk_target_size ||
        event_payload_.size() >= options_.chunk_target_size) {
      flush_pending();
    }
  }

  // Records a successful mremap emits: an in-place resize of an anonymous or untracked
  // mapping is a single VmAllocate record; a move (or a file-backed source, whose view
  // generation the analyzer cannot resize) is a free + create pair.
  [[nodiscard]] std::uint64_t remap_event_records(const LinuxHeapEvent& raw_event) {
    if (raw_event.status != LinuxHeapEventStatus::kSuccess) {
      return 1U;
    }
    if (raw_event.result_address != raw_event.address) {
      return 2U;
    }
    const bool anonymous_source = live_vm_mappings_.contains(raw_event.address);
    const bool section_source = !anonymous_source && find_section_mapping(raw_event.address) !=
                                                         live_section_mappings_.end();
    return section_source ? 2U : 1U;
  }

  // Emits the wire records for a successful mremap; base_event carries the resolved header
  // (status kSuccess, the interned stack, the first of the allocated wire sequences).
  void append_vm_remap_records(const LinuxHeapEvent& raw_event,
                               const noleax::trace::Event& base_event) {
    const auto vm_source = live_vm_mappings_.find(raw_event.address);
    const bool has_vm_source = vm_source != live_vm_mappings_.end();
    const auto section_source =
        has_vm_source ? live_section_mappings_.end() : find_section_mapping(raw_event.address);
    const bool has_section_source = section_source != live_section_mappings_.end();
    const bool in_place = raw_event.result_address == raw_event.address;

    if (!has_section_source && in_place) {
      // In-place resize: an anonymous generation keeps its mapping_id and grows (the
      // analyzer's observe_vm_allocate allows same-base growth); an untracked source is
      // adopted as a fresh generation so its later munmap still pairs.
      if (has_vm_source) {
        vm_source->second.size = raw_event.count;
      }
      noleax::trace::VmAllocateEvent allocation;
      allocation.target = current_process_target();
      allocation.requested_base = raw_event.address;
      allocation.result_base = raw_event.result_address;
      allocation.requested_size = raw_event.count;
      allocation.result_size = raw_event.count;
      allocation.allocation_type = static_cast<std::uint32_t>(raw_event.map_flags);
      allocation.mapping_id =
          has_vm_source ? vm_source->second.mapping_id
                        : create_virtual_mapping(raw_event.result_address, raw_event.count);
      allocation.mapping_base = raw_event.result_address;
      allocation.mapping_size = raw_event.count;
      noleax::trace::Event update = base_event;
      if (!has_vm_source && options_.capture_scope.preexisting_allocations_unknown) {
        update.header.status = noleax::trace::EventStatus::kPreexisting;
      }
      update.payload = allocation;
      noleax::trace::append_event_record(event_payload_, update, options_.maximum_record_size);
      return;
    }

    noleax::trace::Event end_event = base_event;
    if (!has_vm_source && !has_section_source) {
      // Untracked source range (attach blind spot): the free half pairs with nothing.
      end_event.header.status = unmatched_status(raw_event.address);
    }
    if (has_section_source) {
      noleax::trace::UnmapEvent unmap_event;
      unmap_event.target = current_process_target();
      unmap_event.base = section_source->second.base;
      unmap_event.mapping_id = section_source->second.mapping_id;
      live_section_mappings_.erase(section_source);
      end_event.payload = unmap_event;
    } else {
      noleax::trace::VmFreeEvent free_event;
      free_event.target = current_process_target();
      free_event.base = raw_event.address;
      free_event.region_size = raw_event.requested_size;
      free_event.free_type = kVmFreeTypeRelease;
      if (has_vm_source) {
        free_event.mapping_id = vm_source->second.mapping_id;
        live_vm_mappings_.erase(vm_source);
      }
      end_event.payload = free_event;
    }
    noleax::trace::append_event_record(event_payload_, end_event, options_.maximum_record_size);

    noleax::trace::Event create_event = base_event;
    create_event.header.sequence = noleax::trace::Sequence{base_event.header.sequence.value() + 1U};
    if (!has_vm_source && !has_section_source) {
      create_event.header.status = options_.capture_scope.preexisting_allocations_unknown
                                       ? noleax::trace::EventStatus::kPreexisting
                                       : noleax::trace::EventStatus::kSuccess;
    }
    if (has_section_source) {
      // A remapped file-backed view stays file-backed; the raw event carries no fd or
      // protection, so the new view records only what mremap reports.
      noleax::trace::MapEvent map_event;
      map_event.target = current_process_target();
      map_event.result_base = raw_event.result_address;
      map_event.view_size = raw_event.count;
      map_event.mapping_id = create_section_mapping(raw_event.result_address, raw_event.count);
      create_event.payload = map_event;
    } else {
      noleax::trace::VmAllocateEvent allocation;
      allocation.target = current_process_target();
      allocation.requested_base = raw_event.address;
      allocation.result_base = raw_event.result_address;
      allocation.requested_size = raw_event.count;
      allocation.result_size = raw_event.count;
      allocation.allocation_type = static_cast<std::uint32_t>(raw_event.map_flags);
      allocation.mapping_id = create_virtual_mapping(raw_event.result_address, raw_event.count);
      allocation.mapping_base = raw_event.result_address;
      allocation.mapping_size = raw_event.count;
      create_event.payload = allocation;
    }
    noleax::trace::append_event_record(event_payload_, create_event, options_.maximum_record_size);
  }

  void ensure_pending_capacity(std::uint64_t event_records) {
    if (pending_event_count_ == 0U) {
      return;
    }
    const std::uint64_t event_addition = event_records * kMaximumEventAdditionSize;
    const bool stack_would_exceed =
        stack_payload_.size() > options_.chunk_target_size ||
        kMaximumStackDefinitionRecordSize >
            options_.chunk_target_size -
                (std::min)(stack_payload_.size(), options_.chunk_target_size);
    const bool event_would_exceed =
        event_payload_.size() > options_.chunk_target_size ||
        event_addition > options_.chunk_target_size -
                             (std::min)(event_payload_.size(), options_.chunk_target_size);
    if (stack_would_exceed || event_would_exceed) {
      flush_pending();
    }
  }

  void append_stack_definition(noleax::trace::StackId stack_id, const NormalizedStack& stack) {
    noleax::trace::StackDefinition definition;
    definition.stack_id = stack_id;
    definition.status = stack.status;
    definition.frames.reserve(stack.frame_count);
    for (std::uint16_t index = 0U; index < stack.frame_count; ++index) {
      definition.frames.push_back(stack.frames[index]);
    }
    noleax::trace::append_stack_definition_record(stack_payload_, definition,
                                                  options_.maximum_record_size);
  }

  [[nodiscard]] noleax::trace::LossRecord make_stack_capture_loss(std::uint64_t sequence_begin,
                                                                  std::uint64_t event_records,
                                                                  std::uint64_t ticks) const {
    noleax::trace::LossRecord loss;
    loss.reason = noleax::trace::LossReason::kStackCaptureFailed;
    loss.location = noleax::trace::LossLocation::kAgentQueue;
    loss.estimated_event_count = event_records;
    loss.sequence_range =
        noleax::trace::SequenceRange{noleax::trace::Sequence{sequence_begin},
                                     noleax::trace::Sequence{sequence_begin + event_records - 1U}};
    loss.tick_range = noleax::trace::TickRange{ticks, ticks};
    return loss;
  }

  [[nodiscard]] bool write_chunk(noleax::trace::ChunkType type, std::span<const std::byte> payload,
                                 noleax::trace::CompressionCodec codec,
                                 std::uint64_t sequence_begin = 0U,
                                 std::uint64_t sequence_end = 0U) {
    if (const std::uint32_t injected = detail::writer_fault_errno(detail::kWriterFaultWrite)) {
      throw noleax::trace::TraceWriteError{"trace output stream write failed",
                                           noleax::trace::TraceWritePhase::kWrite, injected,
                                           writer_.bytes_written(), type};
    }
    noleax::trace::ChunkDescriptor descriptor;
    descriptor.type = type;
    descriptor.codec = codec;
    descriptor.sequence_begin = noleax::trace::Sequence{sequence_begin};
    descriptor.sequence_end = noleax::trace::Sequence{sequence_end};
    if (writer_.write_chunk(descriptor, payload) == noleax::trace::ChunkWriteResult::kFileLimit) {
      file_limit_reached_ = true;
      return false;
    }
    status_bytes_written_.store(writer_.bytes_written(), std::memory_order_relaxed);
    return true;
  }

  // Flushes the output stream and stamps the live status; a flush failure is a writer
  // failure like any other.
  void flush_stream() {
    if (const std::uint32_t injected = detail::writer_fault_errno(detail::kWriterFaultFlush)) {
      throw noleax::trace::TraceWriteError{"trace output stream flush failed",
                                           noleax::trace::TraceWritePhase::kFlush, injected,
                                           writer_.bytes_written()};
    }
    writer_.flush();
    last_flush_monotonic_ns_.store(monotonic_now_ns(), std::memory_order_relaxed);
  }

  [[nodiscard]] bool write_data_chunk(noleax::trace::ChunkType type,
                                      std::span<const std::byte> payload,
                                      std::uint64_t sequence_begin = 0U,
                                      std::uint64_t sequence_end = 0U) {
    return write_chunk(type, payload, options_.compression, sequence_begin, sequence_end);
  }

  [[nodiscard]] bool write_terminal_chunk(noleax::trace::ChunkType type,
                                          std::span<const std::byte> payload,
                                          std::uint64_t sequence_begin = 0U,
                                          std::uint64_t sequence_end = 0U) {
    return write_chunk(type, payload, noleax::trace::CompressionCodec::kNone, sequence_begin,
                       sequence_end);
  }

  void flush_module_payload() {
    if (module_payload_.empty()) {
      return;
    }
    if (!file_limit_reached_ &&
        write_data_chunk(noleax::trace::ChunkType::kModule, module_payload_)) {
      checked_add(written_module_loads_, pending_module_loads_,
                  "written module load count overflow");
      checked_add(written_module_unloads_, pending_module_unloads_,
                  "written module unload count overflow");
    }
    module_payload_.clear();
    pending_module_loads_ = 0U;
    pending_module_unloads_ = 0U;
  }

  void flush_pending() {
    if (pending_event_count_ == 0U) {
      flush_module_payload();
      return;
    }
    if (file_limit_reached_) {
      flush_module_payload();
      drop_pending_events();
      return;
    }
    flush_module_payload();
    if (file_limit_reached_) {
      drop_pending_events();
      return;
    }
    if (!stack_payload_.empty() &&
        !write_data_chunk(noleax::trace::ChunkType::kStack, stack_payload_)) {
      drop_pending_events();
      return;
    }
    if (!write_data_chunk(noleax::trace::ChunkType::kEvent, event_payload_, pending_sequence_begin_,
                          pending_sequence_end_)) {
      drop_pending_events();
      return;
    }

    checked_add(written_events_, pending_event_count_, "written event count overflow");
    for (ApiCounters& counters : api_counters_) {
      checked_add(counters.written, counters.pending, "written per-API event count overflow");
      counters.pending = 0U;
    }
    checked_add(unique_stacks_, pending_unique_stacks_, "unique stack count overflow");
    checked_add(reused_stacks_, pending_reused_stacks_, "reused stack count overflow");
    clear_pending();
  }

  void drop_pending_events() {
    if (pending_event_count_ != 0U) {
      if (trace_dropped_events_ == 0U) {
        trace_drop_sequence_begin_ = pending_sequence_begin_;
        trace_drop_tick_begin_ = pending_tick_begin_;
      }
      trace_drop_sequence_end_ = pending_sequence_end_;
      trace_drop_tick_end_ = pending_tick_end_;
      checked_add(trace_dropped_events_, pending_event_count_, "trace drop count overflow");
      for (ApiCounters& counters : api_counters_) {
        checked_add(counters.trace_dropped, counters.pending, "per-API trace drop count overflow");
        counters.pending = 0U;
      }
    }
    clear_pending();
  }

  void clear_pending() noexcept {
    stack_payload_.clear();
    event_payload_.clear();
    pending_event_count_ = 0U;
    for (ApiCounters& counters : api_counters_) {
      counters.pending = 0U;
    }
    pending_unique_stacks_ = 0U;
    pending_reused_stacks_ = 0U;
    pending_sequence_begin_ = 0U;
    pending_sequence_end_ = 0U;
    pending_tick_begin_ = 0U;
    pending_tick_end_ = 0U;
  }

  void note_event_trace_drop(const LinuxHeapEvent& raw_event, std::uint64_t ticks,
                             std::uint64_t wire_begin, std::uint64_t event_records) {
    if (trace_dropped_events_ == 0U) {
      trace_drop_sequence_begin_ = wire_begin;
      trace_drop_tick_begin_ = ticks;
    }
    trace_drop_sequence_end_ = wire_begin + event_records - 1U;
    trace_drop_tick_end_ = ticks;
    checked_add(trace_dropped_events_, event_records, "trace drop count overflow");
    checked_add(api_counters_[hook_api_index(raw_event.api_id)].trace_dropped, event_records,
                "per-API trace drop count overflow");
  }

  void finalize_empty_trace() {
    write_metadata();
    writer_.release_file_reserve();
    noleax::trace::CaptureStatistics statistics;
    for (const LinuxHookRegistryEntry& entry : kLinuxHookRegistry) {
      statistics.per_api.push_back({entry.api_id, 0U, 0U, 0U, 0U, 0U});
    }
    for (const noleax::trace::CustomHookDefinition& definition : custom_definitions_) {
      statistics.per_api.push_back({definition.api_id, 0U, 0U, 0U, 0U, 0U});
    }
    write_terminal_records(statistics);
  }

  // Appends Loss records for every drop source collected so far — module notification
  // drops, event-queue overflow, trace-full drops — and observes them in the completeness
  // tracker. Shared by the orderly finalize and the writer-error tail.
  void append_collected_loss_records(std::vector<std::byte>& payload) {
    if (module_notification_drops_ != 0U) {
      noleax::trace::LossRecord module_loss;
      module_loss.reason = noleax::trace::LossReason::kQueueFull;
      module_loss.location = noleax::trace::LossLocation::kAgentQueue;
      module_loss.estimated_event_count = module_notification_drops_;
      completeness_.observe_loss(module_loss);
      noleax::trace::append_loss_record(payload, module_loss, options_.maximum_record_size);
    }
    if (queue_dropped_events_ != 0U) {
      noleax::trace::LossRecord queue_loss;
      queue_loss.reason = noleax::trace::LossReason::kQueueFull;
      queue_loss.location = noleax::trace::LossLocation::kAgentQueue;
      queue_loss.estimated_event_count = queue_dropped_events_;
      completeness_.observe_loss(queue_loss);
      noleax::trace::append_loss_record(payload, queue_loss, options_.maximum_record_size);
    }
    if (trace_dropped_events_ != 0U) {
      noleax::trace::LossRecord trace_loss;
      trace_loss.reason = noleax::trace::LossReason::kTraceFull;
      trace_loss.location = noleax::trace::LossLocation::kWriter;
      trace_loss.estimated_event_count = trace_dropped_events_;
      trace_loss.sequence_range =
          noleax::trace::SequenceRange{noleax::trace::Sequence{trace_drop_sequence_begin_},
                                       noleax::trace::Sequence{trace_drop_sequence_end_}};
      trace_loss.tick_range =
          noleax::trace::TickRange{trace_drop_tick_begin_, trace_drop_tick_end_};
      completeness_.observe_loss(trace_loss);
      noleax::trace::append_loss_record(payload, trace_loss, options_.maximum_record_size);
    }
  }

  void finalize_trace() {
    writer_.release_file_reserve();
    std::vector<std::byte> loss_payload;
    append_collected_loss_records(loss_payload);
    if (!loss_payload.empty()) {
      const std::uint64_t sequence_begin =
          trace_dropped_events_ == 0U ? 0U : trace_drop_sequence_begin_;
      const std::uint64_t sequence_end =
          trace_dropped_events_ == 0U ? 0U : trace_drop_sequence_end_;
      static_cast<void>(write_terminal_chunk(noleax::trace::ChunkType::kEvent, loss_payload,
                                             sequence_begin, sequence_end));
    }

    noleax::trace::CaptureStatistics statistics;
    // When the producer exposes authoritative counters (the runtime wires the hooks'
    // per-API snapshots here), observed/successful/failed/filtered/dropped come from
    // the hot path; events filtered before the queue are invisible to the writer.
    std::vector<LinuxTraceWriterApiCounterSnapshot> counter_snapshots;
    if (options_.counter_source) {
      counter_snapshots = options_.counter_source();
    }
    for (std::size_t index = 0U; index < api_counters_.size(); ++index) {
      const ApiCounters& counters = api_counters_[index];
      const noleax::trace::ApiId api_id =
          index < kLinuxHookRegistry.size()
              ? kLinuxHookRegistry[index].api_id
              : custom_definitions_[index - kLinuxHookRegistry.size()].api_id;
      const LinuxTraceWriterApiCounterSnapshot* snapshot = nullptr;
      for (const auto& candidate : counter_snapshots) {
        if (candidate.api_id == api_id) {
          snapshot = &candidate;
          break;
        }
      }
      noleax::trace::ApiStatistics api;
      api.api_id = api_id;
      if (snapshot != nullptr) {
        api.observed_calls = snapshot->recordable_calls;
        api.successful_operations = snapshot->successful_calls;
        api.failed_operations = snapshot->failed_calls;
        api.filtered_before_queue = snapshot->filtered_calls;
        api.dropped_events = snapshot->dropped_events;
        checked_add(api.dropped_events, counters.trace_dropped,
                    "per-API dropped event count overflow");
        if (snapshot->recordable_calls != snapshot->successful_calls + snapshot->failed_calls) {
          throw std::runtime_error{
              "glibc heap hook counters do not reconcile (recordable "
              "!= successful + failed)"};
        }
        std::uint64_t accounted = counters.written;
        checked_add(accounted, api.filtered_before_queue,
                    "accounted per-API filtered count overflow");
        checked_add(accounted, api.dropped_events, "accounted per-API drop count overflow");
        if (accounted != api.observed_calls) {
          throw std::runtime_error{
              "glibc heap hook counters do not reconcile with drained trace events"};
        }
      } else {
        api.observed_calls = counters.successful;
        checked_add(api.observed_calls, counters.failed, "per-API observed call count overflow");
        api.successful_operations = counters.successful;
        api.failed_operations = counters.failed;
        api.filtered_before_queue = 0U;
        api.dropped_events = counters.trace_dropped;
        // Hard reconciliation per API: every drained event was either written to the
        // trace or accounted as a writer-side drop.
        std::uint64_t accounted = counters.written;
        checked_add(accounted, counters.trace_dropped, "accounted per-API event count overflow");
        if (accounted != api.observed_calls) {
          throw std::runtime_error{
              "glibc heap hook counters do not reconcile with drained trace events"};
        }
      }
      statistics.per_api.push_back(api);
      checked_add(statistics.observed_calls, api.observed_calls,
                  "aggregate observed call count overflow");
      checked_add(statistics.successful_operations, api.successful_operations,
                  "aggregate successful operation count overflow");
      checked_add(statistics.failed_operations, api.failed_operations,
                  "aggregate failed operation count overflow");
      checked_add(statistics.filtered_before_queue, api.filtered_before_queue,
                  "aggregate filtered operation count overflow");
      checked_add(statistics.dropped_events, api.dropped_events,
                  "aggregate dropped event count overflow");
    }
    statistics.unique_stacks = unique_stacks_;
    statistics.reused_stacks = reused_stacks_;
    statistics.written_uncompressed_bytes = writer_.uncompressed_payload_bytes_written();
    statistics.written_stored_bytes = writer_.stored_payload_bytes_written();
    std::uint64_t completed_operations = statistics.successful_operations;
    checked_add(completed_operations, statistics.failed_operations,
                "completed operation count overflow");
    std::uint64_t accounted_events = written_events_;
    checked_add(accounted_events, statistics.filtered_before_queue,
                "accounted filtered event count overflow");
    checked_add(accounted_events, statistics.dropped_events, "accounted event count overflow");
    if (completed_operations != statistics.observed_calls ||
        accounted_events != statistics.observed_calls) {
      throw std::runtime_error{"hook counters do not reconcile with drained trace events"};
    }
    write_terminal_records(statistics);
  }

  void write_terminal_records(const noleax::trace::CaptureStatistics& statistics) {
    noleax::trace::validate_statistics(statistics);
    result_.statistics = statistics;
    result_.per_api.clear();
    for (std::size_t index = 0U; index < statistics.per_api.size(); ++index) {
      const noleax::trace::ApiStatistics& api = statistics.per_api[index];
      result_.per_api.push_back(
          LinuxTraceWriterApiResult{api.api_id, api.observed_calls, api_counters_[index].written,
                                    api.filtered_before_queue, api.dropped_events});
    }

    std::vector<std::byte> statistics_payload;
    noleax::trace::append_statistics_record(statistics_payload, statistics,
                                            options_.maximum_record_size);
    result_.statistics_written =
        write_terminal_chunk(noleax::trace::ChunkType::kStatistics, statistics_payload);

    noleax::trace::EndOfTrace end;
    end.final_sequence = noleax::trace::Sequence{last_wire_sequence_};
    end.final_monotonic_ticks =
        (std::max)((std::max)((std::max)(last_ticks_, last_module_ticks_), last_memory_ticks_),
                   monotonic_origin_);
    end.normal_stop = true;
    end.aggregate_completeness = completeness_.report();
    end.aggregate_completeness.remove(noleax::trace::CompletenessIssue::kMissingEndOfTrace);
    std::vector<std::byte> end_payload;
    noleax::trace::append_end_of_trace_record(end_payload, end, options_.maximum_record_size);
    result_.end_of_trace_written =
        write_terminal_chunk(noleax::trace::ChunkType::kEnd, end_payload);

    flush_stream();
    result_.status = file_limit_reached_ ? LinuxTraceWriterStatus::kFileLimit
                                         : LinuxTraceWriterStatus::kComplete;
    result_.completeness_mask = end.aggregate_completeness.mask();
    fill_result_counters();
  }

  void fill_result_counters() noexcept {
    result_.stack_capture_failures = stack_capture_failures_;
    result_.queue_dropped_events = queue_dropped_events_;
    result_.trace_dropped_events = trace_dropped_events_;
    result_.timestamp_adjustments = timestamp_adjustments_;
    result_.stack_dictionary_segments = dictionary_.segment_count();
    result_.module_load_records = written_module_loads_;
    result_.module_unload_records = written_module_unloads_;
    result_.module_notification_drops = module_notification_drops_;
    result_.bytes_written = writer_.bytes_written();
    result_.memory_chunks = memory_chunks_;
    result_.memory_counters_records = memory_counters_records_;
    result_.memory_map_records = memory_map_records_;
  }

  // Per-API counter slots: the built-in registry entries first, then one slot per declared
  // custom hook point in declaration order.
  [[nodiscard]] std::size_t hook_api_index(noleax::trace::ApiId api_id) const {
    for (std::size_t index = 0U; index < kLinuxHookRegistry.size(); ++index) {
      if (kLinuxHookRegistry[index].api_id == api_id) {
        return index;
      }
    }
    if (api_id >= noleax::trace::kCustomHookApiIdBase) {
      const std::size_t custom_index =
          static_cast<std::size_t>(api_id - noleax::trace::kCustomHookApiIdBase);
      if (custom_index < custom_definitions_.size()) {
        return kLinuxHookRegistry.size() + custom_index;
      }
    }
    throw std::invalid_argument{"raw Linux heap event carries an unknown API ID"};
  }

  struct ApiCounters {
    std::uint64_t successful{0U};
    std::uint64_t failed{0U};
    std::uint64_t pending{0U};
    std::uint64_t written{0U};
    std::uint64_t trace_dropped{0U};
  };

  LinuxHeapEventQueue& event_queue_;
  LinuxModuleTracker& module_tracker_;
  const LinuxTraceWriterOptions options_;
  const std::vector<noleax::trace::CustomHookDefinition> custom_definitions_;
  const std::filesystem::path final_path_;
  const std::filesystem::path partial_path_;
  std::ofstream output_;
  const std::uint64_t monotonic_origin_;
  NormalizedStackDictionary dictionary_;
  noleax::trace::TraceWriter writer_;
  noleax::trace::CompletenessTracker completeness_;

  std::optional<RawModuleEvent> pending_module_event_;
  std::vector<std::byte> module_payload_;
  std::vector<std::byte> stack_payload_;
  std::vector<std::byte> event_payload_;
  std::vector<std::byte> memory_payload_;
  std::unordered_map<std::uint64_t, noleax::trace::AllocationId> live_allocations_;
  std::map<std::uint64_t, LiveModule> live_modules_;
  std::map<std::uint64_t, LiveMapping> live_vm_mappings_;
  std::map<std::uint64_t, LiveMapping> live_section_mappings_;
  std::vector<ApiCounters> api_counters_;
  std::unordered_map<noleax::trace::ApiId, std::uint64_t> custom_allocation_counters_;
  std::vector<noleax::trace::CustomHookFailure> custom_hook_failures_;
  std::thread worker_;
  mutable std::mutex state_mutex_;
  std::condition_variable state_changed_;
  std::atomic<bool> stop_requested_{false};
  std::atomic<bool> running_{true};
  // Live telemetry mirrors, read by live_status() from any thread.
  std::atomic<std::uint64_t> status_bytes_written_{0U};
  std::atomic<std::uint64_t> last_flush_monotonic_ns_{0U};
  bool thread_ready_{false};
  bool capture_begun_{false};
  bool metadata_written_{false};
  bool file_limit_reached_{false};
  bool initial_modules_processed_{false};
  bool inline_finalize_done_{false};
  bool finalized_{false};
  bool error_tail_attempted_{false};
  bool error_recorded_{false};
  bool output_committed_{false};

  LinuxTraceWriterResult result_;
  std::uint64_t next_allocation_id_{1U};
  std::uint64_t next_module_id_{1U};
  std::uint64_t next_mapping_id_{1U};
  std::uint64_t next_wire_sequence_{1U};
  std::uint64_t last_wire_sequence_{0U};
  std::uint64_t last_sequence_{0U};
  std::uint64_t last_ticks_{0U};
  std::uint64_t last_module_ticks_{0U};
  std::uint64_t last_memory_ticks_{0U};
  std::uint64_t pending_module_loads_{0U};
  std::uint64_t pending_module_unloads_{0U};
  std::uint64_t pending_event_count_{0U};
  std::uint64_t pending_unique_stacks_{0U};
  std::uint64_t pending_reused_stacks_{0U};
  std::uint64_t pending_sequence_begin_{0U};
  std::uint64_t pending_sequence_end_{0U};
  std::uint64_t pending_tick_begin_{0U};
  std::uint64_t pending_tick_end_{0U};
  std::uint64_t written_events_{0U};
  std::uint64_t written_module_loads_{0U};
  std::uint64_t written_module_unloads_{0U};
  std::uint64_t module_notification_drops_{0U};
  std::uint64_t queue_dropped_events_{0U};
  std::uint64_t trace_dropped_events_{0U};
  std::uint64_t trace_drop_sequence_begin_{0U};
  std::uint64_t trace_drop_sequence_end_{0U};
  std::uint64_t trace_drop_tick_begin_{0U};
  std::uint64_t trace_drop_tick_end_{0U};
  std::uint64_t stack_capture_failures_{0U};
  std::uint64_t timestamp_adjustments_{0U};
  std::uint64_t unique_stacks_{0U};
  std::uint64_t reused_stacks_{0U};
  std::uint64_t memory_chunks_{0U};
  std::uint64_t memory_counters_records_{0U};
  std::uint64_t memory_map_records_{0U};
};

LinuxTraceWriter::LinuxTraceWriter(LinuxHeapEventQueue& event_queue,
                                   LinuxModuleTracker& module_tracker,
                                   const std::filesystem::path& output_path,
                                   LinuxTraceWriterOptions options)
    : implementation_{
          std::make_unique<Implementation>(event_queue, module_tracker, output_path, options)} {}

LinuxTraceWriter::~LinuxTraceWriter() = default;

void LinuxTraceWriter::begin_capture() { implementation_->begin_capture(); }

void LinuxTraceWriter::note_custom_hook_failures(
    std::vector<noleax::trace::CustomHookFailure> failures) {
  implementation_->note_custom_hook_failures(std::move(failures));
}

LinuxTraceWriterResult LinuxTraceWriter::finish() { return implementation_->finish(); }

LinuxTraceWriterResult LinuxTraceWriter::finish_after_worker_exit() {
  return implementation_->finish_after_worker_exit();
}

bool LinuxTraceWriter::is_running() const noexcept { return implementation_->is_running(); }

LinuxTraceWriterLiveStatus LinuxTraceWriter::live_status() const noexcept {
  return implementation_->live_status();
}

}  // namespace noleax::agent::linux
