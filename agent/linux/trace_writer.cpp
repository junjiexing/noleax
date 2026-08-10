// Linux in-process trace writer (docs/LINUX_PORT_PLAN.md M3): drains the shared glibc
// heap event queue plus the poll-based module tracker on an internal worker thread and
// writes a bounded .nlx trace through the platform-neutral noleax::trace library.
// Mirrors the Windows RtlAllocateHeapTraceWriter architecture and invariants, scoped to
// one queue and one event family: no heap lifecycle, VM/section, custom-hook, or memory
// sampler records yet (M4+). heap_handle is always 0 and heap_id stays invalid in
// allocation records (the wire model only requires heap_id for HeapCreate).

#include "noleax/agent/linux/trace_writer.hpp"

#include <time.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/linux/hook_registry.hpp"
#include "noleax/agent/linux/stack_capture.hpp"
#include "noleax/agent/windows/stack_dictionary.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/record_codec.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/trace_writer.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::agent::linux {
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
constexpr std::uint64_t kMinimumTerminalReserveSize = 1024U;
constexpr std::uint64_t kMaximumTerminalTailSize =
    (noleax::trace::kChunkHeaderSize + 3U * 56U) +
    (noleax::trace::kChunkHeaderSize + 8U + 80U + kLinuxHookRegistry.size() * 48U) +
    (noleax::trace::kChunkHeaderSize + 8U + 40U);
constexpr auto kEmptyPollInterval = std::chrono::milliseconds{1};

static_assert(kMaximumTerminalTailSize <= kMinimumTerminalReserveSize);

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

[[nodiscard]] std::ofstream open_trace_output(const std::filesystem::path& path) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  if (!output) {
    throw std::runtime_error{"cannot create the trace output file"};
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
  options.trace.reserved_tail_size =
      (std::max)(options.trace.reserved_tail_size, kMinimumTerminalReserveSize);
  return options;
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

struct LiveModule {
  noleax::trace::ModuleId module_id;
  std::uint64_t base{0U};
  std::uint64_t size{0U};
};

}  // namespace

class LinuxTraceWriter::Implementation final {
 public:
  Implementation(LinuxHeapEventQueue& event_queue, LinuxModuleTracker& module_tracker,
                 const std::filesystem::path& output_path, LinuxTraceWriterOptions options)
      : event_queue_{validate_event_queue(event_queue)},
        module_tracker_{module_tracker},
        options_{validate_options(options)},
        output_{open_trace_output(output_path)},
        monotonic_origin_{options_.monotonic_origin != 0U ? options_.monotonic_origin
                                                          : monotonic_now_ns()},
        dictionary_{options_.stack_dictionary_capacity},
        writer_{output_, make_file_header(options_, monotonic_origin_), options_.trace},
        completeness_{options_.capture_scope} {
    module_payload_.reserve(options_.chunk_target_size);
    stack_payload_.reserve(options_.chunk_target_size);
    event_payload_.reserve(options_.chunk_target_size);
    worker_ = std::thread{[this] { thread_main(); }};
    std::unique_lock lock{state_mutex_};
    state_changed_.wait(lock, [this] { return thread_ready_; });
  }

  ~Implementation() {
    request_stop();
    if (worker_.joinable()) {
      worker_.join();
    }
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
    capture_begun_ = true;
    state_changed_.notify_all();
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
    } catch (const std::exception& error) {
      record_inline_error(error.what());
    } catch (...) {
      record_inline_error("unknown trace writer failure");
    }
    return result_;
  }

  [[nodiscard]] bool is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
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

  void record_inline_error(const char* message) noexcept {
    result_.error_message = message;
    result_.status = LinuxTraceWriterStatus::kWriterError;
    fill_result_counters();
    try {
      writer_.flush();
    } catch (...) {
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
    } catch (const std::exception& error) {
      result_.error_message = error.what();
      result_.status = LinuxTraceWriterStatus::kWriterError;
      fill_result_counters();
      try {
        writer_.flush();
      } catch (...) {
      }
    } catch (...) {
      result_.error_message = "unknown trace writer failure";
      result_.status = LinuxTraceWriterStatus::kWriterError;
      fill_result_counters();
      try {
        writer_.flush();
      } catch (...) {
      }
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
        next_flush = now + options_.flush_interval;
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
    finalize_trace();
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
    if (hook == nullptr) {
      throw std::invalid_argument{"raw Linux heap event carries an unknown API ID"};
    }
    if (expected_operation(hook->logical_api) != raw_event.operation) {
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

  [[nodiscard]] noleax::trace::AllocationId make_allocation_id() {
    if (next_allocation_id_ == std::numeric_limits<std::uint64_t>::max()) {
      throw std::overflow_error{"allocation ID space is exhausted"};
    }
    return noleax::trace::AllocationId{next_allocation_id_++};
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
    if (raw_event.status == LinuxHeapEventStatus::kSuccess) {
      checked_add(counters.successful, 1U, "successful operation count overflow");
    } else {
      checked_add(counters.failed, 1U, "failed operation count overflow");
    }

    std::optional<noleax::trace::LossRecord> stack_capture_loss;
    if (raw_event.stack.status == StackCaptureStatus::kFailed) {
      stack_capture_loss = make_stack_capture_loss(raw_event.queue_sequence, normalized_ticks);
      checked_add(stack_capture_failures_, 1U, "stack capture failure count overflow");
      completeness_.observe_loss(*stack_capture_loss);
    }
    if (file_limit_reached_) {
      note_event_trace_drop(raw_event, normalized_ticks);
      return;
    }

    ensure_pending_capacity();
    if (file_limit_reached_) {
      note_event_trace_drop(raw_event, normalized_ticks);
      return;
    }

    const bool succeeded = raw_event.status == LinuxHeapEventStatus::kSuccess;
    noleax::trace::Event event;
    event.header.sequence = noleax::trace::Sequence{raw_event.queue_sequence};
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
        allocation.allocation_id = make_allocation_id();
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
            reallocation.new_allocation_id = make_allocation_id();
            reallocation.effect = noleax::trace::ReallocationEffect::kNewGeneration;
            live_allocations_.insert_or_assign(raw_event.result_address,
                                               reallocation.new_allocation_id);
          }
        } else {
          event.header.status = unmatched_status(raw_event.address);
          if (raw_event.result_address != 0U) {
            // realloc(NULL, n) allocates a fresh generation with no old one.
            reallocation.new_allocation_id = make_allocation_id();
            reallocation.effect = noleax::trace::ReallocationEffect::kNewGeneration;
            live_allocations_.insert_or_assign(raw_event.result_address,
                                               reallocation.new_allocation_id);
          }
        }
      }
      event.payload = reallocation;
    } else {
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
    }
    noleax::trace::append_event_record(event_payload_, event, options_.maximum_record_size);

    if (pending_event_count_ == 0U) {
      pending_sequence_begin_ = raw_event.queue_sequence;
      pending_tick_begin_ = normalized_ticks;
    }
    pending_sequence_end_ = raw_event.queue_sequence;
    pending_tick_end_ = normalized_ticks;
    checked_add(pending_event_count_, 1U, "pending event count overflow");
    checked_add(counters.pending, 1U, "pending per-API event count overflow");
    checked_add(pending_unique_stacks_, event_unique_stacks, "pending unique stack count overflow");
    checked_add(pending_reused_stacks_, event_reused_stacks, "pending reused stack count overflow");

    if (stack_payload_.size() >= options_.chunk_target_size ||
        event_payload_.size() >= options_.chunk_target_size) {
      flush_pending();
    }
  }

  void ensure_pending_capacity() {
    if (pending_event_count_ == 0U) {
      return;
    }
    const bool stack_would_exceed =
        stack_payload_.size() > options_.chunk_target_size ||
        kMaximumStackDefinitionRecordSize >
            options_.chunk_target_size -
                (std::min)(stack_payload_.size(), options_.chunk_target_size);
    const bool event_would_exceed =
        event_payload_.size() > options_.chunk_target_size ||
        kMaximumEventAdditionSize >
            options_.chunk_target_size -
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

  [[nodiscard]] noleax::trace::LossRecord make_stack_capture_loss(std::uint64_t sequence,
                                                                  std::uint64_t ticks) const {
    noleax::trace::LossRecord loss;
    loss.reason = noleax::trace::LossReason::kStackCaptureFailed;
    loss.location = noleax::trace::LossLocation::kAgentQueue;
    loss.estimated_event_count = 1U;
    loss.sequence_range = noleax::trace::SequenceRange{noleax::trace::Sequence{sequence},
                                                       noleax::trace::Sequence{sequence}};
    loss.tick_range = noleax::trace::TickRange{ticks, ticks};
    return loss;
  }

  [[nodiscard]] bool write_chunk(noleax::trace::ChunkType type, std::span<const std::byte> payload,
                                 noleax::trace::CompressionCodec codec,
                                 std::uint64_t sequence_begin = 0U,
                                 std::uint64_t sequence_end = 0U) {
    noleax::trace::ChunkDescriptor descriptor;
    descriptor.type = type;
    descriptor.codec = codec;
    descriptor.sequence_begin = noleax::trace::Sequence{sequence_begin};
    descriptor.sequence_end = noleax::trace::Sequence{sequence_end};
    if (writer_.write_chunk(descriptor, payload) == noleax::trace::ChunkWriteResult::kFileLimit) {
      file_limit_reached_ = true;
      return false;
    }
    return true;
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

  void note_event_trace_drop(const LinuxHeapEvent& raw_event, std::uint64_t ticks) {
    if (trace_dropped_events_ == 0U) {
      trace_drop_sequence_begin_ = raw_event.queue_sequence;
      trace_drop_tick_begin_ = ticks;
    }
    trace_drop_sequence_end_ = raw_event.queue_sequence;
    trace_drop_tick_end_ = ticks;
    checked_add(trace_dropped_events_, 1U, "trace drop count overflow");
    checked_add(api_counters_[hook_api_index(raw_event.api_id)].trace_dropped, 1U,
                "per-API trace drop count overflow");
  }

  void finalize_empty_trace() {
    write_metadata();
    writer_.release_file_reserve();
    noleax::trace::CaptureStatistics statistics;
    for (const LinuxHookRegistryEntry& entry : kLinuxHookRegistry) {
      statistics.per_api.push_back({entry.api_id, 0U, 0U, 0U, 0U, 0U});
    }
    write_terminal_records(statistics);
  }

  void finalize_trace() {
    writer_.release_file_reserve();
    noleax::trace::LossRecord module_loss;
    if (module_notification_drops_ != 0U) {
      module_loss.reason = noleax::trace::LossReason::kQueueFull;
      module_loss.location = noleax::trace::LossLocation::kAgentQueue;
      module_loss.estimated_event_count = module_notification_drops_;
      completeness_.observe_loss(module_loss);
    }
    noleax::trace::LossRecord queue_loss;
    if (queue_dropped_events_ != 0U) {
      queue_loss.reason = noleax::trace::LossReason::kQueueFull;
      queue_loss.location = noleax::trace::LossLocation::kAgentQueue;
      queue_loss.estimated_event_count = queue_dropped_events_;
      completeness_.observe_loss(queue_loss);
    }

    noleax::trace::LossRecord trace_loss;
    if (trace_dropped_events_ != 0U) {
      trace_loss.reason = noleax::trace::LossReason::kTraceFull;
      trace_loss.location = noleax::trace::LossLocation::kWriter;
      trace_loss.estimated_event_count = trace_dropped_events_;
      trace_loss.sequence_range =
          noleax::trace::SequenceRange{noleax::trace::Sequence{trace_drop_sequence_begin_},
                                       noleax::trace::Sequence{trace_drop_sequence_end_}};
      trace_loss.tick_range =
          noleax::trace::TickRange{trace_drop_tick_begin_, trace_drop_tick_end_};
      completeness_.observe_loss(trace_loss);
    }

    if (module_notification_drops_ != 0U || queue_dropped_events_ != 0U ||
        trace_dropped_events_ != 0U) {
      std::vector<std::byte> loss_payload;
      if (module_notification_drops_ != 0U) {
        noleax::trace::append_loss_record(loss_payload, module_loss, options_.maximum_record_size);
      }
      if (queue_dropped_events_ != 0U) {
        noleax::trace::append_loss_record(loss_payload, queue_loss, options_.maximum_record_size);
      }
      if (trace_dropped_events_ != 0U) {
        noleax::trace::append_loss_record(loss_payload, trace_loss, options_.maximum_record_size);
      }
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
    for (std::size_t index = 0U; index < kLinuxHookRegistry.size(); ++index) {
      const ApiCounters& counters = api_counters_[index];
      const LinuxTraceWriterApiCounterSnapshot* snapshot = nullptr;
      for (const auto& candidate : counter_snapshots) {
        if (candidate.api_id == kLinuxHookRegistry[index].api_id) {
          snapshot = &candidate;
          break;
        }
      }
      noleax::trace::ApiStatistics api;
      api.api_id = kLinuxHookRegistry[index].api_id;
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
    end.final_sequence = noleax::trace::Sequence{last_sequence_};
    end.final_monotonic_ticks =
        (std::max)((std::max)(last_ticks_, last_module_ticks_), monotonic_origin_);
    end.normal_stop = true;
    end.aggregate_completeness = completeness_.report();
    end.aggregate_completeness.remove(noleax::trace::CompletenessIssue::kMissingEndOfTrace);
    std::vector<std::byte> end_payload;
    noleax::trace::append_end_of_trace_record(end_payload, end, options_.maximum_record_size);
    result_.end_of_trace_written =
        write_terminal_chunk(noleax::trace::ChunkType::kEnd, end_payload);

    writer_.flush();
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
  }

  [[nodiscard]] static std::size_t hook_api_index(noleax::trace::ApiId api_id) {
    for (std::size_t index = 0U; index < kLinuxHookRegistry.size(); ++index) {
      if (kLinuxHookRegistry[index].api_id == api_id) {
        return index;
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
  std::ofstream output_;
  const std::uint64_t monotonic_origin_;
  NormalizedStackDictionary dictionary_;
  noleax::trace::TraceWriter writer_;
  noleax::trace::CompletenessTracker completeness_;

  std::optional<RawModuleEvent> pending_module_event_;
  std::vector<std::byte> module_payload_;
  std::vector<std::byte> stack_payload_;
  std::vector<std::byte> event_payload_;
  std::unordered_map<std::uint64_t, noleax::trace::AllocationId> live_allocations_;
  std::map<std::uint64_t, LiveModule> live_modules_;
  std::array<ApiCounters, kLinuxHookRegistry.size()> api_counters_{};
  std::thread worker_;
  mutable std::mutex state_mutex_;
  std::condition_variable state_changed_;
  std::atomic<bool> stop_requested_{false};
  std::atomic<bool> running_{true};
  bool thread_ready_{false};
  bool capture_begun_{false};
  bool metadata_written_{false};
  bool file_limit_reached_{false};
  bool initial_modules_processed_{false};
  bool inline_finalize_done_{false};
  bool finalized_{false};

  LinuxTraceWriterResult result_;
  std::uint64_t next_allocation_id_{1U};
  std::uint64_t next_module_id_{1U};
  std::uint64_t last_sequence_{0U};
  std::uint64_t last_ticks_{0U};
  std::uint64_t last_module_ticks_{0U};
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
};

LinuxTraceWriter::LinuxTraceWriter(LinuxHeapEventQueue& event_queue,
                                   LinuxModuleTracker& module_tracker,
                                   const std::filesystem::path& output_path,
                                   LinuxTraceWriterOptions options)
    : implementation_{
          std::make_unique<Implementation>(event_queue, module_tracker, output_path, options)} {}

LinuxTraceWriter::~LinuxTraceWriter() = default;

void LinuxTraceWriter::begin_capture() { implementation_->begin_capture(); }

LinuxTraceWriterResult LinuxTraceWriter::finish() { return implementation_->finish(); }

LinuxTraceWriterResult LinuxTraceWriter::finish_after_worker_exit() {
  return implementation_->finish_after_worker_exit();
}

bool LinuxTraceWriter::is_running() const noexcept { return implementation_->is_running(); }

}  // namespace noleax::agent::linux
