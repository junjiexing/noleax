#include "noleax/agent/windows/rtl_allocate_heap_trace_writer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/windows/stack_dictionary.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/record_codec.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/trace_writer.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::agent::windows {
namespace {

constexpr std::size_t kMaximumStackDefinitionRecordSize =
    noleax::trace::kRecordHeaderSize + 16U +
    static_cast<std::size_t>(kMaximumCapturedStackDepth) * 32U;
constexpr std::size_t kMaximumEventAdditionSize = 136U + 56U;
constexpr std::uint64_t kMinimumTerminalReserveSize = 1024U;
constexpr std::uint64_t kMaximumTerminalTailSize =
    (noleax::trace::kChunkHeaderSize + 2U * 56U) +
    (noleax::trace::kChunkHeaderSize + 8U + 80U + 3U * 48U) +
    (noleax::trace::kChunkHeaderSize + 8U + 40U);
constexpr auto kEmptyPollInterval = std::chrono::milliseconds{1};

static_assert(kMaximumTerminalTailSize <= kMinimumTerminalReserveSize);

[[nodiscard]] RtlAllocateHeapHook& validate_hook(RtlAllocateHeapHook& hook) {
  if (hook.is_installed()) {
    throw std::invalid_argument{"trace writer must start before the RtlAllocateHeap hook"};
  }
  if (!hook_guard_runtime_is_ready()) {
    throw std::invalid_argument{"trace writer requires an initialized hook guard runtime"};
  }
  return hook;
}

[[nodiscard]] RtlFreeHeapHook* validate_free_hook(RtlAllocateHeapHook& allocate_hook,
                                                  RtlFreeHeapHook* free_hook) {
  if (free_hook == nullptr) {
    return nullptr;
  }
  if (free_hook->is_installed()) {
    throw std::invalid_argument{"trace writer must start before the RtlFreeHeap hook"};
  }
  if (&allocate_hook.event_queue() != &free_hook->event_queue()) {
    throw std::invalid_argument{"RtlAllocateHeap and RtlFreeHeap must share one event queue"};
  }
  return free_hook;
}

[[nodiscard]] RtlReAllocateHeapHook* validate_reallocate_hook(
    RtlAllocateHeapHook& allocate_hook, RtlReAllocateHeapHook* reallocate_hook) {
  if (reallocate_hook == nullptr) {
    return nullptr;
  }
  if (reallocate_hook->is_installed()) {
    throw std::invalid_argument{"trace writer must start before the RtlReAllocateHeap hook"};
  }
  if (&allocate_hook.event_queue() != &reallocate_hook->event_queue()) {
    throw std::invalid_argument{"RtlAllocateHeap and RtlReAllocateHeap must share one event queue"};
  }
  return reallocate_hook;
}

struct AllocationKey {
  std::uint64_t heap_handle{0U};
  std::uint64_t address{0U};

  bool operator==(const AllocationKey&) const = default;
};

struct AllocationKeyHash {
  [[nodiscard]] std::size_t operator()(const AllocationKey& key) const noexcept {
    const std::size_t first = std::hash<std::uint64_t>{}(key.heap_handle);
    const std::size_t second = std::hash<std::uint64_t>{}(key.address);
    return first ^ (second + static_cast<std::size_t>(0x9e3779b9U) + (first << 6U) + (first >> 2U));
  }
};

[[nodiscard]] bool known_codec(noleax::trace::CompressionCodec codec) noexcept {
  switch (codec) {
    case noleax::trace::CompressionCodec::kNone:
    case noleax::trace::CompressionCodec::kLz4:
    case noleax::trace::CompressionCodec::kZstd:
      return true;
  }
  return false;
}

[[nodiscard]] RtlAllocateHeapTraceWriterOptions validate_options(
    RtlAllocateHeapTraceWriterOptions options) {
  noleax::trace::validate_capture_scope(options.capture_scope);
  if (!known_codec(options.compression)) {
    throw std::invalid_argument{"trace writer compression codec is not supported"};
  }
  if (options.flush_interval <= std::chrono::milliseconds::zero()) {
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
      options.trace.max_uncompressed_chunk_size < kMaximumStackDefinitionRecordSize ||
      options.trace.max_uncompressed_chunk_size < kMaximumEventAdditionSize) {
    throw std::invalid_argument{"trace writer limits cannot hold the largest raw stack event"};
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

}  // namespace

class RtlAllocateHeapTraceWriter::Implementation final {
 public:
  Implementation(RtlAllocateHeapHook& hook, std::ostream& output,
                 const noleax::trace::FileHeader& file_header,
                 RtlAllocateHeapTraceWriterOptions options,
                 RtlReAllocateHeapHook* reallocate_hook = nullptr,
                 RtlFreeHeapHook* free_hook = nullptr)
      : hook_{validate_hook(hook)},
        reallocate_hook_{validate_reallocate_hook(hook_, reallocate_hook)},
        free_hook_{validate_free_hook(hook_, free_hook)},
        options_{validate_options(options)},
        dictionary_{options_.stack_dictionary_capacity},
        writer_{output, file_header, options_.trace},
        completeness_{options_.capture_scope},
        monotonic_origin_{file_header.monotonic_origin} {
    stack_payload_.reserve(options_.chunk_target_size);
    event_payload_.reserve(options_.chunk_target_size);
    write_metadata();
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
    if (!hook_.is_installed() ||
        (reallocate_hook_ != nullptr && !reallocate_hook_->is_installed()) ||
        (free_hook_ != nullptr && !free_hook_->is_installed())) {
      throw std::logic_error{"all Rtl heap hooks must be installed before capture begins"};
    }
    capture_begun_ = true;
    state_changed_.notify_all();
  }

  void request_stop() noexcept {
    stop_requested_.store(true, std::memory_order_release);
    state_changed_.notify_all();
  }

  [[nodiscard]] RtlAllocateHeapTraceWriterResult finish() {
    if (hook_.is_installed() || hook_.has_pending_teardown() ||
        (reallocate_hook_ != nullptr &&
         (reallocate_hook_->is_installed() || reallocate_hook_->has_pending_teardown())) ||
        (free_hook_ != nullptr &&
         (free_hook_->is_installed() || free_hook_->has_pending_teardown()))) {
      throw std::logic_error{"all Rtl heap hooks must be fully uninstalled before writer finish"};
    }
    request_stop();
    if (worker_.joinable()) {
      worker_.join();
    }
    return result_;
  }

  [[nodiscard]] bool is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
  }

 private:
  void write_metadata() {
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
        state_changed_.wait(lock, [this] {
          return capture_begun_ || stop_requested_.load(std::memory_order_acquire);
        });
        capture_begun = capture_begun_;
      }
      if (capture_begun) {
        capture_loop();
      } else {
        finalize_empty_trace();
      }
    } catch (...) {
      result_.status = RtlAllocateHeapTraceWriterStatus::kWriterError;
      result_.stack_capture_failures = stack_capture_failures_;
      result_.queue_dropped_events = queue_dropped_events_;
      result_.trace_dropped_events = trace_dropped_events_;
      result_.timestamp_adjustments = timestamp_adjustments_;
      result_.bytes_written = writer_.bytes_written();
      result_.stack_dictionary_segments = dictionary_.segment_count();
      try {
        writer_.flush();
      } catch (...) {
      }
    }
    running_.store(false, std::memory_order_release);
  }

  void capture_loop() {
    auto next_flush = std::chrono::steady_clock::now() + options_.flush_interval;
    for (;;) {
      bool drained_event = false;
      RtlAllocateHeapEvent raw_event;
      while (hook_.try_dequeue_event(raw_event)) {
        drained_event = true;
        process_event(raw_event);
      }
      collect_queue_drops();

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

    // The P4.7 caller stops producers before requesting writer shutdown. P4.8 adds an explicit
    // replacement in-flight barrier for this final drain boundary.
    RtlAllocateHeapEvent raw_event;
    while (hook_.try_dequeue_event(raw_event)) {
      process_event(raw_event);
    }
    collect_queue_drops();
    flush_pending();
    finalize_trace();
  }

  void validate_raw_event(const RtlAllocateHeapEvent& raw_event) const {
    if (raw_event.queue_sequence == 0U || raw_event.thread_id == 0U ||
        raw_event.monotonic_ticks < monotonic_origin_) {
      throw std::invalid_argument{"raw Rtl heap event header is invalid"};
    }
    const bool succeeded = raw_event.status == RtlAllocateHeapEventStatus::kSuccess;
    const bool exceptional = raw_event.status == RtlAllocateHeapEventStatus::kException;
    if ((raw_event.status != RtlAllocateHeapEventStatus::kSuccess &&
         raw_event.status != RtlAllocateHeapEventStatus::kFailure && !exceptional) ||
        exceptional != (raw_event.exception_status != 0U)) {
      throw std::invalid_argument{"raw Rtl heap event result is inconsistent"};
    }
    switch (raw_event.operation) {
      case RtlHeapEventOperation::kAllocate:
        if (succeeded != (raw_event.result_address != 0U) || raw_event.address != 0U ||
            raw_event.raw_result != 0U) {
          throw std::invalid_argument{"raw RtlAllocateHeap event result is inconsistent"};
        }
        break;
      case RtlHeapEventOperation::kFree:
        if (free_hook_ == nullptr || raw_event.requested_size != 0U ||
            raw_event.result_address != 0U || succeeded != (raw_event.raw_result != 0U)) {
          throw std::invalid_argument{"raw RtlFreeHeap event result is inconsistent"};
        }
        break;
      case RtlHeapEventOperation::kReallocate:
        if (reallocate_hook_ == nullptr || succeeded != (raw_event.result_address != 0U) ||
            raw_event.raw_result != 0U) {
          throw std::invalid_argument{"raw RtlReAllocateHeap event result is inconsistent"};
        }
        break;
      default:
        throw std::invalid_argument{"raw Rtl heap event operation is not supported"};
    }
    if (last_sequence_ == std::numeric_limits<std::uint64_t>::max() ||
        raw_event.queue_sequence != last_sequence_ + 1U) {
      throw std::invalid_argument{"raw Rtl heap event sequence is not contiguous"};
    }
  }

  void validate_raw_stack(const CapturedStack& stack) const {
    if (stack.requested_depth > kMaximumCapturedStackDepth) {
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

  void process_event(const RtlAllocateHeapEvent& raw_event) {
    validate_raw_event(raw_event);
    validate_raw_stack(raw_event.stack);
    last_sequence_ = raw_event.queue_sequence;
    std::uint64_t normalized_ticks = raw_event.monotonic_ticks;
    if (normalized_ticks < last_ticks_) {
      normalized_ticks = last_ticks_;
      checked_add(timestamp_adjustments_, 1U, "timestamp adjustment count overflow");
    }
    last_ticks_ = normalized_ticks;

    std::optional<noleax::trace::LossRecord> stack_capture_loss;
    if (raw_event.stack.status == StackCaptureStatus::kFailed) {
      stack_capture_loss = make_stack_capture_loss(raw_event.queue_sequence, normalized_ticks);
      checked_add(stack_capture_failures_, 1U, "stack capture failure count overflow");
      completeness_.observe_loss(*stack_capture_loss);
    }
    if (file_limit_reached_) {
      note_trace_drop(raw_event.operation, raw_event.queue_sequence, normalized_ticks);
      return;
    }

    ensure_pending_capacity();
    if (file_limit_reached_) {
      note_trace_drop(raw_event.operation, raw_event.queue_sequence, normalized_ticks);
      return;
    }

    noleax::trace::Event event;
    event.header.sequence = noleax::trace::Sequence{raw_event.queue_sequence};
    event.header.monotonic_ticks = normalized_ticks;
    event.header.thread_id = raw_event.thread_id;
    switch (raw_event.operation) {
      case RtlHeapEventOperation::kAllocate:
        event.header.api_id = kRtlAllocateHeapApiId;
        break;
      case RtlHeapEventOperation::kReallocate:
        event.header.api_id = kRtlReAllocateHeapApiId;
        break;
      case RtlHeapEventOperation::kFree:
        event.header.api_id = kRtlFreeHeapApiId;
        break;
    }
    event.header.status = raw_event.status == RtlAllocateHeapEventStatus::kSuccess
                              ? noleax::trace::EventStatus::kSuccess
                              : noleax::trace::EventStatus::kFailure;
    if (raw_event.status == RtlAllocateHeapEventStatus::kException) {
      event.header.system_error = {noleax::trace::SystemErrorDomain::kNtStatus,
                                   raw_event.exception_status};
    }

    std::uint64_t event_unique_stacks = 0U;
    std::uint64_t event_reused_stacks = 0U;
    if (stack_capture_succeeded(raw_event.stack)) {
      const RawStackInternResult interned =
          dictionary_.intern(raw_event.stack, hash_captured_stack(raw_event.stack));
      event.header.stack_id = interned.stack_id;
      if (interned.inserted) {
        append_stack_definition(interned.stack_id, raw_event.stack);
        event_unique_stacks = 1U;
      } else {
        event_reused_stacks = 1U;
      }
    } else if (stack_capture_loss.has_value()) {
      noleax::trace::append_loss_record(event_payload_, *stack_capture_loss,
                                        options_.maximum_record_size);
    }

    if (raw_event.operation == RtlHeapEventOperation::kAllocate) {
      noleax::trace::AllocationEvent allocation;
      allocation.heap_handle = raw_event.heap_handle;
      allocation.requested_size = raw_event.requested_size;
      allocation.result_address = raw_event.result_address;
      allocation.api_flags = raw_event.flags;
      if (raw_event.status == RtlAllocateHeapEventStatus::kSuccess) {
        if (next_allocation_id_ == std::numeric_limits<std::uint64_t>::max()) {
          throw std::overflow_error{"allocation ID space is exhausted"};
        }
        allocation.allocation_id = noleax::trace::AllocationId{next_allocation_id_++};
        live_allocations_.insert_or_assign(
            AllocationKey{raw_event.heap_handle, raw_event.result_address},
            allocation.allocation_id);
      }
      event.payload = allocation;
    } else if (raw_event.operation == RtlHeapEventOperation::kReallocate) {
      noleax::trace::ReallocationEvent reallocation;
      reallocation.heap_handle = raw_event.heap_handle;
      reallocation.old_address = raw_event.address;
      reallocation.requested_size = raw_event.requested_size;
      reallocation.result_address = raw_event.result_address;
      reallocation.api_flags = raw_event.flags;
      const AllocationKey old_key{raw_event.heap_handle, raw_event.address};
      const auto old_allocation = live_allocations_.find(old_key);
      if (old_allocation != live_allocations_.end()) {
        reallocation.old_allocation_id = old_allocation->second;
      }
      if (raw_event.status == RtlAllocateHeapEventStatus::kSuccess) {
        if (next_allocation_id_ == std::numeric_limits<std::uint64_t>::max()) {
          throw std::overflow_error{"allocation ID space is exhausted"};
        }
        if (old_allocation != live_allocations_.end()) {
          live_allocations_.erase(old_allocation);
        } else {
          event.header.status =
              raw_event.address != 0U && options_.capture_scope.preexisting_allocations_unknown
                  ? noleax::trace::EventStatus::kPreexisting
                  : noleax::trace::EventStatus::kUnmatched;
        }
        reallocation.new_allocation_id = noleax::trace::AllocationId{next_allocation_id_++};
        reallocation.effect = noleax::trace::ReallocationEffect::kNewGeneration;
        live_allocations_.insert_or_assign(
            AllocationKey{raw_event.heap_handle, raw_event.result_address},
            reallocation.new_allocation_id);
      }
      event.payload = reallocation;
    } else {
      noleax::trace::FreeEvent free_event;
      free_event.heap_handle = raw_event.heap_handle;
      free_event.address = raw_event.address;
      free_event.raw_result = raw_event.raw_result;
      free_event.api_flags = raw_event.flags;
      if (raw_event.status == RtlAllocateHeapEventStatus::kSuccess) {
        const auto allocation =
            live_allocations_.find(AllocationKey{raw_event.heap_handle, raw_event.address});
        if (allocation != live_allocations_.end()) {
          free_event.allocation_id = allocation->second;
          live_allocations_.erase(allocation);
        } else {
          event.header.status =
              raw_event.address != 0U && options_.capture_scope.preexisting_allocations_unknown
                  ? noleax::trace::EventStatus::kPreexisting
                  : noleax::trace::EventStatus::kUnmatched;
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
    if (raw_event.operation == RtlHeapEventOperation::kAllocate) {
      checked_add(pending_allocate_events_, 1U, "pending allocation event count overflow");
    } else if (raw_event.operation == RtlHeapEventOperation::kReallocate) {
      checked_add(pending_reallocate_events_, 1U, "pending reallocation event count overflow");
    } else {
      checked_add(pending_free_events_, 1U, "pending free event count overflow");
    }
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

  void append_stack_definition(noleax::trace::StackId stack_id, const CapturedStack& stack) {
    noleax::trace::StackDefinition definition;
    definition.stack_id = stack_id;
    definition.status = trace_stack_status(stack.status);
    definition.frames.reserve(stack.frame_count);
    for (std::uint16_t index = 0U; index < stack.frame_count; ++index) {
      definition.frames.push_back({{}, 0U, stack.frames[index], 0U});
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

  void collect_queue_drops() {
    const std::uint64_t allocate_dropped = hook_.take_dropped_event_count();
    checked_add(queue_allocate_dropped_events_, allocate_dropped,
                "allocation queue drop count overflow");
    checked_add(queue_dropped_events_, allocate_dropped, "queue drop count overflow");
    if (free_hook_ != nullptr) {
      const std::uint64_t free_dropped = free_hook_->take_dropped_event_count();
      checked_add(queue_free_dropped_events_, free_dropped, "free queue drop count overflow");
      checked_add(queue_dropped_events_, free_dropped, "queue drop count overflow");
    }
    if (reallocate_hook_ != nullptr) {
      const std::uint64_t reallocate_dropped = reallocate_hook_->take_dropped_event_count();
      checked_add(queue_reallocate_dropped_events_, reallocate_dropped,
                  "reallocation queue drop count overflow");
      checked_add(queue_dropped_events_, reallocate_dropped, "queue drop count overflow");
    }
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

  void flush_pending() {
    if (pending_event_count_ == 0U) {
      return;
    }
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
    checked_add(written_allocate_events_, pending_allocate_events_,
                "written allocation event count overflow");
    checked_add(written_reallocate_events_, pending_reallocate_events_,
                "written reallocation event count overflow");
    checked_add(written_free_events_, pending_free_events_, "written free event count overflow");
    checked_add(unique_stacks_, pending_unique_stacks_, "unique stack count overflow");
    checked_add(reused_stacks_, pending_reused_stacks_, "reused stack count overflow");
    clear_pending();
  }

  void drop_pending_events() {
    if (pending_event_count_ != 0U) {
      note_trace_drop_range(pending_event_count_, pending_allocate_events_,
                            pending_reallocate_events_, pending_free_events_,
                            pending_sequence_begin_, pending_sequence_end_, pending_tick_begin_,
                            pending_tick_end_);
    }
    clear_pending();
  }

  void clear_pending() noexcept {
    stack_payload_.clear();
    event_payload_.clear();
    pending_event_count_ = 0U;
    pending_allocate_events_ = 0U;
    pending_reallocate_events_ = 0U;
    pending_free_events_ = 0U;
    pending_unique_stacks_ = 0U;
    pending_reused_stacks_ = 0U;
    pending_sequence_begin_ = 0U;
    pending_sequence_end_ = 0U;
    pending_tick_begin_ = 0U;
    pending_tick_end_ = 0U;
  }

  void note_trace_drop(RtlHeapEventOperation operation, std::uint64_t sequence,
                       std::uint64_t ticks) {
    const std::uint64_t allocate_count = operation == RtlHeapEventOperation::kAllocate ? 1U : 0U;
    const std::uint64_t reallocate_count =
        operation == RtlHeapEventOperation::kReallocate ? 1U : 0U;
    note_trace_drop_range(1U, allocate_count, reallocate_count,
                          1U - allocate_count - reallocate_count, sequence, sequence, ticks, ticks);
  }

  void note_trace_drop_range(std::uint64_t count, std::uint64_t allocate_count,
                             std::uint64_t reallocate_count, std::uint64_t free_count,
                             std::uint64_t sequence_begin, std::uint64_t sequence_end,
                             std::uint64_t tick_begin, std::uint64_t tick_end) {
    if (allocate_count > count || reallocate_count > count - allocate_count ||
        free_count != count - allocate_count - reallocate_count) {
      throw std::logic_error{"trace drop API accounting is inconsistent"};
    }
    if (trace_dropped_events_ == 0U) {
      trace_drop_sequence_begin_ = sequence_begin;
      trace_drop_tick_begin_ = tick_begin;
    }
    trace_drop_sequence_end_ = sequence_end;
    trace_drop_tick_end_ = tick_end;
    checked_add(trace_dropped_events_, count, "trace drop count overflow");
    checked_add(trace_allocate_dropped_events_, allocate_count,
                "allocation trace drop count overflow");
    checked_add(trace_reallocate_dropped_events_, reallocate_count,
                "reallocation trace drop count overflow");
    checked_add(trace_free_dropped_events_, free_count, "free trace drop count overflow");
  }

  void finalize_empty_trace() {
    writer_.release_file_reserve();
    noleax::trace::CaptureStatistics statistics;
    statistics.per_api.push_back({kRtlAllocateHeapApiId, 0U, 0U, 0U, 0U, 0U});
    if (reallocate_hook_ != nullptr) {
      statistics.per_api.push_back({kRtlReAllocateHeapApiId, 0U, 0U, 0U, 0U, 0U});
    }
    if (free_hook_ != nullptr) {
      statistics.per_api.push_back({kRtlFreeHeapApiId, 0U, 0U, 0U, 0U, 0U});
    }
    write_terminal_records(statistics);
  }

  void finalize_trace() {
    writer_.release_file_reserve();
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

    if (queue_dropped_events_ != 0U || trace_dropped_events_ != 0U) {
      std::vector<std::byte> loss_payload;
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
    std::uint64_t allocate_dropped = queue_allocate_dropped_events_;
    checked_add(allocate_dropped, trace_allocate_dropped_events_,
                "allocation dropped event count overflow");
    const noleax::trace::ApiStatistics allocate_statistics{kRtlAllocateHeapApiId,
                                                           hook_.recordable_call_count(),
                                                           hook_.successful_call_count(),
                                                           hook_.failed_call_count(),
                                                           0U,
                                                           allocate_dropped};
    statistics.per_api.push_back(allocate_statistics);
    std::optional<noleax::trace::ApiStatistics> reallocate_statistics;
    if (reallocate_hook_ != nullptr) {
      std::uint64_t reallocate_dropped = queue_reallocate_dropped_events_;
      checked_add(reallocate_dropped, trace_reallocate_dropped_events_,
                  "reallocation dropped event count overflow");
      reallocate_statistics =
          noleax::trace::ApiStatistics{kRtlReAllocateHeapApiId,
                                       reallocate_hook_->recordable_call_count(),
                                       reallocate_hook_->successful_call_count(),
                                       reallocate_hook_->failed_call_count(),
                                       0U,
                                       reallocate_dropped};
      statistics.per_api.push_back(*reallocate_statistics);
    }
    if (free_hook_ != nullptr) {
      std::uint64_t free_dropped = queue_free_dropped_events_;
      checked_add(free_dropped, trace_free_dropped_events_, "free dropped event count overflow");
      statistics.per_api.push_back({kRtlFreeHeapApiId, free_hook_->recordable_call_count(),
                                    free_hook_->successful_call_count(),
                                    free_hook_->failed_call_count(), 0U, free_dropped});
    }
    for (const noleax::trace::ApiStatistics& api : statistics.per_api) {
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
    checked_add(accounted_events, statistics.dropped_events, "accounted event count overflow");
    if (completed_operations != statistics.observed_calls ||
        accounted_events != statistics.observed_calls) {
      throw std::runtime_error{"hook counters do not reconcile with drained trace events"};
    }
    std::uint64_t accounted_allocations = written_allocate_events_;
    checked_add(accounted_allocations, allocate_statistics.dropped_events,
                "accounted allocation event count overflow");
    if (accounted_allocations != allocate_statistics.observed_calls) {
      throw std::runtime_error{"RtlAllocateHeap counters do not reconcile with trace events"};
    }
    if (free_hook_ != nullptr) {
      const noleax::trace::ApiStatistics& free_statistics = statistics.per_api.back();
      std::uint64_t accounted_frees = written_free_events_;
      checked_add(accounted_frees, free_statistics.dropped_events,
                  "accounted free event count overflow");
      if (accounted_frees != free_statistics.observed_calls) {
        throw std::runtime_error{"RtlFreeHeap counters do not reconcile with trace events"};
      }
    }
    if (reallocate_statistics.has_value()) {
      std::uint64_t accounted_reallocations = written_reallocate_events_;
      checked_add(accounted_reallocations, reallocate_statistics->dropped_events,
                  "accounted reallocation event count overflow");
      if (accounted_reallocations != reallocate_statistics->observed_calls) {
        throw std::runtime_error{"RtlReAllocateHeap counters do not reconcile with trace events"};
      }
    }
    write_terminal_records(statistics);
  }

  void write_terminal_records(const noleax::trace::CaptureStatistics& statistics) {
    noleax::trace::validate_statistics(statistics);
    result_.statistics = statistics;

    std::vector<std::byte> statistics_payload;
    noleax::trace::append_statistics_record(statistics_payload, statistics,
                                            options_.maximum_record_size);
    result_.statistics_written =
        write_terminal_chunk(noleax::trace::ChunkType::kStatistics, statistics_payload);

    noleax::trace::EndOfTrace end;
    end.final_sequence = noleax::trace::Sequence{last_sequence_};
    end.final_monotonic_ticks = (std::max)(last_ticks_, monotonic_origin_);
    end.normal_stop = true;
    end.aggregate_completeness = completeness_.report();
    end.aggregate_completeness.remove(noleax::trace::CompletenessIssue::kMissingEndOfTrace);
    std::vector<std::byte> end_payload;
    noleax::trace::append_end_of_trace_record(end_payload, end, options_.maximum_record_size);
    result_.end_of_trace_written =
        write_terminal_chunk(noleax::trace::ChunkType::kEnd, end_payload);

    writer_.flush();
    result_.status = file_limit_reached_ ? RtlAllocateHeapTraceWriterStatus::kFileLimit
                                         : RtlAllocateHeapTraceWriterStatus::kComplete;
    result_.stack_capture_failures = stack_capture_failures_;
    result_.queue_dropped_events = queue_dropped_events_;
    result_.trace_dropped_events = trace_dropped_events_;
    result_.timestamp_adjustments = timestamp_adjustments_;
    result_.stack_dictionary_segments = dictionary_.segment_count();
    result_.bytes_written = writer_.bytes_written();
  }

  RtlAllocateHeapHook& hook_;
  RtlReAllocateHeapHook* const reallocate_hook_;
  RtlFreeHeapHook* const free_hook_;
  const RtlAllocateHeapTraceWriterOptions options_;
  RawStackDictionary dictionary_;
  noleax::trace::TraceWriter writer_;
  noleax::trace::CompletenessTracker completeness_;
  const std::uint64_t monotonic_origin_;

  std::vector<std::byte> stack_payload_;
  std::vector<std::byte> event_payload_;
  std::unordered_map<AllocationKey, noleax::trace::AllocationId, AllocationKeyHash>
      live_allocations_;
  std::thread worker_;
  mutable std::mutex state_mutex_;
  std::condition_variable state_changed_;
  std::atomic<bool> stop_requested_{false};
  std::atomic<bool> running_{true};
  bool thread_ready_{false};
  bool capture_begun_{false};
  bool file_limit_reached_{false};

  RtlAllocateHeapTraceWriterResult result_;
  std::uint64_t next_allocation_id_{1U};
  std::uint64_t last_sequence_{0U};
  std::uint64_t last_ticks_{0U};
  std::uint64_t pending_event_count_{0U};
  std::uint64_t pending_allocate_events_{0U};
  std::uint64_t pending_reallocate_events_{0U};
  std::uint64_t pending_free_events_{0U};
  std::uint64_t pending_unique_stacks_{0U};
  std::uint64_t pending_reused_stacks_{0U};
  std::uint64_t pending_sequence_begin_{0U};
  std::uint64_t pending_sequence_end_{0U};
  std::uint64_t pending_tick_begin_{0U};
  std::uint64_t pending_tick_end_{0U};
  std::uint64_t written_events_{0U};
  std::uint64_t written_allocate_events_{0U};
  std::uint64_t written_reallocate_events_{0U};
  std::uint64_t written_free_events_{0U};
  std::uint64_t queue_dropped_events_{0U};
  std::uint64_t queue_allocate_dropped_events_{0U};
  std::uint64_t queue_reallocate_dropped_events_{0U};
  std::uint64_t queue_free_dropped_events_{0U};
  std::uint64_t trace_dropped_events_{0U};
  std::uint64_t trace_allocate_dropped_events_{0U};
  std::uint64_t trace_reallocate_dropped_events_{0U};
  std::uint64_t trace_free_dropped_events_{0U};
  std::uint64_t trace_drop_sequence_begin_{0U};
  std::uint64_t trace_drop_sequence_end_{0U};
  std::uint64_t trace_drop_tick_begin_{0U};
  std::uint64_t trace_drop_tick_end_{0U};
  std::uint64_t stack_capture_failures_{0U};
  std::uint64_t timestamp_adjustments_{0U};
  std::uint64_t unique_stacks_{0U};
  std::uint64_t reused_stacks_{0U};
};

RtlAllocateHeapTraceWriter::RtlAllocateHeapTraceWriter(RtlAllocateHeapHook& hook,
                                                       std::ostream& output,
                                                       const noleax::trace::FileHeader& file_header,
                                                       RtlAllocateHeapTraceWriterOptions options)
    : implementation_{std::make_unique<Implementation>(hook, output, file_header, options)} {}

RtlAllocateHeapTraceWriter::RtlAllocateHeapTraceWriter(RtlAllocateHeapHook& allocate_hook,
                                                       RtlFreeHeapHook& free_hook,
                                                       std::ostream& output,
                                                       const noleax::trace::FileHeader& file_header,
                                                       RtlAllocateHeapTraceWriterOptions options)
    : implementation_{std::make_unique<Implementation>(allocate_hook, output, file_header, options,
                                                       nullptr, &free_hook)} {}

RtlAllocateHeapTraceWriter::RtlAllocateHeapTraceWriter(RtlAllocateHeapHook& allocate_hook,
                                                       RtlReAllocateHeapHook& reallocate_hook,
                                                       RtlFreeHeapHook& free_hook,
                                                       std::ostream& output,
                                                       const noleax::trace::FileHeader& file_header,
                                                       RtlAllocateHeapTraceWriterOptions options)
    : implementation_{std::make_unique<Implementation>(allocate_hook, output, file_header, options,
                                                       &reallocate_hook, &free_hook)} {}

RtlAllocateHeapTraceWriter::~RtlAllocateHeapTraceWriter() = default;

void RtlAllocateHeapTraceWriter::begin_capture() { implementation_->begin_capture(); }

RtlAllocateHeapTraceWriterResult RtlAllocateHeapTraceWriter::finish() {
  return implementation_->finish();
}

bool RtlAllocateHeapTraceWriter::is_running() const noexcept {
  return implementation_->is_running();
}

}  // namespace noleax::agent::windows
