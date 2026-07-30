#include "noleax/agent/windows/rtl_allocate_heap_trace_writer.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
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
constexpr std::size_t kMaximumEventAdditionSize = 152U + 56U;
constexpr std::uint64_t kMinimumTerminalReserveSize = 1024U;
constexpr std::uint64_t kMaximumTerminalTailSize =
    (noleax::trace::kChunkHeaderSize + 2U * 56U) +
    (noleax::trace::kChunkHeaderSize + 8U + 80U + 9U * 48U) +
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

[[nodiscard]] NtMemoryHooks& validate_nt_memory_hooks(NtMemoryHooks& hooks) {
  if (hooks.is_installed()) {
    throw std::invalid_argument{"trace writer must start before the NT memory hooks"};
  }
  if (!hook_guard_runtime_is_ready()) {
    throw std::invalid_argument{"trace writer requires an initialized hook guard runtime"};
  }
  return hooks;
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

[[nodiscard]] RtlCreateHeapHook* validate_create_hook(RtlAllocateHeapHook& allocate_hook,
                                                      RtlCreateHeapHook* create_hook) {
  if (create_hook == nullptr) {
    return nullptr;
  }
  if (create_hook->is_installed()) {
    throw std::invalid_argument{"trace writer must start before the RtlCreateHeap hook"};
  }
  if (&allocate_hook.event_queue() != &create_hook->event_queue()) {
    throw std::invalid_argument{"RtlCreateHeap and RtlAllocateHeap must share one event queue"};
  }
  return create_hook;
}

[[nodiscard]] RtlDestroyHeapHook* validate_destroy_hook(RtlAllocateHeapHook& allocate_hook,
                                                        RtlDestroyHeapHook* destroy_hook) {
  if (destroy_hook == nullptr) {
    return nullptr;
  }
  if (destroy_hook->is_installed()) {
    throw std::invalid_argument{"trace writer must start before the RtlDestroyHeap hook"};
  }
  if (&allocate_hook.event_queue() != &destroy_hook->event_queue()) {
    throw std::invalid_argument{"RtlAllocateHeap and RtlDestroyHeap must share one event queue"};
  }
  return destroy_hook;
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

struct VirtualMapping {
  noleax::trace::MappingId mapping_id;
  std::uint64_t base{0U};
  std::uint64_t size{0U};
};

[[nodiscard]] noleax::trace::ProcessTarget classify_process_target(
    std::uint64_t raw_handle, std::uint64_t process_id) noexcept {
  noleax::trace::ProcessTarget target;
  target.process_handle = raw_handle;
  target.process_id = process_id;
  if (process_id == 0U) {
    target.scope = noleax::trace::ProcessMemoryScope::kUnknown;
  } else if (process_id == GetCurrentProcessId()) {
    target.scope = noleax::trace::ProcessMemoryScope::kCurrentProcess;
  } else {
    target.scope = noleax::trace::ProcessMemoryScope::kRemoteProcess;
  }
  return target;
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
                 RtlFreeHeapHook* free_hook = nullptr, RtlCreateHeapHook* create_hook = nullptr,
                 RtlDestroyHeapHook* destroy_hook = nullptr)
      : hook_{&validate_hook(hook)},
        reallocate_hook_{validate_reallocate_hook(*hook_, reallocate_hook)},
        free_hook_{validate_free_hook(*hook_, free_hook)},
        create_hook_{validate_create_hook(*hook_, create_hook)},
        destroy_hook_{validate_destroy_hook(*hook_, destroy_hook)},
        nt_memory_hooks_{nullptr},
        event_queue_{hook_->event_queue()},
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

  Implementation(NtMemoryHooks& nt_memory_hooks, std::ostream& output,
                 const noleax::trace::FileHeader& file_header,
                 RtlAllocateHeapTraceWriterOptions options)
      : hook_{nullptr},
        reallocate_hook_{nullptr},
        free_hook_{nullptr},
        create_hook_{nullptr},
        destroy_hook_{nullptr},
        nt_memory_hooks_{&validate_nt_memory_hooks(nt_memory_hooks)},
        event_queue_{nt_memory_hooks_->event_queue()},
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
    if ((hook_ != nullptr && !hook_->is_installed()) ||
        (reallocate_hook_ != nullptr && !reallocate_hook_->is_installed()) ||
        (free_hook_ != nullptr && !free_hook_->is_installed()) ||
        (create_hook_ != nullptr && !create_hook_->is_installed()) ||
        (destroy_hook_ != nullptr && !destroy_hook_->is_installed()) ||
        (nt_memory_hooks_ != nullptr && !nt_memory_hooks_->is_installed())) {
      throw std::logic_error{"all selected memory hooks must be installed before capture begins"};
    }
    capture_begun_ = true;
    state_changed_.notify_all();
  }

  void request_stop() noexcept {
    stop_requested_.store(true, std::memory_order_release);
    state_changed_.notify_all();
  }

  [[nodiscard]] RtlAllocateHeapTraceWriterResult finish() {
    if ((hook_ != nullptr && (hook_->is_installed() || hook_->has_pending_teardown())) ||
        (reallocate_hook_ != nullptr &&
         (reallocate_hook_->is_installed() || reallocate_hook_->has_pending_teardown())) ||
        (free_hook_ != nullptr &&
         (free_hook_->is_installed() || free_hook_->has_pending_teardown())) ||
        (create_hook_ != nullptr &&
         (create_hook_->is_installed() || create_hook_->has_pending_teardown())) ||
        (destroy_hook_ != nullptr &&
         (destroy_hook_->is_installed() || destroy_hook_->has_pending_teardown())) ||
        (nt_memory_hooks_ != nullptr &&
         (nt_memory_hooks_->is_installed() || nt_memory_hooks_->has_pending_teardown()))) {
      throw std::logic_error{"all selected memory hooks must be fully uninstalled before finish"};
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
    } catch (const std::exception& error) {
      result_.error_message = error.what();
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
    } catch (...) {
      result_.error_message = "unknown trace writer failure";
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
      while (event_queue_.try_pop(raw_event)) {
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
    while (event_queue_.try_pop(raw_event)) {
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
    const bool nt_memory_event = raw_event.operation == RtlHeapEventOperation::kVmAllocate ||
                                 raw_event.operation == RtlHeapEventOperation::kVmFree ||
                                 raw_event.operation == RtlHeapEventOperation::kSectionMap ||
                                 raw_event.operation == RtlHeapEventOperation::kSectionUnmap;
    if ((raw_event.status != RtlAllocateHeapEventStatus::kSuccess &&
         raw_event.status != RtlAllocateHeapEventStatus::kFailure && !exceptional) ||
        exceptional != (raw_event.exception_status != 0U)) {
      throw std::invalid_argument{"raw Rtl heap event result is inconsistent"};
    }
    if (!nt_memory_event && (raw_event.target_process_id != 0U || raw_event.mapping_base != 0U ||
                             raw_event.mapping_size != 0U || raw_event.section_handle != 0U ||
                             raw_event.section_offset != 0U || raw_event.commit_size != 0U ||
                             raw_event.tertiary_flags != 0U)) {
      throw std::invalid_argument{"raw Rtl heap event contains NT memory fields"};
    }
    switch (raw_event.operation) {
      case RtlHeapEventOperation::kCreate:
        if (create_hook_ == nullptr || succeeded != (raw_event.result_address != 0U) ||
            raw_event.secondary_flags != 0U || raw_event.operation_result != 0U) {
          throw std::invalid_argument{"raw RtlCreateHeap event result is inconsistent"};
        }
        break;
      case RtlHeapEventOperation::kAllocate:
        if (hook_ == nullptr || succeeded != (raw_event.result_address != 0U) ||
            raw_event.address != 0U || raw_event.raw_result != 0U ||
            raw_event.auxiliary_address != 0U || raw_event.secondary_flags != 0U ||
            raw_event.operation_result != 0U) {
          throw std::invalid_argument{"raw RtlAllocateHeap event result is inconsistent"};
        }
        break;
      case RtlHeapEventOperation::kFree:
        if (free_hook_ == nullptr || raw_event.requested_size != 0U ||
            raw_event.result_address != 0U || raw_event.auxiliary_address != 0U ||
            raw_event.secondary_flags != 0U || raw_event.operation_result != 0U ||
            succeeded != (raw_event.raw_result != 0U)) {
          throw std::invalid_argument{"raw RtlFreeHeap event result is inconsistent"};
        }
        break;
      case RtlHeapEventOperation::kReallocate:
        if (reallocate_hook_ == nullptr || succeeded != (raw_event.result_address != 0U) ||
            raw_event.raw_result != 0U || raw_event.auxiliary_address != 0U) {
          throw std::invalid_argument{"raw RtlReAllocateHeap event result is inconsistent"};
        }
        if (raw_event.secondary_flags != 0U || raw_event.operation_result != 0U) {
          throw std::invalid_argument{"raw RtlReAllocateHeap event result is inconsistent"};
        }
        break;
      case RtlHeapEventOperation::kDestroy:
        if (destroy_hook_ == nullptr || raw_event.requested_size != 0U ||
            raw_event.result_address != 0U || raw_event.address != 0U ||
            raw_event.auxiliary_address != 0U || raw_event.flags != 0U ||
            raw_event.secondary_flags != 0U || raw_event.operation_result != 0U ||
            (raw_event.status == RtlHeapEventStatus::kSuccess && raw_event.raw_result != 0U) ||
            (raw_event.status == RtlHeapEventStatus::kFailure && raw_event.raw_result == 0U)) {
          throw std::invalid_argument{"raw RtlDestroyHeap event result is inconsistent"};
        }
        break;
      case RtlHeapEventOperation::kVmAllocate:
        if (nt_memory_hooks_ == nullptr || raw_event.section_handle != 0U ||
            raw_event.section_offset != 0U || raw_event.commit_size != 0U ||
            raw_event.tertiary_flags != 0U ||
            (!exceptional &&
             succeeded != (static_cast<std::int32_t>(raw_event.operation_result) >= 0))) {
          throw std::invalid_argument{"raw NtAllocateVirtualMemory event is inconsistent"};
        }
        break;
      case RtlHeapEventOperation::kVmFree:
        if (nt_memory_hooks_ == nullptr || raw_event.auxiliary_address != 0U ||
            raw_event.secondary_flags != 0U || raw_event.mapping_base != 0U ||
            raw_event.mapping_size != 0U || raw_event.section_handle != 0U ||
            raw_event.section_offset != 0U || raw_event.commit_size != 0U ||
            raw_event.tertiary_flags != 0U ||
            (!exceptional &&
             succeeded != (static_cast<std::int32_t>(raw_event.operation_result) >= 0))) {
          throw std::invalid_argument{"raw NtFreeVirtualMemory event is inconsistent"};
        }
        break;
      case RtlHeapEventOperation::kSectionMap:
        if (nt_memory_hooks_ == nullptr ||
            (!exceptional &&
             succeeded != (static_cast<std::int32_t>(raw_event.operation_result) >= 0))) {
          throw std::invalid_argument{"raw NtMapViewOfSection event is inconsistent"};
        }
        break;
      case RtlHeapEventOperation::kSectionUnmap:
        if (nt_memory_hooks_ == nullptr || raw_event.requested_size != 0U ||
            raw_event.raw_result != 0U || raw_event.auxiliary_address != 0U ||
            raw_event.mapping_base != 0U || raw_event.mapping_size != 0U ||
            raw_event.section_handle != 0U || raw_event.section_offset != 0U ||
            raw_event.commit_size != 0U || raw_event.secondary_flags != 0U ||
            raw_event.tertiary_flags != 0U ||
            (!exceptional &&
             succeeded != (static_cast<std::int32_t>(raw_event.operation_result) >= 0))) {
          throw std::invalid_argument{"raw NtUnmapViewOfSection event is inconsistent"};
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

  [[nodiscard]] auto find_virtual_mapping(std::uint64_t address, std::uint64_t size,
                                          bool exact_base) {
    if (address == 0U) {
      return live_virtual_mappings_.end();
    }
    if (exact_base) {
      return live_virtual_mappings_.find(address);
    }
    auto candidate = live_virtual_mappings_.upper_bound(address);
    if (candidate == live_virtual_mappings_.begin()) {
      return live_virtual_mappings_.end();
    }
    --candidate;
    const VirtualMapping& mapping = candidate->second;
    if (address < mapping.base) {
      return live_virtual_mappings_.end();
    }
    const std::uint64_t offset = address - mapping.base;
    if (offset > mapping.size || size > mapping.size - offset) {
      return live_virtual_mappings_.end();
    }
    return candidate;
  }

  [[nodiscard]] noleax::trace::MappingId create_virtual_mapping(std::uint64_t base,
                                                                std::uint64_t size) {
    if (next_mapping_id_ == std::numeric_limits<std::uint64_t>::max()) {
      throw std::overflow_error{"mapping ID space is exhausted"};
    }
    if (base == 0U || size == 0U || live_virtual_mappings_.contains(base)) {
      throw std::runtime_error{
          "virtual mapping creation is inconsistent: base=" + std::to_string(base) +
          " size=" + std::to_string(size) +
          " duplicate=" + std::to_string(live_virtual_mappings_.contains(base) ? 1U : 0U)};
    }
    const noleax::trace::MappingId id{next_mapping_id_++};
    live_virtual_mappings_.emplace(base, VirtualMapping{id, base, size});
    return id;
  }

  [[nodiscard]] auto find_section_mapping(std::uint64_t address) {
    if (address == 0U) {
      return live_section_mappings_.end();
    }
    auto candidate = live_section_mappings_.upper_bound(address);
    if (candidate == live_section_mappings_.begin()) {
      return live_section_mappings_.end();
    }
    --candidate;
    const VirtualMapping& mapping = candidate->second;
    const std::uint64_t offset = address - mapping.base;
    if (offset >= mapping.size) {
      return live_section_mappings_.end();
    }
    return candidate;
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
    live_section_mappings_.emplace(base, VirtualMapping{id, base, size});
    return id;
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
      case RtlHeapEventOperation::kCreate:
        event.header.api_id = kRtlCreateHeapApiId;
        break;
      case RtlHeapEventOperation::kAllocate:
        event.header.api_id = kRtlAllocateHeapApiId;
        break;
      case RtlHeapEventOperation::kReallocate:
        event.header.api_id = kRtlReAllocateHeapApiId;
        break;
      case RtlHeapEventOperation::kFree:
        event.header.api_id = kRtlFreeHeapApiId;
        break;
      case RtlHeapEventOperation::kDestroy:
        event.header.api_id = kRtlDestroyHeapApiId;
        break;
      case RtlHeapEventOperation::kVmAllocate:
        event.header.api_id = kNtAllocateVirtualMemoryApiId;
        break;
      case RtlHeapEventOperation::kVmFree:
        event.header.api_id = kNtFreeVirtualMemoryApiId;
        break;
      case RtlHeapEventOperation::kSectionMap:
        event.header.api_id = kNtMapViewOfSectionApiId;
        break;
      case RtlHeapEventOperation::kSectionUnmap:
        event.header.api_id = kNtUnmapViewOfSectionApiId;
        event.header.flags = raw_event.flags;
        break;
    }
    event.header.status = raw_event.status == RtlAllocateHeapEventStatus::kSuccess
                              ? noleax::trace::EventStatus::kSuccess
                              : noleax::trace::EventStatus::kFailure;
    if (raw_event.status == RtlAllocateHeapEventStatus::kException) {
      event.header.system_error = {noleax::trace::SystemErrorDomain::kNtStatus,
                                   raw_event.exception_status};
    } else if ((raw_event.operation == RtlHeapEventOperation::kVmAllocate ||
                raw_event.operation == RtlHeapEventOperation::kVmFree ||
                raw_event.operation == RtlHeapEventOperation::kSectionMap ||
                raw_event.operation == RtlHeapEventOperation::kSectionUnmap) &&
               raw_event.status == RtlAllocateHeapEventStatus::kFailure) {
      event.header.system_error = {noleax::trace::SystemErrorDomain::kNtStatus,
                                   raw_event.operation_result};
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

    if (raw_event.operation == RtlHeapEventOperation::kCreate) {
      noleax::trace::HeapCreateEvent create;
      create.heap_handle = raw_event.result_address;
      create.heap_flags = raw_event.flags;
      create.reserve_size = raw_event.requested_size;
      create.commit_size = raw_event.raw_result;
      if (raw_event.status == RtlHeapEventStatus::kSuccess) {
        if (next_heap_id_ == std::numeric_limits<std::uint64_t>::max()) {
          throw std::overflow_error{"heap ID space is exhausted"};
        }
        if (live_heaps_.contains(raw_event.result_address)) {
          throw std::runtime_error{"RtlCreateHeap reused a live heap handle"};
        }
        create.heap_id = noleax::trace::HeapId{next_heap_id_++};
        live_heaps_.emplace(raw_event.result_address, create.heap_id);
      }
      event.payload = create;
    } else if (raw_event.operation == RtlHeapEventOperation::kAllocate) {
      noleax::trace::AllocationEvent allocation;
      allocation.heap_handle = raw_event.heap_handle;
      if (const auto heap = live_heaps_.find(raw_event.heap_handle); heap != live_heaps_.end()) {
        allocation.heap_id = heap->second;
      }
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
      if (const auto heap = live_heaps_.find(raw_event.heap_handle); heap != live_heaps_.end()) {
        reallocation.heap_id = heap->second;
      }
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
    } else if (raw_event.operation == RtlHeapEventOperation::kFree) {
      noleax::trace::FreeEvent free_event;
      free_event.heap_handle = raw_event.heap_handle;
      if (const auto heap = live_heaps_.find(raw_event.heap_handle); heap != live_heaps_.end()) {
        free_event.heap_id = heap->second;
      }
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
    } else if (raw_event.operation == RtlHeapEventOperation::kDestroy) {
      noleax::trace::HeapDestroyEvent destroy;
      destroy.heap_handle = raw_event.heap_handle;
      destroy.raw_result = raw_event.raw_result;
      const auto heap = live_heaps_.find(raw_event.heap_handle);
      if (heap != live_heaps_.end()) {
        destroy.heap_id = heap->second;
        if (raw_event.status == RtlHeapEventStatus::kSuccess) {
          live_heaps_.erase(heap);
          for (auto allocation = live_allocations_.begin();
               allocation != live_allocations_.end();) {
            if (allocation->first.heap_handle == raw_event.heap_handle) {
              allocation = live_allocations_.erase(allocation);
            } else {
              ++allocation;
            }
          }
        }
      } else if (raw_event.status == RtlHeapEventStatus::kSuccess) {
        event.header.status = options_.capture_scope.preexisting_allocations_unknown
                                  ? noleax::trace::EventStatus::kPreexisting
                                  : noleax::trace::EventStatus::kUnmatched;
      }
      event.payload = destroy;
    } else if (raw_event.operation == RtlHeapEventOperation::kVmAllocate) {
      noleax::trace::VmAllocateEvent allocation;
      allocation.target =
          classify_process_target(raw_event.heap_handle, raw_event.target_process_id);
      allocation.requested_base = raw_event.address;
      allocation.result_base = raw_event.result_address;
      allocation.requested_size = raw_event.requested_size;
      allocation.result_size = raw_event.raw_result;
      allocation.mapping_base = raw_event.mapping_base;
      allocation.mapping_size = raw_event.mapping_size;
      allocation.allocation_type = raw_event.flags;
      allocation.protection = raw_event.secondary_flags;
      if (raw_event.status == RtlHeapEventStatus::kSuccess &&
          allocation.target.scope == noleax::trace::ProcessMemoryScope::kCurrentProcess) {
        auto existing = find_virtual_mapping(raw_event.result_address, raw_event.raw_result, false);
        const std::uint64_t mapping_base =
            raw_event.mapping_base == 0U ? raw_event.result_address : raw_event.mapping_base;
        const std::uint64_t mapping_size =
            raw_event.mapping_size == 0U ? raw_event.raw_result : raw_event.mapping_size;
        if ((raw_event.flags & MEM_RESERVE) != 0U) {
          auto same_reservation = live_virtual_mappings_.find(mapping_base);
          if (same_reservation != live_virtual_mappings_.end()) {
            same_reservation->second.size = (std::max)(same_reservation->second.size, mapping_size);
            allocation.mapping_id = same_reservation->second.mapping_id;
            allocation.mapping_base = same_reservation->second.base;
            allocation.mapping_size = same_reservation->second.size;
          } else {
            allocation.mapping_id = create_virtual_mapping(mapping_base, mapping_size);
          }
        } else if (existing != live_virtual_mappings_.end()) {
          allocation.mapping_id = existing->second.mapping_id;
          allocation.mapping_base = existing->second.base;
          allocation.mapping_size = existing->second.size;
        } else {
          auto same_reservation = live_virtual_mappings_.find(mapping_base);
          if (same_reservation != live_virtual_mappings_.end()) {
            same_reservation->second.size = (std::max)(same_reservation->second.size, mapping_size);
            allocation.mapping_id = same_reservation->second.mapping_id;
            allocation.mapping_base = same_reservation->second.base;
            allocation.mapping_size = same_reservation->second.size;
          } else {
            allocation.mapping_id = create_virtual_mapping(mapping_base, mapping_size);
          }
          if (raw_event.address != 0U && options_.capture_scope.preexisting_allocations_unknown) {
            event.header.status = noleax::trace::EventStatus::kPreexisting;
          }
        }
      }
      event.payload = allocation;
    } else if (raw_event.operation == RtlHeapEventOperation::kVmFree) {
      noleax::trace::VmFreeEvent free_event;
      free_event.target =
          classify_process_target(raw_event.heap_handle, raw_event.target_process_id);
      free_event.base = raw_event.address;
      free_event.region_size = raw_event.raw_result;
      free_event.free_type = raw_event.flags;
      if (raw_event.status == RtlHeapEventStatus::kSuccess &&
          free_event.target.scope == noleax::trace::ProcessMemoryScope::kCurrentProcess) {
        const bool releases_mapping = (raw_event.flags & MEM_RELEASE) != 0U;
        auto mapping =
            find_virtual_mapping(raw_event.address, raw_event.raw_result, releases_mapping);
        if (mapping != live_virtual_mappings_.end()) {
          free_event.mapping_id = mapping->second.mapping_id;
          if (releases_mapping) {
            live_virtual_mappings_.erase(mapping);
          }
        } else {
          event.header.status = options_.capture_scope.preexisting_allocations_unknown
                                    ? noleax::trace::EventStatus::kPreexisting
                                    : noleax::trace::EventStatus::kUnmatched;
        }
      }
      event.payload = free_event;
    } else if (raw_event.operation == RtlHeapEventOperation::kSectionMap) {
      noleax::trace::MapEvent mapping_event;
      mapping_event.section_handle = raw_event.section_handle;
      mapping_event.target =
          classify_process_target(raw_event.heap_handle, raw_event.target_process_id);
      mapping_event.result_base = raw_event.result_address;
      mapping_event.view_size = raw_event.raw_result;
      mapping_event.section_offset = raw_event.section_offset;
      mapping_event.protection = raw_event.secondary_flags;
      if (raw_event.status == RtlHeapEventStatus::kSuccess &&
          mapping_event.target.scope == noleax::trace::ProcessMemoryScope::kCurrentProcess) {
        mapping_event.mapping_id =
            create_section_mapping(raw_event.result_address, raw_event.raw_result);
      }
      event.payload = mapping_event;
    } else {
      noleax::trace::UnmapEvent unmap_event;
      unmap_event.target =
          classify_process_target(raw_event.heap_handle, raw_event.target_process_id);
      unmap_event.base = raw_event.address;
      if (raw_event.status == RtlHeapEventStatus::kSuccess &&
          unmap_event.target.scope == noleax::trace::ProcessMemoryScope::kCurrentProcess) {
        const auto mapping = find_section_mapping(raw_event.address);
        if (mapping != live_section_mappings_.end()) {
          unmap_event.mapping_id = mapping->second.mapping_id;
          unmap_event.base = mapping->second.base;
          live_section_mappings_.erase(mapping);
        } else {
          event.header.status = options_.capture_scope.preexisting_allocations_unknown
                                    ? noleax::trace::EventStatus::kPreexisting
                                    : noleax::trace::EventStatus::kUnmatched;
        }
      }
      event.payload = unmap_event;
    }
    noleax::trace::append_event_record(event_payload_, event, options_.maximum_record_size);

    if (pending_event_count_ == 0U) {
      pending_sequence_begin_ = raw_event.queue_sequence;
      pending_tick_begin_ = normalized_ticks;
    }
    pending_sequence_end_ = raw_event.queue_sequence;
    pending_tick_end_ = normalized_ticks;
    checked_add(pending_event_count_, 1U, "pending event count overflow");
    if (raw_event.operation == RtlHeapEventOperation::kCreate) {
      checked_add(pending_create_events_, 1U, "pending heap create event count overflow");
    } else if (raw_event.operation == RtlHeapEventOperation::kAllocate) {
      checked_add(pending_allocate_events_, 1U, "pending allocation event count overflow");
    } else if (raw_event.operation == RtlHeapEventOperation::kReallocate) {
      checked_add(pending_reallocate_events_, 1U, "pending reallocation event count overflow");
    } else if (raw_event.operation == RtlHeapEventOperation::kFree) {
      checked_add(pending_free_events_, 1U, "pending free event count overflow");
    } else if (raw_event.operation == RtlHeapEventOperation::kDestroy) {
      checked_add(pending_destroy_events_, 1U, "pending heap destroy event count overflow");
    } else if (raw_event.operation == RtlHeapEventOperation::kVmAllocate) {
      checked_add(pending_vm_allocate_events_, 1U,
                  "pending virtual allocation event count overflow");
    } else if (raw_event.operation == RtlHeapEventOperation::kVmFree) {
      checked_add(pending_vm_free_events_, 1U, "pending virtual free event count overflow");
    } else if (raw_event.operation == RtlHeapEventOperation::kSectionMap) {
      checked_add(pending_map_events_, 1U, "pending section map event count overflow");
    } else {
      checked_add(pending_unmap_events_, 1U, "pending section unmap event count overflow");
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
    if (create_hook_ != nullptr) {
      const std::uint64_t create_dropped = create_hook_->take_dropped_event_count();
      checked_add(queue_create_dropped_events_, create_dropped,
                  "heap create queue drop count overflow");
      checked_add(queue_dropped_events_, create_dropped, "queue drop count overflow");
    }
    if (hook_ != nullptr) {
      const std::uint64_t allocate_dropped = hook_->take_dropped_event_count();
      checked_add(queue_allocate_dropped_events_, allocate_dropped,
                  "allocation queue drop count overflow");
      checked_add(queue_dropped_events_, allocate_dropped, "queue drop count overflow");
    }
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
    if (destroy_hook_ != nullptr) {
      const std::uint64_t destroy_dropped = destroy_hook_->take_dropped_event_count();
      checked_add(queue_destroy_dropped_events_, destroy_dropped,
                  "heap destroy queue drop count overflow");
      checked_add(queue_dropped_events_, destroy_dropped, "queue drop count overflow");
    }
    if (nt_memory_hooks_ != nullptr) {
      const std::uint64_t allocate_dropped = nt_memory_hooks_->take_allocate_dropped_event_count();
      const std::uint64_t free_dropped = nt_memory_hooks_->take_free_dropped_event_count();
      const std::uint64_t map_dropped = nt_memory_hooks_->take_map_dropped_event_count();
      const std::uint64_t unmap_dropped = nt_memory_hooks_->take_unmap_dropped_event_count();
      checked_add(queue_vm_allocate_dropped_events_, allocate_dropped,
                  "virtual allocation queue drop count overflow");
      checked_add(queue_vm_free_dropped_events_, free_dropped,
                  "virtual free queue drop count overflow");
      checked_add(queue_map_dropped_events_, map_dropped, "section map queue drop count overflow");
      checked_add(queue_unmap_dropped_events_, unmap_dropped,
                  "section unmap queue drop count overflow");
      checked_add(queue_dropped_events_, allocate_dropped, "queue drop count overflow");
      checked_add(queue_dropped_events_, free_dropped, "queue drop count overflow");
      checked_add(queue_dropped_events_, map_dropped, "queue drop count overflow");
      checked_add(queue_dropped_events_, unmap_dropped, "queue drop count overflow");
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
    checked_add(written_create_events_, pending_create_events_,
                "written heap create event count overflow");
    checked_add(written_allocate_events_, pending_allocate_events_,
                "written allocation event count overflow");
    checked_add(written_reallocate_events_, pending_reallocate_events_,
                "written reallocation event count overflow");
    checked_add(written_free_events_, pending_free_events_, "written free event count overflow");
    checked_add(written_destroy_events_, pending_destroy_events_,
                "written heap destroy event count overflow");
    checked_add(written_vm_allocate_events_, pending_vm_allocate_events_,
                "written virtual allocation event count overflow");
    checked_add(written_vm_free_events_, pending_vm_free_events_,
                "written virtual free event count overflow");
    checked_add(written_map_events_, pending_map_events_,
                "written section map event count overflow");
    checked_add(written_unmap_events_, pending_unmap_events_,
                "written section unmap event count overflow");
    checked_add(unique_stacks_, pending_unique_stacks_, "unique stack count overflow");
    checked_add(reused_stacks_, pending_reused_stacks_, "reused stack count overflow");
    clear_pending();
  }

  void drop_pending_events() {
    if (pending_event_count_ != 0U) {
      note_trace_drop_range(pending_event_count_, pending_allocate_events_,
                            pending_reallocate_events_, pending_free_events_,
                            pending_create_events_, pending_destroy_events_,
                            pending_vm_allocate_events_, pending_vm_free_events_,
                            pending_map_events_, pending_unmap_events_, pending_sequence_begin_,
                            pending_sequence_end_, pending_tick_begin_, pending_tick_end_);
    }
    clear_pending();
  }

  void clear_pending() noexcept {
    stack_payload_.clear();
    event_payload_.clear();
    pending_event_count_ = 0U;
    pending_create_events_ = 0U;
    pending_allocate_events_ = 0U;
    pending_reallocate_events_ = 0U;
    pending_free_events_ = 0U;
    pending_destroy_events_ = 0U;
    pending_vm_allocate_events_ = 0U;
    pending_vm_free_events_ = 0U;
    pending_map_events_ = 0U;
    pending_unmap_events_ = 0U;
    pending_unique_stacks_ = 0U;
    pending_reused_stacks_ = 0U;
    pending_sequence_begin_ = 0U;
    pending_sequence_end_ = 0U;
    pending_tick_begin_ = 0U;
    pending_tick_end_ = 0U;
  }

  void note_trace_drop(RtlHeapEventOperation operation, std::uint64_t sequence,
                       std::uint64_t ticks) {
    const std::uint64_t create_count = operation == RtlHeapEventOperation::kCreate ? 1U : 0U;
    const std::uint64_t allocate_count = operation == RtlHeapEventOperation::kAllocate ? 1U : 0U;
    const std::uint64_t reallocate_count =
        operation == RtlHeapEventOperation::kReallocate ? 1U : 0U;
    const std::uint64_t free_count = operation == RtlHeapEventOperation::kFree ? 1U : 0U;
    const std::uint64_t destroy_count = operation == RtlHeapEventOperation::kDestroy ? 1U : 0U;
    const std::uint64_t vm_allocate_count =
        operation == RtlHeapEventOperation::kVmAllocate ? 1U : 0U;
    const std::uint64_t vm_free_count = operation == RtlHeapEventOperation::kVmFree ? 1U : 0U;
    const std::uint64_t map_count = operation == RtlHeapEventOperation::kSectionMap ? 1U : 0U;
    const std::uint64_t unmap_count = operation == RtlHeapEventOperation::kSectionUnmap ? 1U : 0U;
    note_trace_drop_range(1U, allocate_count, reallocate_count, free_count, create_count,
                          destroy_count, vm_allocate_count, vm_free_count, map_count, unmap_count,
                          sequence, sequence, ticks, ticks);
  }

  void note_trace_drop_range(std::uint64_t count, std::uint64_t allocate_count,
                             std::uint64_t reallocate_count, std::uint64_t free_count,
                             std::uint64_t create_count, std::uint64_t destroy_count,
                             std::uint64_t vm_allocate_count, std::uint64_t vm_free_count,
                             std::uint64_t map_count, std::uint64_t unmap_count,
                             std::uint64_t sequence_begin, std::uint64_t sequence_end,
                             std::uint64_t tick_begin, std::uint64_t tick_end) {
    if (allocate_count > count || reallocate_count > count - allocate_count ||
        free_count > count - allocate_count - reallocate_count ||
        create_count > count - allocate_count - reallocate_count - free_count ||
        destroy_count > count - allocate_count - reallocate_count - free_count - create_count ||
        vm_allocate_count >
            count - allocate_count - reallocate_count - free_count - create_count - destroy_count ||
        vm_free_count > count - allocate_count - reallocate_count - free_count - create_count -
                            destroy_count - vm_allocate_count ||
        map_count > count - allocate_count - reallocate_count - free_count - create_count -
                        destroy_count - vm_allocate_count - vm_free_count ||
        unmap_count != count - allocate_count - reallocate_count - free_count - create_count -
                           destroy_count - vm_allocate_count - vm_free_count - map_count) {
      throw std::logic_error{"trace drop API accounting is inconsistent"};
    }
    if (trace_dropped_events_ == 0U) {
      trace_drop_sequence_begin_ = sequence_begin;
      trace_drop_tick_begin_ = tick_begin;
    }
    trace_drop_sequence_end_ = sequence_end;
    trace_drop_tick_end_ = tick_end;
    checked_add(trace_dropped_events_, count, "trace drop count overflow");
    checked_add(trace_create_dropped_events_, create_count,
                "heap create trace drop count overflow");
    checked_add(trace_allocate_dropped_events_, allocate_count,
                "allocation trace drop count overflow");
    checked_add(trace_reallocate_dropped_events_, reallocate_count,
                "reallocation trace drop count overflow");
    checked_add(trace_free_dropped_events_, free_count, "free trace drop count overflow");
    checked_add(trace_destroy_dropped_events_, destroy_count,
                "heap destroy trace drop count overflow");
    checked_add(trace_vm_allocate_dropped_events_, vm_allocate_count,
                "virtual allocation trace drop count overflow");
    checked_add(trace_vm_free_dropped_events_, vm_free_count,
                "virtual free trace drop count overflow");
    checked_add(trace_map_dropped_events_, map_count, "section map trace drop count overflow");
    checked_add(trace_unmap_dropped_events_, unmap_count,
                "section unmap trace drop count overflow");
  }

  void finalize_empty_trace() {
    writer_.release_file_reserve();
    noleax::trace::CaptureStatistics statistics;
    if (create_hook_ != nullptr) {
      statistics.per_api.push_back({kRtlCreateHeapApiId, 0U, 0U, 0U, 0U, 0U});
    }
    if (hook_ != nullptr) {
      statistics.per_api.push_back({kRtlAllocateHeapApiId, 0U, 0U, 0U, 0U, 0U});
    }
    if (reallocate_hook_ != nullptr) {
      statistics.per_api.push_back({kRtlReAllocateHeapApiId, 0U, 0U, 0U, 0U, 0U});
    }
    if (free_hook_ != nullptr) {
      statistics.per_api.push_back({kRtlFreeHeapApiId, 0U, 0U, 0U, 0U, 0U});
    }
    if (destroy_hook_ != nullptr) {
      statistics.per_api.push_back({kRtlDestroyHeapApiId, 0U, 0U, 0U, 0U, 0U});
    }
    if (nt_memory_hooks_ != nullptr) {
      statistics.per_api.push_back({kNtAllocateVirtualMemoryApiId, 0U, 0U, 0U, 0U, 0U});
      statistics.per_api.push_back({kNtFreeVirtualMemoryApiId, 0U, 0U, 0U, 0U, 0U});
      statistics.per_api.push_back({kNtMapViewOfSectionApiId, 0U, 0U, 0U, 0U, 0U});
      statistics.per_api.push_back({kNtUnmapViewOfSectionApiId, 0U, 0U, 0U, 0U, 0U});
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

    const auto total_dropped = [](std::uint64_t queue_dropped, std::uint64_t trace_dropped,
                                  const char* error) {
      checked_add(queue_dropped, trace_dropped, error);
      return queue_dropped;
    };

    noleax::trace::CaptureStatistics statistics;
    std::optional<noleax::trace::ApiStatistics> create_statistics;
    if (create_hook_ != nullptr) {
      const std::uint64_t dropped =
          total_dropped(queue_create_dropped_events_, trace_create_dropped_events_,
                        "heap create dropped event count overflow");
      create_statistics = noleax::trace::ApiStatistics{kRtlCreateHeapApiId,
                                                       create_hook_->recordable_call_count(),
                                                       create_hook_->successful_call_count(),
                                                       create_hook_->failed_call_count(),
                                                       0U,
                                                       dropped};
      statistics.per_api.push_back(*create_statistics);
    }
    std::optional<noleax::trace::ApiStatistics> allocate_statistics;
    if (hook_ != nullptr) {
      const std::uint64_t dropped =
          total_dropped(queue_allocate_dropped_events_, trace_allocate_dropped_events_,
                        "allocation dropped event count overflow");
      allocate_statistics = noleax::trace::ApiStatistics{kRtlAllocateHeapApiId,
                                                         hook_->recordable_call_count(),
                                                         hook_->successful_call_count(),
                                                         hook_->failed_call_count(),
                                                         0U,
                                                         dropped};
      statistics.per_api.push_back(*allocate_statistics);
    }
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
    std::optional<noleax::trace::ApiStatistics> free_statistics;
    if (free_hook_ != nullptr) {
      const std::uint64_t dropped =
          total_dropped(queue_free_dropped_events_, trace_free_dropped_events_,
                        "free dropped event count overflow");
      free_statistics = noleax::trace::ApiStatistics{kRtlFreeHeapApiId,
                                                     free_hook_->recordable_call_count(),
                                                     free_hook_->successful_call_count(),
                                                     free_hook_->failed_call_count(),
                                                     0U,
                                                     dropped};
      statistics.per_api.push_back(*free_statistics);
    }
    std::optional<noleax::trace::ApiStatistics> destroy_statistics;
    if (destroy_hook_ != nullptr) {
      const std::uint64_t dropped =
          total_dropped(queue_destroy_dropped_events_, trace_destroy_dropped_events_,
                        "heap destroy dropped event count overflow");
      destroy_statistics = noleax::trace::ApiStatistics{kRtlDestroyHeapApiId,
                                                        destroy_hook_->recordable_call_count(),
                                                        destroy_hook_->successful_call_count(),
                                                        destroy_hook_->failed_call_count(),
                                                        0U,
                                                        dropped};
      statistics.per_api.push_back(*destroy_statistics);
    }
    std::optional<noleax::trace::ApiStatistics> vm_allocate_statistics;
    std::optional<noleax::trace::ApiStatistics> vm_free_statistics;
    std::optional<noleax::trace::ApiStatistics> map_statistics;
    std::optional<noleax::trace::ApiStatistics> unmap_statistics;
    if (nt_memory_hooks_ != nullptr) {
      const NtMemoryHookStatistics allocate = nt_memory_hooks_->allocate_statistics();
      const NtMemoryHookStatistics free = nt_memory_hooks_->free_statistics();
      const NtMemoryHookStatistics map = nt_memory_hooks_->map_statistics();
      const NtMemoryHookStatistics unmap = nt_memory_hooks_->unmap_statistics();
      const std::uint64_t allocate_dropped =
          total_dropped(queue_vm_allocate_dropped_events_, trace_vm_allocate_dropped_events_,
                        "virtual allocation dropped event count overflow");
      const std::uint64_t free_dropped =
          total_dropped(queue_vm_free_dropped_events_, trace_vm_free_dropped_events_,
                        "virtual free dropped event count overflow");
      const std::uint64_t map_dropped =
          total_dropped(queue_map_dropped_events_, trace_map_dropped_events_,
                        "section map dropped event count overflow");
      const std::uint64_t unmap_dropped =
          total_dropped(queue_unmap_dropped_events_, trace_unmap_dropped_events_,
                        "section unmap dropped event count overflow");
      vm_allocate_statistics = noleax::trace::ApiStatistics{kNtAllocateVirtualMemoryApiId,
                                                            allocate.recordable_calls,
                                                            allocate.successful_calls,
                                                            allocate.failed_calls,
                                                            0U,
                                                            allocate_dropped};
      vm_free_statistics = noleax::trace::ApiStatistics{kNtFreeVirtualMemoryApiId,
                                                        free.recordable_calls,
                                                        free.successful_calls,
                                                        free.failed_calls,
                                                        0U,
                                                        free_dropped};
      map_statistics = noleax::trace::ApiStatistics{kNtMapViewOfSectionApiId,
                                                    map.recordable_calls,
                                                    map.successful_calls,
                                                    map.failed_calls,
                                                    0U,
                                                    map_dropped};
      unmap_statistics = noleax::trace::ApiStatistics{kNtUnmapViewOfSectionApiId,
                                                      unmap.recordable_calls,
                                                      unmap.successful_calls,
                                                      unmap.failed_calls,
                                                      0U,
                                                      unmap_dropped};
      statistics.per_api.push_back(*vm_allocate_statistics);
      statistics.per_api.push_back(*vm_free_statistics);
      statistics.per_api.push_back(*map_statistics);
      statistics.per_api.push_back(*unmap_statistics);
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
    if (allocate_statistics.has_value()) {
      std::uint64_t accounted_allocations = written_allocate_events_;
      checked_add(accounted_allocations, allocate_statistics->dropped_events,
                  "accounted allocation event count overflow");
      if (accounted_allocations != allocate_statistics->observed_calls) {
        throw std::runtime_error{"RtlAllocateHeap counters do not reconcile with trace events"};
      }
    }
    if (free_statistics.has_value()) {
      std::uint64_t accounted_frees = written_free_events_;
      checked_add(accounted_frees, free_statistics->dropped_events,
                  "accounted free event count overflow");
      if (accounted_frees != free_statistics->observed_calls) {
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
    if (create_statistics.has_value()) {
      std::uint64_t accounted_creates = written_create_events_;
      checked_add(accounted_creates, create_statistics->dropped_events,
                  "accounted heap create event count overflow");
      if (accounted_creates != create_statistics->observed_calls) {
        throw std::runtime_error{"RtlCreateHeap counters do not reconcile with trace events"};
      }
    }
    if (destroy_statistics.has_value()) {
      std::uint64_t accounted_destroys = written_destroy_events_;
      checked_add(accounted_destroys, destroy_statistics->dropped_events,
                  "accounted heap destroy event count overflow");
      if (accounted_destroys != destroy_statistics->observed_calls) {
        throw std::runtime_error{"RtlDestroyHeap counters do not reconcile with trace events"};
      }
    }
    if (vm_allocate_statistics.has_value()) {
      std::uint64_t accounted_allocations = written_vm_allocate_events_;
      checked_add(accounted_allocations, vm_allocate_statistics->dropped_events,
                  "accounted virtual allocation event count overflow");
      if (accounted_allocations != vm_allocate_statistics->observed_calls) {
        throw std::runtime_error{
            "NtAllocateVirtualMemory counters do not reconcile with trace events"};
      }
    }
    if (vm_free_statistics.has_value()) {
      std::uint64_t accounted_frees = written_vm_free_events_;
      checked_add(accounted_frees, vm_free_statistics->dropped_events,
                  "accounted virtual free event count overflow");
      if (accounted_frees != vm_free_statistics->observed_calls) {
        throw std::runtime_error{"NtFreeVirtualMemory counters do not reconcile with trace events"};
      }
    }
    if (map_statistics.has_value()) {
      std::uint64_t accounted_maps = written_map_events_;
      checked_add(accounted_maps, map_statistics->dropped_events,
                  "accounted section map event count overflow");
      if (accounted_maps != map_statistics->observed_calls) {
        throw std::runtime_error{"NtMapViewOfSection counters do not reconcile with trace events"};
      }
    }
    if (unmap_statistics.has_value()) {
      std::uint64_t accounted_unmaps = written_unmap_events_;
      checked_add(accounted_unmaps, unmap_statistics->dropped_events,
                  "accounted section unmap event count overflow");
      if (accounted_unmaps != unmap_statistics->observed_calls) {
        throw std::runtime_error{
            "NtUnmapViewOfSection counters do not reconcile with trace events"};
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

  RtlAllocateHeapHook* const hook_;
  RtlReAllocateHeapHook* const reallocate_hook_;
  RtlFreeHeapHook* const free_hook_;
  RtlCreateHeapHook* const create_hook_;
  RtlDestroyHeapHook* const destroy_hook_;
  NtMemoryHooks* const nt_memory_hooks_;
  RtlHeapEventQueue& event_queue_;
  const RtlAllocateHeapTraceWriterOptions options_;
  RawStackDictionary dictionary_;
  noleax::trace::TraceWriter writer_;
  noleax::trace::CompletenessTracker completeness_;
  const std::uint64_t monotonic_origin_;

  std::vector<std::byte> stack_payload_;
  std::vector<std::byte> event_payload_;
  std::unordered_map<AllocationKey, noleax::trace::AllocationId, AllocationKeyHash>
      live_allocations_;
  std::unordered_map<std::uint64_t, noleax::trace::HeapId> live_heaps_;
  std::map<std::uint64_t, VirtualMapping> live_virtual_mappings_;
  std::map<std::uint64_t, VirtualMapping> live_section_mappings_;
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
  std::uint64_t next_heap_id_{1U};
  std::uint64_t next_mapping_id_{1U};
  std::uint64_t last_sequence_{0U};
  std::uint64_t last_ticks_{0U};
  std::uint64_t pending_event_count_{0U};
  std::uint64_t pending_create_events_{0U};
  std::uint64_t pending_allocate_events_{0U};
  std::uint64_t pending_reallocate_events_{0U};
  std::uint64_t pending_free_events_{0U};
  std::uint64_t pending_destroy_events_{0U};
  std::uint64_t pending_vm_allocate_events_{0U};
  std::uint64_t pending_vm_free_events_{0U};
  std::uint64_t pending_map_events_{0U};
  std::uint64_t pending_unmap_events_{0U};
  std::uint64_t pending_unique_stacks_{0U};
  std::uint64_t pending_reused_stacks_{0U};
  std::uint64_t pending_sequence_begin_{0U};
  std::uint64_t pending_sequence_end_{0U};
  std::uint64_t pending_tick_begin_{0U};
  std::uint64_t pending_tick_end_{0U};
  std::uint64_t written_events_{0U};
  std::uint64_t written_create_events_{0U};
  std::uint64_t written_allocate_events_{0U};
  std::uint64_t written_reallocate_events_{0U};
  std::uint64_t written_free_events_{0U};
  std::uint64_t written_destroy_events_{0U};
  std::uint64_t written_vm_allocate_events_{0U};
  std::uint64_t written_vm_free_events_{0U};
  std::uint64_t written_map_events_{0U};
  std::uint64_t written_unmap_events_{0U};
  std::uint64_t queue_dropped_events_{0U};
  std::uint64_t queue_create_dropped_events_{0U};
  std::uint64_t queue_allocate_dropped_events_{0U};
  std::uint64_t queue_reallocate_dropped_events_{0U};
  std::uint64_t queue_free_dropped_events_{0U};
  std::uint64_t queue_destroy_dropped_events_{0U};
  std::uint64_t queue_vm_allocate_dropped_events_{0U};
  std::uint64_t queue_vm_free_dropped_events_{0U};
  std::uint64_t queue_map_dropped_events_{0U};
  std::uint64_t queue_unmap_dropped_events_{0U};
  std::uint64_t trace_dropped_events_{0U};
  std::uint64_t trace_create_dropped_events_{0U};
  std::uint64_t trace_allocate_dropped_events_{0U};
  std::uint64_t trace_reallocate_dropped_events_{0U};
  std::uint64_t trace_free_dropped_events_{0U};
  std::uint64_t trace_destroy_dropped_events_{0U};
  std::uint64_t trace_vm_allocate_dropped_events_{0U};
  std::uint64_t trace_vm_free_dropped_events_{0U};
  std::uint64_t trace_map_dropped_events_{0U};
  std::uint64_t trace_unmap_dropped_events_{0U};
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

RtlAllocateHeapTraceWriter::RtlAllocateHeapTraceWriter(
    RtlCreateHeapHook& create_hook, RtlAllocateHeapHook& allocate_hook,
    RtlReAllocateHeapHook& reallocate_hook, RtlFreeHeapHook& free_hook,
    RtlDestroyHeapHook& destroy_hook, std::ostream& output,
    const noleax::trace::FileHeader& file_header, RtlAllocateHeapTraceWriterOptions options)
    : implementation_{std::make_unique<Implementation>(allocate_hook, output, file_header, options,
                                                       &reallocate_hook, &free_hook, &create_hook,
                                                       &destroy_hook)} {}

RtlAllocateHeapTraceWriter::RtlAllocateHeapTraceWriter(NtMemoryHooks& nt_memory_hooks,
                                                       std::ostream& output,
                                                       const noleax::trace::FileHeader& file_header,
                                                       RtlAllocateHeapTraceWriterOptions options)
    : implementation_{
          std::make_unique<Implementation>(nt_memory_hooks, output, file_header, options)} {}

RtlAllocateHeapTraceWriter::~RtlAllocateHeapTraceWriter() = default;

void RtlAllocateHeapTraceWriter::begin_capture() { implementation_->begin_capture(); }

RtlAllocateHeapTraceWriterResult RtlAllocateHeapTraceWriter::finish() {
  return implementation_->finish();
}

bool RtlAllocateHeapTraceWriter::is_running() const noexcept {
  return implementation_->is_running();
}

}  // namespace noleax::agent::windows
