#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <memory>
#include <string>

#include "noleax/agent/windows/nt_memory_hooks.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"
#include "noleax/agent/windows/rtl_create_heap_hook.hpp"
#include "noleax/agent/windows/rtl_destroy_heap_hook.hpp"
#include "noleax/agent/windows/rtl_free_heap_hook.hpp"
#include "noleax/agent/windows/rtl_reallocate_heap_hook.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/trace_reader.hpp"
#include "noleax/trace/trace_writer.hpp"

namespace noleax::agent::windows {

inline constexpr noleax::trace::ApiId kRtlAllocateHeapApiId = 1U;
inline constexpr noleax::trace::ApiId kRtlFreeHeapApiId = 2U;
inline constexpr noleax::trace::ApiId kRtlReAllocateHeapApiId = 3U;
inline constexpr noleax::trace::ApiId kRtlCreateHeapApiId = 4U;
inline constexpr noleax::trace::ApiId kRtlDestroyHeapApiId = 5U;
inline constexpr noleax::trace::ApiId kNtAllocateVirtualMemoryApiId = 6U;
inline constexpr noleax::trace::ApiId kNtFreeVirtualMemoryApiId = 7U;

struct RtlAllocateHeapTraceWriterOptions {
  noleax::trace::TraceWriterOptions trace;
  noleax::trace::CompressionCodec compression{noleax::trace::CompressionCodec::kLz4};
  noleax::trace::CaptureScope capture_scope{false, true};
  std::chrono::milliseconds flush_interval{250};
  std::size_t chunk_target_size{64U * 1024U};
  std::size_t stack_dictionary_capacity{16'384U};
  std::uint32_t maximum_record_size{noleax::trace::kDefaultMaximumRecordSize};
};

enum class RtlAllocateHeapTraceWriterStatus : std::uint8_t {
  kComplete,
  kFileLimit,
  kWriterError,
};

struct RtlAllocateHeapTraceWriterResult {
  RtlAllocateHeapTraceWriterStatus status{RtlAllocateHeapTraceWriterStatus::kWriterError};
  noleax::trace::CaptureStatistics statistics;
  std::uint64_t stack_capture_failures{0U};
  std::uint64_t queue_dropped_events{0U};
  std::uint64_t trace_dropped_events{0U};
  std::uint64_t timestamp_adjustments{0U};
  std::uint64_t stack_dictionary_segments{0U};
  std::uint64_t bytes_written{0U};
  bool statistics_written{false};
  bool end_of_trace_written{false};
  std::string error_message;
};

class RtlAllocateHeapTraceWriter final {
 public:
  RtlAllocateHeapTraceWriter(RtlAllocateHeapHook& hook, std::ostream& output,
                             const noleax::trace::FileHeader& file_header,
                             RtlAllocateHeapTraceWriterOptions options = {});
  RtlAllocateHeapTraceWriter(RtlAllocateHeapHook& allocate_hook, RtlFreeHeapHook& free_hook,
                             std::ostream& output, const noleax::trace::FileHeader& file_header,
                             RtlAllocateHeapTraceWriterOptions options = {});
  RtlAllocateHeapTraceWriter(RtlAllocateHeapHook& allocate_hook,
                             RtlReAllocateHeapHook& reallocate_hook, RtlFreeHeapHook& free_hook,
                             std::ostream& output, const noleax::trace::FileHeader& file_header,
                             RtlAllocateHeapTraceWriterOptions options = {});
  RtlAllocateHeapTraceWriter(RtlCreateHeapHook& create_hook, RtlAllocateHeapHook& allocate_hook,
                             RtlReAllocateHeapHook& reallocate_hook, RtlFreeHeapHook& free_hook,
                             RtlDestroyHeapHook& destroy_hook, std::ostream& output,
                             const noleax::trace::FileHeader& file_header,
                             RtlAllocateHeapTraceWriterOptions options = {});
  RtlAllocateHeapTraceWriter(NtMemoryHooks& nt_memory_hooks, std::ostream& output,
                             const noleax::trace::FileHeader& file_header,
                             RtlAllocateHeapTraceWriterOptions options = {});
  ~RtlAllocateHeapTraceWriter();

  RtlAllocateHeapTraceWriter(const RtlAllocateHeapTraceWriter&) = delete;
  RtlAllocateHeapTraceWriter& operator=(const RtlAllocateHeapTraceWriter&) = delete;
  RtlAllocateHeapTraceWriter(RtlAllocateHeapTraceWriter&&) = delete;
  RtlAllocateHeapTraceWriter& operator=(RtlAllocateHeapTraceWriter&&) = delete;

  void begin_capture();
  [[nodiscard]] RtlAllocateHeapTraceWriterResult finish();
  [[nodiscard]] bool is_running() const noexcept;

 private:
  class Implementation;
  std::unique_ptr<Implementation> implementation_;
};

}  // namespace noleax::agent::windows
