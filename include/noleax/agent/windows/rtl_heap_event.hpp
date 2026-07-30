#pragma once

#include <cstdint>
#include <type_traits>

#include "noleax/agent/bounded_mpsc_queue.hpp"
#include "noleax/agent/windows/stack_capture.hpp"

namespace noleax::agent::windows {

enum class RtlHeapEventOperation : std::uint8_t {
  kCreate,
  kAllocate,
  kReallocate,
  kFree,
  kDestroy,
  kVmAllocate,
  kVmFree,
  kSectionMap,
  kSectionUnmap,
};

enum class RtlHeapEventStatus : std::uint8_t {
  kSuccess,
  kFailure,
  kException,
};

struct RtlHeapEvent {
  std::uint64_t queue_sequence{0U};
  std::uint64_t monotonic_ticks{0U};
  std::uint64_t thread_id{0U};
  std::uint64_t heap_handle{0U};
  std::uint64_t target_process_id{0U};
  std::uint64_t requested_size{0U};
  std::uint64_t result_address{0U};
  std::uint64_t address{0U};
  std::uint64_t raw_result{0U};
  std::uint64_t auxiliary_address{0U};
  std::uint64_t mapping_base{0U};
  std::uint64_t mapping_size{0U};
  std::uint64_t section_handle{0U};
  std::uint64_t section_offset{0U};
  std::uint64_t commit_size{0U};
  std::uint32_t flags{0U};
  std::uint32_t secondary_flags{0U};
  std::uint32_t tertiary_flags{0U};
  std::uint32_t operation_result{0U};
  std::uint32_t exception_status{0U};
  RtlHeapEventOperation operation{RtlHeapEventOperation::kAllocate};
  RtlHeapEventStatus status{RtlHeapEventStatus::kFailure};
  std::uint8_t reserved[2]{};
  CapturedStack stack;

  bool operator==(const RtlHeapEvent&) const = default;
};

using RtlHeapEventQueue = BoundedMpscQueue<RtlHeapEvent>;

static_assert(std::is_trivially_copyable_v<RtlHeapEvent>);
static_assert(std::is_trivially_destructible_v<RtlHeapEvent>);
static_assert(sizeof(RtlHeapEvent) == 664U);

}  // namespace noleax::agent::windows
