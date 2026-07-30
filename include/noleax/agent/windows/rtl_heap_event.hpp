#pragma once

#include <cstdint>
#include <type_traits>

#include "noleax/agent/bounded_mpsc_queue.hpp"
#include "noleax/agent/windows/stack_capture.hpp"

namespace noleax::agent::windows {

enum class RtlHeapEventOperation : std::uint8_t {
  kAllocate,
  kReallocate,
  kFree,
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
  std::uint64_t requested_size{0U};
  std::uint64_t result_address{0U};
  std::uint64_t address{0U};
  std::uint64_t raw_result{0U};
  std::uint32_t flags{0U};
  std::uint32_t exception_status{0U};
  RtlHeapEventOperation operation{RtlHeapEventOperation::kAllocate};
  RtlHeapEventStatus status{RtlHeapEventStatus::kFailure};
  std::uint8_t reserved[6]{};
  CapturedStack stack;

  bool operator==(const RtlHeapEvent&) const = default;
};

using RtlHeapEventQueue = BoundedMpscQueue<RtlHeapEvent>;

static_assert(std::is_trivially_copyable_v<RtlHeapEvent>);
static_assert(std::is_trivially_destructible_v<RtlHeapEvent>);
static_assert(sizeof(RtlHeapEvent) == 600U);

}  // namespace noleax::agent::windows
