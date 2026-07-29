#pragma once

#include <cstdint>
#include <type_traits>

#include "noleax/agent/windows/stack_capture.hpp"

namespace noleax::agent::windows {

enum class RtlAllocateHeapEventStatus : std::uint8_t {
  kSuccess,
  kFailure,
};

struct RtlAllocateHeapEvent {
  std::uint64_t queue_sequence{0U};
  std::uint64_t monotonic_ticks{0U};
  std::uint64_t thread_id{0U};
  std::uint64_t heap_handle{0U};
  std::uint64_t requested_size{0U};
  std::uint64_t result_address{0U};
  std::uint32_t flags{0U};
  RtlAllocateHeapEventStatus status{RtlAllocateHeapEventStatus::kFailure};
  std::uint8_t reserved[3]{};
  CapturedStack stack;

  bool operator==(const RtlAllocateHeapEvent&) const = default;
};

static_assert(std::is_trivially_copyable_v<RtlAllocateHeapEvent>);
static_assert(std::is_trivially_destructible_v<RtlAllocateHeapEvent>);
static_assert(sizeof(RtlAllocateHeapEvent) == 576U);

}  // namespace noleax::agent::windows
