#pragma once

#include <cstdint>
#include <type_traits>

#include "noleax/agent/bounded_mpsc_queue.hpp"
#include "noleax/agent/linux/stack_capture.hpp"

namespace noleax::agent::linux {

enum class LinuxHeapEventOperation : std::uint8_t {
  kAllocate,   // malloc/calloc/aligned family: result_address carries the new pointer
  kReallocate, // realloc/reallocarray: address carries the input pointer
  kFree,       // free: address carries the freed pointer
};

enum class LinuxHeapEventStatus : std::uint8_t {
  kSuccess,
  kFailure,
};

// Fixed-size POD queued by the hook hot paths (same discipline as the Windows 672-byte
// RtlHeapEvent). Field semantics per operation:
//   kAllocate:  requested_size = size (calloc: nmemb*size), count = nmemb (calloc/
//               reallocarray, else 0), alignment = alignment (aligned family, else 0),
//               result_address = new pointer on success
//   kReallocate: address = input pointer, requested_size = new size, count = nmemb
//               (reallocarray, else 0), result_address = new pointer on success
//   kFree:      address = freed pointer
// operation_result carries errno on failure (and the posix_memalign return code, which
// does not set errno); it is zero on success.
struct LinuxHeapEvent {
  std::uint64_t queue_sequence{0U};
  std::uint64_t monotonic_ticks{0U};
  std::uint64_t thread_id{0U};
  std::uint64_t requested_size{0U};
  std::uint64_t count{0U};
  std::uint64_t alignment{0U};
  std::uint64_t result_address{0U};
  std::uint64_t address{0U};
  std::uint32_t operation_result{0U};
  std::uint32_t api_id{0U};
  LinuxHeapEventOperation operation{LinuxHeapEventOperation::kAllocate};
  LinuxHeapEventStatus status{LinuxHeapEventStatus::kFailure};
  std::uint8_t reserved[6]{};
  CapturedStack stack;

  bool operator==(const LinuxHeapEvent&) const = default;
};

using LinuxHeapEventQueue = BoundedMpscQueue<LinuxHeapEvent>;

static_assert(std::is_trivially_copyable_v<LinuxHeapEvent>);
static_assert(std::is_trivially_destructible_v<LinuxHeapEvent>);
static_assert(sizeof(LinuxHeapEvent) == 608U);

}  // namespace noleax::agent::linux
