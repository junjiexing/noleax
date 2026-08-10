#include "noleax/agent/linux/stack_capture.hpp"

#include <unwind.h>

#include <algorithm>

namespace noleax::agent::linux {
namespace {

struct BacktraceState {
  CapturedStack* destination;
  std::uint16_t maximum_depth;
  std::uint32_t frames_to_skip;
  bool truncated;
};

_Unwind_Reason_Code backtrace_callback(_Unwind_Context* context, void* argument) noexcept {
  auto* const state = static_cast<BacktraceState*>(argument);
  const auto pc = static_cast<std::uint64_t>(_Unwind_GetIP(context));
  if (pc == 0U) {
    return _URC_END_OF_STACK;
  }
  if (state->frames_to_skip != 0U) {
    --state->frames_to_skip;
    return _URC_NO_REASON;
  }
  CapturedStack& destination = *state->destination;
  if (destination.frame_count == state->maximum_depth) {
    // One frame more than requested exists: the capture is truncated, not complete.
    state->truncated = true;
    return _URC_END_OF_STACK;
  }
  destination.frames[destination.frame_count++] = pc;
  return _URC_NO_REASON;
}

}  // namespace

void capture_current_stack(CapturedStack& destination, std::uint16_t maximum_depth,
                           std::uint32_t additional_frames_to_skip,
                           StackCaptureMethod method) noexcept {
  destination = CapturedStack{};
  destination.method = method;
  destination.requested_depth = std::min(maximum_depth, kMaximumCapturedStackDepth);
  if (destination.requested_depth == 0U) {
    destination.status = StackCaptureStatus::kDisabled;
    return;
  }

  BacktraceState state{&destination, destination.requested_depth,
                       // Skip this function's own frame plus the caller-requested frames.
                       additional_frames_to_skip + 1U, false};
  static_cast<void>(_Unwind_Backtrace(&backtrace_callback, &state));

  if (destination.frame_count == 0U) {
    destination.status = StackCaptureStatus::kFailed;
    return;
  }
  destination.status =
      state.truncated ? StackCaptureStatus::kTruncated : StackCaptureStatus::kCaptured;
}

bool stack_capture_succeeded(const CapturedStack& stack) noexcept {
  return (stack.status == StackCaptureStatus::kCaptured ||
          stack.status == StackCaptureStatus::kTruncated) &&
         stack.frame_count > 0U && stack.frame_count <= stack.requested_depth &&
         stack.requested_depth <= kMaximumCapturedStackDepth;
}

}  // namespace noleax::agent::linux
