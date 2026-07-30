#include "noleax/agent/windows/stack_capture.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>

#if defined(_MSC_VER)
#define NOLEAX_NOINLINE __declspec(noinline)
#else
#define NOLEAX_NOINLINE __attribute__((noinline))
#endif

namespace noleax::agent::windows {
namespace {

constexpr std::size_t kCaptureBufferDepth =
    static_cast<std::size_t>(kMaximumCapturedStackDepth) + 1U;

void finish_capture(CapturedStack& destination,
                    const std::array<void*, kCaptureBufferDepth>& frames,
                    std::size_t captured_count, std::uint16_t maximum_depth,
                    StackCaptureMethod method) noexcept {
  destination.frame_count = static_cast<std::uint16_t>(
      (std::min)(captured_count, static_cast<std::size_t>(maximum_depth)));
  destination.requested_depth = maximum_depth;
  destination.method = method;
  if (captured_count == 0U) {
    destination.status = StackCaptureStatus::kFailed;
    return;
  }
  destination.status = captured_count > maximum_depth ? StackCaptureStatus::kTruncated
                                                      : StackCaptureStatus::kCaptured;
  for (std::size_t index = 0U; index < destination.frame_count; ++index) {
    destination.frames[index] =
        static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(frames[index]));
  }
}

NOLEAX_NOINLINE void capture_with_rtl(CapturedStack& destination, std::uint16_t maximum_depth,
                                      std::uint32_t additional_frames_to_skip) noexcept {
  // RtlCaptureStackBackTrace initializes exactly the returned prefix; no uncaptured entry is read.
  std::array<void*, kCaptureBufferDepth> frames;
  constexpr std::uint32_t kInternalFramesToSkip = 2U;
  const std::uint32_t frames_to_skip = kInternalFramesToSkip + additional_frames_to_skip;
  const auto frames_to_capture = static_cast<std::uint32_t>(maximum_depth) + 1U;
  const USHORT captured =
      RtlCaptureStackBackTrace(frames_to_skip, frames_to_capture, frames.data(), nullptr);
  finish_capture(destination, frames, captured, maximum_depth,
                 StackCaptureMethod::kRtlCaptureStackBackTrace);
}

#if defined(_M_X64) || defined(__x86_64__)

[[nodiscard]] bool stack_pointer_is_readable(std::uint64_t stack_pointer) noexcept {
  const auto* const tib = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
  const auto stack_limit = reinterpret_cast<std::uintptr_t>(tib->StackLimit);
  const auto stack_base = reinterpret_cast<std::uintptr_t>(tib->StackBase);
  return stack_pointer >= stack_limit && stack_pointer <= stack_base - sizeof(std::uint64_t);
}

NOLEAX_NOINLINE void capture_with_virtual_unwind(CapturedStack& destination,
                                                 std::uint16_t maximum_depth,
                                                 std::uint32_t additional_frames_to_skip) noexcept {
  CONTEXT context{};
  RtlCaptureContext(&context);
  std::array<void*, kCaptureBufferDepth> frames{};
  const std::size_t requested_count = static_cast<std::size_t>(maximum_depth) + 1U;
  constexpr std::uint32_t kInternalFramesToSkip = 2U;
  std::uint32_t frames_to_skip = kInternalFramesToSkip + additional_frames_to_skip;
  std::size_t captured_count = 0U;

  while (context.Rip != 0U && captured_count < requested_count) {
    if (frames_to_skip != 0U) {
      --frames_to_skip;
    } else {
      frames[captured_count++] = std::bit_cast<void*>(static_cast<std::uintptr_t>(context.Rip));
    }

    if (!stack_pointer_is_readable(context.Rsp)) {
      break;
    }
    const DWORD64 previous_rip = context.Rip;
    const DWORD64 previous_rsp = context.Rsp;
    DWORD64 image_base = 0U;
    const PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(context.Rip, &image_base, nullptr);
    if (function == nullptr) {
      context.Rip = *std::bit_cast<const DWORD64*>(static_cast<std::uintptr_t>(context.Rsp));
      context.Rsp += sizeof(DWORD64);
    } else {
      PVOID handler_data = nullptr;
      DWORD64 establisher_frame = 0U;
      static_cast<void>(RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, context.Rip, function,
                                         &context, &handler_data, &establisher_frame, nullptr));
    }
    if (context.Rip == previous_rip || context.Rsp <= previous_rsp) {
      break;
    }
  }

  finish_capture(destination, frames, captured_count, maximum_depth,
                 StackCaptureMethod::kVirtualUnwind);
}

#endif

}  // namespace

void capture_current_stack(CapturedStack& destination, std::uint16_t maximum_depth,
                           std::uint32_t additional_frames_to_skip,
                           StackCaptureMethod method) noexcept {
  destination.frame_count = 0U;
  destination.requested_depth = maximum_depth;
  destination.method = method;
  destination.status = StackCaptureStatus::kDisabled;
  if (maximum_depth == 0U) {
    return;
  }
  if (maximum_depth > kMaximumCapturedStackDepth ||
      additional_frames_to_skip > std::numeric_limits<std::uint32_t>::max() -
                                      static_cast<std::uint32_t>(maximum_depth) - 3U) {
    destination.status = StackCaptureStatus::kFailed;
    return;
  }

  switch (method) {
    case StackCaptureMethod::kRtlCaptureStackBackTrace:
      capture_with_rtl(destination, maximum_depth, additional_frames_to_skip);
      return;
    case StackCaptureMethod::kVirtualUnwind:
#if defined(_M_X64) || defined(__x86_64__)
      capture_with_virtual_unwind(destination, maximum_depth, additional_frames_to_skip);
#else
      destination.status = StackCaptureStatus::kFailed;
#endif
      return;
  }
  destination.status = StackCaptureStatus::kFailed;
}

bool stack_capture_succeeded(const CapturedStack& stack) noexcept {
  return (stack.status == StackCaptureStatus::kCaptured ||
          stack.status == StackCaptureStatus::kTruncated) &&
         stack.frame_count != 0U && stack.frame_count <= stack.requested_depth &&
         stack.requested_depth <= kMaximumCapturedStackDepth;
}

}  // namespace noleax::agent::windows

#undef NOLEAX_NOINLINE
