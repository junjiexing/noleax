#pragma once

#include <array>
#include <cstdint>
#include <type_traits>

namespace noleax::agent::windows {

inline constexpr std::uint16_t kMaximumCapturedStackDepth = 64U;

enum class StackCaptureMethod : std::uint8_t {
  kRtlCaptureStackBackTrace,
  kVirtualUnwind,
};

enum class StackCaptureStatus : std::uint8_t {
  kDisabled,
  kCaptured,
  kTruncated,
  kFailed,
};

struct CapturedStack {
  std::array<std::uint64_t, kMaximumCapturedStackDepth> frames{};
  std::uint16_t frame_count{0U};
  std::uint16_t requested_depth{0U};
  StackCaptureMethod method{StackCaptureMethod::kRtlCaptureStackBackTrace};
  StackCaptureStatus status{StackCaptureStatus::kDisabled};
  std::uint8_t reserved[2]{};

  bool operator==(const CapturedStack&) const = default;
};

static_assert(std::is_trivially_copyable_v<CapturedStack>);
static_assert(std::is_trivially_destructible_v<CapturedStack>);
static_assert(sizeof(CapturedStack) == 520U);

void capture_current_stack(
    CapturedStack& destination, std::uint16_t maximum_depth,
    std::uint32_t additional_frames_to_skip = 0U,
    StackCaptureMethod method = StackCaptureMethod::kRtlCaptureStackBackTrace) noexcept;

[[nodiscard]] bool stack_capture_succeeded(const CapturedStack& stack) noexcept;

}  // namespace noleax::agent::windows
