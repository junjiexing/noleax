#pragma once

#include <array>
#include <cstdint>
#include <type_traits>

namespace noleax::agent::linux {

inline constexpr std::uint16_t kMaximumCapturedStackDepth = 64U;

enum class StackCaptureMethod : std::uint8_t {
  kUnwindBacktrace,
};

enum class StackCaptureStatus : std::uint8_t {
  kDisabled,
  kCaptured,
  kTruncated,
  kFailed,
};

// Same layout discipline as the Windows CapturedStack: a fixed 520-byte POD the event
// queue can copy by value; frames are raw PCs, symbolization is offline.
struct CapturedStack {
  std::array<std::uint64_t, kMaximumCapturedStackDepth> frames{};
  std::uint16_t frame_count{0U};
  std::uint16_t requested_depth{0U};
  StackCaptureMethod method{StackCaptureMethod::kUnwindBacktrace};
  StackCaptureStatus status{StackCaptureStatus::kDisabled};
  std::uint8_t reserved[2]{};

  bool operator==(const CapturedStack&) const = default;
};

static_assert(std::is_trivially_copyable_v<CapturedStack>);
static_assert(std::is_trivially_destructible_v<CapturedStack>);
static_assert(sizeof(CapturedStack) == 520U);

// Hot-path contract (docs/STACK_CAPTURE.md): no allocation, no locks, no I/O.
// _Unwind_Backtrace satisfies this on glibc >= 2.35 (lock-free _dl_find_object).
void capture_current_stack(
    CapturedStack& destination, std::uint16_t maximum_depth,
    std::uint32_t additional_frames_to_skip = 0U,
    StackCaptureMethod method = StackCaptureMethod::kUnwindBacktrace) noexcept;

[[nodiscard]] bool stack_capture_succeeded(const CapturedStack& stack) noexcept;

}  // namespace noleax::agent::linux
