#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>

#include "noleax/agent/linux/stack_capture.hpp"

namespace {

using noleax::agent::linux::capture_current_stack;
using noleax::agent::linux::CapturedStack;
using noleax::agent::linux::stack_capture_succeeded;
using noleax::agent::linux::StackCaptureStatus;

template <int N>
__attribute__((noinline)) std::uint64_t chain_bottom(std::uint16_t depth, std::uint32_t skip,
                                                     CapturedStack& stack) {
  volatile std::uint64_t guard = N;
  if constexpr (N > 0) {
    return chain_bottom<N - 1>(depth, skip, stack) + guard - guard;
  } else {
    capture_current_stack(stack, depth, skip);
    return guard;
  }
}

}  // namespace

TEST_CASE("linux stack capture walks the full chain without frame pointers",
          "[agent][stack-capture][linux]") {
  CapturedStack stack;
  chain_bottom<30>(64U, 0U, stack);

  REQUIRE(stack.status == StackCaptureStatus::kCaptured);
  CHECK(stack.requested_depth == 64U);
  CHECK(stack.frame_count >= 30U);
  CHECK(stack_capture_succeeded(stack));
  for (std::uint16_t index = 0U; index < stack.frame_count; ++index) {
    CHECK(stack.frames[index] > 0x10000U);
  }
}

TEST_CASE("linux stack capture reports truncation at the requested depth",
          "[agent][stack-capture][linux]") {
  CapturedStack stack;
  chain_bottom<30>(3U, 0U, stack);

  CHECK(stack.status == StackCaptureStatus::kTruncated);
  CHECK(stack.frame_count == 3U);
  CHECK(stack.requested_depth == 3U);
  CHECK(stack_capture_succeeded(stack));
}

TEST_CASE("linux stack capture honors disabled and clamped depths",
          "[agent][stack-capture][linux]") {
  CapturedStack disabled;
  capture_current_stack(disabled, 0U);
  CHECK(disabled.status == StackCaptureStatus::kDisabled);
  CHECK(disabled.frame_count == 0U);
  CHECK_FALSE(stack_capture_succeeded(disabled));

  CapturedStack clamped;
  chain_bottom<4>(500U, 0U, clamped);
  CHECK(clamped.requested_depth == 64U);
  CHECK(clamped.frame_count <= 64U);
}

TEST_CASE("linux stack capture skips its own and requested frames",
          "[agent][stack-capture][linux]") {
  CapturedStack full;
  chain_bottom<20>(64U, 0U, full);
  CapturedStack skipped;
  chain_bottom<20>(64U, 3U, skipped);

  REQUIRE(full.status == StackCaptureStatus::kCaptured);
  REQUIRE(skipped.status == StackCaptureStatus::kCaptured);
  // The chain is identical on both runs, so skipping exactly three frames must drop the
  // captured depth by exactly three.
  CHECK(full.frame_count == skipped.frame_count + 3U);
}
