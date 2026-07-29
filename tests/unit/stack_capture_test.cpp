#include "noleax/agent/windows/stack_capture.hpp"

#include <array>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <thread>

#if defined(_MSC_VER)
#define NOLEAX_TEST_NOINLINE __declspec(noinline)
#else
#define NOLEAX_TEST_NOINLINE __attribute__((noinline))
#endif

namespace {

struct CapturePair {
  noleax::agent::windows::CapturedStack rtl;
  noleax::agent::windows::CapturedStack virtual_unwind;
};

NOLEAX_TEST_NOINLINE CapturePair capture_pair() {
  CapturePair pair;
  noleax::agent::windows::capture_current_stack(
      pair.rtl, noleax::agent::windows::kMaximumCapturedStackDepth, 0U,
      noleax::agent::windows::StackCaptureMethod::kRtlCaptureStackBackTrace);
  noleax::agent::windows::capture_current_stack(
      pair.virtual_unwind, noleax::agent::windows::kMaximumCapturedStackDepth, 0U,
      noleax::agent::windows::StackCaptureMethod::kVirtualUnwind);
  return pair;
}

NOLEAX_TEST_NOINLINE CapturePair capture_level_two() { return capture_pair(); }

NOLEAX_TEST_NOINLINE CapturePair capture_level_one() { return capture_level_two(); }

[[nodiscard]] std::size_t common_frame_count(
    const noleax::agent::windows::CapturedStack& left,
    const noleax::agent::windows::CapturedStack& right) noexcept {
  std::size_t common = 0U;
  for (std::uint16_t left_index = 0U; left_index < left.frame_count; ++left_index) {
    for (std::uint16_t right_index = 0U; right_index < right.frame_count; ++right_index) {
      if (left.frames[left_index] == right.frames[right_index]) {
        ++common;
        break;
      }
    }
  }
  return common;
}

[[nodiscard]] bool capture_result_is_well_formed(
    const noleax::agent::windows::CapturedStack& stack,
    noleax::agent::windows::StackCaptureMethod expected_method,
    std::uint16_t expected_depth) noexcept {
  if (stack.method != expected_method || stack.requested_depth != expected_depth) {
    return false;
  }
  if (noleax::agent::windows::stack_capture_succeeded(stack)) {
    for (std::uint16_t index = 0U; index < stack.frame_count; ++index) {
      if (stack.frames[index] == 0U) {
        return false;
      }
    }
    return true;
  }
  return stack.status == noleax::agent::windows::StackCaptureStatus::kFailed &&
         stack.frame_count == 0U;
}

}  // namespace

TEST_CASE("stack capture reports disabled invalid and bounded requests", "[agent][stack]") {
  noleax::agent::windows::CapturedStack stack;
  noleax::agent::windows::capture_current_stack(stack, 0U);
  CHECK(stack.status == noleax::agent::windows::StackCaptureStatus::kDisabled);
  CHECK(stack.frame_count == 0U);
  CHECK_FALSE(noleax::agent::windows::stack_capture_succeeded(stack));

  noleax::agent::windows::capture_current_stack(
      stack, static_cast<std::uint16_t>(noleax::agent::windows::kMaximumCapturedStackDepth + 1U));
  CHECK(stack.status == noleax::agent::windows::StackCaptureStatus::kFailed);
  CHECK(stack.frame_count == 0U);

  noleax::agent::windows::capture_current_stack(stack, 1U);
  CHECK(noleax::agent::windows::stack_capture_succeeded(stack));
  CHECK(stack.status == noleax::agent::windows::StackCaptureStatus::kTruncated);
  CHECK(stack.frame_count == 1U);
  CHECK(stack.requested_depth == 1U);
  CHECK(stack.frames[0] != 0U);
}

TEST_CASE("stack capture strategies agree on their caller chain", "[agent][stack]") {
  const CapturePair pair = capture_level_one();
  REQUIRE(noleax::agent::windows::stack_capture_succeeded(pair.rtl));
  REQUIRE(noleax::agent::windows::stack_capture_succeeded(pair.virtual_unwind));
  CHECK(pair.rtl.method == noleax::agent::windows::StackCaptureMethod::kRtlCaptureStackBackTrace);
  CHECK(pair.virtual_unwind.method == noleax::agent::windows::StackCaptureMethod::kVirtualUnwind);
  CHECK(common_frame_count(pair.rtl, pair.virtual_unwind) >= 2U);
}

TEST_CASE("stack capture strategies survive concurrent unwind pressure", "[agent][stack]") {
  constexpr std::size_t kThreadCount = 8U;
  constexpr std::uint32_t kIterations = 2'000U;
  constexpr std::uint16_t kRequestedDepth = 16U;
  constexpr std::uint64_t kCaptureCount = kThreadCount * kIterations;
  constexpr std::uint64_t kMinimumSuccessCount = kCaptureCount * 99U / 100U;
  std::atomic<bool> start{false};
  std::atomic<std::uint64_t> rtl_successes{0U};
  std::atomic<std::uint64_t> rtl_failures{0U};
  std::atomic<std::uint64_t> virtual_unwind_successes{0U};
  std::atomic<std::uint64_t> virtual_unwind_failures{0U};
  std::atomic<std::uint32_t> malformed_mask{0U};
  std::array<std::thread, kThreadCount> workers;

  for (auto& worker : workers) {
    worker = std::thread{[&] {
      while (!start.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      for (std::uint32_t iteration = 0U; iteration < kIterations; ++iteration) {
        noleax::agent::windows::CapturedStack rtl;
        noleax::agent::windows::CapturedStack virtual_unwind;
        noleax::agent::windows::capture_current_stack(
            rtl, kRequestedDepth, 0U,
            noleax::agent::windows::StackCaptureMethod::kRtlCaptureStackBackTrace);
        noleax::agent::windows::capture_current_stack(
            virtual_unwind, kRequestedDepth, 0U,
            noleax::agent::windows::StackCaptureMethod::kVirtualUnwind);
        if (!capture_result_is_well_formed(
                rtl, noleax::agent::windows::StackCaptureMethod::kRtlCaptureStackBackTrace,
                kRequestedDepth)) {
          malformed_mask.fetch_or(1U, std::memory_order_relaxed);
          return;
        }
        if (!capture_result_is_well_formed(
                virtual_unwind, noleax::agent::windows::StackCaptureMethod::kVirtualUnwind,
                kRequestedDepth)) {
          malformed_mask.fetch_or(2U, std::memory_order_relaxed);
          return;
        }
        (noleax::agent::windows::stack_capture_succeeded(rtl) ? rtl_successes : rtl_failures)
            .fetch_add(1U, std::memory_order_relaxed);
        (noleax::agent::windows::stack_capture_succeeded(virtual_unwind) ? virtual_unwind_successes
                                                                         : virtual_unwind_failures)
            .fetch_add(1U, std::memory_order_relaxed);
      }
    }};
  }

  start.store(true, std::memory_order_release);
  for (auto& worker : workers) {
    worker.join();
  }
  const std::uint64_t rtl_success_count = rtl_successes.load(std::memory_order_relaxed);
  const std::uint64_t rtl_failure_count = rtl_failures.load(std::memory_order_relaxed);
  const std::uint64_t virtual_unwind_success_count =
      virtual_unwind_successes.load(std::memory_order_relaxed);
  const std::uint64_t virtual_unwind_failure_count =
      virtual_unwind_failures.load(std::memory_order_relaxed);
  CHECK(malformed_mask.load(std::memory_order_relaxed) == 0U);
  CHECK(rtl_success_count + rtl_failure_count == kCaptureCount);
  CHECK(virtual_unwind_success_count + virtual_unwind_failure_count == kCaptureCount);
  CHECK(rtl_success_count >= kMinimumSuccessCount);
  CHECK(virtual_unwind_success_count >= kMinimumSuccessCount);
}
