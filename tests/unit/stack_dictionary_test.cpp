#include "noleax/agent/windows/stack_dictionary.hpp"

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <stdexcept>

namespace {

[[nodiscard]] noleax::agent::windows::CapturedStack captured_stack(std::uint64_t first_frame) {
  noleax::agent::windows::CapturedStack stack;
  stack.frame_count = 2U;
  stack.requested_depth = 2U;
  stack.status = noleax::agent::windows::StackCaptureStatus::kCaptured;
  stack.frames[0] = first_frame;
  stack.frames[1] = first_frame + 0x10U;
  return stack;
}

[[nodiscard]] noleax::agent::windows::NormalizedStack normalized_stack(
    std::uint64_t module_id, std::uint64_t absolute_address) {
  noleax::agent::windows::NormalizedStack stack;
  stack.frame_count = 1U;
  stack.status = noleax::trace::StackCaptureStatus::kComplete;
  stack.frames[0] = {noleax::trace::ModuleId{module_id}, 0x20U, absolute_address, 0U};
  return stack;
}

}  // namespace

TEST_CASE("raw stack dictionary compares full stacks after hash collisions",
          "[agent][stack][dictionary]") {
  CHECK_THROWS_AS(noleax::agent::windows::RawStackDictionary{0U}, std::invalid_argument);
  noleax::agent::windows::RawStackDictionary dictionary{2U};
  const auto first = captured_stack(0x1000U);
  const auto second = captured_stack(0x2000U);

  const auto first_insert = dictionary.intern(first, 7U);
  CHECK(first_insert.inserted);
  CHECK_FALSE(first_insert.segment_reset);
  CHECK(first_insert.stack_id.value() == 1U);

  const auto first_reuse = dictionary.intern(first, 7U);
  CHECK_FALSE(first_reuse.inserted);
  CHECK(first_reuse.stack_id == first_insert.stack_id);

  const auto collision = dictionary.intern(second, 7U);
  CHECK(collision.inserted);
  CHECK(collision.stack_id.value() == 2U);
  CHECK(dictionary.size() == 2U);
}

TEST_CASE("raw stack dictionary resets bounded segments without reusing IDs",
          "[agent][stack][dictionary]") {
  noleax::agent::windows::RawStackDictionary dictionary{2U};
  const auto first = dictionary.intern(captured_stack(0x1000U), 1U);
  const auto second = dictionary.intern(captured_stack(0x2000U), 2U);
  const auto third = dictionary.intern(captured_stack(0x3000U), 3U);

  CHECK(first.stack_id.value() == 1U);
  CHECK(second.stack_id.value() == 2U);
  CHECK(third.stack_id.value() == 3U);
  CHECK(third.segment_reset);
  CHECK(dictionary.size() == 1U);
  CHECK(dictionary.capacity() == 2U);
  CHECK(dictionary.segment_count() == 2U);

  auto failed = captured_stack(0x4000U);
  failed.frame_count = 0U;
  failed.status = noleax::agent::windows::StackCaptureStatus::kFailed;
  CHECK_THROWS_AS(dictionary.intern(failed, 4U), std::invalid_argument);
}

TEST_CASE("raw stack hash includes status count and every frame", "[agent][stack][dictionary]") {
  const auto first = captured_stack(0x1000U);
  auto changed_frame = first;
  changed_frame.frames[1] += 1U;
  auto changed_count = first;
  changed_count.frame_count = 1U;
  auto changed_status = first;
  changed_status.status = noleax::agent::windows::StackCaptureStatus::kTruncated;
  CHECK(noleax::agent::windows::hash_captured_stack(first) ==
        noleax::agent::windows::hash_captured_stack(first));
  CHECK(noleax::agent::windows::hash_captured_stack(first) !=
        noleax::agent::windows::hash_captured_stack(changed_frame));
  CHECK(noleax::agent::windows::hash_captured_stack(first) !=
        noleax::agent::windows::hash_captured_stack(changed_count));
  CHECK(noleax::agent::windows::hash_captured_stack(first) !=
        noleax::agent::windows::hash_captured_stack(changed_status));
}

TEST_CASE("normalized stack dictionary distinguishes module generations at reused addresses",
          "[agent][stack][dictionary][module]") {
  noleax::agent::windows::NormalizedStackDictionary dictionary{4U};
  const auto first = normalized_stack(10U, 0x100020U);
  const auto reloaded = normalized_stack(11U, 0x100020U);

  const auto first_insert =
      dictionary.intern(first, noleax::agent::windows::hash_normalized_stack(first));
  const auto first_reuse =
      dictionary.intern(first, noleax::agent::windows::hash_normalized_stack(first));
  const auto reload_insert =
      dictionary.intern(reloaded, noleax::agent::windows::hash_normalized_stack(reloaded));

  CHECK(first_insert.inserted);
  CHECK_FALSE(first_reuse.inserted);
  CHECK(first_reuse.stack_id == first_insert.stack_id);
  CHECK(reload_insert.inserted);
  CHECK(reload_insert.stack_id != first_insert.stack_id);
  CHECK(noleax::agent::windows::hash_normalized_stack(first) !=
        noleax::agent::windows::hash_normalized_stack(reloaded));

  auto invalid = first;
  invalid.frames[0].module_id = {};
  CHECK_THROWS_AS(dictionary.intern(invalid, 1U), std::invalid_argument);
}
