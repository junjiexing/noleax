#include "noleax/agent/replacement_lifecycle.hpp"

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <thread>

TEST_CASE("replacement lifecycle snapshots routes and exposes deterministic quiescence",
          "[agent][replacement-lifecycle]") {
  using noleax::agent::ReplacementLifecycle;
  using noleax::agent::ReplacementRoute;

  ReplacementLifecycle lifecycle;
  CHECK(lifecycle.route() == ReplacementRoute::kTarget);
  CHECK(lifecycle.in_flight() == 0U);
  CHECK(lifecycle.recording_in_flight() == 0U);
  CHECK(lifecycle.wait_for_quiescence(0U));
  CHECK(lifecycle.wait_for_recording_quiescence(0U));

  lifecycle.start_recording();
  {
    const auto held_entry = lifecycle.enter();
    CHECK(held_entry.route() == ReplacementRoute::kRecord);
    CHECK(held_entry.should_record());
    CHECK(lifecycle.in_flight() == 1U);
    CHECK(lifecycle.recording_in_flight() == 1U);

    lifecycle.stop_recording();
    lifecycle.route_to_target();
    CHECK_FALSE(lifecycle.wait_for_quiescence(4U));
    CHECK_FALSE(lifecycle.wait_for_recording_quiescence(4U));
    CHECK(held_entry.route() == ReplacementRoute::kRecord);
  }

  CHECK(lifecycle.wait_for_quiescence(0U));
  CHECK(lifecycle.wait_for_recording_quiescence(0U));
  CHECK(lifecycle.in_flight() == 0U);
  {
    const auto delayed_entry = lifecycle.enter();
    CHECK(delayed_entry.route() == ReplacementRoute::kTarget);
    CHECK_FALSE(delayed_entry.should_record());
  }

  lifecycle.stop_recording();
  {
    const auto passthrough_entry = lifecycle.enter();
    CHECK(passthrough_entry.route() == ReplacementRoute::kOriginal);
    CHECK_FALSE(passthrough_entry.should_record());
  }
  CHECK(lifecycle.wait_for_quiescence(0U));

  lifecycle.start_recording();
  const auto route = lifecycle.enter_unscoped();
  CHECK(route == ReplacementRoute::kRecord);
  CHECK(lifecycle.in_flight() == 1U);
  CHECK(lifecycle.recording_in_flight() == 1U);
  lifecycle.leave_unscoped(route);
  CHECK(lifecycle.wait_for_quiescence(0U));
  CHECK(lifecycle.wait_for_recording_quiescence(0U));
}

TEST_CASE("replacement finalize gate parks new outer entries until reopened",
          "[agent][replacement-lifecycle][quiescence]") {
  using noleax::agent::ReplacementLifecycle;
  using noleax::agent::ReplacementQuiescenceGate;

  struct GateReset final {
    ~GateReset() { ReplacementQuiescenceGate::open(); }
  } reset;

  ReplacementQuiescenceGate::open();
  ReplacementLifecycle lifecycle;
  lifecycle.start_recording();
  {
    const auto active = lifecycle.enter();
    CHECK_FALSE(ReplacementQuiescenceGate::close_and_wait(0U));
    CHECK(ReplacementQuiescenceGate::active_call_count() == 1U);
    ReplacementQuiescenceGate::open();
  }

  REQUIRE(ReplacementQuiescenceGate::close_and_wait(0U));
  std::atomic<bool> entered{false};
  std::thread blocked{[&] {
    const auto entry = lifecycle.enter();
    entered.store(true, std::memory_order_release);
  }};
  while (ReplacementQuiescenceGate::waiter_count() == 0U) {
    std::this_thread::yield();
  }
  CHECK_FALSE(entered.load(std::memory_order_acquire));
  CHECK(ReplacementQuiescenceGate::active_call_count() == 0U);
  ReplacementQuiescenceGate::open();
  blocked.join();
  CHECK(entered.load(std::memory_order_acquire));
  CHECK(ReplacementQuiescenceGate::waiter_count() == 0U);
}
