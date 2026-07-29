#include "noleax/agent/replacement_lifecycle.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("replacement lifecycle snapshots routes and exposes deterministic quiescence",
          "[agent][replacement-lifecycle]") {
  using noleax::agent::ReplacementLifecycle;
  using noleax::agent::ReplacementRoute;

  ReplacementLifecycle lifecycle;
  CHECK(lifecycle.route() == ReplacementRoute::kTarget);
  CHECK(lifecycle.in_flight() == 0U);
  CHECK(lifecycle.wait_for_quiescence(0U));

  lifecycle.start_recording();
  {
    const auto held_entry = lifecycle.enter();
    CHECK(held_entry.route() == ReplacementRoute::kRecord);
    CHECK(held_entry.should_record());
    CHECK(lifecycle.in_flight() == 1U);

    lifecycle.stop_recording();
    lifecycle.route_to_target();
    CHECK_FALSE(lifecycle.wait_for_quiescence(4U));
    CHECK(held_entry.route() == ReplacementRoute::kRecord);
  }

  CHECK(lifecycle.wait_for_quiescence(0U));
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
}
