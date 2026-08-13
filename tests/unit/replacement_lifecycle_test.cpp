#include "noleax/agent/replacement_lifecycle.hpp"

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <thread>

#include "noleax/agent/hook_backend.hpp"

namespace {

// Probe spelling for the deadline-based waits: an already-expired deadline still gets one
// condition evaluation, exactly like the old zero-yield probe.
[[nodiscard]] std::chrono::steady_clock::time_point no_wait() noexcept {
  return std::chrono::steady_clock::now();
}

[[nodiscard]] std::chrono::steady_clock::time_point generous_deadline() noexcept {
  return noleax::agent::quiescence_deadline_after();
}

}  // namespace

TEST_CASE("replacement lifecycle snapshots routes and exposes deterministic quiescence",
          "[agent][replacement-lifecycle]") {
  using noleax::agent::ReplacementLifecycle;
  using noleax::agent::ReplacementRoute;

  ReplacementLifecycle lifecycle;
  CHECK(lifecycle.route() == ReplacementRoute::kTarget);
  CHECK(lifecycle.in_flight() == 0U);
  CHECK(lifecycle.recording_in_flight() == 0U);
  CHECK(lifecycle.wait_for_quiescence(no_wait()));
  CHECK(lifecycle.wait_for_recording_quiescence(no_wait()));

  lifecycle.start_recording();
  {
    const auto held_entry = lifecycle.enter();
    CHECK(held_entry.route() == ReplacementRoute::kRecord);
    CHECK(held_entry.should_record());
    CHECK(lifecycle.in_flight() == 1U);
    CHECK(lifecycle.recording_in_flight() == 1U);

    lifecycle.stop_recording();
    lifecycle.route_to_target();
    CHECK_FALSE(lifecycle.wait_for_quiescence(no_wait()));
    CHECK_FALSE(lifecycle.wait_for_recording_quiescence(no_wait()));
    CHECK(held_entry.route() == ReplacementRoute::kRecord);
  }

  CHECK(lifecycle.wait_for_quiescence(no_wait()));
  CHECK(lifecycle.wait_for_recording_quiescence(no_wait()));
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
  CHECK(lifecycle.wait_for_quiescence(no_wait()));

  lifecycle.start_recording();
  const auto route = lifecycle.enter_unscoped();
  CHECK(route == ReplacementRoute::kRecord);
  CHECK(lifecycle.in_flight() == 1U);
  CHECK(lifecycle.recording_in_flight() == 1U);
  lifecycle.leave_unscoped(route);
  CHECK(lifecycle.wait_for_quiescence(no_wait()));
  CHECK(lifecycle.wait_for_recording_quiescence(no_wait()));
}

TEST_CASE("replacement lifecycle quiescence waits sleep until the deadline",
          "[agent][replacement-lifecycle][quiescence]") {
  using noleax::agent::ReplacementLifecycle;

  ReplacementLifecycle lifecycle;
  lifecycle.start_recording();
  const auto held_entry = lifecycle.enter();

  // A bounded wait against a permanently in-flight call times out instead of spinning:
  // it returns false after roughly the budget, well under any unbounded behavior.
  const auto budget = std::chrono::milliseconds{30};
  const auto begin = std::chrono::steady_clock::now();
  CHECK_FALSE(lifecycle.wait_for_quiescence(begin + budget));
  CHECK_FALSE(lifecycle.wait_for_recording_quiescence(begin + budget));
  const auto elapsed = std::chrono::steady_clock::now() - begin;
  CHECK(elapsed >= budget);
  CHECK(elapsed < std::chrono::seconds{10});
}

TEST_CASE("replacement lifecycle quiescence waits wake on the zero transition",
          "[agent][replacement-lifecycle][quiescence]") {
  using noleax::agent::ReplacementLifecycle;

  ReplacementLifecycle lifecycle;
  lifecycle.start_recording();
  std::atomic<bool> release{false};
  std::atomic<bool> left{false};
  std::thread worker{[&] {
    const auto entry = lifecycle.enter();
    while (!release.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
    left.store(true, std::memory_order_release);
  }};
  while (lifecycle.in_flight() == 0U) {
    std::this_thread::yield();
  }

  // The waiter must sleep (not spin) and wake as soon as the in-flight call leaves: the
  // 30 s deadline is never approached once the notify on the zero transition lands.
  const auto begin = std::chrono::steady_clock::now();
  std::atomic<bool> wait_result{false};
  std::thread waiter{[&] {
    wait_result.store(lifecycle.wait_for_quiescence(generous_deadline()),
                      std::memory_order_release);
  }};
  std::this_thread::sleep_for(std::chrono::milliseconds{50});
  release.store(true, std::memory_order_release);
  waiter.join();
  worker.join();
  CHECK(wait_result.load(std::memory_order_acquire));
  CHECK(left.load(std::memory_order_acquire));
  CHECK(std::chrono::steady_clock::now() - begin < std::chrono::seconds{10});
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
    CHECK_FALSE(ReplacementQuiescenceGate::close_and_wait(no_wait()));
    CHECK(ReplacementQuiescenceGate::active_call_count() == 1U);
    ReplacementQuiescenceGate::open();
  }

  REQUIRE(ReplacementQuiescenceGate::close_and_wait(no_wait()));
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

TEST_CASE("replacement gate drain waits for parked entries to leave",
          "[agent][replacement-lifecycle][quiescence]") {
  using noleax::agent::ReplacementLifecycle;
  using noleax::agent::ReplacementQuiescenceGate;

  struct GateReset final {
    ~GateReset() { ReplacementQuiescenceGate::open(); }
  } reset;

  ReplacementQuiescenceGate::open();
  CHECK(ReplacementQuiescenceGate::wait_for_drain(no_wait()));

  ReplacementLifecycle lifecycle;
  lifecycle.start_recording();
  REQUIRE(ReplacementQuiescenceGate::close_and_wait(no_wait()));

  std::atomic<bool> entered{false};
  std::thread blocked{[&] {
    const auto entry = lifecycle.enter();
    entered.store(true, std::memory_order_release);
  }};
  while (ReplacementQuiescenceGate::waiter_count() == 0U) {
    std::this_thread::yield();
  }
  CHECK_FALSE(ReplacementQuiescenceGate::wait_for_drain(no_wait()));

  ReplacementQuiescenceGate::open();
  // The parked thread wakes and leaves its entry; the drain wait sleeps on the quiescence
  // epoch and the zero transitions of the gate counters wake it well before the deadline.
  REQUIRE(ReplacementQuiescenceGate::wait_for_drain(generous_deadline()));
  blocked.join();
  CHECK(entered.load(std::memory_order_acquire));
  CHECK(ReplacementQuiescenceGate::wait_for_drain(no_wait()));
}
