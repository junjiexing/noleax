#include "noleax/agent/hook_guard.hpp"

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <thread>

namespace {

class HookGuardRuntimeLease final {
 public:
  HookGuardRuntimeLease() noexcept = default;
  ~HookGuardRuntimeLease() noexcept { noleax::agent::release_hook_guard_runtime(); }

  HookGuardRuntimeLease(const HookGuardRuntimeLease&) = delete;
  HookGuardRuntimeLease& operator=(const HookGuardRuntimeLease&) = delete;
  HookGuardRuntimeLease(HookGuardRuntimeLease&&) = delete;
  HookGuardRuntimeLease& operator=(HookGuardRuntimeLease&&) = delete;
};

}  // namespace

TEST_CASE("hook guard runtime retains shared owners", "[agent][hook-guard]") {
  CHECK_FALSE(noleax::agent::hook_guard_runtime_is_ready());
  REQUIRE(noleax::agent::acquire_hook_guard_runtime());
  {
    [[maybe_unused]] const HookGuardRuntimeLease first_runtime;
    CHECK(noleax::agent::hook_guard_runtime_is_ready());

    REQUIRE(noleax::agent::acquire_hook_guard_runtime());
    {
      [[maybe_unused]] const HookGuardRuntimeLease second_runtime;
      CHECK(noleax::agent::hook_guard_runtime_is_ready());
    }
    CHECK(noleax::agent::hook_guard_runtime_is_ready());
  }
  CHECK_FALSE(noleax::agent::hook_guard_runtime_is_ready());
}

TEST_CASE("hook guard classifies outermost and recursive entries", "[agent][hook-guard]") {
  REQUIRE(noleax::agent::acquire_hook_guard_runtime());
  [[maybe_unused]] const HookGuardRuntimeLease runtime;

  CHECK(noleax::agent::current_hook_depth() == 0U);
  CHECK_FALSE(noleax::agent::current_thread_is_internal());

  {
    const noleax::agent::HookInvocationGuard outermost;
    CHECK(outermost.kind() == noleax::agent::HookEntryKind::kOutermost);
    CHECK(outermost.should_record());
    CHECK(noleax::agent::current_hook_depth() == 1U);

    {
      const noleax::agent::HookInvocationGuard recursive;
      CHECK(recursive.kind() == noleax::agent::HookEntryKind::kRecursive);
      CHECK_FALSE(recursive.should_record());
      CHECK(noleax::agent::current_hook_depth() == 2U);
    }
    CHECK(noleax::agent::current_hook_depth() == 1U);
  }

  CHECK(noleax::agent::current_hook_depth() == 0U);
}

TEST_CASE("hook guard exposes balanced unscoped entry for SEH cleanup", "[agent][hook-guard]") {
  REQUIRE(noleax::agent::acquire_hook_guard_runtime());
  [[maybe_unused]] const HookGuardRuntimeLease runtime;

  const auto kind = noleax::agent::enter_hook_invocation_unscoped();
  CHECK(kind == noleax::agent::HookEntryKind::kOutermost);
  CHECK(noleax::agent::current_hook_depth() == 1U);
  noleax::agent::leave_hook_invocation_unscoped();
  CHECK(noleax::agent::current_hook_depth() == 0U);
}

TEST_CASE("hook guard suppresses nested internal-thread scopes", "[agent][hook-guard]") {
  REQUIRE(noleax::agent::acquire_hook_guard_runtime());
  [[maybe_unused]] const HookGuardRuntimeLease runtime;

  CHECK_FALSE(noleax::agent::current_thread_is_internal());
  {
    const noleax::agent::InternalThreadScope first_scope;
    CHECK(noleax::agent::current_thread_is_internal());
    {
      const noleax::agent::InternalThreadScope second_scope;
      const noleax::agent::HookInvocationGuard internal_entry;
      CHECK(internal_entry.kind() == noleax::agent::HookEntryKind::kInternalThread);
      CHECK_FALSE(internal_entry.should_record());
      CHECK(noleax::agent::current_thread_is_internal());
    }
    CHECK(noleax::agent::current_thread_is_internal());
  }
  CHECK_FALSE(noleax::agent::current_thread_is_internal());
  CHECK(noleax::agent::current_hook_depth() == 0U);
}

TEST_CASE("hook guard state is isolated per thread", "[agent][hook-guard]") {
  REQUIRE(noleax::agent::acquire_hook_guard_runtime());
  [[maybe_unused]] const HookGuardRuntimeLease runtime;

  std::atomic<bool> worker_ok{false};
  {
    const noleax::agent::InternalThreadScope main_internal_scope;
    const noleax::agent::HookInvocationGuard main_guard;
    std::thread worker{[&] {
      const bool initially_clear =
          !noleax::agent::current_thread_is_internal() && noleax::agent::current_hook_depth() == 0U;
      const noleax::agent::HookInvocationGuard worker_guard;
      worker_ok.store(initially_clear && worker_guard.should_record() &&
                          noleax::agent::current_hook_depth() == 1U,
                      std::memory_order_release);
    }};
    worker.join();
    CHECK(main_guard.kind() == noleax::agent::HookEntryKind::kInternalThread);
    CHECK(noleax::agent::current_thread_is_internal());
    CHECK(noleax::agent::current_hook_depth() == 1U);
  }

  CHECK(worker_ok.load(std::memory_order_acquire));
  CHECK_FALSE(noleax::agent::current_thread_is_internal());
  CHECK(noleax::agent::current_hook_depth() == 0U);
}

TEST_CASE("hook guard probe reports zero depths until the runtime is ready",
          "[agent][hook-guard]") {
  const auto not_ready = noleax::agent::detail::probe_hook_guard_thread_state();
  CHECK(not_ready.hook_depth == 0U);
  CHECK(not_ready.internal_depth == 0U);

  REQUIRE(noleax::agent::acquire_hook_guard_runtime());
  [[maybe_unused]] const HookGuardRuntimeLease runtime;
  {
    const noleax::agent::InternalThreadScope internal_scope;
    const noleax::agent::HookInvocationGuard guard;
    const auto inside = noleax::agent::detail::probe_hook_guard_thread_state();
    CHECK(inside.hook_depth == 1U);
    CHECK(inside.internal_depth == 1U);
  }
  const auto cleared = noleax::agent::detail::probe_hook_guard_thread_state();
  CHECK(cleared.hook_depth == 0U);
  CHECK(cleared.internal_depth == 0U);
}

#if !defined(_WIN32)
#include <csignal>

namespace {

std::atomic<bool> signal_handler_ran{false};
std::atomic<std::uint32_t> signal_handler_depth{0U};

void probe_signal_handler(int /*signal*/) {
  // The whole point of the Linux guard model: classification must work in contexts where
  // lazy TLS setup would be fatal. With initial-exec TLS this touches nothing but %fs.
  const noleax::agent::HookInvocationGuard guard;
  if (guard.should_record()) {
    signal_handler_depth.store(noleax::agent::current_hook_depth(), std::memory_order_relaxed);
    signal_handler_ran.store(true, std::memory_order_relaxed);
  }
}

}  // namespace

TEST_CASE("hook guard classifies from a POSIX signal handler", "[agent][hook-guard][posix]") {
  REQUIRE(noleax::agent::acquire_hook_guard_runtime());
  [[maybe_unused]] const HookGuardRuntimeLease runtime;

  struct sigaction previous {};
  struct sigaction action {};
  sigemptyset(&action.sa_mask);
  action.sa_handler = probe_signal_handler;
  REQUIRE(sigaction(SIGUSR1, &action, &previous) == 0);
  REQUIRE(std::raise(SIGUSR1) == 0);
  REQUIRE(sigaction(SIGUSR1, &previous, nullptr) == 0);

  CHECK(signal_handler_ran.load(std::memory_order_acquire));
  CHECK(signal_handler_depth.load(std::memory_order_acquire) == 1U);
  CHECK(noleax::agent::current_hook_depth() == 0U);
}
#endif
