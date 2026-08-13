#include "noleax/agent/hook_backend.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <array>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>

namespace {

#if defined(_WIN32)
using FixtureFunction = std::uint64_t(WINAPI*)(std::uint64_t, std::uint64_t) noexcept;
#define NOLEAX_TEST_NOINLINE __declspec(noinline)
#else
using FixtureFunction = std::uint64_t (*)(std::uint64_t, std::uint64_t) noexcept;
#define NOLEAX_TEST_NOINLINE __attribute__((noinline))
#endif

constexpr std::uint64_t kTransformMask = 0xa5a55a5af0f00f0fULL;
constexpr std::uint64_t kCombineMask = 0x5a5aa5a50f0ff0f0ULL;

FixtureFunction transform_original = nullptr;
FixtureFunction combine_original = nullptr;
std::atomic<std::uint64_t> transform_calls{0U};
std::atomic<std::uint64_t> combine_calls{0U};
noleax::agent::OriginalTrampolineSlot published_original{nullptr};
std::atomic<bool> entered_without_published_original{false};

NOLEAX_TEST_NOINLINE std::uint64_t transform_replacement(std::uint64_t left,
                                                         std::uint64_t right) noexcept {
  transform_calls.fetch_add(1U, std::memory_order_relaxed);
  return transform_original(left, right) ^ kTransformMask;
}

NOLEAX_TEST_NOINLINE std::uint64_t combine_replacement(std::uint64_t left,
                                                       std::uint64_t right) noexcept {
  combine_calls.fetch_add(1U, std::memory_order_relaxed);
  return combine_original(left, right) ^ kCombineMask;
}

NOLEAX_TEST_NOINLINE std::uint64_t published_original_replacement(std::uint64_t left,
                                                                  std::uint64_t right) noexcept {
  void* const original_address = published_original.load(std::memory_order_acquire);
  if (original_address == nullptr) {
    entered_without_published_original.store(true, std::memory_order_relaxed);
    return 0U;
  }
  const auto original = reinterpret_cast<FixtureFunction>(original_address);
  return original(left, right) ^ kTransformMask;
}

[[nodiscard]] void* function_address(FixtureFunction function) noexcept {
  return reinterpret_cast<void*>(function);
}

class LoadedHookFixture {
 public:
#if defined(_WIN32)
  LoadedHookFixture()
      : module_{LoadLibraryW(std::filesystem::path{NOLEAX_HOOK_FIXTURE_PATH}.c_str())} {
    if (module_ == nullptr) {
      throw std::runtime_error{"cannot load the hook backend fixture"};
    }
  }

  ~LoadedHookFixture() {
    if (module_ != nullptr) {
      FreeLibrary(module_);
    }
  }

  [[nodiscard]] FixtureFunction function(const char* name) const {
    const FARPROC address = GetProcAddress(module_, name);
    if (address == nullptr) {
      throw std::runtime_error{"hook backend fixture export is missing"};
    }
    return reinterpret_cast<FixtureFunction>(address);
  }

 private:
  HMODULE module_{nullptr};
#else
  LoadedHookFixture() : module_{dlopen(NOLEAX_HOOK_FIXTURE_PATH, RTLD_NOW | RTLD_LOCAL)} {
    if (module_ == nullptr) {
      throw std::runtime_error{"cannot load the hook backend fixture"};
    }
  }

  ~LoadedHookFixture() {
    if (module_ != nullptr) {
      dlclose(module_);
    }
  }

  [[nodiscard]] FixtureFunction function(const char* name) const {
    void* const address = dlsym(module_, name);
    if (address == nullptr) {
      throw std::runtime_error{"hook backend fixture export is missing"};
    }
    return reinterpret_cast<FixtureFunction>(address);
  }

 private:
  void* module_{nullptr};
#endif

 public:
  LoadedHookFixture(const LoadedHookFixture&) = delete;
  LoadedHookFixture& operator=(const LoadedHookFixture&) = delete;
};

class OriginalReset {
 public:
  ~OriginalReset() {
    transform_original = nullptr;
    combine_original = nullptr;
    transform_calls = 0U;
    combine_calls = 0U;
    published_original.store(nullptr, std::memory_order_relaxed);
    entered_without_published_original.store(false, std::memory_order_relaxed);
  }
};

}  // namespace

TEST_CASE("hook backend status names are stable", "[agent][hook-backend]") {
  using Install = noleax::agent::HookInstallStatus;
  constexpr std::array install_cases{
      std::pair{Install::kInstalled, std::string_view{"installed"}},
      std::pair{Install::kInvalidArgument, std::string_view{"invalid_argument"}},
      std::pair{Install::kAlreadyInstalled, std::string_view{"already_installed"}},
      std::pair{Install::kAlreadyReplaced, std::string_view{"already_replaced"}},
      std::pair{Install::kWrongSignature, std::string_view{"wrong_signature"}},
      std::pair{Install::kPolicyViolation, std::string_view{"policy_violation"}},
      std::pair{Install::kWrongType, std::string_view{"wrong_type"}},
      std::pair{Install::kMissingOriginal, std::string_view{"missing_original"}},
      std::pair{Install::kTeardownPending, std::string_view{"teardown_pending"}},
      std::pair{Install::kBackendStopped, std::string_view{"backend_stopped"}},
  };
  for (const auto& [status, name] : install_cases) {
    CHECK(noleax::agent::hook_install_status_name(status) == name);
  }
  CHECK(noleax::agent::hook_install_status_name(static_cast<Install>(0xffU)) == "unknown");

  using Uninstall = noleax::agent::HookUninstallStatus;
  constexpr std::array uninstall_cases{
      std::pair{Uninstall::kUninstalled, std::string_view{"uninstalled"}},
      std::pair{Uninstall::kNotInstalled, std::string_view{"not_installed"}},
      std::pair{Uninstall::kTeardownPending, std::string_view{"teardown_pending"}},
      std::pair{Uninstall::kBackendStopped, std::string_view{"backend_stopped"}},
  };
  for (const auto& [status, name] : uninstall_cases) {
    CHECK(noleax::agent::hook_uninstall_status_name(status) == name);
  }
  CHECK(noleax::agent::hook_uninstall_status_name(static_cast<Uninstall>(0xffU)) == "unknown");
}

TEST_CASE("hook backend installs calls and removes a fast replacement", "[agent][hook-backend]") {
  const LoadedHookFixture fixture;
  const OriginalReset reset;
  const FixtureFunction target = fixture.function("noleax_hook_fixture_transform");
  constexpr std::uint64_t left = 0x123456789abcdef0ULL;
  constexpr std::uint64_t right = 0x0fedcba987654321ULL;
  const std::uint64_t baseline = target(left, right);

  noleax::agent::HookBackend backend;
  REQUIRE(backend.is_active());
  CHECK(backend.installed_count() == 0U);
  CHECK_FALSE(backend.has_pending_teardown());

  const auto installed =
      backend.install_fast(function_address(target), function_address(transform_replacement));
  REQUIRE(installed.status == noleax::agent::HookInstallStatus::kInstalled);
  REQUIRE(installed.original != nullptr);
  REQUIRE(installed.installed());
  transform_original = reinterpret_cast<FixtureFunction>(installed.original);
  CHECK(backend.installed_count() == 1U);
  CHECK(transform_original(left, right) == baseline);
  CHECK(target(left, right) == (baseline ^ kTransformMask));
  CHECK(transform_calls == 1U);

  const auto duplicate =
      backend.install_fast(function_address(target), function_address(transform_replacement));
  CHECK(duplicate.status == noleax::agent::HookInstallStatus::kAlreadyInstalled);
  CHECK(duplicate.original == installed.original);

  noleax::agent::HookBackend competing_backend;
  const auto competing = competing_backend.install_fast(function_address(target),
                                                        function_address(transform_replacement));
  CHECK(competing.status == noleax::agent::HookInstallStatus::kAlreadyReplaced);
  CHECK(competing.original == nullptr);

  CHECK(backend.uninstall(function_address(target)) ==
        noleax::agent::HookUninstallStatus::kUninstalled);
  CHECK(backend.installed_count() == 0U);
  CHECK_FALSE(backend.has_pending_teardown());
  CHECK(target(left, right) == baseline);
  CHECK(transform_calls == 1U);
  CHECK(backend.uninstall(function_address(target)) ==
        noleax::agent::HookUninstallStatus::kNotInstalled);
}

TEST_CASE("hook backend publishes an original slot before activation", "[agent][hook-backend]") {
  const LoadedHookFixture fixture;
  const OriginalReset reset;
  const FixtureFunction target = fixture.function("noleax_hook_fixture_transform");
  constexpr std::uint64_t left = 0x1020304050607080ULL;
  constexpr std::uint64_t right = 0x8877665544332211ULL;
  const std::uint64_t baseline = target(left, right);
  noleax::agent::HookBackend backend;

  const auto installed =
      backend.install_fast(function_address(target),
                           function_address(published_original_replacement), &published_original);
  REQUIRE(installed.installed());
  REQUIRE(installed.original != nullptr);
  CHECK(published_original.load(std::memory_order_acquire) == installed.original);
  CHECK(target(left, right) == (baseline ^ kTransformMask));
  CHECK_FALSE(entered_without_published_original.load(std::memory_order_relaxed));

  CHECK(backend.uninstall(function_address(target)) ==
        noleax::agent::HookUninstallStatus::kUninstalled);
  published_original.store(nullptr, std::memory_order_release);
  CHECK(target(left, right) == baseline);
}

TEST_CASE("hook backend serializes transactions across instances", "[agent][hook-backend]") {
  const LoadedHookFixture fixture;
  const OriginalReset reset;
  const FixtureFunction transform = fixture.function("noleax_hook_fixture_transform");
  const FixtureFunction combine = fixture.function("noleax_hook_fixture_combine");
  constexpr std::uint64_t left = 17U;
  constexpr std::uint64_t right = 29U;
  const std::uint64_t transform_baseline = transform(left, right);
  const std::uint64_t combine_baseline = combine(left, right);

  for (std::uint32_t iteration = 0U; iteration < 10U; ++iteration) {
    noleax::agent::HookBackend transform_backend;
    noleax::agent::HookBackend combine_backend;
    noleax::agent::FastHookResult transform_result;
    noleax::agent::FastHookResult combine_result;
    std::atomic<std::uint32_t> ready{0U};
    std::atomic<bool> start{false};

    auto wait_for_start = [&] {
      ready.fetch_add(1U, std::memory_order_release);
      while (!start.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
    };
    std::thread transform_installer{[&] {
      wait_for_start();
      transform_result = transform_backend.install_fast(function_address(transform),
                                                        function_address(transform_replacement));
    }};
    std::thread combine_installer{[&] {
      wait_for_start();
      combine_result = combine_backend.install_fast(function_address(combine),
                                                    function_address(combine_replacement));
    }};
    while (ready.load(std::memory_order_acquire) != 2U) {
      std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);
    transform_installer.join();
    combine_installer.join();

    REQUIRE(transform_result.installed());
    REQUIRE(combine_result.installed());
    transform_original = reinterpret_cast<FixtureFunction>(transform_result.original);
    combine_original = reinterpret_cast<FixtureFunction>(combine_result.original);
    CHECK(transform(left + iteration, right) ==
          (transform_original(left + iteration, right) ^ kTransformMask));
    CHECK(combine(left, right + iteration) ==
          (combine_original(left, right + iteration) ^ kCombineMask));
    CHECK(transform_backend.uninstall(function_address(transform)) ==
          noleax::agent::HookUninstallStatus::kUninstalled);
    CHECK(combine_backend.uninstall(function_address(combine)) ==
          noleax::agent::HookUninstallStatus::kUninstalled);
  }

  CHECK(transform(left, right) == transform_baseline);
  CHECK(combine(left, right) == combine_baseline);
}

TEST_CASE("hook backend validates input and becomes inert after shutdown",
          "[agent][hook-backend]") {
  const LoadedHookFixture fixture;
  const FixtureFunction target = fixture.function("noleax_hook_fixture_transform");
  noleax::agent::HookBackend backend;

  CHECK(backend.install_fast(nullptr, function_address(transform_replacement)).status ==
        noleax::agent::HookInstallStatus::kInvalidArgument);
  CHECK(backend.install_fast(function_address(target), nullptr).status ==
        noleax::agent::HookInstallStatus::kInvalidArgument);
  CHECK(backend.install_fast(function_address(target), function_address(target)).status ==
        noleax::agent::HookInstallStatus::kInvalidArgument);
  CHECK(backend.flush());
  CHECK(backend.shutdown());
  CHECK_FALSE(backend.is_active());
  CHECK(backend.shutdown());
  CHECK(backend.install_fast(function_address(target), function_address(transform_replacement))
            .status == noleax::agent::HookInstallStatus::kBackendStopped);
  CHECK(backend.uninstall(function_address(target)) ==
        noleax::agent::HookUninstallStatus::kBackendStopped);
}

TEST_CASE("hook backend exposes deferred teardown until an explicit flush",
          "[agent][hook-backend]") {
  const LoadedHookFixture fixture;
  const OriginalReset reset;
  const FixtureFunction target = fixture.function("noleax_hook_fixture_transform");
  constexpr std::uint64_t left = 41U;
  constexpr std::uint64_t right = 97U;
  const std::uint64_t baseline = target(left, right);
  noleax::agent::HookBackend backend;

  const auto installed =
      backend.install_fast(function_address(target), function_address(transform_replacement));
  REQUIRE(installed.installed());
  transform_original = reinterpret_cast<FixtureFunction>(installed.original);
  REQUIRE(target(left, right) == (baseline ^ kTransformMask));

  CHECK(backend.uninstall(function_address(target), std::chrono::steady_clock::now()) ==
        noleax::agent::HookUninstallStatus::kTeardownPending);
  CHECK(backend.has_pending_teardown());
  CHECK(backend.installed_count() == 0U);
  CHECK(target(left, right) == baseline);
  CHECK(backend.install_fast(function_address(target), function_address(transform_replacement))
            .status == noleax::agent::HookInstallStatus::kTeardownPending);

  CHECK(backend.flush());
  CHECK_FALSE(backend.has_pending_teardown());
  const auto reinstalled =
      backend.install_fast(function_address(target), function_address(transform_replacement));
  REQUIRE(reinstalled.installed());
  transform_original = reinterpret_cast<FixtureFunction>(reinstalled.original);
  CHECK(backend.uninstall(function_address(target)) ==
        noleax::agent::HookUninstallStatus::kUninstalled);
}

TEST_CASE("hook backend lifetime lease blocks trampoline flush and deinit",
          "[agent][hook-backend][quiescence]") {
  const LoadedHookFixture fixture;
  const OriginalReset reset;
  const FixtureFunction target = fixture.function("noleax_hook_fixture_transform");
  constexpr std::uint64_t left = 73U;
  constexpr std::uint64_t right = 151U;
  const std::uint64_t baseline = target(left, right);

  SECTION("deferred uninstall") {
    noleax::agent::HookBackend backend;
    REQUIRE(backend.acquire_trampoline_lifetime_lease());
    CHECK(backend.trampoline_lifetime_lease_count() == 1U);
    const auto installed =
        backend.install_fast(function_address(target), function_address(transform_replacement));
    REQUIRE(installed.installed());
    transform_original = reinterpret_cast<FixtureFunction>(installed.original);
    REQUIRE(target(left, right) == (baseline ^ kTransformMask));

    CHECK(backend.uninstall(function_address(target), std::chrono::steady_clock::now()) ==
          noleax::agent::HookUninstallStatus::kTeardownPending);
    CHECK(target(left, right) == baseline);
    CHECK_FALSE(backend.flush());

    backend.release_trampoline_lifetime_lease();
    CHECK(backend.trampoline_lifetime_lease_count() == 0U);
    CHECK(backend.flush());
    CHECK_FALSE(backend.has_pending_teardown());
  }

  SECTION("shutdown") {
    noleax::agent::HookBackend backend;
    REQUIRE(backend.acquire_trampoline_lifetime_lease());
    const auto installed =
        backend.install_fast(function_address(target), function_address(transform_replacement));
    REQUIRE(installed.installed());
    transform_original = reinterpret_cast<FixtureFunction>(installed.original);
    REQUIRE(target(left, right) == (baseline ^ kTransformMask));

    CHECK_FALSE(backend.shutdown());
    CHECK(target(left, right) == baseline);
    CHECK(backend.has_pending_teardown());
    backend.release_trampoline_lifetime_lease();
    CHECK(backend.shutdown());
    CHECK_FALSE(backend.is_active());
  }
}

TEST_CASE("hook backend reverts all hooks during shutdown and destruction",
          "[agent][hook-backend]") {
  const LoadedHookFixture fixture;
  const OriginalReset reset;
  const FixtureFunction transform = fixture.function("noleax_hook_fixture_transform");
  const FixtureFunction combine = fixture.function("noleax_hook_fixture_combine");
  constexpr std::uint64_t left = 101U;
  constexpr std::uint64_t right = 303U;
  const std::uint64_t transform_baseline = transform(left, right);
  const std::uint64_t combine_baseline = combine(left, right);

  {
    noleax::agent::HookBackend backend;
    const auto first =
        backend.install_fast(function_address(transform), function_address(transform_replacement));
    const auto second =
        backend.install_fast(function_address(combine), function_address(combine_replacement));
    REQUIRE(first.installed());
    REQUIRE(second.installed());
    transform_original = reinterpret_cast<FixtureFunction>(first.original);
    combine_original = reinterpret_cast<FixtureFunction>(second.original);
    CHECK(transform(left, right) == (transform_baseline ^ kTransformMask));
    CHECK(combine(left, right) == (combine_baseline ^ kCombineMask));
    CHECK(backend.installed_count() == 2U);
    CHECK(backend.shutdown());
    CHECK(backend.installed_count() == 0U);
  }
  CHECK(transform(left, right) == transform_baseline);
  CHECK(combine(left, right) == combine_baseline);

  for (std::uint32_t iteration = 0U; iteration < 25U; ++iteration) {
    noleax::agent::HookBackend backend;
    const auto installed =
        backend.install_fast(function_address(transform), function_address(transform_replacement));
    REQUIRE(installed.installed());
    transform_original = reinterpret_cast<FixtureFunction>(installed.original);
    CHECK(transform(left + iteration, right) ==
          (transform_original(left + iteration, right) ^ kTransformMask));
  }
  CHECK(transform(left, right) == transform_baseline);
}
