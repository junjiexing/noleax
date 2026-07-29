#include "noleax/agent/hook_backend.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace {

using FixtureFunction = std::uint64_t(WINAPI*)(std::uint64_t, std::uint64_t) noexcept;

constexpr std::uint64_t kTransformMask = 0xa5a55a5af0f00f0fULL;
constexpr std::uint64_t kCombineMask = 0x5a5aa5a50f0ff0f0ULL;

FixtureFunction transform_original = nullptr;
FixtureFunction combine_original = nullptr;
std::atomic<std::uint64_t> transform_calls{0U};
std::atomic<std::uint64_t> combine_calls{0U};

__declspec(noinline) std::uint64_t WINAPI transform_replacement(std::uint64_t left,
                                                                std::uint64_t right) noexcept {
  transform_calls.fetch_add(1U, std::memory_order_relaxed);
  return transform_original(left, right) ^ kTransformMask;
}

__declspec(noinline) std::uint64_t WINAPI combine_replacement(std::uint64_t left,
                                                              std::uint64_t right) noexcept {
  combine_calls.fetch_add(1U, std::memory_order_relaxed);
  return combine_original(left, right) ^ kCombineMask;
}

[[nodiscard]] void* function_address(FixtureFunction function) noexcept {
  return reinterpret_cast<void*>(function);
}

class LoadedHookFixture {
 public:
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

  LoadedHookFixture(const LoadedHookFixture&) = delete;
  LoadedHookFixture& operator=(const LoadedHookFixture&) = delete;

  [[nodiscard]] FixtureFunction function(const char* name) const {
    const FARPROC address = GetProcAddress(module_, name);
    if (address == nullptr) {
      throw std::runtime_error{"hook backend fixture export is missing"};
    }
    return reinterpret_cast<FixtureFunction>(address);
  }

 private:
  HMODULE module_{nullptr};
};

class OriginalReset {
 public:
  ~OriginalReset() {
    transform_original = nullptr;
    combine_original = nullptr;
    transform_calls = 0U;
    combine_calls = 0U;
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

  CHECK(backend.uninstall(function_address(target), 0U) ==
        noleax::agent::HookUninstallStatus::kTeardownPending);
  CHECK(backend.has_pending_teardown());
  CHECK(backend.installed_count() == 0U);
  CHECK(target(left, right) == baseline);
  CHECK(backend.install_fast(function_address(target), function_address(transform_replacement))
            .status == noleax::agent::HookInstallStatus::kTeardownPending);

  CHECK(backend.flush(1U));
  CHECK_FALSE(backend.has_pending_teardown());
  const auto reinstalled =
      backend.install_fast(function_address(target), function_address(transform_replacement));
  REQUIRE(reinstalled.installed());
  transform_original = reinterpret_cast<FixtureFunction>(reinstalled.original);
  CHECK(backend.uninstall(function_address(target)) ==
        noleax::agent::HookUninstallStatus::kUninstalled);
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
