#include "noleax/agent/patch_rendezvous.hpp"

#include "noleax/agent/hook_section.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <intrin.h>
#include <windows.h>
#endif

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <thread>

namespace {

// Plain volatile flag: the spin loop must compile to inline instructions only (no STL atomic
// helper calls, which /Od emits as out-of-line calls into .text), otherwise a suspended spinner
// can legitimately sit outside the section and the rendezvous test becomes probabilistic.
volatile bool spin_stop{false};
std::atomic<bool> spin_entered{false};

NOLEAX_HOOK_SECTION_PUSH

NOLEAX_HOOK_SECTION
void spin_in_hook_section() noexcept {
  spin_entered.store(true, std::memory_order_release);
  while (!spin_stop) {
#if defined(_WIN32)
    _mm_pause();
#elif defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#endif
  }
}

NOLEAX_HOOK_SECTION_POP

[[nodiscard]] bool address_inside(const noleax::agent::HookCodeRegion& region,
                                  const void* address) noexcept {
  const auto cursor = reinterpret_cast<std::uintptr_t>(address);
  return cursor >= reinterpret_cast<std::uintptr_t>(region.begin) &&
         cursor < reinterpret_cast<std::uintptr_t>(region.end);
}

}  // namespace

TEST_CASE("hook code region resolves the .nlxhk section of the local module",
          "[agent][patch-rendezvous]") {
  using noleax::agent::hook_code_region;

  const auto region = hook_code_region(reinterpret_cast<const void*>(&spin_in_hook_section));
  REQUIRE(region.begin != nullptr);
  REQUIRE(region.end != nullptr);
  CHECK(region.begin < region.end);
  CHECK(address_inside(region, reinterpret_cast<const void*>(&spin_in_hook_section)));

  int stack_value = 0;
  const auto empty = hook_code_region(&stack_value);
  CHECK(empty.begin == nullptr);
  CHECK(empty.end == nullptr);
  CHECK(hook_code_region(nullptr).begin == nullptr);
}

TEST_CASE("replacement evacuation fails closed for empty regions", "[agent][patch-rendezvous]") {
  using noleax::agent::HookCodeRegion;
  using noleax::agent::verify_replacement_evacuated;

  CHECK_FALSE(verify_replacement_evacuated(HookCodeRegion{}, 4U));
  const auto region =
      noleax::agent::hook_code_region(reinterpret_cast<const void*>(&spin_in_hook_section));
  REQUIRE(region.begin != nullptr);
  CHECK_FALSE(verify_replacement_evacuated(HookCodeRegion{region.begin, region.begin}, 4U));
}

TEST_CASE("replacement evacuation observes threads inside the section",
          "[agent][patch-rendezvous]") {
  using noleax::agent::hook_code_region;
  using noleax::agent::verify_replacement_evacuated;

  const auto region = hook_code_region(reinterpret_cast<const void*>(&spin_in_hook_section));
  REQUIRE(region.begin != nullptr);
  CHECK(verify_replacement_evacuated(region, 100U));

  spin_stop = false;
  spin_entered.store(false, std::memory_order_release);
  std::thread spinner{&spin_in_hook_section};
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
  while (!spin_entered.load(std::memory_order_acquire) &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::yield();
  }
  REQUIRE(spin_entered.load(std::memory_order_acquire));
  CHECK_FALSE(verify_replacement_evacuated(region, 4U));

  spin_stop = true;
  spinner.join();
  CHECK(verify_replacement_evacuated(region, 100U));
}

TEST_CASE("agent module reference counter round-trips", "[agent][patch-rendezvous]") {
  const std::uint32_t base = noleax::agent::agent_module_reference_count();
  noleax::agent::note_agent_module_reference_acquired();
  noleax::agent::note_agent_module_reference_acquired();
  CHECK(noleax::agent::agent_module_reference_count() == base + 2U);
  noleax::agent::note_agent_module_reference_released();
  noleax::agent::note_agent_module_reference_released();
  CHECK(noleax::agent::agent_module_reference_count() == base);
}
