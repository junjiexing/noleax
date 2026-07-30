#include "noleax/agent/windows/hook_registry.hpp"
#include "noleax/agent/windows/windows_memory_hooks.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

using noleax::agent::windows::WindowsHookProfile;
using noleax::agent::windows::WindowsLogicalHookApi;

struct TestedHook {
  WindowsLogicalHookApi logical_api;
  noleax::trace::ApiId api_id;
  std::string_view contract;
};

// This table is intentionally independent from the product registry. A new product hook must add
// its contract here, and a removed hook must remove the stale contract entry.
constexpr auto kTestRegistry = std::array{
    TestedHook{WindowsLogicalHookApi::kRtlAllocateHeap, 1U, "rtl-allocate-heap-contract"},
    TestedHook{WindowsLogicalHookApi::kRtlFreeHeap, 2U, "rtl-free-heap-contract"},
    TestedHook{WindowsLogicalHookApi::kRtlReAllocateHeap, 3U, "rtl-reallocate-heap-contract"},
    TestedHook{WindowsLogicalHookApi::kRtlCreateHeap, 4U, "rtl-heap-lifecycle-contract"},
    TestedHook{WindowsLogicalHookApi::kRtlDestroyHeap, 5U, "rtl-heap-lifecycle-contract"},
    TestedHook{WindowsLogicalHookApi::kNtAllocateVirtualMemory, 6U, "nt-virtual-memory-contract"},
    TestedHook{WindowsLogicalHookApi::kNtFreeVirtualMemory, 7U, "nt-virtual-memory-contract"},
    TestedHook{WindowsLogicalHookApi::kNtMapViewOfSection, 8U, "nt-section-view-contract"},
    TestedHook{WindowsLogicalHookApi::kNtUnmapViewOfSection, 9U, "nt-section-view-contract"},
};

template <std::size_t Size>
void check_profile(WindowsHookProfile profile,
                   const std::array<WindowsLogicalHookApi, Size>& expected) {
  std::size_t selected = 0U;
  for (const auto& hook : noleax::agent::windows::kWindowsHookRegistry) {
    const bool should_select = [&] {
      for (const WindowsLogicalHookApi logical_api : expected) {
        if (logical_api == hook.logical_api) {
          return true;
        }
      }
      return false;
    }();
    CAPTURE(hook.canonical_name);
    CHECK(noleax::agent::windows::profile_contains_api(profile, hook) == should_select);
    selected += should_select ? 1U : 0U;
  }
  CHECK(selected == expected.size());
}

}  // namespace

TEST_CASE("Windows hook and test registries are one-to-one", "[agent][windows][registry]") {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  REQUIRE(ntdll != nullptr);
  REQUIRE(noleax::agent::windows::kWindowsHookRegistry.size() == kTestRegistry.size());

  std::size_t physical_export_count = 0U;
  for (const auto& hook : noleax::agent::windows::kWindowsHookRegistry) {
    std::size_t matches = 0U;
    for (const TestedHook& tested : kTestRegistry) {
      if (tested.logical_api == hook.logical_api && tested.api_id == hook.api_id) {
        ++matches;
        CHECK_FALSE(tested.contract.empty());
      }
    }
    CAPTURE(hook.canonical_name, hook.api_id);
    CHECK(matches == 1U);
    CHECK(hook.api_id != 0U);
    CHECK(hook.module_name == "ntdll.dll");
    CHECK_FALSE(hook.canonical_name.empty());
    CHECK(hook.exports().size() == hook.physical_export_count);
    REQUIRE_FALSE(hook.exports().empty());
    for (const std::string_view physical_export : hook.exports()) {
      CHECK_FALSE(physical_export.empty());
      CHECK(GetProcAddress(ntdll, physical_export.data()) != nullptr);
      ++physical_export_count;
    }
    CHECK(noleax::agent::windows::find_windows_hook(hook.logical_api) == &hook);
    CHECK(noleax::agent::windows::find_windows_hook(hook.api_id) == &hook);
  }
  CHECK(physical_export_count == 10U);
}

TEST_CASE("Windows profiles select exact normalized API sets", "[agent][windows][registry]") {
  using enum WindowsLogicalHookApi;
  check_profile(WindowsHookProfile::kNtHeap,
                std::array{kRtlAllocateHeap, kRtlFreeHeap, kRtlReAllocateHeap, kRtlCreateHeap,
                           kRtlDestroyHeap});
  check_profile(WindowsHookProfile::kVirtualMemory,
                std::array{kNtAllocateVirtualMemory, kNtFreeVirtualMemory, kNtMapViewOfSection,
                           kNtUnmapViewOfSection});
  check_profile(WindowsHookProfile::kNative,
                std::array{kRtlAllocateHeap, kRtlFreeHeap, kRtlReAllocateHeap, kRtlCreateHeap,
                           kRtlDestroyHeap, kNtAllocateVirtualMemory, kNtFreeVirtualMemory,
                           kNtMapViewOfSection, kNtUnmapViewOfSection});
  CHECK(noleax::agent::windows::windows_hook_profile_name(WindowsHookProfile::kNtHeap) ==
        "windows-nt-heap");
  CHECK(noleax::agent::windows::windows_hook_profile_name(WindowsHookProfile::kVirtualMemory) ==
        "windows-virtual-memory");
  CHECK(noleax::agent::windows::windows_hook_profile_name(WindowsHookProfile::kNative) ==
        "windows-native");
}

TEST_CASE("Windows profile coordinator materializes only selected hook families",
          "[agent][windows][profile]") {
  for (const WindowsHookProfile profile :
       {WindowsHookProfile::kNtHeap, WindowsHookProfile::kVirtualMemory,
        WindowsHookProfile::kNative}) {
    noleax::agent::HookBackend backend;
    noleax::agent::windows::WindowsMemoryHookOptions options;
    options.profile = profile;
    options.event_queue_capacity = 64U;
    options.maximum_stack_depth = 0U;
    noleax::agent::windows::WindowsMemoryHooks hooks{backend, options};
    const bool expects_heap = profile != WindowsHookProfile::kVirtualMemory;
    const bool expects_virtual_memory = profile != WindowsHookProfile::kNtHeap;
    CHECK((hooks.nt_heap_hooks() != nullptr) == expects_heap);
    CHECK((hooks.virtual_memory_hooks() != nullptr) == expects_virtual_memory);
    if (hooks.nt_heap_hooks() != nullptr) {
      CHECK(&hooks.nt_heap_hooks()->event_queue() == &hooks.event_queue());
    }
    if (hooks.virtual_memory_hooks() != nullptr) {
      CHECK(&hooks.virtual_memory_hooks()->event_queue() == &hooks.event_queue());
    }
    CHECK(hooks.profile() == profile);
    CHECK(hooks.minimum_capture_size() == 0U);
    CHECK(hooks.stop_recording(0U));
    CHECK(hooks.uninstall(0U));
    CHECK(backend.shutdown());
  }
}
