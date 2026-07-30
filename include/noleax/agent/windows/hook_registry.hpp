#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "noleax/trace/identifiers.hpp"

namespace noleax::agent::windows {

inline constexpr noleax::trace::ApiId kRtlAllocateHeapApiId = 1U;
inline constexpr noleax::trace::ApiId kRtlFreeHeapApiId = 2U;
inline constexpr noleax::trace::ApiId kRtlReAllocateHeapApiId = 3U;
inline constexpr noleax::trace::ApiId kRtlCreateHeapApiId = 4U;
inline constexpr noleax::trace::ApiId kRtlDestroyHeapApiId = 5U;
inline constexpr noleax::trace::ApiId kNtAllocateVirtualMemoryApiId = 6U;
inline constexpr noleax::trace::ApiId kNtFreeVirtualMemoryApiId = 7U;
inline constexpr noleax::trace::ApiId kNtMapViewOfSectionApiId = 8U;
inline constexpr noleax::trace::ApiId kNtUnmapViewOfSectionApiId = 9U;

enum class WindowsHookProfile : std::uint8_t {
  kNtHeap,
  kVirtualMemory,
  kNative,
};

enum class WindowsHookApiGroup : std::uint8_t {
  kNtHeap,
  kVirtualMemory,
};

enum class WindowsLogicalHookApi : std::uint8_t {
  kRtlAllocateHeap,
  kRtlFreeHeap,
  kRtlReAllocateHeap,
  kRtlCreateHeap,
  kRtlDestroyHeap,
  kNtAllocateVirtualMemory,
  kNtFreeVirtualMemory,
  kNtMapViewOfSection,
  kNtUnmapViewOfSection,
};

struct WindowsHookRegistryEntry {
  WindowsLogicalHookApi logical_api;
  noleax::trace::ApiId api_id;
  std::string_view canonical_name;
  std::string_view module_name;
  WindowsHookApiGroup group;
  std::array<std::string_view, 2U> physical_exports;
  std::uint8_t physical_export_count;

  [[nodiscard]] constexpr std::span<const std::string_view> exports() const noexcept {
    return {physical_exports.data(), physical_export_count};
  }
};

inline constexpr auto kWindowsHookRegistry = std::array{
    WindowsHookRegistryEntry{WindowsLogicalHookApi::kRtlAllocateHeap,
                             kRtlAllocateHeapApiId,
                             "RtlAllocateHeap",
                             "ntdll.dll",
                             WindowsHookApiGroup::kNtHeap,
                             {"RtlAllocateHeap", {}},
                             1U},
    WindowsHookRegistryEntry{WindowsLogicalHookApi::kRtlFreeHeap,
                             kRtlFreeHeapApiId,
                             "RtlFreeHeap",
                             "ntdll.dll",
                             WindowsHookApiGroup::kNtHeap,
                             {"RtlFreeHeap", {}},
                             1U},
    WindowsHookRegistryEntry{WindowsLogicalHookApi::kRtlReAllocateHeap,
                             kRtlReAllocateHeapApiId,
                             "RtlReAllocateHeap",
                             "ntdll.dll",
                             WindowsHookApiGroup::kNtHeap,
                             {"RtlReAllocateHeap", {}},
                             1U},
    WindowsHookRegistryEntry{WindowsLogicalHookApi::kRtlCreateHeap,
                             kRtlCreateHeapApiId,
                             "RtlCreateHeap",
                             "ntdll.dll",
                             WindowsHookApiGroup::kNtHeap,
                             {"RtlCreateHeap", {}},
                             1U},
    WindowsHookRegistryEntry{WindowsLogicalHookApi::kRtlDestroyHeap,
                             kRtlDestroyHeapApiId,
                             "RtlDestroyHeap",
                             "ntdll.dll",
                             WindowsHookApiGroup::kNtHeap,
                             {"RtlDestroyHeap", {}},
                             1U},
    WindowsHookRegistryEntry{WindowsLogicalHookApi::kNtAllocateVirtualMemory,
                             kNtAllocateVirtualMemoryApiId,
                             "NtAllocateVirtualMemory",
                             "ntdll.dll",
                             WindowsHookApiGroup::kVirtualMemory,
                             {"NtAllocateVirtualMemory", {}},
                             1U},
    WindowsHookRegistryEntry{WindowsLogicalHookApi::kNtFreeVirtualMemory,
                             kNtFreeVirtualMemoryApiId,
                             "NtFreeVirtualMemory",
                             "ntdll.dll",
                             WindowsHookApiGroup::kVirtualMemory,
                             {"NtFreeVirtualMemory", {}},
                             1U},
    WindowsHookRegistryEntry{WindowsLogicalHookApi::kNtMapViewOfSection,
                             kNtMapViewOfSectionApiId,
                             "NtMapViewOfSection",
                             "ntdll.dll",
                             WindowsHookApiGroup::kVirtualMemory,
                             {"NtMapViewOfSection", {}},
                             1U},
    WindowsHookRegistryEntry{WindowsLogicalHookApi::kNtUnmapViewOfSection,
                             kNtUnmapViewOfSectionApiId,
                             "NtUnmapViewOfSection",
                             "ntdll.dll",
                             WindowsHookApiGroup::kVirtualMemory,
                             {"NtUnmapViewOfSection", "NtUnmapViewOfSectionEx"},
                             2U},
};

[[nodiscard]] constexpr std::string_view windows_hook_profile_name(
    WindowsHookProfile profile) noexcept {
  switch (profile) {
    case WindowsHookProfile::kNtHeap:
      return "windows-nt-heap";
    case WindowsHookProfile::kVirtualMemory:
      return "windows-virtual-memory";
    case WindowsHookProfile::kNative:
      return "windows-native";
  }
  return {};
}

[[nodiscard]] constexpr bool profile_contains_group(WindowsHookProfile profile,
                                                    WindowsHookApiGroup group) noexcept {
  return profile == WindowsHookProfile::kNative ||
         (profile == WindowsHookProfile::kNtHeap && group == WindowsHookApiGroup::kNtHeap) ||
         (profile == WindowsHookProfile::kVirtualMemory &&
          group == WindowsHookApiGroup::kVirtualMemory);
}

[[nodiscard]] constexpr bool profile_contains_api(WindowsHookProfile profile,
                                                  const WindowsHookRegistryEntry& entry) noexcept {
  return profile_contains_group(profile, entry.group);
}

[[nodiscard]] constexpr const WindowsHookRegistryEntry* find_windows_hook(
    WindowsLogicalHookApi logical_api) noexcept {
  for (const WindowsHookRegistryEntry& entry : kWindowsHookRegistry) {
    if (entry.logical_api == logical_api) {
      return &entry;
    }
  }
  return nullptr;
}

[[nodiscard]] constexpr const WindowsHookRegistryEntry* find_windows_hook(
    noleax::trace::ApiId api_id) noexcept {
  for (const WindowsHookRegistryEntry& entry : kWindowsHookRegistry) {
    if (entry.api_id == api_id) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace noleax::agent::windows
