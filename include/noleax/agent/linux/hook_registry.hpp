#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "noleax/trace/identifiers.hpp"

namespace noleax::agent::linux {

// Linux built-in hook registry (docs/LINUX_HOOK_PROFILES.md). Windows built-ins occupy
// api_id 1-9; Linux built-ins start at 10. Custom hooks share kCustomHookApiIdBase.
inline constexpr noleax::trace::ApiId kMallocApiId = 10U;
inline constexpr noleax::trace::ApiId kCallocApiId = 11U;
inline constexpr noleax::trace::ApiId kReallocApiId = 12U;
inline constexpr noleax::trace::ApiId kFreeApiId = 13U;
inline constexpr noleax::trace::ApiId kPosixMemalignApiId = 14U;
inline constexpr noleax::trace::ApiId kAlignedAllocApiId = 15U;
inline constexpr noleax::trace::ApiId kMemalignApiId = 16U;
inline constexpr noleax::trace::ApiId kReallocarrayApiId = 17U;

enum class LinuxHookProfile : std::uint8_t {
  kGlibcHeap,
};

enum class LinuxHookApiGroup : std::uint8_t {
  kGlibcHeap,
};

enum class LinuxLogicalHookApi : std::uint8_t {
  kMalloc,
  kCalloc,
  kRealloc,
  kFree,
  kPosixMemalign,
  kAlignedAlloc,
  kMemalign,
  kReallocarray,
};

struct LinuxHookRegistryEntry {
  LinuxLogicalHookApi logical_api;
  noleax::trace::ApiId api_id;
  std::string_view canonical_name;
  std::string_view module_name;
  LinuxHookApiGroup group;
  std::array<std::string_view, 1> physical_exports;

  [[nodiscard]] constexpr std::span<const std::string_view> exports() const noexcept {
    return {physical_exports.data(), physical_exports.size()};
  }
};

inline constexpr auto kLinuxHookRegistry = std::array{
    LinuxHookRegistryEntry{LinuxLogicalHookApi::kMalloc, kMallocApiId, "malloc", "libc.so.6",
                           LinuxHookApiGroup::kGlibcHeap, {"malloc"}},
    LinuxHookRegistryEntry{LinuxLogicalHookApi::kCalloc, kCallocApiId, "calloc", "libc.so.6",
                           LinuxHookApiGroup::kGlibcHeap, {"calloc"}},
    LinuxHookRegistryEntry{LinuxLogicalHookApi::kRealloc, kReallocApiId, "realloc", "libc.so.6",
                           LinuxHookApiGroup::kGlibcHeap, {"realloc"}},
    LinuxHookRegistryEntry{LinuxLogicalHookApi::kFree, kFreeApiId, "free", "libc.so.6",
                           LinuxHookApiGroup::kGlibcHeap, {"free"}},
    LinuxHookRegistryEntry{LinuxLogicalHookApi::kPosixMemalign, kPosixMemalignApiId,
                           "posix_memalign", "libc.so.6", LinuxHookApiGroup::kGlibcHeap,
                           {"posix_memalign"}},
    LinuxHookRegistryEntry{LinuxLogicalHookApi::kAlignedAlloc, kAlignedAllocApiId,
                           "aligned_alloc", "libc.so.6", LinuxHookApiGroup::kGlibcHeap,
                           {"aligned_alloc"}},
    LinuxHookRegistryEntry{LinuxLogicalHookApi::kMemalign, kMemalignApiId, "memalign",
                           "libc.so.6", LinuxHookApiGroup::kGlibcHeap, {"memalign"}},
    LinuxHookRegistryEntry{LinuxLogicalHookApi::kReallocarray, kReallocarrayApiId,
                           "reallocarray", "libc.so.6", LinuxHookApiGroup::kGlibcHeap,
                           {"reallocarray"}},
};

[[nodiscard]] constexpr std::string_view linux_hook_profile_name(
    LinuxHookProfile profile) noexcept {
  switch (profile) {
    case LinuxHookProfile::kGlibcHeap:
      return "linux-glibc-heap";
  }
  return "unknown";
}

[[nodiscard]] constexpr const LinuxHookRegistryEntry* find_linux_hook(
    noleax::trace::ApiId api_id) noexcept {
  for (const LinuxHookRegistryEntry& entry : kLinuxHookRegistry) {
    if (entry.api_id == api_id) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace noleax::agent::linux
