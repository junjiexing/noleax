#pragma once

// Shared config → IPC hook-profile conversion. The CLI (`noleax run`/`attach`) and the
// standalone agent bootstrap must never drift apart on which config profile maps to which
// wire profile, so both call these; each side keeps its own error style for a mismatch.

#include <optional>

#include "noleax/config/configuration.hpp"
#include "noleax/ipc/protocol.hpp"

namespace noleax::config {

[[nodiscard]] inline std::optional<noleax::ipc::HookProfile> windows_ipc_hook_profile(
    HookProfile profile) noexcept {
  switch (profile) {
    case HookProfile::kWindowsNtHeap:
      return noleax::ipc::HookProfile::kWindowsNtHeap;
    case HookProfile::kWindowsVirtualMemory:
      return noleax::ipc::HookProfile::kWindowsVirtualMemory;
    case HookProfile::kWindowsNative:
      return noleax::ipc::HookProfile::kWindowsNative;
    case HookProfile::kLinuxGlibcHeap:
    case HookProfile::kLinuxVirtualMemory:
    case HookProfile::kLinuxNative:
      return std::nullopt;
  }
  return std::nullopt;
}

[[nodiscard]] inline std::optional<noleax::ipc::HookProfile> linux_ipc_hook_profile(
    HookProfile profile) noexcept {
  switch (profile) {
    case HookProfile::kLinuxGlibcHeap:
      return noleax::ipc::HookProfile::kLinuxGlibcHeap;
    case HookProfile::kLinuxVirtualMemory:
      return noleax::ipc::HookProfile::kLinuxVirtualMemory;
    case HookProfile::kLinuxNative:
      return noleax::ipc::HookProfile::kLinuxNative;
    case HookProfile::kWindowsNtHeap:
    case HookProfile::kWindowsVirtualMemory:
    case HookProfile::kWindowsNative:
      return std::nullopt;
  }
  return std::nullopt;
}

}  // namespace noleax::config
