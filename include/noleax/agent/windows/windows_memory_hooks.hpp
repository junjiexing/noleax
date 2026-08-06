#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/custom_symbol_hooks.hpp"
#include "noleax/agent/windows/hook_registry.hpp"
#include "noleax/agent/windows/nt_memory_hooks.hpp"
#include "noleax/agent/windows/rtl_heap_hooks.hpp"
#include "noleax/ipc/protocol.hpp"

namespace noleax::agent::windows {

struct WindowsMemoryHookOptions {
  WindowsHookProfile profile{WindowsHookProfile::kNative};
  std::size_t event_queue_capacity{RtlHeapHooks::kDefaultEventQueueCapacity};
  std::uint16_t maximum_stack_depth{RtlHeapHooks::kDefaultMaximumStackDepth};
  std::uint64_t minimum_capture_size{0U};
  std::vector<noleax::ipc::CustomHookSpec> custom_hooks;
};

struct WindowsMemoryHookInstallResult {
  std::optional<RtlHeapHookInstallResult> nt_heap;
  std::optional<NtMemoryHookInstallResult> virtual_memory;
  // Present when custom hooks were declared. Custom installation is per hook point
  // all-or-nothing: failed points are rolled back and listed here while the remaining
  // points (and the built-in families) keep recording.
  std::optional<std::vector<noleax::trace::CustomHookFailure>> custom_hooks;

  [[nodiscard]] bool installed() const noexcept {
    return (!nt_heap.has_value() || nt_heap->installed()) &&
           (!virtual_memory.has_value() || virtual_memory->installed()) &&
           (nt_heap.has_value() || virtual_memory.has_value() || custom_hooks.has_value());
  }
};

class WindowsMemoryHooks final {
 public:
  explicit WindowsMemoryHooks(HookBackend& backend, WindowsMemoryHookOptions options = {});
  ~WindowsMemoryHooks();

  WindowsMemoryHooks(const WindowsMemoryHooks&) = delete;
  WindowsMemoryHooks& operator=(const WindowsMemoryHooks&) = delete;
  WindowsMemoryHooks(WindowsMemoryHooks&&) = delete;
  WindowsMemoryHooks& operator=(WindowsMemoryHooks&&) = delete;

  [[nodiscard]] WindowsMemoryHookInstallResult install();
  [[nodiscard]] bool stop_recording(
      std::uint32_t max_attempts = HookBackend::kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool uninstall(
      std::uint32_t flush_attempts = HookBackend::kDefaultFlushAttempts) noexcept;

  [[nodiscard]] bool is_installed() const noexcept;
  [[nodiscard]] bool is_recording() const noexcept;
  [[nodiscard]] std::uint64_t recording_in_flight_count() const noexcept;
  [[nodiscard]] WindowsHookProfile profile() const noexcept;
  [[nodiscard]] std::uint64_t minimum_capture_size() const noexcept;
  [[nodiscard]] RtlHeapEventQueue& event_queue() noexcept;
  [[nodiscard]] const RtlHeapEventQueue& event_queue() const noexcept;
  [[nodiscard]] RtlHeapHooks* nt_heap_hooks() noexcept;
  [[nodiscard]] const RtlHeapHooks* nt_heap_hooks() const noexcept;
  [[nodiscard]] NtMemoryHooks* virtual_memory_hooks() noexcept;
  [[nodiscard]] const NtMemoryHooks* virtual_memory_hooks() const noexcept;
  [[nodiscard]] CustomSymbolHooks* custom_hooks() noexcept;
  [[nodiscard]] const CustomSymbolHooks* custom_hooks() const noexcept;

 private:
  std::unique_ptr<RtlHeapEventQueue> event_queue_;
  std::unique_ptr<RtlHeapHooks> nt_heap_hooks_;
  std::unique_ptr<NtMemoryHooks> virtual_memory_hooks_;
  std::unique_ptr<CustomSymbolHooks> custom_hooks_;
  WindowsMemoryHookOptions options_;
};

}  // namespace noleax::agent::windows
