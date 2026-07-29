#pragma once

#include <cstdint>

#include "noleax/agent/hook_backend.hpp"

namespace noleax::agent::windows {

class RtlAllocateHeapHook {
 public:
  explicit RtlAllocateHeapHook(HookBackend& backend);
  ~RtlAllocateHeapHook();

  RtlAllocateHeapHook(const RtlAllocateHeapHook&) = delete;
  RtlAllocateHeapHook& operator=(const RtlAllocateHeapHook&) = delete;
  RtlAllocateHeapHook(RtlAllocateHeapHook&&) = delete;
  RtlAllocateHeapHook& operator=(RtlAllocateHeapHook&&) = delete;

  [[nodiscard]] FastHookResult install();
  [[nodiscard]] HookUninstallStatus uninstall(
      std::uint32_t flush_attempts = HookBackend::kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool flush(
      std::uint32_t max_attempts = HookBackend::kDefaultFlushAttempts) noexcept;

  [[nodiscard]] bool is_installed() const noexcept;
  [[nodiscard]] bool has_pending_teardown() const noexcept;
  [[nodiscard]] std::uint64_t call_count() const noexcept;
  [[nodiscard]] std::uint64_t recordable_call_count() const noexcept;
  [[nodiscard]] std::uint64_t recursive_call_count() const noexcept;
  [[nodiscard]] std::uint64_t internal_call_count() const noexcept;
  [[nodiscard]] void* target_address() const noexcept;

 private:
  enum class State : std::uint8_t {
    kInactive,
    kInstalled,
    kTeardownPending,
  };

  void finish_teardown() noexcept;

  HookBackend* backend_{nullptr};
  void* target_{nullptr};
  State state_{State::kInactive};
  bool guard_runtime_acquired_{false};
};

}  // namespace noleax::agent::windows
