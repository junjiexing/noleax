#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_free_heap_event.hpp"

namespace noleax::agent::windows {

struct RtlFreeHeapHookState;

class RtlFreeHeapHook {
 public:
  static constexpr std::size_t kDefaultEventQueueCapacity = 16'384U;
  static constexpr std::uint16_t kDefaultMaximumStackDepth = kMaximumCapturedStackDepth;

  explicit RtlFreeHeapHook(HookBackend& backend,
                           std::size_t event_queue_capacity = kDefaultEventQueueCapacity,
                           std::uint16_t maximum_stack_depth = kDefaultMaximumStackDepth);
  RtlFreeHeapHook(HookBackend& backend, RtlHeapEventQueue& event_queue,
                  std::uint16_t maximum_stack_depth = kDefaultMaximumStackDepth);
  ~RtlFreeHeapHook();

  RtlFreeHeapHook(const RtlFreeHeapHook&) = delete;
  RtlFreeHeapHook& operator=(const RtlFreeHeapHook&) = delete;
  RtlFreeHeapHook(RtlFreeHeapHook&&) = delete;
  RtlFreeHeapHook& operator=(RtlFreeHeapHook&&) = delete;

  [[nodiscard]] FastHookResult install();
  [[nodiscard]] HookUninstallStatus uninstall(
      std::uint32_t flush_attempts = HookBackend::kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool flush(
      std::uint32_t max_attempts = HookBackend::kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool stop_recording(
      std::uint32_t max_attempts = HookBackend::kDefaultFlushAttempts) noexcept;

  [[nodiscard]] bool is_installed() const noexcept;
  [[nodiscard]] bool is_recording() const noexcept;
  [[nodiscard]] std::uint64_t recording_in_flight_count() const noexcept;
  [[nodiscard]] bool has_pending_teardown() const noexcept;
  [[nodiscard]] bool replacement_module_is_referenced() const noexcept;
  [[nodiscard]] std::uint64_t replacement_in_flight_count() const noexcept;
  [[nodiscard]] std::uint64_t call_count() const noexcept;
  [[nodiscard]] std::uint64_t recordable_call_count() const noexcept;
  [[nodiscard]] std::uint64_t recursive_call_count() const noexcept;
  [[nodiscard]] std::uint64_t internal_call_count() const noexcept;
  [[nodiscard]] std::uint64_t successful_call_count() const noexcept;
  [[nodiscard]] std::uint64_t failed_call_count() const noexcept;
  [[nodiscard]] std::uint64_t exceptional_call_count() const noexcept;
  [[nodiscard]] std::uint64_t dropped_event_count() const noexcept;
  [[nodiscard]] std::uint64_t take_dropped_event_count() noexcept;
  [[nodiscard]] std::size_t event_queue_capacity() const noexcept;
  [[nodiscard]] std::uint16_t maximum_stack_depth() const noexcept;
  [[nodiscard]] bool try_dequeue_event(RtlFreeHeapEvent& event) noexcept;
  [[nodiscard]] RtlHeapEventQueue& event_queue() noexcept;
  [[nodiscard]] const RtlHeapEventQueue& event_queue() const noexcept;
  [[nodiscard]] void* target_address() const noexcept;

 private:
  enum class State : std::uint8_t {
    kInactive,
    kInstalled,
    kTeardownPending,
    kRetired,
  };

  [[nodiscard]] bool try_finish_teardown(std::uint32_t max_attempts) noexcept;
  void initialize();
  void finish_teardown() noexcept;
  void abandon_pending_teardown() noexcept;

  std::unique_ptr<RtlFreeHeapHookState> hook_state_;
  HookBackend* backend_{nullptr};
  void* target_{nullptr};
  std::uint16_t maximum_stack_depth_{kDefaultMaximumStackDepth};
  State state_{State::kInactive};
  bool guard_runtime_acquired_{false};
  bool trampoline_lease_acquired_{false};
  bool replacement_quiescent_{false};
  bool backend_teardown_complete_{false};
};

}  // namespace noleax::agent::windows
