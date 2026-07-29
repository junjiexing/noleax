#pragma once

#include <cstddef>
#include <cstdint>

#include "noleax/agent/bounded_mpsc_queue.hpp"
#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_event.hpp"

namespace noleax::agent::windows {

class RtlAllocateHeapHook {
 public:
  static constexpr std::size_t kDefaultEventQueueCapacity = 65'536U;

  explicit RtlAllocateHeapHook(HookBackend& backend,
                               std::size_t event_queue_capacity = kDefaultEventQueueCapacity);
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
  [[nodiscard]] std::uint64_t dropped_event_count() const noexcept;
  [[nodiscard]] std::size_t event_queue_capacity() const noexcept;
  [[nodiscard]] bool try_dequeue_event(RtlAllocateHeapEvent& event) noexcept;
  [[nodiscard]] void* target_address() const noexcept;

 private:
  enum class State : std::uint8_t {
    kInactive,
    kInstalled,
    kTeardownPending,
  };

  void finish_teardown() noexcept;

  BoundedMpscQueue<RtlAllocateHeapEvent> event_queue_;
  HookBackend* backend_{nullptr};
  void* target_{nullptr};
  State state_{State::kInactive};
  bool guard_runtime_acquired_{false};
};

}  // namespace noleax::agent::windows
