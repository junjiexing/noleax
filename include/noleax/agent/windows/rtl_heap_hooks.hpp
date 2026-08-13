#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"
#include "noleax/agent/windows/rtl_create_heap_hook.hpp"
#include "noleax/agent/windows/rtl_destroy_heap_hook.hpp"
#include "noleax/agent/windows/rtl_free_heap_hook.hpp"
#include "noleax/agent/windows/rtl_reallocate_heap_hook.hpp"

namespace noleax::agent::windows {

struct RtlHeapHookInstallResult {
  FastHookResult create;
  FastHookResult allocate;
  FastHookResult reallocate;
  FastHookResult free;
  FastHookResult destroy;

  [[nodiscard]] bool installed() const noexcept {
    return create.installed() && allocate.installed() && reallocate.installed() &&
           free.installed() && destroy.installed();
  }
};

class RtlHeapHooks final {
 public:
  static constexpr std::size_t kDefaultEventQueueCapacity =
      RtlAllocateHeapHook::kDefaultEventQueueCapacity;
  static constexpr std::uint16_t kDefaultMaximumStackDepth =
      RtlAllocateHeapHook::kDefaultMaximumStackDepth;

  explicit RtlHeapHooks(HookBackend& backend,
                        std::size_t event_queue_capacity = kDefaultEventQueueCapacity,
                        std::uint16_t maximum_stack_depth = kDefaultMaximumStackDepth,
                        std::uint64_t minimum_capture_size = 0U);
  RtlHeapHooks(HookBackend& backend, RtlHeapEventQueue& event_queue,
               std::uint16_t maximum_stack_depth = kDefaultMaximumStackDepth,
               std::uint64_t minimum_capture_size = 0U);
  ~RtlHeapHooks();

  RtlHeapHooks(const RtlHeapHooks&) = delete;
  RtlHeapHooks& operator=(const RtlHeapHooks&) = delete;
  RtlHeapHooks(RtlHeapHooks&&) = delete;
  RtlHeapHooks& operator=(RtlHeapHooks&&) = delete;

  [[nodiscard]] RtlHeapHookInstallResult install();
  [[nodiscard]] bool uninstall(QuiescenceDeadline deadline = quiescence_deadline_after()) noexcept;
  [[nodiscard]] bool flush(QuiescenceDeadline deadline = quiescence_deadline_after()) noexcept;
  [[nodiscard]] bool stop_recording(
      QuiescenceDeadline deadline = quiescence_deadline_after()) noexcept;
  [[nodiscard]] bool is_installed() const noexcept;
  [[nodiscard]] bool is_recording() const noexcept;
  [[nodiscard]] std::uint64_t recording_in_flight_count() const noexcept;
  [[nodiscard]] bool has_pending_teardown() const noexcept;

  [[nodiscard]] RtlCreateHeapHook& create_hook() noexcept;
  [[nodiscard]] const RtlCreateHeapHook& create_hook() const noexcept;
  [[nodiscard]] RtlAllocateHeapHook& allocate_hook() noexcept;
  [[nodiscard]] const RtlAllocateHeapHook& allocate_hook() const noexcept;
  [[nodiscard]] RtlReAllocateHeapHook& reallocate_hook() noexcept;
  [[nodiscard]] const RtlReAllocateHeapHook& reallocate_hook() const noexcept;
  [[nodiscard]] RtlFreeHeapHook& free_hook() noexcept;
  [[nodiscard]] const RtlFreeHeapHook& free_hook() const noexcept;
  [[nodiscard]] RtlDestroyHeapHook& destroy_hook() noexcept;
  [[nodiscard]] const RtlDestroyHeapHook& destroy_hook() const noexcept;
  [[nodiscard]] RtlHeapEventQueue& event_queue() noexcept;
  [[nodiscard]] const RtlHeapEventQueue& event_queue() const noexcept;
  [[nodiscard]] std::uint64_t minimum_capture_size() const noexcept;

 private:
  std::unique_ptr<RtlHeapEventQueue> owned_event_queue_;
  RtlHeapEventQueue* event_queue_{nullptr};
  RtlCreateHeapHook create_hook_;
  RtlAllocateHeapHook allocate_hook_;
  RtlReAllocateHeapHook reallocate_hook_;
  RtlFreeHeapHook free_hook_;
  RtlDestroyHeapHook destroy_hook_;
  std::uint64_t minimum_capture_size_{0U};
};

}  // namespace noleax::agent::windows
