#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/agent/linux/hook_registry.hpp"

namespace noleax::agent::linux {

struct VirtualMemoryHookChannelSet;

// Per-API hot-path counters, the linux-virtual-memory counterpart of the heap profile set
// (docs/LINUX_HOOK_API_MATRIX.md §2). The trace writer maps them into trace::ApiStatistics:
// observed_calls = recordable_calls, filtered_before_queue = filtered_calls. Once the profile
// is quiescent, every channel satisfies:
//   replacement_calls == recordable_calls + recursive_calls + internal_calls
//   recordable_calls  == successful_calls + failed_calls
//   recordable_calls  == queued events + filtered_calls + dropped_events
struct VirtualMemoryHookApiCounters {
  std::uint64_t replacement_calls{0U};
  std::uint64_t recordable_calls{0U};
  std::uint64_t recursive_calls{0U};
  std::uint64_t internal_calls{0U};
  std::uint64_t successful_calls{0U};
  std::uint64_t failed_calls{0U};
  std::uint64_t filtered_calls{0U};
  std::uint64_t dropped_events{0U};
  // Calls that emit a wire record PAIR (an mremap that moves): the writer emits two
  // records for one such call, so wire-space statistics count recordable/successful
  // plus this many on the mremap channel.
  std::uint64_t paired_records{0U};

  bool operator==(const VirtualMemoryHookApiCounters&) const = default;
};

// The linux-virtual-memory profile (docs/LINUX_HOOK_PROFILES.md): one adapter covering the
// three glibc virtual-memory entry points of the registry (mmap, munmap, mremap). The
// default constructor owns the event queue; the shared-queue constructor merges this
// family's events into a queue owned elsewhere (the linux-native profile's single queue,
// the same pattern as agent/windows/nt_memory_hooks.cpp). Routing, quiescence, and counter
// discipline mirror GlibcHeapHooks: the original's errno is saved right after its single
// call and restored before the replacement returns.
class VirtualMemoryHooks final {
 public:
  static constexpr std::size_t kChannelCount = kVirtualMemoryHookCount;
  static constexpr std::size_t kDefaultEventQueueCapacity = 16'384U;
  static constexpr std::uint16_t kDefaultMaximumStackDepth = kMaximumCapturedStackDepth;

  explicit VirtualMemoryHooks(HookBackend& backend,
                              std::size_t event_queue_capacity = kDefaultEventQueueCapacity,
                              std::uint16_t maximum_stack_depth = kDefaultMaximumStackDepth,
                              std::uint64_t minimum_capture_size = 0U);
  VirtualMemoryHooks(HookBackend& backend, LinuxHeapEventQueue& shared_queue,
                     std::uint16_t maximum_stack_depth = kDefaultMaximumStackDepth,
                     std::uint64_t minimum_capture_size = 0U);
  ~VirtualMemoryHooks();

  VirtualMemoryHooks(const VirtualMemoryHooks&) = delete;
  VirtualMemoryHooks& operator=(const VirtualMemoryHooks&) = delete;
  VirtualMemoryHooks(VirtualMemoryHooks&&) = delete;
  VirtualMemoryHooks& operator=(VirtualMemoryHooks&&) = delete;

  // Resolves every registry symbol from libc.so.6 and patches it. On any failure the
  // already-installed channels are rolled back through the same teardown path as
  // uninstall() and false is returned. A shared queue is never reset here; the queue owner
  // coordinates that before installing the profiles that produce into it.
  [[nodiscard]] bool install();
  [[nodiscard]] bool stop_recording(
      std::uint32_t max_yields = HookBackend::kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool uninstall(
      std::uint32_t max_yields = HookBackend::kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool flush(std::uint32_t max_yields = HookBackend::kDefaultFlushAttempts) noexcept;

  [[nodiscard]] bool is_installed() const noexcept;
  [[nodiscard]] bool is_recording() const noexcept;
  [[nodiscard]] bool has_pending_teardown() const noexcept;
  [[nodiscard]] std::uint64_t recording_in_flight_count() const noexcept;
  [[nodiscard]] VirtualMemoryHookApiCounters counters(LinuxLogicalHookApi api) const noexcept;
  [[nodiscard]] LinuxHeapEventQueue& event_queue() noexcept;
  [[nodiscard]] const LinuxHeapEventQueue& event_queue() const noexcept;
  [[nodiscard]] std::uint16_t maximum_stack_depth() const noexcept;
  [[nodiscard]] std::uint64_t minimum_capture_size() const noexcept;
  [[nodiscard]] void* target_address(LinuxLogicalHookApi api) const noexcept;

 private:
  enum class State : std::uint8_t {
    kInactive,
    kInstalled,
    kTeardownPending,
    kRetired,
  };

  void initialize();
  [[nodiscard]] bool try_finish_teardown(std::uint32_t max_yields) noexcept;
  void finish_teardown() noexcept;
  void abandon_pending_teardown() noexcept;

  std::unique_ptr<VirtualMemoryHookChannelSet> channel_set_;
  HookBackend* backend_{nullptr};
  std::array<void*, kChannelCount> targets_{};
  std::uint16_t maximum_stack_depth_{kDefaultMaximumStackDepth};
  std::uint64_t minimum_capture_size_{0U};
  State state_{State::kInactive};
  bool guard_runtime_acquired_{false};
  bool trampoline_lease_acquired_{false};
  bool replacements_quiescent_{false};
  bool backend_teardown_complete_{false};
};

}  // namespace noleax::agent::linux
