#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/agent/linux/hook_registry.hpp"

namespace noleax::agent::linux {

struct GlibcHeapHookChannelSet;

// Per-API hot-path counters, the linux-glibc-heap counterpart of the Windows per-hook
// counter set (docs/HOOK_API_MATRIX.md §2). The trace writer maps them into
// trace::ApiStatistics: observed_calls = recordable_calls,
// filtered_before_queue = filtered_calls. Once the profile is quiescent, every channel
// satisfies:
//   replacement_calls == recordable_calls + recursive_calls + internal_calls
//   recordable_calls  == successful_calls + failed_calls
//   recordable_calls  == queued events + filtered_calls + dropped_events
struct GlibcHeapHookApiCounters {
  std::uint64_t replacement_calls{0U};
  std::uint64_t recordable_calls{0U};
  std::uint64_t recursive_calls{0U};
  std::uint64_t internal_calls{0U};
  std::uint64_t successful_calls{0U};
  std::uint64_t failed_calls{0U};
  std::uint64_t filtered_calls{0U};
  std::uint64_t dropped_events{0U};

  bool operator==(const GlibcHeapHookApiCounters&) const = default;
};

// The linux-glibc-heap profile (docs/LINUX_HOOK_PROFILES.md): one adapter covering the
// eight glibc allocation entry points of the registry (malloc, calloc, realloc, free,
// posix_memalign, aligned_alloc, memalign, reallocarray). All replacements share the
// event queue owned here. Routing, quiescence, and counter discipline mirror
// agent/windows/rtl_allocate_heap_hook.cpp, minus SEH/LastError and plus errno
// preservation: the original's errno is saved right after its single call and restored
// before the replacement returns.
class GlibcHeapHooks final {
 public:
  static constexpr std::size_t kChannelCount = kLinuxHookRegistry.size();
  static constexpr std::size_t kDefaultEventQueueCapacity = 16'384U;
  static constexpr std::uint16_t kDefaultMaximumStackDepth = kMaximumCapturedStackDepth;

  explicit GlibcHeapHooks(HookBackend& backend,
                          std::size_t event_queue_capacity = kDefaultEventQueueCapacity,
                          std::uint16_t maximum_stack_depth = kDefaultMaximumStackDepth,
                          std::uint64_t minimum_capture_size = 0U);
  ~GlibcHeapHooks();

  GlibcHeapHooks(const GlibcHeapHooks&) = delete;
  GlibcHeapHooks& operator=(const GlibcHeapHooks&) = delete;
  GlibcHeapHooks(GlibcHeapHooks&&) = delete;
  GlibcHeapHooks& operator=(GlibcHeapHooks&&) = delete;

  // Resolves every registry symbol from libc.so.6 and patches it. On any failure the
  // already-installed channels are rolled back through the same teardown path as
  // uninstall() and false is returned.
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
  [[nodiscard]] GlibcHeapHookApiCounters counters(LinuxLogicalHookApi api) const noexcept;
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

  [[nodiscard]] bool try_finish_teardown(std::uint32_t max_yields) noexcept;
  void finish_teardown() noexcept;
  void abandon_pending_teardown() noexcept;

  std::unique_ptr<LinuxHeapEventQueue> owned_event_queue_;
  std::unique_ptr<GlibcHeapHookChannelSet> channel_set_;
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
