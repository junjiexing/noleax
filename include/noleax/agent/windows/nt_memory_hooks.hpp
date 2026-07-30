#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/nt_virtual_memory_event.hpp"

namespace noleax::agent::windows {

struct NtMemoryHookState;

struct NtMemoryHookInstallResult {
  FastHookResult allocate;
  FastHookResult free;
  FastHookResult map;
  FastHookResult unmap;
  FastHookResult unmap_ex;

  [[nodiscard]] bool installed() const noexcept {
    return allocate.installed() && free.installed() && map.installed() && unmap.installed() &&
           unmap_ex.installed();
  }
};

struct NtMemoryHookStatistics {
  std::uint64_t calls{0U};
  std::uint64_t recordable_calls{0U};
  std::uint64_t recursive_calls{0U};
  std::uint64_t internal_calls{0U};
  std::uint64_t successful_calls{0U};
  std::uint64_t failed_calls{0U};
  std::uint64_t exceptional_calls{0U};
  std::uint64_t dropped_events{0U};

  bool operator==(const NtMemoryHookStatistics&) const = default;
};

class NtMemoryHooks final {
 public:
  static constexpr std::size_t kDefaultEventQueueCapacity = 16'384U;
  static constexpr std::uint16_t kDefaultMaximumStackDepth = kMaximumCapturedStackDepth;

  explicit NtMemoryHooks(HookBackend& backend,
                         std::size_t event_queue_capacity = kDefaultEventQueueCapacity,
                         std::uint16_t maximum_stack_depth = kDefaultMaximumStackDepth);
  NtMemoryHooks(HookBackend& backend, NtVirtualMemoryEventQueue& event_queue,
                std::uint16_t maximum_stack_depth = kDefaultMaximumStackDepth);
  ~NtMemoryHooks();

  NtMemoryHooks(const NtMemoryHooks&) = delete;
  NtMemoryHooks& operator=(const NtMemoryHooks&) = delete;
  NtMemoryHooks(NtMemoryHooks&&) = delete;
  NtMemoryHooks& operator=(NtMemoryHooks&&) = delete;

  [[nodiscard]] NtMemoryHookInstallResult install();
  [[nodiscard]] bool uninstall(
      std::uint32_t flush_attempts = HookBackend::kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool flush(
      std::uint32_t max_attempts = HookBackend::kDefaultFlushAttempts) noexcept;

  [[nodiscard]] bool is_installed() const noexcept;
  [[nodiscard]] bool has_pending_teardown() const noexcept;
  [[nodiscard]] bool replacement_module_is_pinned() const noexcept;
  [[nodiscard]] std::uint64_t replacement_in_flight_count() const noexcept;
  [[nodiscard]] NtMemoryHookStatistics allocate_statistics() const noexcept;
  [[nodiscard]] NtMemoryHookStatistics free_statistics() const noexcept;
  [[nodiscard]] NtMemoryHookStatistics map_statistics() const noexcept;
  [[nodiscard]] NtMemoryHookStatistics unmap_statistics() const noexcept;
  [[nodiscard]] std::uint64_t take_allocate_dropped_event_count() noexcept;
  [[nodiscard]] std::uint64_t take_free_dropped_event_count() noexcept;
  [[nodiscard]] std::uint64_t take_map_dropped_event_count() noexcept;
  [[nodiscard]] std::uint64_t take_unmap_dropped_event_count() noexcept;
  [[nodiscard]] std::size_t event_queue_capacity() const noexcept;
  [[nodiscard]] std::uint16_t maximum_stack_depth() const noexcept;
  [[nodiscard]] bool try_dequeue_event(NtVirtualMemoryEvent& event) noexcept;
  [[nodiscard]] NtVirtualMemoryEventQueue& event_queue() noexcept;
  [[nodiscard]] const NtVirtualMemoryEventQueue& event_queue() const noexcept;
  [[nodiscard]] void* allocate_target_address() const noexcept;
  [[nodiscard]] void* free_target_address() const noexcept;
  [[nodiscard]] void* map_target_address() const noexcept;
  [[nodiscard]] void* unmap_target_address() const noexcept;
  [[nodiscard]] void* unmap_ex_target_address() const noexcept;

 private:
  enum class State : std::uint8_t {
    kInactive,
    kInstalled,
    kTeardownPending,
    kRetired,
  };

  void initialize();
  void release_failed_initial_install() noexcept;
  [[nodiscard]] bool try_finish_teardown(std::uint32_t max_attempts) noexcept;
  void finish_teardown() noexcept;
  void abandon_pending_teardown() noexcept;

  std::unique_ptr<NtMemoryHookState> hook_state_;
  HookBackend* backend_{nullptr};
  void* allocate_target_{nullptr};
  void* free_target_{nullptr};
  void* map_target_{nullptr};
  void* unmap_target_{nullptr};
  void* unmap_ex_target_{nullptr};
  std::uint16_t maximum_stack_depth_{kDefaultMaximumStackDepth};
  State state_{State::kInactive};
  bool guard_runtime_acquired_{false};
  bool allocate_lifecycle_started_{false};
  bool free_lifecycle_started_{false};
  bool map_lifecycle_started_{false};
  bool unmap_lifecycle_started_{false};
  bool allocate_hook_installed_{false};
  bool free_hook_installed_{false};
  bool map_hook_installed_{false};
  bool unmap_hook_installed_{false};
  bool unmap_ex_hook_installed_{false};
  bool allocate_lease_acquired_{false};
  bool free_lease_acquired_{false};
  bool map_lease_acquired_{false};
  bool unmap_lease_acquired_{false};
  bool unmap_ex_lease_acquired_{false};
  bool allocate_replacement_quiescent_{false};
  bool free_replacement_quiescent_{false};
  bool map_replacement_quiescent_{false};
  bool unmap_replacement_quiescent_{false};
  bool backend_teardown_complete_{false};
};

}  // namespace noleax::agent::windows
