#include "noleax/agent/windows/windows_memory_hooks.hpp"

#include <limits>
#include <stdexcept>

#include "noleax/agent/hook_guard.hpp"

namespace noleax::agent::windows {

WindowsMemoryHooks::WindowsMemoryHooks(HookBackend& backend, WindowsMemoryHookOptions options)
    : event_queue_{std::make_unique<RtlHeapEventQueue>(options.event_queue_capacity)},
      options_{options} {
  if (options_.event_queue_capacity == 0U) {
    throw std::invalid_argument{"Windows memory hook queue capacity must be nonzero"};
  }
  if (options_.maximum_stack_depth > kMaximumCapturedStackDepth) {
    throw std::invalid_argument{"Windows memory hook stack depth exceeds the fixed event limit"};
  }
  if (profile_contains_group(options_.profile, WindowsHookApiGroup::kNtHeap)) {
    nt_heap_hooks_ = std::make_unique<RtlHeapHooks>(
        backend, *event_queue_, options_.maximum_stack_depth, options_.minimum_capture_size);
  }
  if (profile_contains_group(options_.profile, WindowsHookApiGroup::kVirtualMemory)) {
    virtual_memory_hooks_ = std::make_unique<NtMemoryHooks>(
        backend, *event_queue_, options_.maximum_stack_depth, options_.minimum_capture_size);
  }
  if (nt_heap_hooks_ == nullptr && virtual_memory_hooks_ == nullptr) {
    throw std::invalid_argument{"Windows memory hook profile selects no APIs"};
  }
}

WindowsMemoryHooks::~WindowsMemoryHooks() {
  static_cast<void>(stop_recording());
  if (!uninstall()) {
    // A coordinator that cannot prove physical teardown must keep the shared storage alive for
    // any process-lifetime replacement state retained by an individual hook.
    static_cast<void>(event_queue_.release());
  }
}

WindowsMemoryHookInstallResult WindowsMemoryHooks::install() {
  const InternalThreadScope internal_thread;
  if ((nt_heap_hooks_ != nullptr && nt_heap_hooks_->is_installed()) ||
      (virtual_memory_hooks_ != nullptr && virtual_memory_hooks_->is_installed())) {
    throw std::logic_error{"Windows memory hook profile is already installed"};
  }
  // reset_quiescent requires that no producer or consumer is using the queue; a hook
  // stuck in teardown-pending can still publish into it, so refuse to reset then.
  const bool teardown_pending =
      (nt_heap_hooks_ != nullptr && nt_heap_hooks_->has_pending_teardown()) ||
      (virtual_memory_hooks_ != nullptr && virtual_memory_hooks_->has_pending_teardown());
  if (!teardown_pending) {
    event_queue_->reset_quiescent();
  }

  WindowsMemoryHookInstallResult result;
  if (nt_heap_hooks_ != nullptr) {
    result.nt_heap = nt_heap_hooks_->install();
    if (!result.nt_heap->installed()) {
      static_cast<void>(nt_heap_hooks_->stop_recording(0U));
      static_cast<void>(nt_heap_hooks_->uninstall());
      return result;
    }
  }
  if (virtual_memory_hooks_ != nullptr) {
    try {
      result.virtual_memory = virtual_memory_hooks_->install();
    } catch (...) {
      if (nt_heap_hooks_ != nullptr) {
        static_cast<void>(nt_heap_hooks_->stop_recording(0U));
        static_cast<void>(nt_heap_hooks_->uninstall());
      }
      throw;
    }
    if (!result.virtual_memory->installed()) {
      static_cast<void>(virtual_memory_hooks_->stop_recording(0U));
      static_cast<void>(virtual_memory_hooks_->uninstall());
      if (nt_heap_hooks_ != nullptr) {
        static_cast<void>(nt_heap_hooks_->stop_recording(0U));
        static_cast<void>(nt_heap_hooks_->uninstall());
      }
    }
  }
  return result;
}

bool WindowsMemoryHooks::stop_recording(std::uint32_t max_attempts) noexcept {
  // Route every selected family to its original trampoline before waiting for any one family.
  if (nt_heap_hooks_ != nullptr) {
    static_cast<void>(nt_heap_hooks_->stop_recording(0U));
  }
  if (virtual_memory_hooks_ != nullptr) {
    static_cast<void>(virtual_memory_hooks_->stop_recording(0U));
  }
  const bool heap_done = nt_heap_hooks_ == nullptr || nt_heap_hooks_->stop_recording(max_attempts);
  const bool virtual_memory_done =
      virtual_memory_hooks_ == nullptr || virtual_memory_hooks_->stop_recording(max_attempts);
  return heap_done && virtual_memory_done;
}

bool WindowsMemoryHooks::uninstall(std::uint32_t flush_attempts) noexcept {
  const InternalThreadScope internal_thread;
  if (is_recording() || recording_in_flight_count() != 0U) {
    return false;
  }
  // Revert every physical target before asking either family to flush the shared backend. A
  // family-local flush cannot complete while the other family still owns installed targets.
  if (virtual_memory_hooks_ != nullptr) {
    static_cast<void>(virtual_memory_hooks_->uninstall(0U));
  }
  if (nt_heap_hooks_ != nullptr) {
    static_cast<void>(nt_heap_hooks_->uninstall(0U));
  }
  const bool virtual_memory_done =
      virtual_memory_hooks_ == nullptr || virtual_memory_hooks_->uninstall(flush_attempts);
  const bool heap_done = nt_heap_hooks_ == nullptr || nt_heap_hooks_->uninstall(flush_attempts);
  return virtual_memory_done && heap_done;
}

bool WindowsMemoryHooks::is_installed() const noexcept {
  return (nt_heap_hooks_ == nullptr || nt_heap_hooks_->is_installed()) &&
         (virtual_memory_hooks_ == nullptr || virtual_memory_hooks_->is_installed());
}

bool WindowsMemoryHooks::is_recording() const noexcept {
  return (nt_heap_hooks_ != nullptr && nt_heap_hooks_->is_recording()) ||
         (virtual_memory_hooks_ != nullptr && virtual_memory_hooks_->is_recording());
}

std::uint64_t WindowsMemoryHooks::recording_in_flight_count() const noexcept {
  std::uint64_t total =
      nt_heap_hooks_ == nullptr ? 0U : nt_heap_hooks_->recording_in_flight_count();
  const std::uint64_t virtual_memory =
      virtual_memory_hooks_ == nullptr ? 0U : virtual_memory_hooks_->recording_in_flight_count();
  return virtual_memory > std::numeric_limits<std::uint64_t>::max() - total
             ? std::numeric_limits<std::uint64_t>::max()
             : total + virtual_memory;
}

WindowsHookProfile WindowsMemoryHooks::profile() const noexcept { return options_.profile; }

std::uint64_t WindowsMemoryHooks::minimum_capture_size() const noexcept {
  return options_.minimum_capture_size;
}

RtlHeapEventQueue& WindowsMemoryHooks::event_queue() noexcept { return *event_queue_; }

const RtlHeapEventQueue& WindowsMemoryHooks::event_queue() const noexcept { return *event_queue_; }

RtlHeapHooks* WindowsMemoryHooks::nt_heap_hooks() noexcept { return nt_heap_hooks_.get(); }

const RtlHeapHooks* WindowsMemoryHooks::nt_heap_hooks() const noexcept {
  return nt_heap_hooks_.get();
}

NtMemoryHooks* WindowsMemoryHooks::virtual_memory_hooks() noexcept {
  return virtual_memory_hooks_.get();
}

const NtMemoryHooks* WindowsMemoryHooks::virtual_memory_hooks() const noexcept {
  return virtual_memory_hooks_.get();
}

}  // namespace noleax::agent::windows
