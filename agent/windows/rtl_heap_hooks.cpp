#include "noleax/agent/windows/rtl_heap_hooks.hpp"

#include <limits>

#include "noleax/agent/hook_guard.hpp"

namespace noleax::agent::windows {

RtlHeapHooks::RtlHeapHooks(HookBackend& backend, std::size_t event_queue_capacity,
                           std::uint16_t maximum_stack_depth, std::uint64_t minimum_capture_size)
    : owned_event_queue_{std::make_unique<RtlHeapEventQueue>(event_queue_capacity)},
      event_queue_{owned_event_queue_.get()},
      create_hook_{backend, *event_queue_, maximum_stack_depth},
      allocate_hook_{backend, *event_queue_, maximum_stack_depth, minimum_capture_size},
      reallocate_hook_{backend, *event_queue_, maximum_stack_depth},
      free_hook_{backend, *event_queue_, maximum_stack_depth},
      destroy_hook_{backend, *event_queue_, maximum_stack_depth},
      minimum_capture_size_{minimum_capture_size} {}

RtlHeapHooks::RtlHeapHooks(HookBackend& backend, RtlHeapEventQueue& event_queue,
                           std::uint16_t maximum_stack_depth, std::uint64_t minimum_capture_size)
    : event_queue_{&event_queue},
      create_hook_{backend, *event_queue_, maximum_stack_depth},
      allocate_hook_{backend, *event_queue_, maximum_stack_depth, minimum_capture_size},
      reallocate_hook_{backend, *event_queue_, maximum_stack_depth},
      free_hook_{backend, *event_queue_, maximum_stack_depth},
      destroy_hook_{backend, *event_queue_, maximum_stack_depth},
      minimum_capture_size_{minimum_capture_size} {}

RtlHeapHooks::~RtlHeapHooks() {
  if (!uninstall()) {
    // Any hook can transfer an active state to process lifetime when quiescence cannot be
    // proven. Preserve the shared queue as well so that a counted replacement cannot publish
    // into storage destroyed by this coordinator.
    static_cast<void>(owned_event_queue_.release());
  }
}

RtlHeapHookInstallResult RtlHeapHooks::install() {
  const InternalThreadScope internal_thread;
  if (!create_hook_.is_installed() && !allocate_hook_.is_installed() &&
      !reallocate_hook_.is_installed() && !free_hook_.is_installed() &&
      !destroy_hook_.is_installed()) {
    if (owned_event_queue_ != nullptr) {
      event_queue_->reset_quiescent();
    }
  }
  RtlHeapHookInstallResult result;
  result.create = create_hook_.install();
  if (!result.create.installed()) {
    return result;
  }

  try {
    result.allocate = allocate_hook_.install();
    if (!result.allocate.installed()) {
      static_cast<void>(uninstall());
      return result;
    }

    result.reallocate = reallocate_hook_.install();
    if (!result.reallocate.installed()) {
      static_cast<void>(uninstall());
      return result;
    }

    result.free = free_hook_.install();
    if (!result.free.installed()) {
      static_cast<void>(uninstall());
      return result;
    }
    result.destroy = destroy_hook_.install();
    if (!result.destroy.installed()) {
      static_cast<void>(uninstall());
    }
  } catch (...) {
    static_cast<void>(uninstall());
    throw;
  }
  return result;
}

bool RtlHeapHooks::uninstall(std::uint32_t flush_attempts) noexcept {
  const InternalThreadScope internal_thread;
  auto create_status = create_hook_.uninstall(0U);
  auto allocate_status = allocate_hook_.uninstall(0U);
  auto reallocate_status = reallocate_hook_.uninstall(0U);
  auto free_status = free_hook_.uninstall(0U);
  auto destroy_status = destroy_hook_.uninstall(0U);

  if (destroy_status == HookUninstallStatus::kTeardownPending &&
      destroy_hook_.flush(flush_attempts)) {
    destroy_status = HookUninstallStatus::kUninstalled;
  }
  if (free_status == HookUninstallStatus::kTeardownPending && free_hook_.flush(flush_attempts)) {
    free_status = HookUninstallStatus::kUninstalled;
  }
  if (reallocate_status == HookUninstallStatus::kTeardownPending &&
      reallocate_hook_.flush(flush_attempts)) {
    reallocate_status = HookUninstallStatus::kUninstalled;
  }
  if (allocate_status == HookUninstallStatus::kTeardownPending &&
      allocate_hook_.flush(flush_attempts)) {
    allocate_status = HookUninstallStatus::kUninstalled;
  }
  if (create_status == HookUninstallStatus::kTeardownPending &&
      create_hook_.flush(flush_attempts)) {
    create_status = HookUninstallStatus::kUninstalled;
  }

  const bool create_done = create_status == HookUninstallStatus::kUninstalled ||
                           create_status == HookUninstallStatus::kNotInstalled;
  const bool allocate_done = allocate_status == HookUninstallStatus::kUninstalled ||
                             allocate_status == HookUninstallStatus::kNotInstalled;
  const bool reallocate_done = reallocate_status == HookUninstallStatus::kUninstalled ||
                               reallocate_status == HookUninstallStatus::kNotInstalled;
  const bool free_done = free_status == HookUninstallStatus::kUninstalled ||
                         free_status == HookUninstallStatus::kNotInstalled;
  const bool destroy_done = destroy_status == HookUninstallStatus::kUninstalled ||
                            destroy_status == HookUninstallStatus::kNotInstalled;
  return create_done && allocate_done && reallocate_done && free_done && destroy_done;
}

bool RtlHeapHooks::flush(std::uint32_t max_attempts) noexcept {
  const bool destroy_done = destroy_hook_.flush(max_attempts);
  const bool free_done = free_hook_.flush(max_attempts);
  const bool reallocate_done = reallocate_hook_.flush(max_attempts);
  const bool allocate_done = allocate_hook_.flush(max_attempts);
  const bool create_done = create_hook_.flush(max_attempts);
  return destroy_done && free_done && reallocate_done && allocate_done && create_done;
}

bool RtlHeapHooks::stop_recording(std::uint32_t max_attempts) noexcept {
  static_cast<void>(create_hook_.stop_recording(0U));
  static_cast<void>(allocate_hook_.stop_recording(0U));
  static_cast<void>(reallocate_hook_.stop_recording(0U));
  static_cast<void>(free_hook_.stop_recording(0U));
  static_cast<void>(destroy_hook_.stop_recording(0U));
  const bool create_done = create_hook_.stop_recording(max_attempts);
  const bool allocate_done = allocate_hook_.stop_recording(max_attempts);
  const bool reallocate_done = reallocate_hook_.stop_recording(max_attempts);
  const bool free_done = free_hook_.stop_recording(max_attempts);
  const bool destroy_done = destroy_hook_.stop_recording(max_attempts);
  return create_done && allocate_done && reallocate_done && free_done && destroy_done;
}

bool RtlHeapHooks::is_installed() const noexcept {
  return create_hook_.is_installed() && allocate_hook_.is_installed() &&
         reallocate_hook_.is_installed() && free_hook_.is_installed() &&
         destroy_hook_.is_installed();
}

bool RtlHeapHooks::is_recording() const noexcept {
  return create_hook_.is_recording() || allocate_hook_.is_recording() ||
         reallocate_hook_.is_recording() || free_hook_.is_recording() ||
         destroy_hook_.is_recording();
}

std::uint64_t RtlHeapHooks::recording_in_flight_count() const noexcept {
  std::uint64_t total = create_hook_.recording_in_flight_count();
  const auto add_saturating = [&total](std::uint64_t value) {
    total = value > std::numeric_limits<std::uint64_t>::max() - total
                ? std::numeric_limits<std::uint64_t>::max()
                : total + value;
  };
  add_saturating(allocate_hook_.recording_in_flight_count());
  add_saturating(reallocate_hook_.recording_in_flight_count());
  add_saturating(free_hook_.recording_in_flight_count());
  add_saturating(destroy_hook_.recording_in_flight_count());
  return total;
}

RtlCreateHeapHook& RtlHeapHooks::create_hook() noexcept { return create_hook_; }

const RtlCreateHeapHook& RtlHeapHooks::create_hook() const noexcept { return create_hook_; }

RtlAllocateHeapHook& RtlHeapHooks::allocate_hook() noexcept { return allocate_hook_; }

const RtlAllocateHeapHook& RtlHeapHooks::allocate_hook() const noexcept { return allocate_hook_; }

RtlReAllocateHeapHook& RtlHeapHooks::reallocate_hook() noexcept { return reallocate_hook_; }

const RtlReAllocateHeapHook& RtlHeapHooks::reallocate_hook() const noexcept {
  return reallocate_hook_;
}

RtlFreeHeapHook& RtlHeapHooks::free_hook() noexcept { return free_hook_; }

const RtlFreeHeapHook& RtlHeapHooks::free_hook() const noexcept { return free_hook_; }

RtlDestroyHeapHook& RtlHeapHooks::destroy_hook() noexcept { return destroy_hook_; }

const RtlDestroyHeapHook& RtlHeapHooks::destroy_hook() const noexcept { return destroy_hook_; }

RtlHeapEventQueue& RtlHeapHooks::event_queue() noexcept { return *event_queue_; }

const RtlHeapEventQueue& RtlHeapHooks::event_queue() const noexcept { return *event_queue_; }

std::uint64_t RtlHeapHooks::minimum_capture_size() const noexcept { return minimum_capture_size_; }

}  // namespace noleax::agent::windows
