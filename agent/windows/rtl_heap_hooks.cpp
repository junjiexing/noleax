#include "noleax/agent/windows/rtl_heap_hooks.hpp"

namespace noleax::agent::windows {

RtlHeapHooks::RtlHeapHooks(HookBackend& backend, std::size_t event_queue_capacity,
                           std::uint16_t maximum_stack_depth)
    : event_queue_{std::make_unique<RtlHeapEventQueue>(event_queue_capacity)},
      allocate_hook_{backend, *event_queue_, maximum_stack_depth},
      reallocate_hook_{backend, *event_queue_, maximum_stack_depth},
      free_hook_{backend, *event_queue_, maximum_stack_depth} {}

RtlHeapHooks::~RtlHeapHooks() {
  if (!uninstall()) {
    // Either hook can transfer an active state to process lifetime when quiescence cannot be
    // proven. Preserve the shared queue as well so that a counted replacement cannot publish
    // into storage destroyed by this coordinator.
    static_cast<void>(event_queue_.release());
  }
}

RtlHeapHookInstallResult RtlHeapHooks::install() {
  RtlHeapHookInstallResult result;
  result.allocate = allocate_hook_.install();
  if (!result.allocate.installed()) {
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
  }
  return result;
}

bool RtlHeapHooks::uninstall(std::uint32_t flush_attempts) noexcept {
  auto allocate_status = allocate_hook_.uninstall(0U);
  auto reallocate_status = reallocate_hook_.uninstall(0U);
  auto free_status = free_hook_.uninstall(0U);

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

  const bool allocate_done = allocate_status == HookUninstallStatus::kUninstalled ||
                             allocate_status == HookUninstallStatus::kNotInstalled;
  const bool reallocate_done = reallocate_status == HookUninstallStatus::kUninstalled ||
                               reallocate_status == HookUninstallStatus::kNotInstalled;
  const bool free_done = free_status == HookUninstallStatus::kUninstalled ||
                         free_status == HookUninstallStatus::kNotInstalled;
  return allocate_done && reallocate_done && free_done;
}

bool RtlHeapHooks::flush(std::uint32_t max_attempts) noexcept {
  const bool free_done = free_hook_.flush(max_attempts);
  const bool reallocate_done = reallocate_hook_.flush(max_attempts);
  const bool allocate_done = allocate_hook_.flush(max_attempts);
  return free_done && reallocate_done && allocate_done;
}

RtlAllocateHeapHook& RtlHeapHooks::allocate_hook() noexcept { return allocate_hook_; }

const RtlAllocateHeapHook& RtlHeapHooks::allocate_hook() const noexcept { return allocate_hook_; }

RtlReAllocateHeapHook& RtlHeapHooks::reallocate_hook() noexcept { return reallocate_hook_; }

const RtlReAllocateHeapHook& RtlHeapHooks::reallocate_hook() const noexcept {
  return reallocate_hook_;
}

RtlFreeHeapHook& RtlHeapHooks::free_hook() noexcept { return free_hook_; }

const RtlFreeHeapHook& RtlHeapHooks::free_hook() const noexcept { return free_hook_; }

RtlHeapEventQueue& RtlHeapHooks::event_queue() noexcept { return *event_queue_; }

const RtlHeapEventQueue& RtlHeapHooks::event_queue() const noexcept { return *event_queue_; }

}  // namespace noleax::agent::windows
