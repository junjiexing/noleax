#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"

#include "noleax/agent/bounded_mpsc_queue.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/replacement_lifecycle.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace noleax::agent::windows {

struct RtlAllocateHeapHookState final {
  explicit RtlAllocateHeapHookState(std::size_t event_queue_capacity)
      : event_queue{event_queue_capacity} {}

  void reset_quiescent() noexcept {
    original_trampoline.store(nullptr, std::memory_order_relaxed);
    event_queue.reset_quiescent();
    replacement_calls.store(0U, std::memory_order_relaxed);
    recordable_calls.store(0U, std::memory_order_relaxed);
    recursive_calls.store(0U, std::memory_order_relaxed);
    internal_calls.store(0U, std::memory_order_relaxed);
    successful_calls.store(0U, std::memory_order_relaxed);
    failed_calls.store(0U, std::memory_order_relaxed);
  }

  BoundedMpscQueue<RtlAllocateHeapEvent> event_queue;
  OriginalTrampolineSlot original_trampoline{nullptr};
  std::atomic<std::uint64_t> replacement_calls{0U};
  std::atomic<std::uint64_t> recordable_calls{0U};
  std::atomic<std::uint64_t> recursive_calls{0U};
  std::atomic<std::uint64_t> internal_calls{0U};
  std::atomic<std::uint64_t> successful_calls{0U};
  std::atomic<std::uint64_t> failed_calls{0U};
  std::uint16_t maximum_stack_depth{0U};
};

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);

ReplacementLifecycle replacement_lifecycle;
std::atomic<RtlAllocateHeapHookState*> active_hook_state{nullptr};
std::atomic<void*> restored_target{nullptr};
std::atomic<RtlAllocateHeapHook*> active_owner{nullptr};
std::atomic<bool> installation_retired{false};
std::atomic<bool> replacement_module_pinned{false};

static_assert(OriginalTrampolineSlot::is_always_lock_free);
static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
static_assert(decltype(active_hook_state)::is_always_lock_free);

[[noreturn]] void fail_broken_replacement_route() noexcept {
#if defined(_MSC_VER)
  __fastfail(FAST_FAIL_FATAL_APP_EXIT);
#else
  std::abort();
#endif
}

[[nodiscard]] RtlAllocateHeapFunction load_function(std::atomic<void*>& slot) noexcept {
  void* const address = slot.load(std::memory_order_acquire);
  if (address == nullptr) {
    fail_broken_replacement_route();
  }
  return reinterpret_cast<RtlAllocateHeapFunction>(address);
}

PVOID NTAPI replacement_rtl_allocate_heap(PVOID heap, ULONG flags, SIZE_T size) noexcept {
  const auto lifecycle_entry = replacement_lifecycle.enter();
  if (lifecycle_entry.route() == ReplacementRoute::kTarget) {
    return load_function(restored_target)(heap, flags, size);
  }

  auto* const hook_state = active_hook_state.load(std::memory_order_acquire);
  if (hook_state == nullptr) {
    fail_broken_replacement_route();
  }
  void* const original_address =
      hook_state->original_trampoline.load(std::memory_order_acquire);
  if (original_address == nullptr) {
    fail_broken_replacement_route();
  }
  const auto original = reinterpret_cast<RtlAllocateHeapFunction>(original_address);
  if (!lifecycle_entry.should_record()) {
    return original(heap, flags, size);
  }

  const HookInvocationGuard guard;
  hook_state->replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  const HookEntryKind entry_kind = guard.kind();
  switch (entry_kind) {
    case HookEntryKind::kOutermost:
      hook_state->recordable_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
    case HookEntryKind::kRecursive:
      hook_state->recursive_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
    case HookEntryKind::kInternalThread:
      hook_state->internal_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
  }

  PVOID const result = original(heap, flags, size);
  const DWORD original_last_error = GetLastError();

  if (entry_kind == HookEntryKind::kOutermost) {
    (result == nullptr ? hook_state->failed_calls : hook_state->successful_calls)
        .fetch_add(1U, std::memory_order_relaxed);
    const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
    static_cast<void>(hook_state->event_queue.try_emplace(
        [heap, flags, size, result, maximum_stack_depth](RtlAllocateHeapEvent& event,
                                                         std::uint64_t queue_sequence) noexcept {
          LARGE_INTEGER ticks{};
          static_cast<void>(QueryPerformanceCounter(&ticks));
          event.queue_sequence = queue_sequence;
          event.monotonic_ticks = static_cast<std::uint64_t>(ticks.QuadPart);
          event.thread_id = static_cast<std::uint64_t>(GetCurrentThreadId());
          event.heap_handle = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(heap));
          event.requested_size = static_cast<std::uint64_t>(size);
          event.result_address =
              static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
          event.flags = flags;
          event.status = result == nullptr ? RtlAllocateHeapEventStatus::kFailure
                                           : RtlAllocateHeapEventStatus::kSuccess;
          capture_current_stack(event.stack, maximum_stack_depth, 1U);
        }));
  }

  SetLastError(original_last_error);
  return result;
}

[[nodiscard]] void* replacement_address() noexcept {
  return reinterpret_cast<void*>(&replacement_rtl_allocate_heap);
}

[[nodiscard]] bool pin_replacement_module() noexcept {
  if (replacement_module_pinned.load(std::memory_order_acquire)) {
    return true;
  }
  HMODULE module = nullptr;
  const DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN;
  if (GetModuleHandleExW(flags, reinterpret_cast<LPCWSTR>(replacement_address()), &module) ==
      FALSE) {
    return false;
  }
  replacement_module_pinned.store(true, std::memory_order_release);
  return true;
}

void release_owner(RtlAllocateHeapHook* owner, bool clear_hook_state) noexcept {
  if (clear_hook_state) {
    active_hook_state.store(nullptr, std::memory_order_release);
  }
  RtlAllocateHeapHook* expected = owner;
  static_cast<void>(active_owner.compare_exchange_strong(
      expected, nullptr, std::memory_order_release, std::memory_order_relaxed));
}

}  // namespace

RtlAllocateHeapHook::RtlAllocateHeapHook(HookBackend& backend, std::size_t event_queue_capacity,
                                         std::uint16_t maximum_stack_depth)
    : hook_state_{std::make_unique<RtlAllocateHeapHookState>(event_queue_capacity)},
      backend_{&backend},
      maximum_stack_depth_{maximum_stack_depth} {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    throw HookBackendError{"ntdll.dll is not loaded"};
  }
  const FARPROC address = GetProcAddress(ntdll, "RtlAllocateHeap");
  if (address == nullptr) {
    throw HookBackendError{"ntdll.dll does not export RtlAllocateHeap"};
  }
  target_ = reinterpret_cast<void*>(address);
  if (maximum_stack_depth_ > kMaximumCapturedStackDepth) {
    throw HookBackendError{"maximum stack depth exceeds the fixed event capacity"};
  }
  CapturedStack preflight_stack;
  capture_current_stack(preflight_stack, maximum_stack_depth_);
  if (maximum_stack_depth_ != 0U && !stack_capture_succeeded(preflight_stack)) {
    throw HookBackendError{"RtlCaptureStackBackTrace preflight failed"};
  }
  if (!acquire_hook_guard_runtime()) {
    throw HookBackendError{"a fixed Windows TLS slot is unavailable for the hook guard"};
  }
  guard_runtime_acquired_ = true;
  hook_state_->maximum_stack_depth = maximum_stack_depth_;
}

RtlAllocateHeapHook::~RtlAllocateHeapHook() {
  if (state_ == State::kInstalled) {
    static_cast<void>(uninstall());
  }
  if (state_ == State::kTeardownPending) {
    static_cast<void>(flush());
  }
  if (state_ == State::kTeardownPending) {
    abandon_pending_teardown();
  }
  if (guard_runtime_acquired_) {
    release_hook_guard_runtime();
    guard_runtime_acquired_ = false;
  }
}

FastHookResult RtlAllocateHeapHook::install() {
  if (state_ == State::kInstalled) {
    return {HookInstallStatus::kAlreadyInstalled,
            hook_state_->original_trampoline.load(std::memory_order_acquire)};
  }
  if (state_ == State::kTeardownPending) {
    return {HookInstallStatus::kTeardownPending, nullptr};
  }
  if (state_ == State::kRetired || installation_retired.load(std::memory_order_acquire)) {
    return {HookInstallStatus::kBackendStopped, nullptr};
  }

  RtlAllocateHeapHook* expected = nullptr;
  if (!active_owner.compare_exchange_strong(expected, this, std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
    return {HookInstallStatus::kAlreadyReplaced, nullptr};
  }
  if (!pin_replacement_module()) {
    release_owner(this, true);
    throw HookBackendError{"the replacement module could not be pinned"};
  }
  if (!backend_->acquire_trampoline_lifetime_lease()) {
    release_owner(this, true);
    return {HookInstallStatus::kBackendStopped, nullptr};
  }
  trampoline_lease_acquired_ = true;

  hook_state_->reset_quiescent();
  hook_state_->maximum_stack_depth = maximum_stack_depth_;
  restored_target.store(target_, std::memory_order_release);
  active_hook_state.store(hook_state_.get(), std::memory_order_release);
  replacement_lifecycle.start_recording();
  replacement_quiescent_ = false;
  backend_teardown_complete_ = false;

  FastHookResult result;
  try {
    result = backend_->install_fast(target_, replacement_address(),
                                    &hook_state_->original_trampoline);
  } catch (...) {
    replacement_lifecycle.route_to_target();
    backend_->release_trampoline_lifetime_lease();
    trampoline_lease_acquired_ = false;
    release_owner(this, true);
    throw;
  }

  if (result.installed()) {
    installation_retired.store(true, std::memory_order_release);
    state_ = State::kInstalled;
  } else {
    replacement_lifecycle.route_to_target();
    backend_->release_trampoline_lifetime_lease();
    trampoline_lease_acquired_ = false;
    release_owner(this, true);
  }
  return result;
}

HookUninstallStatus RtlAllocateHeapHook::uninstall(std::uint32_t flush_attempts) noexcept {
  if (state_ == State::kInactive || state_ == State::kRetired) {
    return HookUninstallStatus::kNotInstalled;
  }
  if (state_ == State::kTeardownPending) {
    return HookUninstallStatus::kTeardownPending;
  }

  replacement_lifecycle.stop_recording();
  state_ = State::kTeardownPending;

  // Never let Hoox flush here: a replacement paused before its original call is invisible to
  // Hoox's trampoline usage counter. Revert first, publish the restored-target route, then wait
  // for Noleax replacement quiescence before releasing the lifetime lease.
  const HookUninstallStatus backend_status = backend_->uninstall(target_, 0U);
  replacement_lifecycle.route_to_target();
  backend_teardown_complete_ = backend_status == HookUninstallStatus::kUninstalled;

  return try_finish_teardown(flush_attempts) ? HookUninstallStatus::kUninstalled
                                             : HookUninstallStatus::kTeardownPending;
}

bool RtlAllocateHeapHook::flush(std::uint32_t max_attempts) noexcept {
  if (state_ == State::kInactive || state_ == State::kRetired) {
    return true;
  }
  if (state_ == State::kInstalled) {
    return false;
  }
  return try_finish_teardown(max_attempts);
}

bool RtlAllocateHeapHook::is_installed() const noexcept { return state_ == State::kInstalled; }

bool RtlAllocateHeapHook::has_pending_teardown() const noexcept {
  return state_ == State::kTeardownPending;
}

bool RtlAllocateHeapHook::replacement_module_is_pinned() const noexcept {
  return replacement_module_pinned.load(std::memory_order_acquire);
}

std::uint64_t RtlAllocateHeapHook::replacement_in_flight_count() const noexcept {
  return replacement_lifecycle.in_flight();
}

std::uint64_t RtlAllocateHeapHook::call_count() const noexcept {
  return hook_state_->replacement_calls.load(std::memory_order_relaxed);
}

std::uint64_t RtlAllocateHeapHook::recordable_call_count() const noexcept {
  return hook_state_->recordable_calls.load(std::memory_order_relaxed);
}

std::uint64_t RtlAllocateHeapHook::recursive_call_count() const noexcept {
  return hook_state_->recursive_calls.load(std::memory_order_relaxed);
}

std::uint64_t RtlAllocateHeapHook::internal_call_count() const noexcept {
  return hook_state_->internal_calls.load(std::memory_order_relaxed);
}

std::uint64_t RtlAllocateHeapHook::successful_call_count() const noexcept {
  return hook_state_->successful_calls.load(std::memory_order_relaxed);
}

std::uint64_t RtlAllocateHeapHook::failed_call_count() const noexcept {
  return hook_state_->failed_calls.load(std::memory_order_relaxed);
}

std::uint64_t RtlAllocateHeapHook::dropped_event_count() const noexcept {
  return hook_state_->event_queue.dropped_count();
}

std::uint64_t RtlAllocateHeapHook::take_dropped_event_count() noexcept {
  return hook_state_->event_queue.take_dropped_count();
}

std::size_t RtlAllocateHeapHook::event_queue_capacity() const noexcept {
  return hook_state_->event_queue.capacity();
}

std::uint16_t RtlAllocateHeapHook::maximum_stack_depth() const noexcept {
  return maximum_stack_depth_;
}

bool RtlAllocateHeapHook::try_dequeue_event(RtlAllocateHeapEvent& event) noexcept {
  return hook_state_->event_queue.try_pop(event);
}

void* RtlAllocateHeapHook::target_address() const noexcept { return target_; }

bool RtlAllocateHeapHook::try_finish_teardown(std::uint32_t max_attempts) noexcept {
  if (!replacement_quiescent_) {
    if (!replacement_lifecycle.wait_for_quiescence(max_attempts)) {
      return false;
    }
    replacement_quiescent_ = true;
    if (trampoline_lease_acquired_) {
      backend_->release_trampoline_lifetime_lease();
      trampoline_lease_acquired_ = false;
    }
  }
  if (!backend_teardown_complete_) {
    backend_teardown_complete_ = backend_->flush(max_attempts);
  }
  if (!backend_teardown_complete_) {
    return false;
  }
  finish_teardown();
  return true;
}

void RtlAllocateHeapHook::finish_teardown() noexcept {
  hook_state_->original_trampoline.store(nullptr, std::memory_order_release);
  state_ = State::kRetired;
  release_owner(this, true);
}

void RtlAllocateHeapHook::abandon_pending_teardown() noexcept {
  replacement_lifecycle.route_to_target();
  if (trampoline_lease_acquired_) {
    // A counted replacement may still load the state and original trampoline. Transfer both the
    // state and guard reference to process lifetime; the backend lease prevents Hoox flush.
    static_cast<void>(hook_state_.release());
    guard_runtime_acquired_ = false;
    release_owner(this, false);
  } else {
    release_owner(this, true);
  }
  state_ = State::kRetired;
}

}  // namespace noleax::agent::windows
