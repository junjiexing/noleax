#include "noleax/agent/windows/rtl_create_heap_hook.hpp"

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/patch_rendezvous.hpp"
#include "noleax/agent/replacement_lifecycle.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <limits>
#include <memory>
#include <new>

#include "noleax/agent/windows/stack_capture.hpp"

namespace noleax::agent::windows {

struct RtlCreateHeapHookState final {
  explicit RtlCreateHeapHookState(std::size_t event_queue_capacity)
      : owned_event_queue{std::make_unique<RtlHeapEventQueue>(event_queue_capacity)},
        event_queue{owned_event_queue.get()} {}

  explicit RtlCreateHeapHookState(RtlHeapEventQueue& shared_event_queue)
      : event_queue{&shared_event_queue} {}

  void reset_quiescent() noexcept {
    replacement_calls.store(0U, std::memory_order_relaxed);
    recordable_calls.store(0U, std::memory_order_relaxed);
    recursive_calls.store(0U, std::memory_order_relaxed);
    internal_calls.store(0U, std::memory_order_relaxed);
    successful_calls.store(0U, std::memory_order_relaxed);
    failed_calls.store(0U, std::memory_order_relaxed);
    exceptional_calls.store(0U, std::memory_order_relaxed);
    dropped_events.store(0U, std::memory_order_relaxed);
    if (owned_event_queue != nullptr) {
      owned_event_queue->reset_quiescent();
    }
  }

  std::unique_ptr<RtlHeapEventQueue> owned_event_queue;
  RtlHeapEventQueue* event_queue{nullptr};
  std::atomic<void*> original_trampoline{nullptr};
  std::atomic<std::uint64_t> replacement_calls{0U};
  std::atomic<std::uint64_t> recordable_calls{0U};
  std::atomic<std::uint64_t> recursive_calls{0U};
  std::atomic<std::uint64_t> internal_calls{0U};
  std::atomic<std::uint64_t> successful_calls{0U};
  std::atomic<std::uint64_t> failed_calls{0U};
  std::atomic<std::uint64_t> exceptional_calls{0U};
  std::atomic<std::uint64_t> dropped_events{0U};
  std::uint16_t maximum_stack_depth{kMaximumCapturedStackDepth};
};

namespace {

using RtlCreateHeapFunction = PVOID(NTAPI*)(ULONG flags, PVOID heap_base, SIZE_T reserve_size,
                                            SIZE_T commit_size, PVOID lock, PVOID parameters);

ReplacementLifecycle replacement_lifecycle;
std::atomic<RtlCreateHeapHookState*> active_hook_state{nullptr};
std::atomic<void*> restored_target{nullptr};
std::atomic<RtlCreateHeapHook*> active_owner{nullptr};
std::atomic<bool> installation_retired{false};
std::atomic<bool> replacement_module_referenced{false};
HMODULE replacement_module_handle{nullptr};

[[noreturn]] void fail_broken_replacement_route() noexcept {
#if defined(_MSC_VER)
  __fastfail(FAST_FAIL_FATAL_APP_EXIT);
#else
  std::terminate();
#endif
}

void increment_saturating(std::atomic<std::uint64_t>& value) noexcept {
  std::uint64_t current = value.load(std::memory_order_relaxed);
  while (current != std::numeric_limits<std::uint64_t>::max() &&
         !value.compare_exchange_weak(current, current + 1U, std::memory_order_relaxed,
                                      std::memory_order_relaxed)) {
  }
}

[[nodiscard]] RtlCreateHeapFunction load_function(std::atomic<void*>& slot) noexcept {
  void* const address = slot.load(std::memory_order_acquire);
  if (address == nullptr) {
    fail_broken_replacement_route();
  }
  return reinterpret_cast<RtlCreateHeapFunction>(address);
}

void fill_event(RtlCreateHeapEvent& event, std::uint64_t queue_sequence, ULONG flags,
                PVOID heap_base, SIZE_T reserve_size, SIZE_T commit_size, PVOID lock,
                PVOID parameters, PVOID result, RtlCreateHeapEventStatus status,
                std::uint32_t exception_status, std::uint16_t maximum_stack_depth) noexcept {
  event = RtlCreateHeapEvent{};
  LARGE_INTEGER ticks{};
  static_cast<void>(QueryPerformanceCounter(&ticks));
  event.queue_sequence = queue_sequence;
  event.monotonic_ticks = static_cast<std::uint64_t>(ticks.QuadPart);
  event.thread_id = static_cast<std::uint64_t>(GetCurrentThreadId());
  event.heap_handle = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(heap_base));
  event.requested_size = static_cast<std::uint64_t>(reserve_size);
  event.result_address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
  event.address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(lock));
  event.raw_result = static_cast<std::uint64_t>(commit_size);
  event.auxiliary_address =
      static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(parameters));
  event.flags = flags;
  event.exception_status = exception_status;
  event.operation = RtlHeapEventOperation::kCreate;
  event.status = status;
  if (status == RtlCreateHeapEventStatus::kException) {
    event.stack.frame_count = 0U;
    event.stack.requested_depth = maximum_stack_depth;
    event.stack.method = StackCaptureMethod::kRtlCaptureStackBackTrace;
    event.stack.status = StackCaptureStatus::kFailed;
  } else {
    capture_current_stack(event.stack, maximum_stack_depth, 1U);
  }
}

#if defined(_MSC_VER)

[[nodiscard]] LONG record_exception_filter(EXCEPTION_POINTERS* exception_pointers,
                                           ReplacementRoute route,
                                           RtlCreateHeapHookState* hook_state, bool guard_entered,
                                           HookEntryKind entry_kind, bool original_completed,
                                           ULONG flags, PVOID heap_base, SIZE_T reserve_size,
                                           SIZE_T commit_size, PVOID lock,
                                           PVOID parameters) noexcept {
  const DWORD preserved_last_error = GetLastError();
  if (route == ReplacementRoute::kRecord && hook_state != nullptr && guard_entered &&
      entry_kind == HookEntryKind::kOutermost && !original_completed &&
      exception_pointers != nullptr && exception_pointers->ExceptionRecord != nullptr) {
    hook_state->failed_calls.fetch_add(1U, std::memory_order_relaxed);
    hook_state->exceptional_calls.fetch_add(1U, std::memory_order_relaxed);
    const std::uint32_t exception_status = exception_pointers->ExceptionRecord->ExceptionCode;
    const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
    const bool queued = hook_state->event_queue->try_emplace(
        [=](RtlCreateHeapEvent& event, std::uint64_t queue_sequence) noexcept {
          fill_event(event, queue_sequence, flags, heap_base, reserve_size, commit_size, lock,
                     parameters, nullptr, RtlCreateHeapEventStatus::kException, exception_status,
                     maximum_stack_depth);
        });
    if (!queued) {
      increment_saturating(hook_state->dropped_events);
    }
  }
  SetLastError(preserved_last_error);
  return EXCEPTION_CONTINUE_SEARCH;
}

#endif

// Not noexcept: SEH exceptions raised by the original API must unwind through this frame
// (for example HEAP_GENERATE_EXCEPTIONS failures); clang terminates when an exception
// leaves a noexcept function. The definition stays in ".nlxhk" so the patch rendezvous covers
// the window before the lifecycle counters engage.
#pragma code_seg(push, ".nlxhk")

PVOID NTAPI replacement_rtl_create_heap(ULONG flags, PVOID heap_base, SIZE_T reserve_size,
                                        SIZE_T commit_size, PVOID lock, PVOID parameters) {
  const ReplacementRoute route = replacement_lifecycle.enter_unscoped();
  RtlCreateHeapHookState* hook_state = nullptr;
  RtlCreateHeapFunction original = nullptr;
  HookEntryKind entry_kind = HookEntryKind::kRecursive;
  PVOID result = nullptr;
  DWORD original_last_error = ERROR_SUCCESS;
  bool guard_entered = false;
  bool original_completed = false;

#if defined(_MSC_VER)
  __try {
    __try {
#endif
      if (route == ReplacementRoute::kTarget) {
        result = load_function(restored_target)(flags, heap_base, reserve_size, commit_size, lock,
                                                parameters);
        original_completed = true;
      } else {
        hook_state = active_hook_state.load(std::memory_order_acquire);
        if (hook_state == nullptr) {
          fail_broken_replacement_route();
        }
        void* const original_address =
            hook_state->original_trampoline.load(std::memory_order_acquire);
        if (original_address == nullptr) {
          fail_broken_replacement_route();
        }
        original = reinterpret_cast<RtlCreateHeapFunction>(original_address);
        if (route == ReplacementRoute::kOriginal) {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          result = original(flags, heap_base, reserve_size, commit_size, lock, parameters);
          original_completed = true;
        } else {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          hook_state->replacement_calls.fetch_add(1U, std::memory_order_relaxed);
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

          result = original(flags, heap_base, reserve_size, commit_size, lock, parameters);
          original_last_error = GetLastError();
          original_completed = true;

          if (entry_kind == HookEntryKind::kOutermost) {
            (result == nullptr ? hook_state->failed_calls : hook_state->successful_calls)
                .fetch_add(1U, std::memory_order_relaxed);
            const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
            const bool queued = hook_state->event_queue->try_emplace(
                [=](RtlCreateHeapEvent& event, std::uint64_t queue_sequence) noexcept {
                  fill_event(event, queue_sequence, flags, heap_base, reserve_size, commit_size,
                             lock, parameters, result,
                             result == nullptr ? RtlCreateHeapEventStatus::kFailure
                                               : RtlCreateHeapEventStatus::kSuccess,
                             0U, maximum_stack_depth);
                });
            if (!queued) {
              increment_saturating(hook_state->dropped_events);
            }
          }
          SetLastError(original_last_error);
        }
      }
#if defined(_MSC_VER)
    } __finally {
      if (guard_entered) {
        leave_hook_invocation_unscoped();
      }
      replacement_lifecycle.leave_unscoped(route);
    }
  } __except (record_exception_filter(GetExceptionInformation(), route, hook_state, guard_entered,
                                      entry_kind, original_completed, flags, heap_base,
                                      reserve_size, commit_size, lock, parameters)) {
    fail_broken_replacement_route();
  }
#else
  if (guard_entered) {
    leave_hook_invocation_unscoped();
  }
  replacement_lifecycle.leave_unscoped(route);
#endif
  return result;
}

#pragma code_seg(pop)

[[nodiscard]] void* replacement_address() noexcept {
  return reinterpret_cast<void*>(&replacement_rtl_create_heap);
}

[[nodiscard]] bool reference_replacement_module() noexcept {
  if (replacement_module_referenced.load(std::memory_order_acquire)) {
    return true;
  }
  HMODULE module = nullptr;
  const DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS;
  if (GetModuleHandleExW(flags, reinterpret_cast<LPCWSTR>(replacement_address()), &module) ==
      FALSE) {
    return false;
  }
  replacement_module_handle = module;
  replacement_module_referenced.store(true, std::memory_order_release);
  return true;
}

void release_replacement_module() noexcept {
  if (!replacement_module_referenced.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  static_cast<void>(FreeLibrary(replacement_module_handle));
  replacement_module_handle = nullptr;
}

void release_owner(RtlCreateHeapHook* owner, bool clear_hook_state) noexcept {
  if (clear_hook_state) {
    active_hook_state.store(nullptr, std::memory_order_release);
  }
  RtlCreateHeapHook* expected = owner;
  static_cast<void>(active_owner.compare_exchange_strong(
      expected, nullptr, std::memory_order_release, std::memory_order_relaxed));
}

}  // namespace

RtlCreateHeapHook::RtlCreateHeapHook(HookBackend& backend, std::size_t event_queue_capacity,
                                     std::uint16_t maximum_stack_depth)
    : hook_state_{std::make_unique<RtlCreateHeapHookState>(event_queue_capacity)},
      backend_{&backend},
      maximum_stack_depth_{maximum_stack_depth} {
  initialize();
}

RtlCreateHeapHook::RtlCreateHeapHook(HookBackend& backend, RtlHeapEventQueue& event_queue,
                                     std::uint16_t maximum_stack_depth)
    : hook_state_{std::make_unique<RtlCreateHeapHookState>(event_queue)},
      backend_{&backend},
      maximum_stack_depth_{maximum_stack_depth} {
  initialize();
}

void RtlCreateHeapHook::initialize() {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    throw HookBackendError{"ntdll.dll is not loaded"};
  }
  const FARPROC address = GetProcAddress(ntdll, "RtlCreateHeap");
  if (address == nullptr) {
    throw HookBackendError{"ntdll.dll does not export RtlCreateHeap"};
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

RtlCreateHeapHook::~RtlCreateHeapHook() {
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

FastHookResult RtlCreateHeapHook::install() {
  const InternalThreadScope internal_thread;
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

  RtlCreateHeapHook* expected = nullptr;
  if (!active_owner.compare_exchange_strong(expected, this, std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
    return {HookInstallStatus::kAlreadyReplaced, nullptr};
  }
  if (!reference_replacement_module()) {
    release_owner(this, true);
    throw HookBackendError{"the replacement module could not be referenced"};
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
    result =
        backend_->install_fast(target_, replacement_address(), &hook_state_->original_trampoline);
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

HookUninstallStatus RtlCreateHeapHook::uninstall(std::uint32_t flush_attempts) noexcept {
  const InternalThreadScope internal_thread;
  if (state_ == State::kInactive || state_ == State::kRetired) {
    return HookUninstallStatus::kNotInstalled;
  }
  if (state_ == State::kTeardownPending) {
    return HookUninstallStatus::kTeardownPending;
  }

  replacement_lifecycle.stop_recording();
  state_ = State::kTeardownPending;
  const HookUninstallStatus backend_status = backend_->uninstall(target_, 0U);
  replacement_lifecycle.route_to_target();
  backend_teardown_complete_ = backend_status == HookUninstallStatus::kUninstalled;
  return try_finish_teardown(flush_attempts) ? HookUninstallStatus::kUninstalled
                                             : HookUninstallStatus::kTeardownPending;
}

bool RtlCreateHeapHook::flush(std::uint32_t max_attempts) noexcept {
  if (state_ == State::kInactive || state_ == State::kRetired) {
    return true;
  }
  if (state_ == State::kInstalled) {
    return false;
  }
  return try_finish_teardown(max_attempts);
}

bool RtlCreateHeapHook::stop_recording(std::uint32_t max_attempts) noexcept {
  if (state_ != State::kInstalled) {
    return state_ == State::kInactive || state_ == State::kRetired;
  }
  replacement_lifecycle.stop_recording();
  return replacement_lifecycle.wait_for_recording_quiescence(max_attempts);
}

bool RtlCreateHeapHook::is_installed() const noexcept { return state_ == State::kInstalled; }
bool RtlCreateHeapHook::is_recording() const noexcept {
  return state_ == State::kInstalled && replacement_lifecycle.route() == ReplacementRoute::kRecord;
}
std::uint64_t RtlCreateHeapHook::recording_in_flight_count() const noexcept {
  return replacement_lifecycle.recording_in_flight();
}
bool RtlCreateHeapHook::has_pending_teardown() const noexcept {
  return state_ == State::kTeardownPending;
}
bool RtlCreateHeapHook::replacement_module_is_referenced() const noexcept {
  return replacement_module_referenced.load(std::memory_order_acquire);
}
std::uint64_t RtlCreateHeapHook::replacement_in_flight_count() const noexcept {
  return replacement_lifecycle.in_flight();
}
std::uint64_t RtlCreateHeapHook::call_count() const noexcept {
  return hook_state_->replacement_calls.load(std::memory_order_relaxed);
}
std::uint64_t RtlCreateHeapHook::recordable_call_count() const noexcept {
  return hook_state_->recordable_calls.load(std::memory_order_relaxed);
}
std::uint64_t RtlCreateHeapHook::recursive_call_count() const noexcept {
  return hook_state_->recursive_calls.load(std::memory_order_relaxed);
}
std::uint64_t RtlCreateHeapHook::internal_call_count() const noexcept {
  return hook_state_->internal_calls.load(std::memory_order_relaxed);
}
std::uint64_t RtlCreateHeapHook::successful_call_count() const noexcept {
  return hook_state_->successful_calls.load(std::memory_order_relaxed);
}
std::uint64_t RtlCreateHeapHook::failed_call_count() const noexcept {
  return hook_state_->failed_calls.load(std::memory_order_relaxed);
}
std::uint64_t RtlCreateHeapHook::exceptional_call_count() const noexcept {
  return hook_state_->exceptional_calls.load(std::memory_order_relaxed);
}
std::uint64_t RtlCreateHeapHook::dropped_event_count() const noexcept {
  return hook_state_->dropped_events.load(std::memory_order_relaxed);
}
std::uint64_t RtlCreateHeapHook::take_dropped_event_count() noexcept {
  return hook_state_->dropped_events.exchange(0U, std::memory_order_relaxed);
}
std::size_t RtlCreateHeapHook::event_queue_capacity() const noexcept {
  return hook_state_->event_queue->capacity();
}
std::uint16_t RtlCreateHeapHook::maximum_stack_depth() const noexcept {
  return maximum_stack_depth_;
}
bool RtlCreateHeapHook::try_dequeue_event(RtlCreateHeapEvent& event) noexcept {
  return hook_state_->event_queue->try_pop(event);
}
RtlHeapEventQueue& RtlCreateHeapHook::event_queue() noexcept { return *hook_state_->event_queue; }
const RtlHeapEventQueue& RtlCreateHeapHook::event_queue() const noexcept {
  return *hook_state_->event_queue;
}
void* RtlCreateHeapHook::target_address() const noexcept { return target_; }

bool RtlCreateHeapHook::try_finish_teardown(std::uint32_t max_attempts) noexcept {
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
  // The lifecycle counters cannot see a thread between the restored jump and the entry
  // increment. Prove the replacement code section is empty before releasing the module
  // reference; on failure stay teardown-pending and keep both the reference and the retired
  // flag so a later flush can retry.
  if (!verify_replacement_evacuated(hook_code_region(replacement_address()),
                                    kDefaultRendezvousMaxAttempts)) {
    return false;
  }
  release_replacement_module();
  installation_retired.store(false, std::memory_order_release);
  finish_teardown();
  return true;
}

void RtlCreateHeapHook::finish_teardown() noexcept {
  hook_state_->original_trampoline.store(nullptr, std::memory_order_release);
  state_ = State::kRetired;
  release_owner(this, true);
}

void RtlCreateHeapHook::abandon_pending_teardown() noexcept {
  replacement_lifecycle.route_to_target();
  if (trampoline_lease_acquired_) {
    static_cast<void>(hook_state_.release());
    guard_runtime_acquired_ = false;
    release_owner(this, false);
  } else {
    release_owner(this, true);
  }
  state_ = State::kRetired;
}

}  // namespace noleax::agent::windows
