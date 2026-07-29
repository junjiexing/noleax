#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"

#include "noleax/agent/hook_guard.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace noleax::agent::windows {
namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);

OriginalTrampolineSlot original_trampoline{nullptr};
std::atomic<std::uint64_t> replacement_calls{0U};
std::atomic<std::uint64_t> recordable_calls{0U};
std::atomic<std::uint64_t> recursive_calls{0U};
std::atomic<std::uint64_t> internal_calls{0U};
std::atomic<RtlAllocateHeapHook*> active_owner{nullptr};
std::atomic<BoundedMpscQueue<RtlAllocateHeapEvent>*> active_event_queue{nullptr};

static_assert(OriginalTrampolineSlot::is_always_lock_free);
static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
static_assert(decltype(active_event_queue)::is_always_lock_free);

[[noreturn]] void fail_missing_original() noexcept {
#if defined(_MSC_VER)
  __fastfail(FAST_FAIL_FATAL_APP_EXIT);
#else
  std::abort();
#endif
}

PVOID NTAPI replacement_rtl_allocate_heap(PVOID heap, ULONG flags, SIZE_T size) noexcept {
  const HookInvocationGuard guard;
  replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  const HookEntryKind entry_kind = guard.kind();
  switch (entry_kind) {
    case HookEntryKind::kOutermost:
      recordable_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
    case HookEntryKind::kRecursive:
      recursive_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
    case HookEntryKind::kInternalThread:
      internal_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
  }
  void* const original_address = original_trampoline.load(std::memory_order_acquire);
  if (original_address == nullptr) {
    fail_missing_original();
  }
  const auto original = reinterpret_cast<RtlAllocateHeapFunction>(original_address);
  PVOID const result = original(heap, flags, size);
  const DWORD original_last_error = GetLastError();

  if (entry_kind == HookEntryKind::kOutermost) {
    auto* const queue = active_event_queue.load(std::memory_order_acquire);
    if (queue == nullptr) {
      fail_missing_original();
    }
    static_cast<void>(queue->try_emplace([heap, flags, size, result](
                                             RtlAllocateHeapEvent& event,
                                             std::uint64_t queue_sequence) noexcept {
      LARGE_INTEGER ticks{};
      static_cast<void>(QueryPerformanceCounter(&ticks));
      event = {};
      event.queue_sequence = queue_sequence;
      event.monotonic_ticks = static_cast<std::uint64_t>(ticks.QuadPart);
      event.thread_id = static_cast<std::uint64_t>(GetCurrentThreadId());
      event.heap_handle = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(heap));
      event.requested_size = static_cast<std::uint64_t>(size);
      event.result_address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result));
      event.flags = flags;
      event.status = result == nullptr ? RtlAllocateHeapEventStatus::kFailure
                                       : RtlAllocateHeapEventStatus::kSuccess;
    }));
  }

  SetLastError(original_last_error);
  return result;
}

[[nodiscard]] void* replacement_address() noexcept {
  return reinterpret_cast<void*>(&replacement_rtl_allocate_heap);
}

void release_owner(RtlAllocateHeapHook* owner) noexcept {
  active_event_queue.store(nullptr, std::memory_order_release);
  original_trampoline.store(nullptr, std::memory_order_release);
  RtlAllocateHeapHook* expected = owner;
  static_cast<void>(active_owner.compare_exchange_strong(
      expected, nullptr, std::memory_order_release, std::memory_order_relaxed));
}

}  // namespace

RtlAllocateHeapHook::RtlAllocateHeapHook(HookBackend& backend, std::size_t event_queue_capacity)
    : event_queue_{event_queue_capacity}, backend_{&backend} {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    throw HookBackendError{"ntdll.dll is not loaded"};
  }
  const FARPROC address = GetProcAddress(ntdll, "RtlAllocateHeap");
  if (address == nullptr) {
    throw HookBackendError{"ntdll.dll does not export RtlAllocateHeap"};
  }
  target_ = reinterpret_cast<void*>(address);
  if (!acquire_hook_guard_runtime()) {
    throw HookBackendError{"a fixed Windows TLS slot is unavailable for the hook guard"};
  }
  guard_runtime_acquired_ = true;
}

RtlAllocateHeapHook::~RtlAllocateHeapHook() {
  if (state_ == State::kInstalled) {
    static_cast<void>(uninstall());
  }
  if (state_ == State::kTeardownPending) {
    static_cast<void>(flush());
  }
  if (state_ == State::kInactive && guard_runtime_acquired_) {
    release_hook_guard_runtime();
    guard_runtime_acquired_ = false;
  }
}

FastHookResult RtlAllocateHeapHook::install() {
  if (state_ == State::kInstalled) {
    return {HookInstallStatus::kAlreadyInstalled,
            original_trampoline.load(std::memory_order_acquire)};
  }
  if (state_ == State::kTeardownPending) {
    return {HookInstallStatus::kTeardownPending, nullptr};
  }

  RtlAllocateHeapHook* expected = nullptr;
  if (!active_owner.compare_exchange_strong(expected, this, std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
    return {HookInstallStatus::kAlreadyReplaced, nullptr};
  }

  original_trampoline.store(nullptr, std::memory_order_relaxed);
  event_queue_.reset_quiescent();
  active_event_queue.store(&event_queue_, std::memory_order_release);
  replacement_calls.store(0U, std::memory_order_relaxed);
  recordable_calls.store(0U, std::memory_order_relaxed);
  recursive_calls.store(0U, std::memory_order_relaxed);
  internal_calls.store(0U, std::memory_order_relaxed);
  FastHookResult result;
  try {
    result = backend_->install_fast(target_, replacement_address(), &original_trampoline);
  } catch (...) {
    release_owner(this);
    throw;
  }

  if (result.installed()) {
    state_ = State::kInstalled;
  } else {
    release_owner(this);
  }
  return result;
}

HookUninstallStatus RtlAllocateHeapHook::uninstall(std::uint32_t flush_attempts) noexcept {
  if (state_ == State::kInactive) {
    return HookUninstallStatus::kNotInstalled;
  }
  if (state_ == State::kTeardownPending) {
    return HookUninstallStatus::kTeardownPending;
  }

  const HookUninstallStatus result = backend_->uninstall(target_, flush_attempts);
  if (result == HookUninstallStatus::kUninstalled ||
      result == HookUninstallStatus::kBackendStopped) {
    finish_teardown();
  } else if (result == HookUninstallStatus::kTeardownPending) {
    state_ = State::kTeardownPending;
  } else if (backend_->flush(flush_attempts == 0U ? 1U : flush_attempts)) {
    finish_teardown();
  } else {
    state_ = State::kTeardownPending;
  }
  return result;
}

bool RtlAllocateHeapHook::flush(std::uint32_t max_attempts) noexcept {
  if (state_ == State::kInactive) {
    return true;
  }
  const bool complete = backend_->flush(max_attempts);
  if (complete && state_ == State::kTeardownPending) {
    finish_teardown();
  }
  return complete;
}

bool RtlAllocateHeapHook::is_installed() const noexcept { return state_ == State::kInstalled; }

bool RtlAllocateHeapHook::has_pending_teardown() const noexcept {
  return state_ == State::kTeardownPending;
}

std::uint64_t RtlAllocateHeapHook::call_count() const noexcept {
  return replacement_calls.load(std::memory_order_relaxed);
}

std::uint64_t RtlAllocateHeapHook::recordable_call_count() const noexcept {
  return recordable_calls.load(std::memory_order_relaxed);
}

std::uint64_t RtlAllocateHeapHook::recursive_call_count() const noexcept {
  return recursive_calls.load(std::memory_order_relaxed);
}

std::uint64_t RtlAllocateHeapHook::internal_call_count() const noexcept {
  return internal_calls.load(std::memory_order_relaxed);
}

std::uint64_t RtlAllocateHeapHook::dropped_event_count() const noexcept {
  return event_queue_.dropped_count();
}

std::size_t RtlAllocateHeapHook::event_queue_capacity() const noexcept {
  return event_queue_.capacity();
}

bool RtlAllocateHeapHook::try_dequeue_event(RtlAllocateHeapEvent& event) noexcept {
  return event_queue_.try_pop(event);
}

void* RtlAllocateHeapHook::target_address() const noexcept { return target_; }

void RtlAllocateHeapHook::finish_teardown() noexcept {
  state_ = State::kInactive;
  release_owner(this);
}

}  // namespace noleax::agent::windows
