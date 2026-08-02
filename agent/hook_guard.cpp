#include "noleax/agent/hook_guard.hpp"

#include <atomic>
#include <bit>
#include <cstdint>
#include <exception>
#include <limits>
#include <mutex>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#endif

namespace noleax::agent {
namespace {

constexpr std::uint32_t kDepthBits = 16U;
constexpr std::uintptr_t kDepthMask = (std::uintptr_t{1U} << kDepthBits) - 1U;
constexpr std::uint32_t kMaximumDepth = static_cast<std::uint32_t>(kDepthMask);

struct ThreadHookState {
  std::uint32_t hook_depth{0U};
  std::uint32_t internal_depth{0U};
};

std::mutex runtime_mutex;
std::uint32_t runtime_references{0U};

#if defined(_WIN32)

std::atomic<DWORD> state_tls_index{TLS_OUT_OF_INDEXES};

[[nodiscard]] ThreadHookState load_thread_state() noexcept {
  const DWORD index = state_tls_index.load(std::memory_order_acquire);
  if (index == TLS_OUT_OF_INDEXES || index >= TLS_MINIMUM_AVAILABLE) {
    std::terminate();
  }
  // A fixed TEB slot is available before the loader builds a new thread's static TLS vector.
  // Avoid TlsGetValue here because its API contract also changes LastError.
  const auto packed = reinterpret_cast<std::uintptr_t>(NtCurrentTeb()->TlsSlots[index]);
  return {static_cast<std::uint32_t>(packed & kDepthMask),
          static_cast<std::uint32_t>((packed >> kDepthBits) & kDepthMask)};
}

void store_thread_state(const ThreadHookState& state) noexcept {
  const DWORD index = state_tls_index.load(std::memory_order_relaxed);
  if (index == TLS_OUT_OF_INDEXES || index >= TLS_MINIMUM_AVAILABLE ||
      state.hook_depth > kMaximumDepth || state.internal_depth > kMaximumDepth) {
    std::terminate();
  }
  const std::uintptr_t packed = static_cast<std::uintptr_t>(state.hook_depth) |
                                (static_cast<std::uintptr_t>(state.internal_depth) << kDepthBits);
  NtCurrentTeb()->TlsSlots[index] = std::bit_cast<void*>(packed);
}

#else

constinit thread_local ThreadHookState thread_state;
std::atomic<bool> runtime_ready{false};

[[nodiscard]] ThreadHookState load_thread_state() noexcept {
  if (!runtime_ready.load(std::memory_order_acquire)) {
    std::terminate();
  }
  return thread_state;
}

void store_thread_state(const ThreadHookState& state) noexcept {
  if (!runtime_ready.load(std::memory_order_relaxed) || state.hook_depth > kMaximumDepth ||
      state.internal_depth > kMaximumDepth) {
    std::terminate();
  }
  thread_state = state;
}

#endif

void increment_or_terminate(std::uint32_t& value) noexcept {
  if (value == kMaximumDepth) {
    std::terminate();
  }
  ++value;
}

void decrement_or_terminate(std::uint32_t& value) noexcept {
  if (value == 0U) {
    std::terminate();
  }
  --value;
}

}  // namespace

bool acquire_hook_guard_runtime() noexcept {
  std::scoped_lock lock{runtime_mutex};
  if (runtime_references == std::numeric_limits<std::uint32_t>::max()) {
    return false;
  }
  if (runtime_references != 0U) {
    ++runtime_references;
    return true;
  }

#if defined(_WIN32)
  const DWORD index = TlsAlloc();
  if (index == TLS_OUT_OF_INDEXES) {
    return false;
  }
  // Expansion slots can require storage while RtlAllocateHeap itself is inside the guard.
  if (index >= TLS_MINIMUM_AVAILABLE) {
    static_cast<void>(TlsFree(index));
    return false;
  }
  state_tls_index.store(index, std::memory_order_release);
#else
  runtime_ready.store(true, std::memory_order_release);
#endif

  runtime_references = 1U;
  return true;
}

void release_hook_guard_runtime() noexcept {
  std::scoped_lock lock{runtime_mutex};
  if (runtime_references == 0U) {
    std::terminate();
  }
  if (--runtime_references != 0U) {
    return;
  }

#if defined(_WIN32)
  const DWORD index = state_tls_index.exchange(TLS_OUT_OF_INDEXES, std::memory_order_acq_rel);
  if (index == TLS_OUT_OF_INDEXES || TlsFree(index) == FALSE) {
    std::terminate();
  }
#else
  runtime_ready.store(false, std::memory_order_release);
#endif
}

bool hook_guard_runtime_is_ready() noexcept {
#if defined(_WIN32)
  return state_tls_index.load(std::memory_order_acquire) != TLS_OUT_OF_INDEXES;
#else
  return runtime_ready.load(std::memory_order_acquire);
#endif
}

HookEntryKind enter_hook_invocation_unscoped() noexcept {
  ThreadHookState state = load_thread_state();
  HookEntryKind kind = HookEntryKind::kOutermost;
  if (state.internal_depth != 0U) {
    kind = HookEntryKind::kInternalThread;
  } else if (state.hook_depth != 0U) {
    kind = HookEntryKind::kRecursive;
  }
  increment_or_terminate(state.hook_depth);
  store_thread_state(state);
  return kind;
}

void leave_hook_invocation_unscoped() noexcept {
  ThreadHookState state = load_thread_state();
  decrement_or_terminate(state.hook_depth);
  store_thread_state(state);
}

HookInvocationGuard::HookInvocationGuard() noexcept : kind_{enter_hook_invocation_unscoped()} {}

HookInvocationGuard::~HookInvocationGuard() noexcept { leave_hook_invocation_unscoped(); }

HookEntryKind HookInvocationGuard::kind() const noexcept { return kind_; }

bool HookInvocationGuard::should_record() const noexcept {
  return kind_ == HookEntryKind::kOutermost;
}

InternalThreadScope::InternalThreadScope() noexcept {
  ThreadHookState state = load_thread_state();
  increment_or_terminate(state.internal_depth);
  store_thread_state(state);
}

InternalThreadScope::~InternalThreadScope() noexcept {
  ThreadHookState state = load_thread_state();
  decrement_or_terminate(state.internal_depth);
  store_thread_state(state);
}

std::uint32_t current_hook_depth() noexcept { return load_thread_state().hook_depth; }

std::uint32_t current_internal_depth() noexcept { return load_thread_state().internal_depth; }

bool current_thread_is_internal() noexcept { return load_thread_state().internal_depth != 0U; }

#pragma code_seg(push, ".nlxhk")

namespace detail {

HookGuardThreadState probe_hook_guard_thread_state() noexcept {
#if defined(_WIN32)
  const DWORD index = state_tls_index.load(std::memory_order_acquire);
  if (index == TLS_OUT_OF_INDEXES || index >= TLS_MINIMUM_AVAILABLE) {
    return {};
  }
  const auto packed = reinterpret_cast<std::uintptr_t>(NtCurrentTeb()->TlsSlots[index]);
  return {static_cast<std::uint32_t>(packed & kDepthMask),
          static_cast<std::uint32_t>((packed >> kDepthBits) & kDepthMask)};
#else
  if (!runtime_ready.load(std::memory_order_acquire)) {
    return {};
  }
  return {thread_state.hook_depth, thread_state.internal_depth};
#endif
}

}  // namespace detail

#pragma code_seg(pop)

}  // namespace noleax::agent
