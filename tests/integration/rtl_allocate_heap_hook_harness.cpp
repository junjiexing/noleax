#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstdint>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"

#define NOLEAX_HOOK_HARNESS_EXPORT extern "C" __declspec(dllexport)

namespace {

noleax::agent::HookBackend* backend = nullptr;
noleax::agent::windows::RtlAllocateHeapHook* hook = nullptr;

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
constexpr std::size_t kHarnessQueueCapacity = 256U;

void destroy_harness() noexcept {
  delete hook;
  hook = nullptr;
  delete backend;
  backend = nullptr;
}

[[nodiscard]] std::uint32_t verify_event_queue() noexcept {
  std::uint64_t dequeued = 0U;
  noleax::agent::windows::RtlAllocateHeapEvent event;
  while (hook->try_dequeue_event(event)) {
    ++dequeued;
    if (event.queue_sequence != dequeued || event.monotonic_ticks == 0U || event.thread_id == 0U) {
      return 1U;
    }
    if (event.status != noleax::agent::windows::RtlAllocateHeapEventStatus::kSuccess &&
        event.status != noleax::agent::windows::RtlAllocateHeapEventStatus::kFailure) {
      return 2U;
    }
    const bool succeeded =
        event.status == noleax::agent::windows::RtlAllocateHeapEventStatus::kSuccess;
    if (succeeded != (event.result_address != 0U)) {
      return 3U;
    }
  }

  const std::uint64_t dropped = hook->dropped_event_count();
  if (hook->event_queue_capacity() != kHarnessQueueCapacity || dropped == 0U) {
    return 4U;
  }
  if (dequeued > hook->recordable_call_count() ||
      dropped != hook->recordable_call_count() - dequeued) {
    return 5U;
  }
  return 0U;
}

[[nodiscard]] std::uint32_t stop_harness(bool verify_queue = true) noexcept {
  if (hook == nullptr || backend == nullptr) {
    return 1U;
  }

  auto uninstall_status = hook->uninstall();
  if (uninstall_status == noleax::agent::HookUninstallStatus::kTeardownPending && hook->flush()) {
    uninstall_status = noleax::agent::HookUninstallStatus::kUninstalled;
  }
  if (uninstall_status != noleax::agent::HookUninstallStatus::kUninstalled) {
    return 2U;
  }
  const std::uint32_t queue_status = verify_queue ? verify_event_queue() : 0U;
  if (!backend->shutdown()) {
    return 3U;
  }

  destroy_harness();
  return queue_status == 0U ? 0U : 10U + queue_status;
}

[[nodiscard]] std::uint32_t verify_guard_behavior() noexcept {
  const auto target = reinterpret_cast<RtlAllocateHeapFunction>(hook->target_address());
  const HANDLE process_heap = GetProcessHeap();
  if (target == nullptr || process_heap == nullptr) {
    return 1U;
  }

  const std::uint64_t recordable_before = hook->recordable_call_count();
  const std::uint64_t recursive_before_outermost = hook->recursive_call_count();
  const std::uint64_t internal_before_outermost = hook->internal_call_count();
  PVOID outermost_allocation = target(process_heap, 0U, 48U);
  if (outermost_allocation == nullptr || hook->recordable_call_count() <= recordable_before ||
      hook->recursive_call_count() != recursive_before_outermost ||
      hook->internal_call_count() != internal_before_outermost ||
      noleax::agent::current_hook_depth() != 0U) {
    return 2U;
  }
  if (HeapFree(process_heap, 0U, outermost_allocation) == FALSE) {
    return 3U;
  }

  const std::uint64_t recursive_before = hook->recursive_call_count();
  const std::uint64_t recordable_before_recursion = hook->recordable_call_count();
  const std::uint64_t internal_before_recursion = hook->internal_call_count();
  PVOID recursive_allocation = nullptr;
  {
    const noleax::agent::HookInvocationGuard simulated_outer_hook;
    recursive_allocation = target(process_heap, 0U, 64U);
  }
  if (recursive_allocation == nullptr || hook->recursive_call_count() <= recursive_before ||
      hook->recordable_call_count() != recordable_before_recursion ||
      hook->internal_call_count() != internal_before_recursion ||
      noleax::agent::current_hook_depth() != 0U) {
    return 4U;
  }
  if (HeapFree(process_heap, 0U, recursive_allocation) == FALSE) {
    return 5U;
  }

  const std::uint64_t internal_before = hook->internal_call_count();
  const std::uint64_t recordable_before_internal = hook->recordable_call_count();
  const std::uint64_t recursive_before_internal = hook->recursive_call_count();
  PVOID internal_allocation = nullptr;
  {
    const noleax::agent::InternalThreadScope internal_thread;
    internal_allocation = target(process_heap, 0U, 96U);
  }
  if (internal_allocation == nullptr || hook->internal_call_count() <= internal_before ||
      hook->recordable_call_count() != recordable_before_internal ||
      hook->recursive_call_count() != recursive_before_internal ||
      noleax::agent::current_thread_is_internal()) {
    return 6U;
  }
  if (HeapFree(process_heap, 0U, internal_allocation) == FALSE) {
    return 7U;
  }

  return 0U;
}

}  // namespace

NOLEAX_HOOK_HARNESS_EXPORT std::uint32_t noleax_test_rtl_allocate_heap_hook_abi_version() noexcept {
  return 1U;
}

NOLEAX_HOOK_HARNESS_EXPORT std::uint32_t noleax_test_rtl_allocate_heap_hook_install() noexcept {
  if (hook != nullptr) {
    return 1U;
  }

  try {
    backend = new noleax::agent::HookBackend{};
    hook = new noleax::agent::windows::RtlAllocateHeapHook{*backend, kHarnessQueueCapacity};
    const auto result = hook->install();
    if (!result.installed()) {
      const auto status = static_cast<std::uint32_t>(result.status);
      destroy_harness();
      return 100U + status;
    }
    const std::uint32_t guard_status = verify_guard_behavior();
    if (guard_status != 0U) {
      const std::uint32_t stop_status = stop_harness(false);
      return stop_status == 0U ? 200U + guard_status : 300U + stop_status;
    }
  } catch (...) {
    destroy_harness();
    return 0xffffffffU;
  }
  return 0U;
}

NOLEAX_HOOK_HARNESS_EXPORT std::uint64_t noleax_test_rtl_allocate_heap_hook_call_count() noexcept {
  return hook != nullptr ? hook->call_count() : 0U;
}

NOLEAX_HOOK_HARNESS_EXPORT std::uint32_t noleax_test_rtl_allocate_heap_hook_stop() noexcept {
  return stop_harness();
}
