#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstdint>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"
#include "noleax/agent/windows/rtl_free_heap_hook.hpp"
#include "noleax/agent/windows/rtl_heap_hooks.hpp"
#include "noleax/agent/windows/rtl_reallocate_heap_hook.hpp"

#define NOLEAX_HOOK_HARNESS_EXPORT extern "C" __declspec(dllexport)

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlReAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, PVOID address,
                                                SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID address);

constexpr std::size_t kHarnessQueueCapacity = 256U;

noleax::agent::HookBackend* backend = nullptr;
noleax::agent::windows::RtlHeapHooks* hook_set = nullptr;
noleax::agent::windows::RtlHeapEventQueue* event_queue = nullptr;
noleax::agent::windows::RtlAllocateHeapHook* allocate_hook = nullptr;
noleax::agent::windows::RtlReAllocateHeapHook* reallocate_hook = nullptr;
noleax::agent::windows::RtlFreeHeapHook* free_hook = nullptr;

void destroy_harness() noexcept {
  delete hook_set;
  hook_set = nullptr;
  free_hook = nullptr;
  reallocate_hook = nullptr;
  allocate_hook = nullptr;
  event_queue = nullptr;
  delete backend;
  backend = nullptr;
}

[[nodiscard]] bool counters_reconcile(std::uint64_t successful, std::uint64_t failed,
                                      std::uint64_t recordable) noexcept {
  return successful <= recordable && failed == recordable - successful;
}

[[nodiscard]] std::uint32_t verify_event_queue() noexcept {
  std::uint64_t dequeued = 0U;
  std::uint64_t allocate_events = 0U;
  std::uint64_t reallocate_events = 0U;
  std::uint64_t free_events = 0U;
  std::uint64_t captured_stacks = 0U;
  noleax::agent::windows::RtlHeapEvent event;
  while (event_queue->try_pop(event)) {
    ++dequeued;
    if (event.queue_sequence != dequeued || event.monotonic_ticks == 0U || event.thread_id == 0U) {
      return 1U;
    }
    if (event.status != noleax::agent::windows::RtlHeapEventStatus::kSuccess &&
        event.status != noleax::agent::windows::RtlHeapEventStatus::kFailure &&
        event.status != noleax::agent::windows::RtlHeapEventStatus::kException) {
      return 2U;
    }
    const bool succeeded = event.status == noleax::agent::windows::RtlHeapEventStatus::kSuccess;
    const bool exceptional = event.status == noleax::agent::windows::RtlHeapEventStatus::kException;
    if (exceptional != (event.exception_status != 0U)) {
      return 3U;
    }
    if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kAllocate) {
      ++allocate_events;
      if (succeeded != (event.result_address != 0U) || event.address != 0U ||
          event.raw_result != 0U) {
        return 4U;
      }
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kReallocate) {
      ++reallocate_events;
      if (succeeded != (event.result_address != 0U) || event.raw_result != 0U) {
        return 5U;
      }
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kFree) {
      ++free_events;
      if (succeeded != (event.raw_result != 0U) || event.requested_size != 0U ||
          event.result_address != 0U) {
        return 6U;
      }
    } else {
      return 7U;
    }
    if (event.stack.method !=
            noleax::agent::windows::StackCaptureMethod::kRtlCaptureStackBackTrace ||
        event.stack.requested_depth != noleax::agent::windows::kMaximumCapturedStackDepth) {
      return 8U;
    }
    if (noleax::agent::windows::stack_capture_succeeded(event.stack)) {
      ++captured_stacks;
      for (std::uint16_t index = 0U; index < event.stack.frame_count; ++index) {
        if (event.stack.frames[index] == 0U) {
          return 9U;
        }
      }
    } else if (event.stack.status != noleax::agent::windows::StackCaptureStatus::kFailed ||
               event.stack.frame_count != 0U) {
      return 9U;
    }
  }

  const std::uint64_t allocate_dropped = allocate_hook->dropped_event_count();
  const std::uint64_t reallocate_dropped = reallocate_hook->dropped_event_count();
  const std::uint64_t free_dropped = free_hook->dropped_event_count();
  const std::uint64_t total_dropped = allocate_dropped + reallocate_dropped + free_dropped;
  const std::uint64_t total_recordable = allocate_hook->recordable_call_count() +
                                         reallocate_hook->recordable_call_count() +
                                         free_hook->recordable_call_count();
  if (allocate_hook->event_queue_capacity() != kHarnessQueueCapacity ||
      reallocate_hook->event_queue_capacity() != kHarnessQueueCapacity ||
      free_hook->event_queue_capacity() != kHarnessQueueCapacity ||
      allocate_hook->maximum_stack_depth() != noleax::agent::windows::kMaximumCapturedStackDepth ||
      reallocate_hook->maximum_stack_depth() !=
          noleax::agent::windows::kMaximumCapturedStackDepth ||
      free_hook->maximum_stack_depth() != noleax::agent::windows::kMaximumCapturedStackDepth ||
      total_dropped == 0U || event_queue->dropped_count() != total_dropped ||
      allocate_events == 0U || reallocate_events == 0U || free_events == 0U ||
      captured_stacks == 0U) {
    return 10U;
  }
  if (dequeued > total_recordable || total_dropped != total_recordable - dequeued) {
    return 11U;
  }
  if (!counters_reconcile(allocate_hook->successful_call_count(),
                          allocate_hook->failed_call_count(),
                          allocate_hook->recordable_call_count()) ||
      !counters_reconcile(reallocate_hook->successful_call_count(),
                          reallocate_hook->failed_call_count(),
                          reallocate_hook->recordable_call_count()) ||
      !counters_reconcile(free_hook->successful_call_count(), free_hook->failed_call_count(),
                          free_hook->recordable_call_count())) {
    return 12U;
  }
  return 0U;
}

[[nodiscard]] std::uint32_t stop_harness(bool verify_queue = true) noexcept {
  if (hook_set == nullptr || allocate_hook == nullptr || reallocate_hook == nullptr ||
      free_hook == nullptr || event_queue == nullptr || backend == nullptr) {
    return 1U;
  }
  if (!hook_set->uninstall()) {
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
  const auto allocate = reinterpret_cast<RtlAllocateHeapFunction>(allocate_hook->target_address());
  const auto reallocate =
      reinterpret_cast<RtlReAllocateHeapFunction>(reallocate_hook->target_address());
  const auto free_heap = reinterpret_cast<RtlFreeHeapFunction>(free_hook->target_address());
  const HANDLE process_heap = GetProcessHeap();
  if (allocate == nullptr || reallocate == nullptr || free_heap == nullptr ||
      process_heap == nullptr) {
    return 1U;
  }

  const std::uint64_t allocate_recordable_before = allocate_hook->recordable_call_count();
  const std::uint64_t free_recordable_before = free_hook->recordable_call_count();
  PVOID outermost = allocate(process_heap, 0U, 48U);
  if (outermost == nullptr ||
      allocate_hook->recordable_call_count() <= allocate_recordable_before ||
      noleax::agent::current_hook_depth() != 0U ||
      free_heap(process_heap, 0U, outermost) == FALSE ||
      free_hook->recordable_call_count() <= free_recordable_before) {
    return 2U;
  }

  PVOID outermost_reallocation = allocate(process_heap, 0U, 56U);
  const std::uint64_t reallocate_recordable_before = reallocate_hook->recordable_call_count();
  outermost_reallocation = reallocate(process_heap, 0U, outermost_reallocation, 88U);
  if (outermost_reallocation == nullptr ||
      reallocate_hook->recordable_call_count() <= reallocate_recordable_before ||
      noleax::agent::current_hook_depth() != 0U ||
      free_heap(process_heap, 0U, outermost_reallocation) == FALSE) {
    return 3U;
  }

  const std::uint64_t allocate_recursive_before = allocate_hook->recursive_call_count();
  const std::uint64_t allocate_recordable_before_recursion = allocate_hook->recordable_call_count();
  PVOID recursive_allocation = nullptr;
  {
    const noleax::agent::HookInvocationGuard simulated_outer_hook;
    recursive_allocation = allocate(process_heap, 0U, 64U);
  }
  if (recursive_allocation == nullptr ||
      allocate_hook->recursive_call_count() <= allocate_recursive_before ||
      allocate_hook->recordable_call_count() != allocate_recordable_before_recursion ||
      noleax::agent::current_hook_depth() != 0U ||
      free_heap(process_heap, 0U, recursive_allocation) == FALSE) {
    return 4U;
  }

  const std::uint64_t allocate_internal_before = allocate_hook->internal_call_count();
  const std::uint64_t allocate_recordable_before_internal = allocate_hook->recordable_call_count();
  PVOID internal_allocation = nullptr;
  {
    const noleax::agent::InternalThreadScope internal_thread;
    internal_allocation = allocate(process_heap, 0U, 96U);
  }
  if (internal_allocation == nullptr ||
      allocate_hook->internal_call_count() <= allocate_internal_before ||
      allocate_hook->recordable_call_count() != allocate_recordable_before_internal ||
      noleax::agent::current_thread_is_internal() ||
      free_heap(process_heap, 0U, internal_allocation) == FALSE) {
    return 5U;
  }

  PVOID recursive_reallocation = allocate(process_heap, 0U, 72U);
  const std::uint64_t reallocate_recursive_before = reallocate_hook->recursive_call_count();
  const std::uint64_t reallocate_recordable_before_recursion =
      reallocate_hook->recordable_call_count();
  {
    const noleax::agent::HookInvocationGuard simulated_outer_hook;
    recursive_reallocation =
        reallocate(process_heap, 0U, recursive_reallocation, static_cast<SIZE_T>(104U));
  }
  if (recursive_reallocation == nullptr ||
      reallocate_hook->recursive_call_count() <= reallocate_recursive_before ||
      reallocate_hook->recordable_call_count() != reallocate_recordable_before_recursion ||
      noleax::agent::current_hook_depth() != 0U ||
      free_heap(process_heap, 0U, recursive_reallocation) == FALSE) {
    return 6U;
  }

  PVOID internal_reallocation = allocate(process_heap, 0U, 80U);
  const std::uint64_t reallocate_internal_before = reallocate_hook->internal_call_count();
  const std::uint64_t reallocate_recordable_before_internal =
      reallocate_hook->recordable_call_count();
  {
    const noleax::agent::InternalThreadScope internal_thread;
    internal_reallocation =
        reallocate(process_heap, 0U, internal_reallocation, static_cast<SIZE_T>(120U));
  }
  if (internal_reallocation == nullptr ||
      reallocate_hook->internal_call_count() <= reallocate_internal_before ||
      reallocate_hook->recordable_call_count() != reallocate_recordable_before_internal ||
      noleax::agent::current_thread_is_internal() ||
      free_heap(process_heap, 0U, internal_reallocation) == FALSE) {
    return 7U;
  }

  PVOID recursive_free_allocation = allocate(process_heap, 0U, 112U);
  const std::uint64_t free_recursive_before = free_hook->recursive_call_count();
  const std::uint64_t free_recordable_before_recursion = free_hook->recordable_call_count();
  BOOLEAN recursive_free = FALSE;
  {
    const noleax::agent::HookInvocationGuard simulated_outer_hook;
    recursive_free = free_heap(process_heap, 0U, recursive_free_allocation);
  }
  if (recursive_free_allocation == nullptr || recursive_free == FALSE ||
      free_hook->recursive_call_count() <= free_recursive_before ||
      free_hook->recordable_call_count() != free_recordable_before_recursion ||
      noleax::agent::current_hook_depth() != 0U) {
    return 8U;
  }

  PVOID internal_free_allocation = allocate(process_heap, 0U, 128U);
  const std::uint64_t free_internal_before = free_hook->internal_call_count();
  const std::uint64_t free_recordable_before_internal = free_hook->recordable_call_count();
  BOOLEAN internal_free = FALSE;
  {
    const noleax::agent::InternalThreadScope internal_thread;
    internal_free = free_heap(process_heap, 0U, internal_free_allocation);
  }
  if (internal_free_allocation == nullptr || internal_free == FALSE ||
      free_hook->internal_call_count() <= free_internal_before ||
      free_hook->recordable_call_count() != free_recordable_before_internal ||
      noleax::agent::current_thread_is_internal()) {
    return 9U;
  }
  return 0U;
}

}  // namespace

NOLEAX_HOOK_HARNESS_EXPORT std::uint32_t noleax_test_rtl_allocate_heap_hook_abi_version() noexcept {
  return 1U;
}

NOLEAX_HOOK_HARNESS_EXPORT std::uint32_t noleax_test_rtl_allocate_heap_hook_install() noexcept {
  if (allocate_hook != nullptr) {
    return 1U;
  }

  try {
    backend = new noleax::agent::HookBackend{};
    hook_set = new noleax::agent::windows::RtlHeapHooks{
        *backend, kHarnessQueueCapacity, noleax::agent::windows::kMaximumCapturedStackDepth};
    event_queue = &hook_set->event_queue();
    allocate_hook = &hook_set->allocate_hook();
    reallocate_hook = &hook_set->reallocate_hook();
    free_hook = &hook_set->free_hook();

    const auto result = hook_set->install();
    if (!result.installed()) {
      std::uint32_t status = static_cast<std::uint32_t>(result.allocate.status);
      if (result.allocate.installed()) {
        status = result.reallocate.installed()
                     ? static_cast<std::uint32_t>(result.free.status) + 40U
                     : static_cast<std::uint32_t>(result.reallocate.status) + 20U;
      }
      static_cast<void>(backend->shutdown());
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
  return allocate_hook != nullptr ? allocate_hook->call_count() : 0U;
}

NOLEAX_HOOK_HARNESS_EXPORT std::uint32_t noleax_test_rtl_allocate_heap_hook_stop() noexcept {
  return stop_harness();
}
