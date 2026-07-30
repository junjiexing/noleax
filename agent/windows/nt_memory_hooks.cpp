#include "noleax/agent/windows/nt_memory_hooks.hpp"

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/replacement_lifecycle.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <algorithm>
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
namespace {

struct ApiHookState {
  void reset_quiescent() noexcept {
    original_trampoline.store(nullptr, std::memory_order_relaxed);
    replacement_calls.store(0U, std::memory_order_relaxed);
    recordable_calls.store(0U, std::memory_order_relaxed);
    recursive_calls.store(0U, std::memory_order_relaxed);
    internal_calls.store(0U, std::memory_order_relaxed);
    successful_calls.store(0U, std::memory_order_relaxed);
    failed_calls.store(0U, std::memory_order_relaxed);
    exceptional_calls.store(0U, std::memory_order_relaxed);
    filtered_calls.store(0U, std::memory_order_relaxed);
    dropped_events.store(0U, std::memory_order_relaxed);
  }

  std::atomic<void*> original_trampoline{nullptr};
  std::atomic<std::uint64_t> replacement_calls{0U};
  std::atomic<std::uint64_t> recordable_calls{0U};
  std::atomic<std::uint64_t> recursive_calls{0U};
  std::atomic<std::uint64_t> internal_calls{0U};
  std::atomic<std::uint64_t> successful_calls{0U};
  std::atomic<std::uint64_t> failed_calls{0U};
  std::atomic<std::uint64_t> exceptional_calls{0U};
  std::atomic<std::uint64_t> filtered_calls{0U};
  std::atomic<std::uint64_t> dropped_events{0U};
};

using NtAllocateVirtualMemoryFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID* base_address,
                                                         ULONG_PTR zero_bits, PSIZE_T region_size,
                                                         ULONG allocation_type, ULONG protect);
using NtFreeVirtualMemoryFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID* base_address,
                                                     PSIZE_T region_size, ULONG free_type);
using NtMapViewOfSectionFunction = NTSTATUS(NTAPI*)(HANDLE section, HANDLE process,
                                                    PVOID* base_address, ULONG_PTR zero_bits,
                                                    SIZE_T commit_size,
                                                    PLARGE_INTEGER section_offset,
                                                    PSIZE_T view_size, ULONG inherit_disposition,
                                                    ULONG allocation_type, ULONG protect);
using NtUnmapViewOfSectionFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID base_address);
using NtUnmapViewOfSectionExFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID base_address,
                                                        ULONG flags);

ReplacementLifecycle allocate_replacement_lifecycle;
ReplacementLifecycle free_replacement_lifecycle;
ReplacementLifecycle map_replacement_lifecycle;
ReplacementLifecycle unmap_replacement_lifecycle;
std::atomic<NtMemoryHookState*> active_hook_state{nullptr};
std::atomic<void*> restored_allocate_target{nullptr};
std::atomic<void*> restored_free_target{nullptr};
std::atomic<void*> restored_map_target{nullptr};
std::atomic<void*> restored_unmap_target{nullptr};
std::atomic<void*> restored_unmap_ex_target{nullptr};
std::atomic<NtMemoryHooks*> active_owner{nullptr};
std::atomic<bool> installation_retired{false};
std::atomic<bool> replacement_module_pinned{false};

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

[[nodiscard]] bool nt_success(NTSTATUS status) noexcept { return status >= 0; }

template <typename T>
[[nodiscard]] bool safely_read(const T* source, T& destination) noexcept {
  const DWORD preserved_last_error = GetLastError();
  bool read = false;
#if defined(_MSC_VER)
  __try {
    if (source != nullptr) {
      destination = *source;
      read = true;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    read = false;
  }
#else
  if (source != nullptr) {
    destination = *source;
    read = true;
  }
#endif
  SetLastError(preserved_last_error);
  return read;
}

[[nodiscard]] NtAllocateVirtualMemoryFunction load_allocate_function(
    std::atomic<void*>& slot) noexcept {
  void* const address = slot.load(std::memory_order_acquire);
  if (address == nullptr) {
    fail_broken_replacement_route();
  }
  return reinterpret_cast<NtAllocateVirtualMemoryFunction>(address);
}

[[nodiscard]] NtFreeVirtualMemoryFunction load_free_function(std::atomic<void*>& slot) noexcept {
  void* const address = slot.load(std::memory_order_acquire);
  if (address == nullptr) {
    fail_broken_replacement_route();
  }
  return reinterpret_cast<NtFreeVirtualMemoryFunction>(address);
}

[[nodiscard]] NtMapViewOfSectionFunction load_map_function(std::atomic<void*>& slot) noexcept {
  void* const address = slot.load(std::memory_order_acquire);
  if (address == nullptr) {
    fail_broken_replacement_route();
  }
  return reinterpret_cast<NtMapViewOfSectionFunction>(address);
}

[[nodiscard]] NtUnmapViewOfSectionFunction load_unmap_function(std::atomic<void*>& slot) noexcept {
  void* const address = slot.load(std::memory_order_acquire);
  if (address == nullptr) {
    fail_broken_replacement_route();
  }
  return reinterpret_cast<NtUnmapViewOfSectionFunction>(address);
}

[[nodiscard]] NtUnmapViewOfSectionExFunction load_unmap_ex_function(
    std::atomic<void*>& slot) noexcept {
  void* const address = slot.load(std::memory_order_acquire);
  if (address == nullptr) {
    fail_broken_replacement_route();
  }
  return reinterpret_cast<NtUnmapViewOfSectionExFunction>(address);
}

void classify_entry(ApiHookState& api, HookEntryKind entry_kind) noexcept {
  api.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  switch (entry_kind) {
    case HookEntryKind::kOutermost:
      api.recordable_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
    case HookEntryKind::kRecursive:
      api.recursive_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
    case HookEntryKind::kInternalThread:
      api.internal_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
  }
}

void fill_vm_event(NtVirtualMemoryEvent& event, std::uint64_t queue_sequence,
                   RtlHeapEventOperation operation, HANDLE process, PVOID requested_base,
                   PVOID result_base, SIZE_T requested_size, SIZE_T result_size,
                   ULONG_PTR zero_bits, ULONG flags, ULONG secondary_flags, NTSTATUS result,
                   NtVirtualMemoryEventStatus status, std::uint32_t exception_status,
                   std::uint16_t maximum_stack_depth) noexcept {
  event = NtVirtualMemoryEvent{};
  LARGE_INTEGER ticks{};
  static_cast<void>(QueryPerformanceCounter(&ticks));
  event.queue_sequence = queue_sequence;
  event.monotonic_ticks = static_cast<std::uint64_t>(ticks.QuadPart);
  event.thread_id = static_cast<std::uint64_t>(GetCurrentThreadId());
  event.heap_handle = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(process));
  event.target_process_id = process == GetCurrentProcess()
                                ? static_cast<std::uint64_t>(GetCurrentProcessId())
                                : static_cast<std::uint64_t>(GetProcessId(process));
  event.requested_size = static_cast<std::uint64_t>(requested_size);
  event.result_address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(result_base));
  event.address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(requested_base));
  event.raw_result = static_cast<std::uint64_t>(result_size);
  event.auxiliary_address = static_cast<std::uint64_t>(zero_bits);
  if (operation == RtlHeapEventOperation::kVmAllocate &&
      status == NtVirtualMemoryEventStatus::kSuccess && result_base != nullptr &&
      event.target_process_id == static_cast<std::uint64_t>(GetCurrentProcessId())) {
    MEMORY_BASIC_INFORMATION information{};
    if (VirtualQuery(result_base, &information, sizeof(information)) == sizeof(information)) {
      event.mapping_base =
          static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(information.AllocationBase));
      const std::uint64_t region_base =
          static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(information.BaseAddress));
      const std::uint64_t region_size = static_cast<std::uint64_t>(information.RegionSize);
      if (region_base >= event.mapping_base &&
          region_size <=
              std::numeric_limits<std::uint64_t>::max() - (region_base - event.mapping_base)) {
        event.mapping_size = region_base - event.mapping_base + region_size;
      }
    }
    if (event.mapping_base == 0U) {
      event.mapping_base = event.result_address;
    }
    event.mapping_size = (std::max)(event.mapping_size, event.raw_result);
  }
  event.flags = flags;
  event.secondary_flags = secondary_flags;
  event.operation_result = static_cast<std::uint32_t>(result);
  event.exception_status = exception_status;
  event.operation = operation;
  event.status = status;
  if (status == NtVirtualMemoryEventStatus::kException) {
    event.stack.frame_count = 0U;
    event.stack.requested_depth = maximum_stack_depth;
    event.stack.method = StackCaptureMethod::kRtlCaptureStackBackTrace;
    event.stack.status =
        maximum_stack_depth == 0U ? StackCaptureStatus::kDisabled : StackCaptureStatus::kFailed;
  } else {
    capture_current_stack(event.stack, maximum_stack_depth, 1U);
  }
}

void fill_section_event(NtVirtualMemoryEvent& event, std::uint64_t queue_sequence,
                        RtlHeapEventOperation operation, HANDLE section, HANDLE process,
                        PVOID requested_base, PVOID result_base, SIZE_T requested_view_size,
                        SIZE_T result_view_size, ULONG_PTR zero_bits, SIZE_T commit_size,
                        std::uint64_t section_offset, ULONG inherit_disposition,
                        ULONG allocation_type, ULONG protect, NTSTATUS result,
                        NtVirtualMemoryEventStatus status, std::uint32_t exception_status,
                        std::uint16_t maximum_stack_depth) noexcept {
  fill_vm_event(event, queue_sequence, operation, process, requested_base, result_base,
                requested_view_size, result_view_size, zero_bits, allocation_type, protect, result,
                status, exception_status, maximum_stack_depth);
  event.section_handle = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(section));
  event.section_offset = section_offset;
  event.commit_size = static_cast<std::uint64_t>(commit_size);
  event.tertiary_flags = static_cast<std::uint32_t>(inherit_disposition);
  if (operation == RtlHeapEventOperation::kSectionMap &&
      status == NtVirtualMemoryEventStatus::kSuccess && result_base != nullptr &&
      event.target_process_id == static_cast<std::uint64_t>(GetCurrentProcessId())) {
    event.mapping_base = event.result_address;
    event.mapping_size = event.raw_result;
  }
}

#if defined(_MSC_VER)

[[nodiscard]] LONG record_allocate_exception_filter(
    EXCEPTION_POINTERS* exception_pointers, ReplacementRoute route, NtMemoryHookState* hook_state,
    bool guard_entered, HookEntryKind entry_kind, bool original_completed, HANDLE process,
    PVOID requested_base, SIZE_T requested_size, ULONG_PTR zero_bits, ULONG allocation_type,
    ULONG protect) noexcept;

[[nodiscard]] LONG record_free_exception_filter(EXCEPTION_POINTERS* exception_pointers,
                                                ReplacementRoute route,
                                                NtMemoryHookState* hook_state, bool guard_entered,
                                                HookEntryKind entry_kind, bool original_completed,
                                                HANDLE process, PVOID requested_base,
                                                SIZE_T requested_size, ULONG free_type) noexcept;

[[nodiscard]] LONG record_map_exception_filter(
    EXCEPTION_POINTERS* exception_pointers, ReplacementRoute route, NtMemoryHookState* hook_state,
    bool guard_entered, HookEntryKind entry_kind, bool original_completed, HANDLE section,
    HANDLE process, PVOID requested_base, SIZE_T requested_view_size, ULONG_PTR zero_bits,
    SIZE_T commit_size, std::uint64_t section_offset, ULONG inherit_disposition,
    ULONG allocation_type, ULONG protect) noexcept;

[[nodiscard]] LONG record_unmap_exception_filter(EXCEPTION_POINTERS* exception_pointers,
                                                 ReplacementRoute route,
                                                 NtMemoryHookState* hook_state, bool guard_entered,
                                                 HookEntryKind entry_kind, bool original_completed,
                                                 HANDLE process, PVOID base_address,
                                                 ULONG flags) noexcept;

#endif

NTSTATUS NTAPI replacement_nt_allocate_virtual_memory(HANDLE process, PVOID* base_address,
                                                      ULONG_PTR zero_bits, PSIZE_T region_size,
                                                      ULONG allocation_type,
                                                      ULONG protect) noexcept;
NTSTATUS NTAPI replacement_nt_free_virtual_memory(HANDLE process, PVOID* base_address,
                                                  PSIZE_T region_size, ULONG free_type) noexcept;
NTSTATUS NTAPI replacement_nt_map_view_of_section(HANDLE section, HANDLE process,
                                                  PVOID* base_address, ULONG_PTR zero_bits,
                                                  SIZE_T commit_size, PLARGE_INTEGER section_offset,
                                                  PSIZE_T view_size, ULONG inherit_disposition,
                                                  ULONG allocation_type, ULONG protect) noexcept;
NTSTATUS NTAPI replacement_nt_unmap_view_of_section(HANDLE process, PVOID base_address) noexcept;
NTSTATUS NTAPI replacement_nt_unmap_view_of_section_ex(HANDLE process, PVOID base_address,
                                                       ULONG flags) noexcept;

[[nodiscard]] void* allocate_replacement_address() noexcept {
  return reinterpret_cast<void*>(&replacement_nt_allocate_virtual_memory);
}

[[nodiscard]] void* free_replacement_address() noexcept {
  return reinterpret_cast<void*>(&replacement_nt_free_virtual_memory);
}

[[nodiscard]] void* map_replacement_address() noexcept {
  return reinterpret_cast<void*>(&replacement_nt_map_view_of_section);
}

[[nodiscard]] void* unmap_replacement_address() noexcept {
  return reinterpret_cast<void*>(&replacement_nt_unmap_view_of_section);
}

[[nodiscard]] void* unmap_ex_replacement_address() noexcept {
  return reinterpret_cast<void*>(&replacement_nt_unmap_view_of_section_ex);
}

[[nodiscard]] bool pin_replacement_module() noexcept {
  if (replacement_module_pinned.load(std::memory_order_acquire)) {
    return true;
  }
  HMODULE module = nullptr;
  const DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN;
  if (GetModuleHandleExW(flags, reinterpret_cast<LPCWSTR>(allocate_replacement_address()),
                         &module) == FALSE) {
    return false;
  }
  replacement_module_pinned.store(true, std::memory_order_release);
  return true;
}

void release_owner(NtMemoryHooks* owner, bool clear_hook_state) noexcept {
  if (clear_hook_state) {
    active_hook_state.store(nullptr, std::memory_order_release);
  }
  NtMemoryHooks* expected = owner;
  static_cast<void>(active_owner.compare_exchange_strong(
      expected, nullptr, std::memory_order_release, std::memory_order_relaxed));
}

[[nodiscard]] NtMemoryHookStatistics snapshot(const ApiHookState& api) noexcept {
  return NtMemoryHookStatistics{
      api.replacement_calls.load(std::memory_order_relaxed),
      api.recordable_calls.load(std::memory_order_relaxed),
      api.recursive_calls.load(std::memory_order_relaxed),
      api.internal_calls.load(std::memory_order_relaxed),
      api.successful_calls.load(std::memory_order_relaxed),
      api.failed_calls.load(std::memory_order_relaxed),
      api.exceptional_calls.load(std::memory_order_relaxed),
      api.filtered_calls.load(std::memory_order_relaxed),
      api.dropped_events.load(std::memory_order_relaxed),
  };
}

}  // namespace

struct NtMemoryHookState final {
  explicit NtMemoryHookState(std::size_t event_queue_capacity)
      : owned_event_queue{std::make_unique<NtVirtualMemoryEventQueue>(event_queue_capacity)},
        event_queue{owned_event_queue.get()} {}

  explicit NtMemoryHookState(NtVirtualMemoryEventQueue& shared_event_queue)
      : event_queue{&shared_event_queue} {}

  void reset_quiescent(std::uint16_t stack_depth) noexcept {
    allocate.reset_quiescent();
    free.reset_quiescent();
    map.reset_quiescent();
    unmap.reset_quiescent();
    unmap_ex_original_trampoline.store(nullptr, std::memory_order_relaxed);
    maximum_stack_depth = stack_depth;
    if (owned_event_queue != nullptr) {
      owned_event_queue->reset_quiescent();
    }
  }

  std::unique_ptr<NtVirtualMemoryEventQueue> owned_event_queue;
  NtVirtualMemoryEventQueue* event_queue{nullptr};
  ApiHookState allocate;
  ApiHookState free;
  ApiHookState map;
  ApiHookState unmap;
  std::atomic<void*> unmap_ex_original_trampoline{nullptr};
  std::uint16_t maximum_stack_depth{kMaximumCapturedStackDepth};
  std::uint64_t minimum_capture_size{0U};
};

namespace {

#if defined(_MSC_VER)

LONG record_allocate_exception_filter(EXCEPTION_POINTERS* exception_pointers,
                                      ReplacementRoute route, NtMemoryHookState* hook_state,
                                      bool guard_entered, HookEntryKind entry_kind,
                                      bool original_completed, HANDLE process, PVOID requested_base,
                                      SIZE_T requested_size, ULONG_PTR zero_bits,
                                      ULONG allocation_type, ULONG protect) noexcept {
  const DWORD preserved_last_error = GetLastError();
  if (route == ReplacementRoute::kRecord && hook_state != nullptr && guard_entered &&
      entry_kind == HookEntryKind::kOutermost && !original_completed &&
      exception_pointers != nullptr && exception_pointers->ExceptionRecord != nullptr) {
    hook_state->allocate.failed_calls.fetch_add(1U, std::memory_order_relaxed);
    hook_state->allocate.exceptional_calls.fetch_add(1U, std::memory_order_relaxed);
    if (static_cast<std::uint64_t>(requested_size) < hook_state->minimum_capture_size) {
      increment_saturating(hook_state->allocate.filtered_calls);
      SetLastError(preserved_last_error);
      return EXCEPTION_CONTINUE_SEARCH;
    }
    const std::uint32_t exception_status = exception_pointers->ExceptionRecord->ExceptionCode;
    const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
    const bool queued = hook_state->event_queue->try_emplace(
        [=](NtVirtualMemoryEvent& event, std::uint64_t queue_sequence) noexcept {
          fill_vm_event(event, queue_sequence, RtlHeapEventOperation::kVmAllocate, process,
                        requested_base, nullptr, requested_size, 0U, zero_bits, allocation_type,
                        protect, 0, NtVirtualMemoryEventStatus::kException, exception_status,
                        maximum_stack_depth);
        });
    if (!queued) {
      increment_saturating(hook_state->allocate.dropped_events);
    }
  }
  SetLastError(preserved_last_error);
  return EXCEPTION_CONTINUE_SEARCH;
}

LONG record_free_exception_filter(EXCEPTION_POINTERS* exception_pointers, ReplacementRoute route,
                                  NtMemoryHookState* hook_state, bool guard_entered,
                                  HookEntryKind entry_kind, bool original_completed, HANDLE process,
                                  PVOID requested_base, SIZE_T requested_size,
                                  ULONG free_type) noexcept {
  const DWORD preserved_last_error = GetLastError();
  if (route == ReplacementRoute::kRecord && hook_state != nullptr && guard_entered &&
      entry_kind == HookEntryKind::kOutermost && !original_completed &&
      exception_pointers != nullptr && exception_pointers->ExceptionRecord != nullptr) {
    hook_state->free.failed_calls.fetch_add(1U, std::memory_order_relaxed);
    hook_state->free.exceptional_calls.fetch_add(1U, std::memory_order_relaxed);
    const std::uint32_t exception_status = exception_pointers->ExceptionRecord->ExceptionCode;
    const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
    const bool queued = hook_state->event_queue->try_emplace(
        [=](NtVirtualMemoryEvent& event, std::uint64_t queue_sequence) noexcept {
          fill_vm_event(event, queue_sequence, RtlHeapEventOperation::kVmFree, process,
                        requested_base, nullptr, requested_size, 0U, 0U, free_type, 0U, 0,
                        NtVirtualMemoryEventStatus::kException, exception_status,
                        maximum_stack_depth);
        });
    if (!queued) {
      increment_saturating(hook_state->free.dropped_events);
    }
  }
  SetLastError(preserved_last_error);
  return EXCEPTION_CONTINUE_SEARCH;
}

LONG record_map_exception_filter(EXCEPTION_POINTERS* exception_pointers, ReplacementRoute route,
                                 NtMemoryHookState* hook_state, bool guard_entered,
                                 HookEntryKind entry_kind, bool original_completed, HANDLE section,
                                 HANDLE process, PVOID requested_base, SIZE_T requested_view_size,
                                 ULONG_PTR zero_bits, SIZE_T commit_size,
                                 std::uint64_t section_offset, ULONG inherit_disposition,
                                 ULONG allocation_type, ULONG protect) noexcept {
  const DWORD preserved_last_error = GetLastError();
  if (route == ReplacementRoute::kRecord && hook_state != nullptr && guard_entered &&
      entry_kind == HookEntryKind::kOutermost && !original_completed &&
      exception_pointers != nullptr && exception_pointers->ExceptionRecord != nullptr) {
    hook_state->map.failed_calls.fetch_add(1U, std::memory_order_relaxed);
    hook_state->map.exceptional_calls.fetch_add(1U, std::memory_order_relaxed);
    if (static_cast<std::uint64_t>(requested_view_size) < hook_state->minimum_capture_size) {
      increment_saturating(hook_state->map.filtered_calls);
      SetLastError(preserved_last_error);
      return EXCEPTION_CONTINUE_SEARCH;
    }
    const std::uint32_t exception_status = exception_pointers->ExceptionRecord->ExceptionCode;
    const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
    const bool queued = hook_state->event_queue->try_emplace(
        [=](NtVirtualMemoryEvent& event, std::uint64_t queue_sequence) noexcept {
          fill_section_event(event, queue_sequence, RtlHeapEventOperation::kSectionMap, section,
                             process, requested_base, nullptr, requested_view_size, 0U, zero_bits,
                             commit_size, section_offset, inherit_disposition, allocation_type,
                             protect, 0, NtVirtualMemoryEventStatus::kException, exception_status,
                             maximum_stack_depth);
        });
    if (!queued) {
      increment_saturating(hook_state->map.dropped_events);
    }
  }
  SetLastError(preserved_last_error);
  return EXCEPTION_CONTINUE_SEARCH;
}

LONG record_unmap_exception_filter(EXCEPTION_POINTERS* exception_pointers, ReplacementRoute route,
                                   NtMemoryHookState* hook_state, bool guard_entered,
                                   HookEntryKind entry_kind, bool original_completed,
                                   HANDLE process, PVOID base_address, ULONG flags) noexcept {
  const DWORD preserved_last_error = GetLastError();
  if (route == ReplacementRoute::kRecord && hook_state != nullptr && guard_entered &&
      entry_kind == HookEntryKind::kOutermost && !original_completed &&
      exception_pointers != nullptr && exception_pointers->ExceptionRecord != nullptr) {
    hook_state->unmap.failed_calls.fetch_add(1U, std::memory_order_relaxed);
    hook_state->unmap.exceptional_calls.fetch_add(1U, std::memory_order_relaxed);
    const std::uint32_t exception_status = exception_pointers->ExceptionRecord->ExceptionCode;
    const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
    const bool queued = hook_state->event_queue->try_emplace(
        [=](NtVirtualMemoryEvent& event, std::uint64_t queue_sequence) noexcept {
          fill_section_event(event, queue_sequence, RtlHeapEventOperation::kSectionUnmap, nullptr,
                             process, base_address, nullptr, 0U, 0U, 0U, 0U, 0U, 0U, flags, 0U, 0,
                             NtVirtualMemoryEventStatus::kException, exception_status,
                             maximum_stack_depth);
        });
    if (!queued) {
      increment_saturating(hook_state->unmap.dropped_events);
    }
  }
  SetLastError(preserved_last_error);
  return EXCEPTION_CONTINUE_SEARCH;
}

#endif

NTSTATUS NTAPI replacement_nt_allocate_virtual_memory(HANDLE process, PVOID* base_address,
                                                      ULONG_PTR zero_bits, PSIZE_T region_size,
                                                      ULONG allocation_type,
                                                      ULONG protect) noexcept {
  const ReplacementRoute route = allocate_replacement_lifecycle.enter_unscoped();
  NtMemoryHookState* hook_state = nullptr;
  NtAllocateVirtualMemoryFunction original = nullptr;
  HookEntryKind entry_kind = HookEntryKind::kRecursive;
  NTSTATUS result = 0;
  DWORD original_last_error = ERROR_SUCCESS;
  PVOID requested_base = nullptr;
  SIZE_T requested_size = 0U;
  PVOID result_base = nullptr;
  SIZE_T result_size = 0U;
  bool guard_entered = false;
  bool original_completed = false;

#if defined(_MSC_VER)
  __try {
    __try {
#endif
      if (route == ReplacementRoute::kTarget) {
        result = load_allocate_function(restored_allocate_target)(
            process, base_address, zero_bits, region_size, allocation_type, protect);
        original_completed = true;
      } else {
        hook_state = active_hook_state.load(std::memory_order_acquire);
        if (hook_state == nullptr) {
          fail_broken_replacement_route();
        }
        original = load_allocate_function(hook_state->allocate.original_trampoline);
        if (route == ReplacementRoute::kOriginal) {
          result =
              original(process, base_address, zero_bits, region_size, allocation_type, protect);
          original_completed = true;
        } else {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          classify_entry(hook_state->allocate, entry_kind);
          if (entry_kind == HookEntryKind::kOutermost) {
            static_cast<void>(safely_read(base_address, requested_base));
            static_cast<void>(safely_read(region_size, requested_size));
          }

          result =
              original(process, base_address, zero_bits, region_size, allocation_type, protect);
          original_last_error = GetLastError();
          original_completed = true;

          if (entry_kind == HookEntryKind::kOutermost) {
            static_cast<void>(safely_read(base_address, result_base));
            static_cast<void>(safely_read(region_size, result_size));
            (nt_success(result) ? hook_state->allocate.successful_calls
                                : hook_state->allocate.failed_calls)
                .fetch_add(1U, std::memory_order_relaxed);
            const std::uint64_t filter_size = static_cast<std::uint64_t>(
                nt_success(result) && result_size != 0U ? result_size : requested_size);
            if (filter_size < hook_state->minimum_capture_size) {
              increment_saturating(hook_state->allocate.filtered_calls);
            } else {
              const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
              const bool queued = hook_state->event_queue->try_emplace(
                  [=](NtVirtualMemoryEvent& event, std::uint64_t queue_sequence) noexcept {
                    fill_vm_event(event, queue_sequence, RtlHeapEventOperation::kVmAllocate,
                                  process, requested_base, result_base, requested_size, result_size,
                                  zero_bits, allocation_type, protect, result,
                                  nt_success(result) ? NtVirtualMemoryEventStatus::kSuccess
                                                     : NtVirtualMemoryEventStatus::kFailure,
                                  0U, maximum_stack_depth);
                  });
              if (!queued) {
                increment_saturating(hook_state->allocate.dropped_events);
              }
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
      allocate_replacement_lifecycle.leave_unscoped(route);
    }
  } __except (record_allocate_exception_filter(
      GetExceptionInformation(), route, hook_state, guard_entered, entry_kind, original_completed,
      process, requested_base, requested_size, zero_bits, allocation_type, protect)) {
    fail_broken_replacement_route();
  }
#else
  if (guard_entered) {
    leave_hook_invocation_unscoped();
  }
  allocate_replacement_lifecycle.leave_unscoped(route);
#endif
  return result;
}

NTSTATUS NTAPI replacement_nt_free_virtual_memory(HANDLE process, PVOID* base_address,
                                                  PSIZE_T region_size, ULONG free_type) noexcept {
  const ReplacementRoute route = free_replacement_lifecycle.enter_unscoped();
  NtMemoryHookState* hook_state = nullptr;
  NtFreeVirtualMemoryFunction original = nullptr;
  HookEntryKind entry_kind = HookEntryKind::kRecursive;
  NTSTATUS result = 0;
  DWORD original_last_error = ERROR_SUCCESS;
  PVOID requested_base = nullptr;
  SIZE_T requested_size = 0U;
  PVOID result_base = nullptr;
  SIZE_T result_size = 0U;
  bool guard_entered = false;
  bool original_completed = false;

#if defined(_MSC_VER)
  __try {
    __try {
#endif
      if (route == ReplacementRoute::kTarget) {
        result =
            load_free_function(restored_free_target)(process, base_address, region_size, free_type);
        original_completed = true;
      } else {
        hook_state = active_hook_state.load(std::memory_order_acquire);
        if (hook_state == nullptr) {
          fail_broken_replacement_route();
        }
        original = load_free_function(hook_state->free.original_trampoline);
        if (route == ReplacementRoute::kOriginal) {
          result = original(process, base_address, region_size, free_type);
          original_completed = true;
        } else {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          classify_entry(hook_state->free, entry_kind);
          if (entry_kind == HookEntryKind::kOutermost) {
            static_cast<void>(safely_read(base_address, requested_base));
            static_cast<void>(safely_read(region_size, requested_size));
          }

          result = original(process, base_address, region_size, free_type);
          original_last_error = GetLastError();
          original_completed = true;

          if (entry_kind == HookEntryKind::kOutermost) {
            static_cast<void>(safely_read(base_address, result_base));
            static_cast<void>(safely_read(region_size, result_size));
            (nt_success(result) ? hook_state->free.successful_calls : hook_state->free.failed_calls)
                .fetch_add(1U, std::memory_order_relaxed);
            const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
            const bool queued = hook_state->event_queue->try_emplace(
                [=](NtVirtualMemoryEvent& event, std::uint64_t queue_sequence) noexcept {
                  fill_vm_event(event, queue_sequence, RtlHeapEventOperation::kVmFree, process,
                                requested_base, result_base, requested_size, result_size, 0U,
                                free_type, 0U, result,
                                nt_success(result) ? NtVirtualMemoryEventStatus::kSuccess
                                                   : NtVirtualMemoryEventStatus::kFailure,
                                0U, maximum_stack_depth);
                });
            if (!queued) {
              increment_saturating(hook_state->free.dropped_events);
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
      free_replacement_lifecycle.leave_unscoped(route);
    }
  } __except (record_free_exception_filter(GetExceptionInformation(), route, hook_state,
                                           guard_entered, entry_kind, original_completed, process,
                                           requested_base, requested_size, free_type)) {
    fail_broken_replacement_route();
  }
#else
  if (guard_entered) {
    leave_hook_invocation_unscoped();
  }
  free_replacement_lifecycle.leave_unscoped(route);
#endif
  return result;
}

NTSTATUS NTAPI replacement_nt_map_view_of_section(HANDLE section, HANDLE process,
                                                  PVOID* base_address, ULONG_PTR zero_bits,
                                                  SIZE_T commit_size, PLARGE_INTEGER section_offset,
                                                  PSIZE_T view_size, ULONG inherit_disposition,
                                                  ULONG allocation_type, ULONG protect) noexcept {
  const ReplacementRoute route = map_replacement_lifecycle.enter_unscoped();
  NtMemoryHookState* hook_state = nullptr;
  NtMapViewOfSectionFunction original = nullptr;
  HookEntryKind entry_kind = HookEntryKind::kRecursive;
  NTSTATUS result = 0;
  DWORD original_last_error = ERROR_SUCCESS;
  PVOID requested_base = nullptr;
  SIZE_T requested_view_size = 0U;
  LARGE_INTEGER requested_section_offset{};
  PVOID result_base = nullptr;
  SIZE_T result_view_size = 0U;
  bool guard_entered = false;
  bool original_completed = false;

#if defined(_MSC_VER)
  __try {
    __try {
#endif
      if (route == ReplacementRoute::kTarget) {
        result = load_map_function(restored_map_target)(
            section, process, base_address, zero_bits, commit_size, section_offset, view_size,
            inherit_disposition, allocation_type, protect);
        original_completed = true;
      } else {
        hook_state = active_hook_state.load(std::memory_order_acquire);
        if (hook_state == nullptr) {
          fail_broken_replacement_route();
        }
        original = load_map_function(hook_state->map.original_trampoline);
        if (route == ReplacementRoute::kOriginal) {
          result = original(section, process, base_address, zero_bits, commit_size, section_offset,
                            view_size, inherit_disposition, allocation_type, protect);
          original_completed = true;
        } else {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          classify_entry(hook_state->map, entry_kind);
          if (entry_kind == HookEntryKind::kOutermost) {
            static_cast<void>(safely_read(base_address, requested_base));
            static_cast<void>(safely_read(view_size, requested_view_size));
            static_cast<void>(safely_read(section_offset, requested_section_offset));
          }

          result = original(section, process, base_address, zero_bits, commit_size, section_offset,
                            view_size, inherit_disposition, allocation_type, protect);
          original_last_error = GetLastError();
          original_completed = true;

          if (entry_kind == HookEntryKind::kOutermost) {
            static_cast<void>(safely_read(base_address, result_base));
            static_cast<void>(safely_read(view_size, result_view_size));
            (nt_success(result) ? hook_state->map.successful_calls : hook_state->map.failed_calls)
                .fetch_add(1U, std::memory_order_relaxed);
            const std::uint64_t filter_size = static_cast<std::uint64_t>(
                nt_success(result) && result_view_size != 0U ? result_view_size
                                                             : requested_view_size);
            if (filter_size < hook_state->minimum_capture_size) {
              increment_saturating(hook_state->map.filtered_calls);
            } else {
              const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
              const std::uint64_t raw_section_offset =
                  static_cast<std::uint64_t>(requested_section_offset.QuadPart);
              const bool queued = hook_state->event_queue->try_emplace(
                  [=](NtVirtualMemoryEvent& event, std::uint64_t queue_sequence) noexcept {
                    fill_section_event(event, queue_sequence, RtlHeapEventOperation::kSectionMap,
                                       section, process, requested_base, result_base,
                                       requested_view_size, result_view_size, zero_bits,
                                       commit_size, raw_section_offset, inherit_disposition,
                                       allocation_type, protect, result,
                                       nt_success(result) ? NtVirtualMemoryEventStatus::kSuccess
                                                          : NtVirtualMemoryEventStatus::kFailure,
                                       0U, maximum_stack_depth);
                  });
              if (!queued) {
                increment_saturating(hook_state->map.dropped_events);
              }
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
      map_replacement_lifecycle.leave_unscoped(route);
    }
  } __except (record_map_exception_filter(
      GetExceptionInformation(), route, hook_state, guard_entered, entry_kind, original_completed,
      section, process, requested_base, requested_view_size, zero_bits, commit_size,
      static_cast<std::uint64_t>(requested_section_offset.QuadPart), inherit_disposition,
      allocation_type, protect)) {
    fail_broken_replacement_route();
  }
#else
  if (guard_entered) {
    leave_hook_invocation_unscoped();
  }
  map_replacement_lifecycle.leave_unscoped(route);
#endif
  return result;
}

NTSTATUS NTAPI replacement_nt_unmap_view_of_section(HANDLE process, PVOID base_address) noexcept {
  const ReplacementRoute route = unmap_replacement_lifecycle.enter_unscoped();
  NtMemoryHookState* hook_state = nullptr;
  NtUnmapViewOfSectionFunction original = nullptr;
  HookEntryKind entry_kind = HookEntryKind::kRecursive;
  NTSTATUS result = 0;
  DWORD original_last_error = ERROR_SUCCESS;
  bool guard_entered = false;
  bool original_completed = false;

#if defined(_MSC_VER)
  __try {
    __try {
#endif
      if (route == ReplacementRoute::kTarget) {
        result = load_unmap_function(restored_unmap_target)(process, base_address);
        original_completed = true;
      } else {
        hook_state = active_hook_state.load(std::memory_order_acquire);
        if (hook_state == nullptr) {
          fail_broken_replacement_route();
        }
        original = load_unmap_function(hook_state->unmap.original_trampoline);
        if (route == ReplacementRoute::kOriginal) {
          result = original(process, base_address);
          original_completed = true;
        } else {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          classify_entry(hook_state->unmap, entry_kind);
          result = original(process, base_address);
          original_last_error = GetLastError();
          original_completed = true;

          if (entry_kind == HookEntryKind::kOutermost) {
            (nt_success(result) ? hook_state->unmap.successful_calls
                                : hook_state->unmap.failed_calls)
                .fetch_add(1U, std::memory_order_relaxed);
            const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
            const bool queued = hook_state->event_queue->try_emplace(
                [=](NtVirtualMemoryEvent& event, std::uint64_t queue_sequence) noexcept {
                  fill_section_event(event, queue_sequence, RtlHeapEventOperation::kSectionUnmap,
                                     nullptr, process, base_address, base_address, 0U, 0U, 0U, 0U,
                                     0U, 0U, 0U, 0U, result,
                                     nt_success(result) ? NtVirtualMemoryEventStatus::kSuccess
                                                        : NtVirtualMemoryEventStatus::kFailure,
                                     0U, maximum_stack_depth);
                });
            if (!queued) {
              increment_saturating(hook_state->unmap.dropped_events);
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
      unmap_replacement_lifecycle.leave_unscoped(route);
    }
  } __except (record_unmap_exception_filter(GetExceptionInformation(), route, hook_state,
                                            guard_entered, entry_kind, original_completed, process,
                                            base_address, 0U)) {
    fail_broken_replacement_route();
  }
#else
  if (guard_entered) {
    leave_hook_invocation_unscoped();
  }
  unmap_replacement_lifecycle.leave_unscoped(route);
#endif
  return result;
}

NTSTATUS NTAPI replacement_nt_unmap_view_of_section_ex(HANDLE process, PVOID base_address,
                                                       ULONG flags) noexcept {
  const ReplacementRoute route = unmap_replacement_lifecycle.enter_unscoped();
  NtMemoryHookState* hook_state = nullptr;
  NtUnmapViewOfSectionExFunction original = nullptr;
  HookEntryKind entry_kind = HookEntryKind::kRecursive;
  NTSTATUS result = 0;
  DWORD original_last_error = ERROR_SUCCESS;
  bool guard_entered = false;
  bool original_completed = false;

#if defined(_MSC_VER)
  __try {
    __try {
#endif
      if (route == ReplacementRoute::kTarget) {
        result = load_unmap_ex_function(restored_unmap_ex_target)(process, base_address, flags);
        original_completed = true;
      } else {
        hook_state = active_hook_state.load(std::memory_order_acquire);
        if (hook_state == nullptr) {
          fail_broken_replacement_route();
        }
        original = load_unmap_ex_function(hook_state->unmap_ex_original_trampoline);
        if (route == ReplacementRoute::kOriginal) {
          result = original(process, base_address, flags);
          original_completed = true;
        } else {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          classify_entry(hook_state->unmap, entry_kind);
          result = original(process, base_address, flags);
          original_last_error = GetLastError();
          original_completed = true;

          if (entry_kind == HookEntryKind::kOutermost) {
            (nt_success(result) ? hook_state->unmap.successful_calls
                                : hook_state->unmap.failed_calls)
                .fetch_add(1U, std::memory_order_relaxed);
            const std::uint16_t maximum_stack_depth = hook_state->maximum_stack_depth;
            const bool queued = hook_state->event_queue->try_emplace(
                [=](NtVirtualMemoryEvent& event, std::uint64_t queue_sequence) noexcept {
                  fill_section_event(event, queue_sequence, RtlHeapEventOperation::kSectionUnmap,
                                     nullptr, process, base_address, base_address, 0U, 0U, 0U, 0U,
                                     0U, 0U, flags, 0U, result,
                                     nt_success(result) ? NtVirtualMemoryEventStatus::kSuccess
                                                        : NtVirtualMemoryEventStatus::kFailure,
                                     0U, maximum_stack_depth);
                });
            if (!queued) {
              increment_saturating(hook_state->unmap.dropped_events);
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
      unmap_replacement_lifecycle.leave_unscoped(route);
    }
  } __except (record_unmap_exception_filter(GetExceptionInformation(), route, hook_state,
                                            guard_entered, entry_kind, original_completed, process,
                                            base_address, flags)) {
    fail_broken_replacement_route();
  }
#else
  if (guard_entered) {
    leave_hook_invocation_unscoped();
  }
  unmap_replacement_lifecycle.leave_unscoped(route);
#endif
  return result;
}

}  // namespace

NtMemoryHooks::NtMemoryHooks(HookBackend& backend, std::size_t event_queue_capacity,
                             std::uint16_t maximum_stack_depth, std::uint64_t minimum_capture_size)
    : hook_state_{std::make_unique<NtMemoryHookState>(event_queue_capacity)},
      backend_{&backend},
      maximum_stack_depth_{maximum_stack_depth},
      minimum_capture_size_{minimum_capture_size} {
  initialize();
}

NtMemoryHooks::NtMemoryHooks(HookBackend& backend, NtVirtualMemoryEventQueue& event_queue,
                             std::uint16_t maximum_stack_depth, std::uint64_t minimum_capture_size)
    : hook_state_{std::make_unique<NtMemoryHookState>(event_queue)},
      backend_{&backend},
      maximum_stack_depth_{maximum_stack_depth},
      minimum_capture_size_{minimum_capture_size} {
  initialize();
}

void NtMemoryHooks::initialize() {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    throw HookBackendError{"ntdll.dll is not loaded"};
  }
  allocate_target_ = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
  free_target_ = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtFreeVirtualMemory"));
  map_target_ = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtMapViewOfSection"));
  unmap_target_ = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtUnmapViewOfSection"));
  unmap_ex_target_ = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtUnmapViewOfSectionEx"));
  if (allocate_target_ == nullptr || free_target_ == nullptr || map_target_ == nullptr ||
      unmap_target_ == nullptr || unmap_ex_target_ == nullptr) {
    throw HookBackendError{"ntdll.dll does not export the NT memory API set"};
  }
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
  hook_state_->minimum_capture_size = minimum_capture_size_;
}

NtMemoryHooks::~NtMemoryHooks() {
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

NtMemoryHookInstallResult NtMemoryHooks::install() {
  const InternalThreadScope internal_thread;
  if (state_ == State::kInstalled) {
    return {{HookInstallStatus::kAlreadyInstalled,
             hook_state_->allocate.original_trampoline.load(std::memory_order_acquire)},
            {HookInstallStatus::kAlreadyInstalled,
             hook_state_->free.original_trampoline.load(std::memory_order_acquire)},
            {HookInstallStatus::kAlreadyInstalled,
             hook_state_->map.original_trampoline.load(std::memory_order_acquire)},
            {HookInstallStatus::kAlreadyInstalled,
             hook_state_->unmap.original_trampoline.load(std::memory_order_acquire)},
            {HookInstallStatus::kAlreadyInstalled,
             hook_state_->unmap_ex_original_trampoline.load(std::memory_order_acquire)}};
  }
  if (state_ == State::kTeardownPending) {
    return {{HookInstallStatus::kTeardownPending, nullptr},
            {HookInstallStatus::kTeardownPending, nullptr},
            {HookInstallStatus::kTeardownPending, nullptr},
            {HookInstallStatus::kTeardownPending, nullptr},
            {HookInstallStatus::kTeardownPending, nullptr}};
  }
  if (state_ == State::kRetired || installation_retired.load(std::memory_order_acquire)) {
    return {{HookInstallStatus::kBackendStopped, nullptr},
            {HookInstallStatus::kBackendStopped, nullptr},
            {HookInstallStatus::kBackendStopped, nullptr},
            {HookInstallStatus::kBackendStopped, nullptr},
            {HookInstallStatus::kBackendStopped, nullptr}};
  }

  NtMemoryHooks* expected = nullptr;
  if (!active_owner.compare_exchange_strong(expected, this, std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
    return {{HookInstallStatus::kAlreadyReplaced, nullptr},
            {HookInstallStatus::kAlreadyReplaced, nullptr},
            {HookInstallStatus::kAlreadyReplaced, nullptr},
            {HookInstallStatus::kAlreadyReplaced, nullptr},
            {HookInstallStatus::kAlreadyReplaced, nullptr}};
  }
  if (!pin_replacement_module()) {
    release_owner(this, true);
    throw HookBackendError{"the replacement module could not be pinned"};
  }

  hook_state_->reset_quiescent(maximum_stack_depth_);
  restored_allocate_target.store(allocate_target_, std::memory_order_release);
  restored_free_target.store(free_target_, std::memory_order_release);
  restored_map_target.store(map_target_, std::memory_order_release);
  restored_unmap_target.store(unmap_target_, std::memory_order_release);
  restored_unmap_ex_target.store(unmap_ex_target_, std::memory_order_release);
  active_hook_state.store(hook_state_.get(), std::memory_order_release);

  NtMemoryHookInstallResult result;
  allocate_replacement_lifecycle.start_recording();
  allocate_lifecycle_started_ = true;
  if (!backend_->acquire_trampoline_lifetime_lease()) {
    result.allocate = {HookInstallStatus::kBackendStopped, nullptr};
    result.free = {HookInstallStatus::kBackendStopped, nullptr};
    result.map = {HookInstallStatus::kBackendStopped, nullptr};
    result.unmap = {HookInstallStatus::kBackendStopped, nullptr};
    result.unmap_ex = {HookInstallStatus::kBackendStopped, nullptr};
    release_failed_initial_install();
    return result;
  }
  allocate_lease_acquired_ = true;
  try {
    result.allocate = backend_->install_fast(allocate_target_, allocate_replacement_address(),
                                             &hook_state_->allocate.original_trampoline);
  } catch (...) {
    release_failed_initial_install();
    throw;
  }
  if (!result.allocate.installed()) {
    release_failed_initial_install();
    return result;
  }

  allocate_hook_installed_ = true;
  installation_retired.store(true, std::memory_order_release);
  state_ = State::kInstalled;

  free_replacement_lifecycle.start_recording();
  free_lifecycle_started_ = true;
  if (!backend_->acquire_trampoline_lifetime_lease()) {
    result.free = {HookInstallStatus::kBackendStopped, nullptr};
    static_cast<void>(uninstall());
    return result;
  }
  free_lease_acquired_ = true;
  try {
    result.free = backend_->install_fast(free_target_, free_replacement_address(),
                                         &hook_state_->free.original_trampoline);
  } catch (...) {
    static_cast<void>(uninstall());
    throw;
  }
  if (!result.free.installed()) {
    static_cast<void>(uninstall());
    return result;
  }
  free_hook_installed_ = true;

  map_replacement_lifecycle.start_recording();
  map_lifecycle_started_ = true;
  if (!backend_->acquire_trampoline_lifetime_lease()) {
    result.map = {HookInstallStatus::kBackendStopped, nullptr};
    static_cast<void>(uninstall());
    return result;
  }
  map_lease_acquired_ = true;
  try {
    result.map = backend_->install_fast(map_target_, map_replacement_address(),
                                        &hook_state_->map.original_trampoline);
  } catch (...) {
    static_cast<void>(uninstall());
    throw;
  }
  if (!result.map.installed()) {
    static_cast<void>(uninstall());
    return result;
  }
  map_hook_installed_ = true;

  unmap_replacement_lifecycle.start_recording();
  unmap_lifecycle_started_ = true;
  if (!backend_->acquire_trampoline_lifetime_lease()) {
    result.unmap = {HookInstallStatus::kBackendStopped, nullptr};
    static_cast<void>(uninstall());
    return result;
  }
  unmap_lease_acquired_ = true;
  try {
    result.unmap = backend_->install_fast(unmap_target_, unmap_replacement_address(),
                                          &hook_state_->unmap.original_trampoline);
  } catch (...) {
    static_cast<void>(uninstall());
    throw;
  }
  if (!result.unmap.installed()) {
    static_cast<void>(uninstall());
    return result;
  }
  unmap_hook_installed_ = true;

  if (!backend_->acquire_trampoline_lifetime_lease()) {
    result.unmap_ex = {HookInstallStatus::kBackendStopped, nullptr};
    static_cast<void>(uninstall());
    return result;
  }
  unmap_ex_lease_acquired_ = true;
  try {
    result.unmap_ex = backend_->install_fast(unmap_ex_target_, unmap_ex_replacement_address(),
                                             &hook_state_->unmap_ex_original_trampoline);
  } catch (...) {
    static_cast<void>(uninstall());
    throw;
  }
  if (!result.unmap_ex.installed()) {
    static_cast<void>(uninstall());
    return result;
  }
  unmap_ex_hook_installed_ = true;
  return result;
}

void NtMemoryHooks::release_failed_initial_install() noexcept {
  allocate_replacement_lifecycle.route_to_target();
  free_replacement_lifecycle.route_to_target();
  map_replacement_lifecycle.route_to_target();
  unmap_replacement_lifecycle.route_to_target();
  if (allocate_lease_acquired_) {
    backend_->release_trampoline_lifetime_lease();
    allocate_lease_acquired_ = false;
  }
  if (free_lease_acquired_) {
    backend_->release_trampoline_lifetime_lease();
    free_lease_acquired_ = false;
  }
  if (map_lease_acquired_) {
    backend_->release_trampoline_lifetime_lease();
    map_lease_acquired_ = false;
  }
  if (unmap_lease_acquired_) {
    backend_->release_trampoline_lifetime_lease();
    unmap_lease_acquired_ = false;
  }
  if (unmap_ex_lease_acquired_) {
    backend_->release_trampoline_lifetime_lease();
    unmap_ex_lease_acquired_ = false;
  }
  allocate_lifecycle_started_ = false;
  free_lifecycle_started_ = false;
  map_lifecycle_started_ = false;
  unmap_lifecycle_started_ = false;
  release_owner(this, true);
}

bool NtMemoryHooks::uninstall(std::uint32_t flush_attempts) noexcept {
  const InternalThreadScope internal_thread;
  if (state_ == State::kInactive || state_ == State::kRetired) {
    return true;
  }
  if (state_ == State::kTeardownPending) {
    return try_finish_teardown(flush_attempts);
  }

  if (allocate_lifecycle_started_) {
    allocate_replacement_lifecycle.stop_recording();
  }
  if (free_lifecycle_started_) {
    free_replacement_lifecycle.stop_recording();
  }
  if (map_lifecycle_started_) {
    map_replacement_lifecycle.stop_recording();
  }
  if (unmap_lifecycle_started_) {
    unmap_replacement_lifecycle.stop_recording();
  }
  state_ = State::kTeardownPending;

  HookUninstallStatus allocate_status = HookUninstallStatus::kNotInstalled;
  HookUninstallStatus free_status = HookUninstallStatus::kNotInstalled;
  HookUninstallStatus map_status = HookUninstallStatus::kNotInstalled;
  HookUninstallStatus unmap_status = HookUninstallStatus::kNotInstalled;
  HookUninstallStatus unmap_ex_status = HookUninstallStatus::kNotInstalled;
  if (allocate_hook_installed_) {
    allocate_status = backend_->uninstall(allocate_target_, 0U);
  }
  if (free_hook_installed_) {
    free_status = backend_->uninstall(free_target_, 0U);
  }
  if (map_hook_installed_) {
    map_status = backend_->uninstall(map_target_, 0U);
  }
  if (unmap_hook_installed_) {
    unmap_status = backend_->uninstall(unmap_target_, 0U);
  }
  if (unmap_ex_hook_installed_) {
    unmap_ex_status = backend_->uninstall(unmap_ex_target_, 0U);
  }
  allocate_replacement_lifecycle.route_to_target();
  free_replacement_lifecycle.route_to_target();
  map_replacement_lifecycle.route_to_target();
  unmap_replacement_lifecycle.route_to_target();
  const auto finished = [](HookUninstallStatus status) {
    return status == HookUninstallStatus::kUninstalled ||
           status == HookUninstallStatus::kNotInstalled;
  };
  backend_teardown_complete_ = finished(allocate_status) && finished(free_status) &&
                               finished(map_status) && finished(unmap_status) &&
                               finished(unmap_ex_status);
  return try_finish_teardown(flush_attempts);
}

bool NtMemoryHooks::flush(std::uint32_t max_attempts) noexcept {
  if (state_ == State::kInactive || state_ == State::kRetired) {
    return true;
  }
  if (state_ == State::kInstalled) {
    return false;
  }
  return try_finish_teardown(max_attempts);
}

bool NtMemoryHooks::stop_recording(std::uint32_t max_attempts) noexcept {
  if (state_ != State::kInstalled) {
    return state_ == State::kInactive || state_ == State::kRetired;
  }
  allocate_replacement_lifecycle.stop_recording();
  free_replacement_lifecycle.stop_recording();
  map_replacement_lifecycle.stop_recording();
  unmap_replacement_lifecycle.stop_recording();
  const bool allocate_done =
      allocate_replacement_lifecycle.wait_for_recording_quiescence(max_attempts);
  const bool free_done = free_replacement_lifecycle.wait_for_recording_quiescence(max_attempts);
  const bool map_done = map_replacement_lifecycle.wait_for_recording_quiescence(max_attempts);
  const bool unmap_done = unmap_replacement_lifecycle.wait_for_recording_quiescence(max_attempts);
  return allocate_done && free_done && map_done && unmap_done;
}

bool NtMemoryHooks::try_finish_teardown(std::uint32_t max_attempts) noexcept {
  if (!allocate_replacement_quiescent_) {
    if (allocate_lifecycle_started_ &&
        !allocate_replacement_lifecycle.wait_for_quiescence(max_attempts)) {
      return false;
    }
    allocate_replacement_quiescent_ = true;
    if (allocate_lease_acquired_) {
      backend_->release_trampoline_lifetime_lease();
      allocate_lease_acquired_ = false;
    }
  }
  if (!free_replacement_quiescent_) {
    if (free_lifecycle_started_ && !free_replacement_lifecycle.wait_for_quiescence(max_attempts)) {
      return false;
    }
    free_replacement_quiescent_ = true;
    if (free_lease_acquired_) {
      backend_->release_trampoline_lifetime_lease();
      free_lease_acquired_ = false;
    }
  }
  if (!map_replacement_quiescent_) {
    if (map_lifecycle_started_ && !map_replacement_lifecycle.wait_for_quiescence(max_attempts)) {
      return false;
    }
    map_replacement_quiescent_ = true;
    if (map_lease_acquired_) {
      backend_->release_trampoline_lifetime_lease();
      map_lease_acquired_ = false;
    }
  }
  if (!unmap_replacement_quiescent_) {
    if (unmap_lifecycle_started_ &&
        !unmap_replacement_lifecycle.wait_for_quiescence(max_attempts)) {
      return false;
    }
    unmap_replacement_quiescent_ = true;
    if (unmap_lease_acquired_) {
      backend_->release_trampoline_lifetime_lease();
      unmap_lease_acquired_ = false;
    }
    if (unmap_ex_lease_acquired_) {
      backend_->release_trampoline_lifetime_lease();
      unmap_ex_lease_acquired_ = false;
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

void NtMemoryHooks::finish_teardown() noexcept {
  hook_state_->allocate.original_trampoline.store(nullptr, std::memory_order_release);
  hook_state_->free.original_trampoline.store(nullptr, std::memory_order_release);
  hook_state_->map.original_trampoline.store(nullptr, std::memory_order_release);
  hook_state_->unmap.original_trampoline.store(nullptr, std::memory_order_release);
  hook_state_->unmap_ex_original_trampoline.store(nullptr, std::memory_order_release);
  allocate_hook_installed_ = false;
  free_hook_installed_ = false;
  map_hook_installed_ = false;
  unmap_hook_installed_ = false;
  unmap_ex_hook_installed_ = false;
  state_ = State::kRetired;
  release_owner(this, true);
}

void NtMemoryHooks::abandon_pending_teardown() noexcept {
  allocate_replacement_lifecycle.route_to_target();
  free_replacement_lifecycle.route_to_target();
  map_replacement_lifecycle.route_to_target();
  unmap_replacement_lifecycle.route_to_target();
  if (allocate_lease_acquired_ || free_lease_acquired_ || map_lease_acquired_ ||
      unmap_lease_acquired_ || unmap_ex_lease_acquired_) {
    static_cast<void>(hook_state_.release());
    guard_runtime_acquired_ = false;
    release_owner(this, false);
  } else {
    release_owner(this, true);
  }
  state_ = State::kRetired;
}

bool NtMemoryHooks::is_installed() const noexcept { return state_ == State::kInstalled; }

bool NtMemoryHooks::is_recording() const noexcept {
  return state_ == State::kInstalled &&
         (allocate_replacement_lifecycle.route() == ReplacementRoute::kRecord ||
          free_replacement_lifecycle.route() == ReplacementRoute::kRecord ||
          map_replacement_lifecycle.route() == ReplacementRoute::kRecord ||
          unmap_replacement_lifecycle.route() == ReplacementRoute::kRecord);
}

std::uint64_t NtMemoryHooks::recording_in_flight_count() const noexcept {
  std::uint64_t total = allocate_replacement_lifecycle.recording_in_flight();
  const auto add_saturating = [&total](std::uint64_t value) {
    total = value > std::numeric_limits<std::uint64_t>::max() - total
                ? std::numeric_limits<std::uint64_t>::max()
                : total + value;
  };
  add_saturating(free_replacement_lifecycle.recording_in_flight());
  add_saturating(map_replacement_lifecycle.recording_in_flight());
  add_saturating(unmap_replacement_lifecycle.recording_in_flight());
  return total;
}

bool NtMemoryHooks::has_pending_teardown() const noexcept {
  return state_ == State::kTeardownPending;
}

bool NtMemoryHooks::replacement_module_is_pinned() const noexcept {
  return replacement_module_pinned.load(std::memory_order_acquire);
}

std::uint64_t NtMemoryHooks::replacement_in_flight_count() const noexcept {
  const std::uint64_t allocate = allocate_replacement_lifecycle.in_flight();
  const std::uint64_t free = free_replacement_lifecycle.in_flight();
  const std::uint64_t map = map_replacement_lifecycle.in_flight();
  const std::uint64_t unmap = unmap_replacement_lifecycle.in_flight();
  if (free > std::numeric_limits<std::uint64_t>::max() - allocate) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  const std::uint64_t virtual_memory = allocate + free;
  if (map > std::numeric_limits<std::uint64_t>::max() - virtual_memory) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  const std::uint64_t with_map = virtual_memory + map;
  if (unmap > std::numeric_limits<std::uint64_t>::max() - with_map) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return with_map + unmap;
}

NtMemoryHookStatistics NtMemoryHooks::allocate_statistics() const noexcept {
  return snapshot(hook_state_->allocate);
}

NtMemoryHookStatistics NtMemoryHooks::free_statistics() const noexcept {
  return snapshot(hook_state_->free);
}

NtMemoryHookStatistics NtMemoryHooks::map_statistics() const noexcept {
  return snapshot(hook_state_->map);
}

NtMemoryHookStatistics NtMemoryHooks::unmap_statistics() const noexcept {
  return snapshot(hook_state_->unmap);
}

std::uint64_t NtMemoryHooks::take_allocate_dropped_event_count() noexcept {
  return hook_state_->allocate.dropped_events.exchange(0U, std::memory_order_relaxed);
}

std::uint64_t NtMemoryHooks::take_free_dropped_event_count() noexcept {
  return hook_state_->free.dropped_events.exchange(0U, std::memory_order_relaxed);
}

std::uint64_t NtMemoryHooks::take_map_dropped_event_count() noexcept {
  return hook_state_->map.dropped_events.exchange(0U, std::memory_order_relaxed);
}

std::uint64_t NtMemoryHooks::take_unmap_dropped_event_count() noexcept {
  return hook_state_->unmap.dropped_events.exchange(0U, std::memory_order_relaxed);
}

std::size_t NtMemoryHooks::event_queue_capacity() const noexcept {
  return hook_state_->event_queue->capacity();
}

std::uint16_t NtMemoryHooks::maximum_stack_depth() const noexcept { return maximum_stack_depth_; }

std::uint64_t NtMemoryHooks::minimum_capture_size() const noexcept { return minimum_capture_size_; }

bool NtMemoryHooks::try_dequeue_event(NtVirtualMemoryEvent& event) noexcept {
  return hook_state_->event_queue->try_pop(event);
}

NtVirtualMemoryEventQueue& NtMemoryHooks::event_queue() noexcept {
  return *hook_state_->event_queue;
}

const NtVirtualMemoryEventQueue& NtMemoryHooks::event_queue() const noexcept {
  return *hook_state_->event_queue;
}

void* NtMemoryHooks::allocate_target_address() const noexcept { return allocate_target_; }

void* NtMemoryHooks::free_target_address() const noexcept { return free_target_; }

void* NtMemoryHooks::map_target_address() const noexcept { return map_target_; }

void* NtMemoryHooks::unmap_target_address() const noexcept { return unmap_target_; }

void* NtMemoryHooks::unmap_ex_target_address() const noexcept { return unmap_ex_target_; }

}  // namespace noleax::agent::windows
