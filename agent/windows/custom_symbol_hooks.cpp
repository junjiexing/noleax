#include "noleax/agent/windows/custom_symbol_hooks.hpp"

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/patch_rendezvous.hpp"
#include "noleax/agent/replacement_lifecycle.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace noleax::agent::windows {
namespace {

inline constexpr std::size_t kPoolSize = CustomSymbolHooks::kMaximumHookPoints;
inline constexpr std::uint8_t kNoArgumentSlot = 0xFFU;
inline constexpr auto kModulePollInterval = std::chrono::milliseconds{100};

using noleax::trace::CustomHookFailure;
using noleax::trace::CustomHookFailureReason;
using noleax::trace::CustomHookFailureRole;

[[nodiscard]] constexpr const char* custom_hook_role_name(CustomHookFailureRole role) noexcept {
  switch (role) {
    case CustomHookFailureRole::kAlloc:
      return "alloc";
    case CustomHookFailureRole::kRealloc:
      return "realloc";
    case CustomHookFailureRole::kFree:
      return "free";
    case CustomHookFailureRole::kPoint:
      return "point";
  }
  return "unknown";
}

// Per-point descriptor block shared between the control path and the generic replacements:
// routing state, original trampolines, argument mapping, queue, and accounting. One code copy
// per role reads its context from the slot bound to its thunk at install time.
struct CustomHookSlot {
  ReplacementLifecycle lifecycle;
  OriginalTrampolineSlot alloc_trampoline{nullptr};
  OriginalTrampolineSlot realloc_trampoline{nullptr};
  OriginalTrampolineSlot free_trampoline{nullptr};
  std::atomic<void*> alloc_restored_target{nullptr};
  std::atomic<void*> realloc_restored_target{nullptr};
  std::atomic<void*> free_restored_target{nullptr};
  RtlHeapEventQueue* event_queue{nullptr};
  std::uint32_t api_id{0U};
  std::uint8_t alloc_size_arg{0U};
  std::uint8_t alloc_count_arg{kNoArgumentSlot};
  std::uint8_t realloc_ptr_arg{0U};
  std::uint8_t realloc_size_arg{0U};
  std::uint8_t free_ptr_arg{0U};
  std::uint8_t result_arg{kNoArgumentSlot};
  std::uint8_t free_size_arg{kNoArgumentSlot};
  bool calloc{false};
  std::uint16_t maximum_stack_depth{0U};
  std::uint64_t minimum_capture_size{0U};
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

CustomHookSlot g_custom_hook_slots[kPoolSize];
// Slots are claimed monotonically and never recycled: a slot that ever hosted a hook may still
// be referenced by an in-transit thread after teardown, so reuse is only provably safe never.
std::atomic<std::size_t> g_custom_hook_next_slot{0U};

using CustomHookFunction = PVOID(NTAPI*)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);

static_assert(OriginalTrampolineSlot::is_always_lock_free);
static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

[[noreturn]] void fail_broken_custom_route() noexcept {
#if defined(_MSC_VER)
  __fastfail(FAST_FAIL_FATAL_APP_EXIT);
#else
  std::abort();
#endif
}

void increment_saturating(std::atomic<std::uint64_t>& value) noexcept {
  std::uint64_t current = value.load(std::memory_order_relaxed);
  while (current != std::numeric_limits<std::uint64_t>::max() &&
         !value.compare_exchange_weak(current, current + 1U, std::memory_order_relaxed,
                                      std::memory_order_relaxed)) {
  }
}

[[nodiscard]] CustomHookFunction load_custom_function(std::atomic<void*>& slot) noexcept {
  void* const address = slot.load(std::memory_order_acquire);
  if (address == nullptr) {
    fail_broken_custom_route();
  }
  return reinterpret_cast<CustomHookFunction>(address);
}

[[nodiscard]] std::uint64_t argument_value(const PVOID* args, std::uint8_t index) noexcept {
  return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(args[index]));
}

void note_custom_call(CustomHookSlot& slot, HookEntryKind entry_kind) noexcept {
  slot.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  switch (entry_kind) {
    case HookEntryKind::kOutermost:
      slot.recordable_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
    case HookEntryKind::kRecursive:
      slot.recursive_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
    case HookEntryKind::kInternalThread:
      slot.internal_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
  }
}

void fill_event_header(RtlHeapEvent& event, std::uint64_t queue_sequence,
                       RtlHeapEventOperation operation, std::uint32_t api_id,
                       std::uint16_t maximum_stack_depth) noexcept {
  LARGE_INTEGER ticks{};
  static_cast<void>(QueryPerformanceCounter(&ticks));
  event.queue_sequence = queue_sequence;
  event.monotonic_ticks = static_cast<std::uint64_t>(ticks.QuadPart);
  event.thread_id = static_cast<std::uint64_t>(GetCurrentThreadId());
  event.heap_handle = 0U;
  event.flags = 0U;
  event.operation = operation;
  event.api_id = api_id;
  capture_current_stack(event.stack, maximum_stack_depth, 1U);
}

#if defined(_MSC_VER)

[[nodiscard]] LONG custom_exception_filter(EXCEPTION_POINTERS* exception_pointers,
                                           ReplacementRoute route, CustomHookSlot* slot,
                                           RtlHeapEventOperation operation, bool guard_entered,
                                           HookEntryKind entry_kind,
                                           bool original_completed) noexcept {
  const DWORD preserved_last_error = GetLastError();
  if (route == ReplacementRoute::kRecord && slot != nullptr && guard_entered &&
      entry_kind == HookEntryKind::kOutermost && !original_completed &&
      exception_pointers != nullptr && exception_pointers->ExceptionRecord != nullptr) {
    const std::uint32_t exception_status = exception_pointers->ExceptionRecord->ExceptionCode;
    slot->failed_calls.fetch_add(1U, std::memory_order_relaxed);
    slot->exceptional_calls.fetch_add(1U, std::memory_order_relaxed);
    const std::uint16_t maximum_stack_depth = slot->maximum_stack_depth;
    const std::uint32_t api_id = slot->api_id;
    const bool queued = slot->event_queue->try_emplace(
        [operation, api_id, exception_status, maximum_stack_depth](
            RtlHeapEvent& event, std::uint64_t queue_sequence) noexcept {
          event = RtlHeapEvent{};
          event.stack.frame_count = 0U;
          event.stack.requested_depth = maximum_stack_depth;
          event.stack.method = StackCaptureMethod::kRtlCaptureStackBackTrace;
          event.stack.status = maximum_stack_depth == 0U ? StackCaptureStatus::kDisabled
                                                         : StackCaptureStatus::kFailed;
          LARGE_INTEGER ticks{};
          static_cast<void>(QueryPerformanceCounter(&ticks));
          event.queue_sequence = queue_sequence;
          event.monotonic_ticks = static_cast<std::uint64_t>(ticks.QuadPart);
          event.thread_id = static_cast<std::uint64_t>(GetCurrentThreadId());
          event.operation = operation;
          event.api_id = api_id;
          event.status = RtlHeapEventStatus::kException;
          event.exception_status = exception_status;
        });
    if (!queued) {
      increment_saturating(slot->dropped_events);
    }
  }
  SetLastError(preserved_last_error);
  return EXCEPTION_CONTINUE_SEARCH;
}

#endif

// Not noexcept: SEH exceptions raised by the original function must unwind through these frames.
// The definitions stay in ".nlxhk" so the patch rendezvous covers the window before the
// lifecycle counters engage.
#pragma code_seg(push, ".nlxhk")

__declspec(noinline) PVOID NTAPI custom_alloc_impl(CustomHookSlot* slot, PVOID a0, PVOID a1,
                                                   PVOID a2, PVOID a3, PVOID a4, PVOID a5, PVOID a6,
                                                   PVOID a7) {
  const ReplacementRoute route = slot->lifecycle.enter_unscoped();
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
        result = load_custom_function(slot->alloc_restored_target)(a0, a1, a2, a3, a4, a5, a6, a7);
        original_completed = true;
      } else {
        CustomHookFunction original = reinterpret_cast<CustomHookFunction>(
            slot->alloc_trampoline.load(std::memory_order_acquire));
        if (original == nullptr) {
          fail_broken_custom_route();
        }
        if (route == ReplacementRoute::kOriginal) {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          result = original(a0, a1, a2, a3, a4, a5, a6, a7);
          original_completed = true;
        } else {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          note_custom_call(*slot, entry_kind);
          result = original(a0, a1, a2, a3, a4, a5, a6, a7);
          original_last_error = GetLastError();
          original_completed = true;

          if (entry_kind == HookEntryKind::kOutermost) {
            const PVOID args[8U] = {a0, a1, a2, a3, a4, a5, a6, a7};
            std::uint64_t size = 0U;
            bool size_valid = true;
            if (slot->calloc) {
              const std::uint64_t count = argument_value(args, slot->alloc_count_arg);
              const std::uint64_t element = argument_value(args, slot->alloc_size_arg);
              if (count != 0U && element > std::numeric_limits<std::uint64_t>::max() / count) {
                size_valid = false;
              } else {
                size = count * element;
              }
            } else {
              size = argument_value(args, slot->alloc_size_arg);
            }
            PVOID result_pointer = result;
            if (slot->result_arg != kNoArgumentSlot) {
              result_pointer = *static_cast<PVOID*>(args[slot->result_arg]);
            }
            const bool succeeded = size_valid && result_pointer != nullptr;
            (succeeded ? slot->successful_calls : slot->failed_calls)
                .fetch_add(1U, std::memory_order_relaxed);
            if (succeeded && size < slot->minimum_capture_size) {
              increment_saturating(slot->filtered_calls);
            } else {
              const std::uint16_t maximum_stack_depth = slot->maximum_stack_depth;
              const std::uint32_t api_id = slot->api_id;
              const std::uintptr_t recorded_result =
                  reinterpret_cast<std::uintptr_t>(succeeded ? result_pointer : nullptr);
              const bool queued = slot->event_queue->try_emplace(
                  [size, recorded_result, api_id, maximum_stack_depth](
                      RtlHeapEvent& event, std::uint64_t queue_sequence) noexcept {
                    event = RtlHeapEvent{};
                    fill_event_header(event, queue_sequence, RtlHeapEventOperation::kAllocate,
                                      api_id, maximum_stack_depth);
                    event.requested_size = size;
                    event.result_address = static_cast<std::uint64_t>(recorded_result);
                    event.status = recorded_result != 0U ? RtlHeapEventStatus::kSuccess
                                                         : RtlHeapEventStatus::kFailure;
                  });
              if (!queued) {
                increment_saturating(slot->dropped_events);
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
      slot->lifecycle.leave_unscoped(route);
    }
  } __except (custom_exception_filter(GetExceptionInformation(), route, slot,
                                      RtlHeapEventOperation::kAllocate, guard_entered, entry_kind,
                                      original_completed)) {
    fail_broken_custom_route();
  }
#else
  if (guard_entered) {
    leave_hook_invocation_unscoped();
  }
  slot->lifecycle.leave_unscoped(route);
#endif
  return result;
}

__declspec(noinline) PVOID NTAPI custom_realloc_impl(CustomHookSlot* slot, PVOID a0, PVOID a1,
                                                     PVOID a2, PVOID a3, PVOID a4, PVOID a5,
                                                     PVOID a6, PVOID a7) {
  const ReplacementRoute route = slot->lifecycle.enter_unscoped();
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
        result =
            load_custom_function(slot->realloc_restored_target)(a0, a1, a2, a3, a4, a5, a6, a7);
        original_completed = true;
      } else {
        CustomHookFunction original = reinterpret_cast<CustomHookFunction>(
            slot->realloc_trampoline.load(std::memory_order_acquire));
        if (original == nullptr) {
          fail_broken_custom_route();
        }
        if (route == ReplacementRoute::kOriginal) {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          result = original(a0, a1, a2, a3, a4, a5, a6, a7);
          original_completed = true;
        } else {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          note_custom_call(*slot, entry_kind);
          result = original(a0, a1, a2, a3, a4, a5, a6, a7);
          original_last_error = GetLastError();
          original_completed = true;

          if (entry_kind == HookEntryKind::kOutermost) {
            const PVOID args[8U] = {a0, a1, a2, a3, a4, a5, a6, a7};
            const std::uint64_t size = argument_value(args, slot->realloc_size_arg);
            const std::uintptr_t old_address = argument_value(args, slot->realloc_ptr_arg);
            PVOID result_pointer = result;
            if (slot->result_arg != kNoArgumentSlot) {
              result_pointer = *static_cast<PVOID*>(args[slot->result_arg]);
            }
            const bool succeeded = result_pointer != nullptr;
            (succeeded ? slot->successful_calls : slot->failed_calls)
                .fetch_add(1U, std::memory_order_relaxed);
            const std::uint16_t maximum_stack_depth = slot->maximum_stack_depth;
            const std::uint32_t api_id = slot->api_id;
            const std::uintptr_t recorded_result =
                reinterpret_cast<std::uintptr_t>(succeeded ? result_pointer : nullptr);
            const bool queued = slot->event_queue->try_emplace(
                [size, old_address, recorded_result, api_id, maximum_stack_depth](
                    RtlHeapEvent& event, std::uint64_t queue_sequence) noexcept {
                  event = RtlHeapEvent{};
                  fill_event_header(event, queue_sequence, RtlHeapEventOperation::kReallocate,
                                    api_id, maximum_stack_depth);
                  event.address = static_cast<std::uint64_t>(old_address);
                  event.requested_size = size;
                  event.result_address = static_cast<std::uint64_t>(recorded_result);
                  event.status = recorded_result != 0U ? RtlHeapEventStatus::kSuccess
                                                       : RtlHeapEventStatus::kFailure;
                });
            if (!queued) {
              increment_saturating(slot->dropped_events);
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
      slot->lifecycle.leave_unscoped(route);
    }
  } __except (custom_exception_filter(GetExceptionInformation(), route, slot,
                                      RtlHeapEventOperation::kReallocate, guard_entered, entry_kind,
                                      original_completed)) {
    fail_broken_custom_route();
  }
#else
  if (guard_entered) {
    leave_hook_invocation_unscoped();
  }
  slot->lifecycle.leave_unscoped(route);
#endif
  return result;
}

__declspec(noinline) PVOID NTAPI custom_free_impl(CustomHookSlot* slot, PVOID a0, PVOID a1,
                                                  PVOID a2, PVOID a3, PVOID a4, PVOID a5, PVOID a6,
                                                  PVOID a7) {
  const ReplacementRoute route = slot->lifecycle.enter_unscoped();
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
        result = load_custom_function(slot->free_restored_target)(a0, a1, a2, a3, a4, a5, a6, a7);
        original_completed = true;
      } else {
        CustomHookFunction original = reinterpret_cast<CustomHookFunction>(
            slot->free_trampoline.load(std::memory_order_acquire));
        if (original == nullptr) {
          fail_broken_custom_route();
        }
        if (route == ReplacementRoute::kOriginal) {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          result = original(a0, a1, a2, a3, a4, a5, a6, a7);
          original_completed = true;
        } else {
          entry_kind = enter_hook_invocation_unscoped();
          guard_entered = true;
          note_custom_call(*slot, entry_kind);
          result = original(a0, a1, a2, a3, a4, a5, a6, a7);
          original_last_error = GetLastError();
          original_completed = true;

          if (entry_kind == HookEntryKind::kOutermost) {
            const PVOID args[8U] = {a0, a1, a2, a3, a4, a5, a6, a7};
            const std::uintptr_t freed_address = argument_value(args, slot->free_ptr_arg);
            const std::uint64_t freed_size = slot->free_size_arg != kNoArgumentSlot
                                                 ? argument_value(args, slot->free_size_arg)
                                                 : 0U;
            slot->successful_calls.fetch_add(1U, std::memory_order_relaxed);
            const std::uint16_t maximum_stack_depth = slot->maximum_stack_depth;
            const std::uint32_t api_id = slot->api_id;
            const bool queued = slot->event_queue->try_emplace(
                [freed_address, freed_size, api_id, maximum_stack_depth](
                    RtlHeapEvent& event, std::uint64_t queue_sequence) noexcept {
                  event = RtlHeapEvent{};
                  fill_event_header(event, queue_sequence, RtlHeapEventOperation::kFree, api_id,
                                    maximum_stack_depth);
                  event.address = static_cast<std::uint64_t>(freed_address);
                  event.requested_size = freed_size;
                  event.raw_result = 1U;
                  event.status = RtlHeapEventStatus::kSuccess;
                });
            if (!queued) {
              increment_saturating(slot->dropped_events);
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
      slot->lifecycle.leave_unscoped(route);
    }
  } __except (custom_exception_filter(GetExceptionInformation(), route, slot,
                                      RtlHeapEventOperation::kFree, guard_entered, entry_kind,
                                      original_completed)) {
    fail_broken_custom_route();
  }
#else
  if (guard_entered) {
    leave_hook_invocation_unscoped();
  }
  slot->lifecycle.leave_unscoped(route);
#endif
  return result;
}

#define NLXHK_CUSTOM_ALLOC_THUNK(index)                                                    \
  PVOID NTAPI custom_alloc_thunk_##index(PVOID a0, PVOID a1, PVOID a2, PVOID a3, PVOID a4, \
                                         PVOID a5, PVOID a6, PVOID a7) {                   \
    return custom_alloc_impl(&g_custom_hook_slots[index], a0, a1, a2, a3, a4, a5, a6, a7); \
  }

#define NLXHK_CUSTOM_REALLOC_THUNK(index)                                                    \
  PVOID NTAPI custom_realloc_thunk_##index(PVOID a0, PVOID a1, PVOID a2, PVOID a3, PVOID a4, \
                                           PVOID a5, PVOID a6, PVOID a7) {                   \
    return custom_realloc_impl(&g_custom_hook_slots[index], a0, a1, a2, a3, a4, a5, a6, a7); \
  }

#define NLXHK_CUSTOM_FREE_THUNK(index)                                                    \
  PVOID NTAPI custom_free_thunk_##index(PVOID a0, PVOID a1, PVOID a2, PVOID a3, PVOID a4, \
                                        PVOID a5, PVOID a6, PVOID a7) {                   \
    return custom_free_impl(&g_custom_hook_slots[index], a0, a1, a2, a3, a4, a5, a6, a7); \
  }

// clang-format off: the fixed thunk pool indexes stay one row per eight slots.
#define NLXHK_CUSTOM_SLOT_NUMBERS(X) \
  X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) \
  X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15) \
  X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23) \
  X(24) X(25) X(26) X(27) X(28) X(29) X(30) X(31)
// clang-format on

NLXHK_CUSTOM_SLOT_NUMBERS(NLXHK_CUSTOM_ALLOC_THUNK)
NLXHK_CUSTOM_SLOT_NUMBERS(NLXHK_CUSTOM_REALLOC_THUNK)
NLXHK_CUSTOM_SLOT_NUMBERS(NLXHK_CUSTOM_FREE_THUNK)

#pragma code_seg(pop)

#define NLXHK_ALLOC_THUNK_ENTRY(index) &custom_alloc_thunk_##index,
#define NLXHK_REALLOC_THUNK_ENTRY(index) &custom_realloc_thunk_##index,
#define NLXHK_FREE_THUNK_ENTRY(index) &custom_free_thunk_##index,

const std::array<CustomHookFunction, kPoolSize> kAllocThunks{
    NLXHK_CUSTOM_SLOT_NUMBERS(NLXHK_ALLOC_THUNK_ENTRY)};
const std::array<CustomHookFunction, kPoolSize> kReallocThunks{
    NLXHK_CUSTOM_SLOT_NUMBERS(NLXHK_REALLOC_THUNK_ENTRY)};
const std::array<CustomHookFunction, kPoolSize> kFreeThunks{
    NLXHK_CUSTOM_SLOT_NUMBERS(NLXHK_FREE_THUNK_ENTRY)};

[[nodiscard]] std::wstring widen_module_name(std::string_view name) {
  if (name.empty() || name.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
    throw CustomHookError{"custom hook module name is empty or too long"};
  }
  const int input_size = static_cast<int>(name.size());
  const int output_size =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), input_size, nullptr, 0);
  if (output_size <= 0) {
    throw CustomHookError{"custom hook module name is not valid UTF-8: " + std::string{name}};
  }
  std::wstring wide(static_cast<std::size_t>(output_size), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), input_size, wide.data(),
                          output_size) != output_size) {
    throw CustomHookError{"custom hook module name conversion failed: " + std::string{name}};
  }
  return wide;
}

struct PeHeaders {
  const std::byte* base{nullptr};
  const IMAGE_NT_HEADERS64* nt{nullptr};
};

[[nodiscard]] std::optional<PeHeaders> pe_headers(void* module_base) noexcept {
  if (module_base == nullptr) {
    return std::nullopt;
  }
  const auto* base = static_cast<const std::byte*>(module_base);
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return std::nullopt;
  }
  const auto* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + static_cast<std::size_t>(dos->e_lfanew));
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return std::nullopt;
  }
  return PeHeaders{base, nt};
}

enum class ExportLookup : std::uint8_t {
  kFound,
  kNotFound,
  kForwarded,
};

struct ExportLookupResult {
  ExportLookup status{ExportLookup::kNotFound};
  std::uint32_t rva{0U};
};

// Read-only walk of the in-memory export table; no loader API is called.
[[nodiscard]] ExportLookupResult find_export_rva(const PeHeaders& pe,
                                                 std::string_view name) noexcept {
  const auto& directory = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  ExportLookupResult result;
  if (directory.VirtualAddress == 0U || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
    return result;
  }
  const auto* exports =
      reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(pe.base + directory.VirtualAddress);
  const auto* names = reinterpret_cast<const std::uint32_t*>(pe.base + exports->AddressOfNames);
  const auto* ordinals =
      reinterpret_cast<const std::uint16_t*>(pe.base + exports->AddressOfNameOrdinals);
  const auto* functions =
      reinterpret_cast<const std::uint32_t*>(pe.base + exports->AddressOfFunctions);
  for (std::uint32_t index = 0U; index < exports->NumberOfNames; ++index) {
    const auto* export_name = reinterpret_cast<const char*>(pe.base + names[index]);
    if (name != export_name) {
      continue;
    }
    const std::uint32_t rva = functions[ordinals[index]];
    if (rva >= directory.VirtualAddress && rva < directory.VirtualAddress + directory.Size) {
      result.status = ExportLookup::kForwarded;
      return result;
    }
    result.status = ExportLookup::kFound;
    result.rva = rva;
    return result;
  }
  return result;
}

[[nodiscard]] bool rva_is_executable(const PeHeaders& pe, std::uint32_t rva) noexcept {
  const auto* section = IMAGE_FIRST_SECTION(pe.nt);
  for (std::uint16_t index = 0U; index < pe.nt->FileHeader.NumberOfSections; ++index) {
    const std::uint32_t begin = section[index].VirtualAddress;
    const std::uint32_t size =
        (std::max)(section[index].Misc.VirtualSize, section[index].SizeOfRawData);
    if (rva >= begin && static_cast<std::uint64_t>(rva - begin) < size) {
      return (section[index].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0U;
    }
  }
  return false;
}

[[nodiscard]] HMODULE wait_for_module(const noleax::ipc::CustomHookSpec& hook,
                                      const std::wstring& module_name) {
  HMODULE module = GetModuleHandleW(module_name.c_str());
  if (module != nullptr) {
    return module;
  }
  const auto wait = std::chrono::milliseconds{hook.wait_module_ms};
  if (wait <= std::chrono::milliseconds::zero()) {
    throw CustomHookError{hook.module, CustomHookFailureRole::kPoint,
                          CustomHookFailureReason::kModuleNotLoaded,
                          "custom hook module '" + hook.module + "' is not loaded"};
  }
  const auto deadline = std::chrono::steady_clock::now() + wait;
  for (;;) {
    Sleep(static_cast<DWORD>(kModulePollInterval.count()));
    module = GetModuleHandleW(module_name.c_str());
    if (module != nullptr) {
      return module;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      throw CustomHookError{hook.module, CustomHookFailureRole::kPoint,
                            CustomHookFailureReason::kModuleNotLoaded,
                            "custom hook module '" + hook.module + "' did not load within " +
                                std::to_string(wait.count()) + " ms"};
    }
  }
}

[[nodiscard]] void* replacement_module_base() noexcept {
  return reinterpret_cast<void*>(&custom_alloc_impl);
}

}  // namespace

class CustomSymbolHooks::Implementation final {
 public:
  Implementation(HookBackend& backend, RtlHeapEventQueue& event_queue,
                 std::vector<noleax::ipc::CustomHookSpec> hooks, std::uint16_t maximum_stack_depth,
                 std::uint64_t minimum_capture_size)
      : backend_{&backend},
        event_queue_{&event_queue},
        maximum_stack_depth_{maximum_stack_depth},
        minimum_capture_size_{minimum_capture_size} {
    if (hooks.empty() || hooks.size() > kPoolSize) {
      throw std::invalid_argument{"custom symbol hooks require between 1 and 32 hook points"};
    }
    if (maximum_stack_depth > kMaximumCapturedStackDepth) {
      throw std::invalid_argument{"maximum stack depth exceeds the fixed event capacity"};
    }
    if (!acquire_hook_guard_runtime()) {
      throw HookBackendError{"a fixed Windows TLS slot is unavailable for the hook guard"};
    }
    guard_runtime_acquired_ = true;
    points_.reserve(hooks.size());
    definitions_.reserve(hooks.size());
    noleax::trace::ApiId api_id = noleax::trace::kCustomHookApiIdBase;
    for (auto& hook : hooks) {
      const std::size_t slot_index =
          g_custom_hook_next_slot.fetch_add(1U, std::memory_order_acq_rel);
      if (slot_index >= kPoolSize) {
        throw CustomHookError{"the custom hook replacement slot pool is exhausted"};
      }
      PointState point;
      point.spec = std::move(hook);
      point.slot_index = slot_index;
      point.api_id = api_id;
      point.alloc.spec = point.spec.alloc;
      point.realloc.spec = point.spec.realloc;
      point.free.spec = point.spec.free;
      points_.push_back(std::move(point));
      noleax::trace::CustomHookDefinition definition;
      definition.api_id = api_id;
      definition.module_name = points_.back().spec.module;
      definition.label = points_.back().spec.label;
      definitions_.push_back(std::move(definition));
      ++api_id;
    }
  }

  ~Implementation() {
    if (is_installed()) {
      static_cast<void>(uninstall(HookBackend::kDefaultFlushAttempts));
    }
    if (has_pending_teardown()) {
      static_cast<void>(flush(HookBackend::kDefaultFlushAttempts));
    }
    if (has_pending_teardown()) {
      abandon_pending_teardown();
    }
    if (guard_runtime_acquired_) {
      release_hook_guard_runtime();
      guard_runtime_acquired_ = false;
    }
  }

  Implementation(const Implementation&) = delete;
  Implementation& operator=(const Implementation&) = delete;

  std::vector<CustomHookFailure> install() {
    const InternalThreadScope internal_thread;
    if (is_installed()) {
      throw std::logic_error{"custom symbol hooks are already installed"};
    }
    if (!replacement_module_referenced_) {
      HMODULE module = nullptr;
      if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                             reinterpret_cast<LPCWSTR>(replacement_module_base()),
                             &module) == FALSE) {
        std::vector<CustomHookFailure> failures;
        failures.reserve(points_.size());
        for (const PointState& point : points_) {
          failures.push_back(
              CustomHookFailure{point.spec.module, CustomHookFailureRole::kPoint,
                                CustomHookFailureReason::kBackendUnavailable,
                                "the custom hook replacement module could not be referenced"});
        }
        return failures;
      }
      replacement_module_handle_ = module;
      replacement_module_referenced_ = true;
      note_agent_module_reference_acquired();
    }
    std::vector<CustomHookFailure> failures;
    for (PointState& point : points_) {
      if (point.installed) {
        continue;
      }
      try {
        install_point(point);
      } catch (const CustomHookError& error) {
        // install_point leaves a failed point fully reverted. Record the failure and keep
        // installing the remaining points: one bad declaration must not silence the rest of
        // the capture (the failure surfaces through the trace completeness issue instead).
        failures.push_back(
            CustomHookFailure{error.module().empty() ? point.spec.module : error.module(),
                              error.role(), error.reason(), error.what()});
      }
    }
    return failures;
  }

  [[nodiscard]] bool uninstall(std::uint32_t flush_attempts) noexcept {
    const InternalThreadScope internal_thread;
    for (PointState& point : points_) {
      if (!point.installed || point.teardown_pending) {
        continue;
      }
      CustomHookSlot& slot = g_custom_hook_slots[point.slot_index];
      slot.lifecycle.stop_recording();
      point.teardown_pending = true;
      // Never let Hoox flush here: revert first, publish the restored-target route, then wait
      // for replacement quiescence before releasing the trampoline lifetime leases.
      for (RoleState* role : {&point.alloc, &point.realloc, &point.free}) {
        if (role->installed) {
          static_cast<void>(backend_->uninstall(role->target, 0U));
        }
      }
      slot.lifecycle.route_to_target();
    }
    return try_finish_teardown(flush_attempts);
  }

  [[nodiscard]] bool flush(std::uint32_t max_attempts) noexcept {
    if (is_installed()) {
      return false;
    }
    return try_finish_teardown(max_attempts);
  }

  [[nodiscard]] bool stop_recording(std::uint32_t max_attempts) noexcept {
    bool recording = false;
    for (PointState& point : points_) {
      if (point.installed && !point.teardown_pending) {
        recording = true;
        g_custom_hook_slots[point.slot_index].lifecycle.stop_recording();
      }
    }
    if (!recording) {
      return true;
    }
    for (PointState& point : points_) {
      if (point.installed && !point.teardown_pending &&
          !g_custom_hook_slots[point.slot_index].lifecycle.wait_for_recording_quiescence(
              max_attempts)) {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] bool is_installed() const noexcept {
    return std::all_of(points_.begin(), points_.end(), [](const PointState& point) {
      return point.installed && !point.teardown_pending;
    });
  }

  [[nodiscard]] bool is_recording() const noexcept {
    return std::any_of(points_.begin(), points_.end(), [](const PointState& point) {
      return point.installed && !point.teardown_pending &&
             g_custom_hook_slots[point.slot_index].lifecycle.route() == ReplacementRoute::kRecord;
    });
  }

  [[nodiscard]] std::uint64_t recording_in_flight_count() const noexcept {
    std::uint64_t total = 0U;
    for (const PointState& point : points_) {
      const std::uint64_t count =
          g_custom_hook_slots[point.slot_index].lifecycle.recording_in_flight();
      total = count > std::numeric_limits<std::uint64_t>::max() - total
                  ? std::numeric_limits<std::uint64_t>::max()
                  : total + count;
    }
    return total;
  }

  [[nodiscard]] bool has_pending_teardown() const noexcept {
    return std::any_of(points_.begin(), points_.end(), [](const PointState& point) {
      return point.teardown_pending && !point.retired;
    });
  }

  [[nodiscard]] bool replacement_module_is_referenced() const noexcept {
    return replacement_module_referenced_;
  }

  [[nodiscard]] RtlHeapEventQueue& event_queue() noexcept { return *event_queue_; }
  [[nodiscard]] const RtlHeapEventQueue& event_queue() const noexcept { return *event_queue_; }

  [[nodiscard]] const std::vector<noleax::trace::CustomHookDefinition>& definitions()
      const noexcept {
    return definitions_;
  }

  [[nodiscard]] std::vector<CustomHookApiStatistics> api_statistics() const noexcept {
    std::vector<CustomHookApiStatistics> statistics;
    statistics.reserve(points_.size());
    for (const PointState& point : points_) {
      const CustomHookSlot& slot = g_custom_hook_slots[point.slot_index];
      CustomHookApiStatistics entry;
      // Read the API ID from the point, not the slot: a point whose install failed before the
      // slot was initialized still owns its API ID, while the slot's field is never set.
      entry.api_id = point.api_id;
      entry.recordable_calls = slot.recordable_calls.load(std::memory_order_relaxed);
      entry.successful_calls = slot.successful_calls.load(std::memory_order_relaxed);
      entry.failed_calls = slot.failed_calls.load(std::memory_order_relaxed);
      entry.filtered_calls = slot.filtered_calls.load(std::memory_order_relaxed);
      entry.dropped_events = slot.dropped_events.load(std::memory_order_relaxed);
      statistics.push_back(entry);
    }
    return statistics;
  }

  [[nodiscard]] std::vector<std::pair<noleax::trace::ApiId, std::uint64_t>>
  take_dropped_event_counts() noexcept {
    std::vector<std::pair<noleax::trace::ApiId, std::uint64_t>> dropped;
    dropped.reserve(points_.size());
    for (PointState& point : points_) {
      CustomHookSlot& slot = g_custom_hook_slots[point.slot_index];
      dropped.emplace_back(point.api_id,
                           slot.dropped_events.exchange(0U, std::memory_order_relaxed));
    }
    return dropped;
  }

  [[nodiscard]] std::uint64_t dropped_event_count() const noexcept {
    std::uint64_t total = 0U;
    for (const PointState& point : points_) {
      const std::uint64_t count =
          g_custom_hook_slots[point.slot_index].dropped_events.load(std::memory_order_relaxed);
      total = count > std::numeric_limits<std::uint64_t>::max() - total
                  ? std::numeric_limits<std::uint64_t>::max()
                  : total + count;
    }
    return total;
  }

  [[nodiscard]] std::uint64_t recordable_call_count() const noexcept {
    std::uint64_t total = 0U;
    for (const PointState& point : points_) {
      const std::uint64_t count =
          g_custom_hook_slots[point.slot_index].recordable_calls.load(std::memory_order_relaxed);
      total = count > std::numeric_limits<std::uint64_t>::max() - total
                  ? std::numeric_limits<std::uint64_t>::max()
                  : total + count;
    }
    return total;
  }

  [[nodiscard]] std::uint64_t filtered_call_count() const noexcept {
    std::uint64_t total = 0U;
    for (const PointState& point : points_) {
      const std::uint64_t count =
          g_custom_hook_slots[point.slot_index].filtered_calls.load(std::memory_order_relaxed);
      total = count > std::numeric_limits<std::uint64_t>::max() - total
                  ? std::numeric_limits<std::uint64_t>::max()
                  : total + count;
    }
    return total;
  }

 private:
  struct RoleState {
    noleax::ipc::CustomHookRoleSpec spec;
    void* target{nullptr};
    bool installed{false};
    bool lease_acquired{false};
  };

  struct PointState {
    noleax::ipc::CustomHookSpec spec;
    std::size_t slot_index{0U};
    std::uint32_t api_id{0U};
    RoleState alloc;
    RoleState realloc;
    RoleState free;
    bool installed{false};
    bool teardown_pending{false};
    bool retired{false};
  };

  void install_point(PointState& point) {
    const std::wstring module_name = widen_module_name(point.spec.module);
    void* const module = wait_for_module(point.spec, module_name);
    const auto pe = pe_headers(module);
    if (!pe.has_value()) {
      throw CustomHookError{
          point.spec.module, CustomHookFailureRole::kPoint, CustomHookFailureReason::kOther,
          "custom hook module '" + point.spec.module + "' is not a valid x64 PE image"};
    }
    verify_image_identity(point, *pe);
    point.alloc.target =
        resolve_role_target(point, point.alloc.spec, *pe, CustomHookFailureRole::kAlloc);
    point.realloc.target =
        resolve_role_target(point, point.realloc.spec, *pe, CustomHookFailureRole::kRealloc);
    point.free.target =
        resolve_role_target(point, point.free.spec, *pe, CustomHookFailureRole::kFree);

    CustomHookSlot& slot = g_custom_hook_slots[point.slot_index];
    slot.event_queue = event_queue_;
    slot.api_id = point.api_id;
    slot.alloc_size_arg = point.spec.alloc_size_arg;
    slot.alloc_count_arg = point.spec.alloc_count_arg.value_or(kNoArgumentSlot);
    slot.realloc_ptr_arg = point.spec.realloc_ptr_arg;
    slot.realloc_size_arg = point.spec.realloc_size_arg;
    slot.free_ptr_arg = point.spec.free_ptr_arg;
    slot.result_arg = point.spec.result_arg.value_or(kNoArgumentSlot);
    slot.free_size_arg = point.spec.free_size_arg.value_or(kNoArgumentSlot);
    slot.calloc = point.spec.calloc;
    slot.maximum_stack_depth = maximum_stack_depth_;
    slot.minimum_capture_size = minimum_capture_size_;
    slot.lifecycle.start_recording();
    try {
      install_role(point, point.alloc, slot.alloc_trampoline, slot.alloc_restored_target,
                   kAllocThunks[point.slot_index], CustomHookFailureRole::kAlloc);
      if (point.realloc.spec.locator != noleax::ipc::CustomHookLocator::kNone) {
        install_role(point, point.realloc, slot.realloc_trampoline, slot.realloc_restored_target,
                     kReallocThunks[point.slot_index], CustomHookFailureRole::kRealloc);
      }
      install_role(point, point.free, slot.free_trampoline, slot.free_restored_target,
                   kFreeThunks[point.slot_index], CustomHookFailureRole::kFree);
    } catch (...) {
      for (RoleState* role : {&point.alloc, &point.realloc, &point.free}) {
        if (role->installed) {
          static_cast<void>(backend_->uninstall(role->target, 0U));
          role->installed = false;
        }
        if (role->lease_acquired) {
          backend_->release_trampoline_lifetime_lease();
          role->lease_acquired = false;
        }
      }
      slot.lifecycle.route_to_target();
      slot.lifecycle.stop_recording();
      throw;
    }
    point.installed = true;
  }

  void install_role(PointState& point, RoleState& role, OriginalTrampolineSlot& trampoline_slot,
                    std::atomic<void*>& restored_slot, CustomHookFunction thunk,
                    CustomHookFailureRole failure_role) {
    const char* const role_name = custom_hook_role_name(failure_role);
    if (!backend_->acquire_trampoline_lifetime_lease()) {
      throw CustomHookError{
          point.spec.module, failure_role, CustomHookFailureReason::kBackendUnavailable,
          std::string{"custom hook "} + role_name + " install failed: the hook backend is stopped"};
    }
    role.lease_acquired = true;
    restored_slot.store(role.target, std::memory_order_release);
    const FastHookResult result =
        point.spec.forced
            ? backend_->install_fast_forced(role.target, reinterpret_cast<void*>(thunk),
                                            &trampoline_slot)
            : backend_->install_fast(role.target, reinterpret_cast<void*>(thunk), &trampoline_slot);
    if (!result.installed()) {
      backend_->release_trampoline_lifetime_lease();
      role.lease_acquired = false;
      restored_slot.store(nullptr, std::memory_order_release);
      throw CustomHookError{point.spec.module, failure_role, install_failure_reason(result.status),
                            std::string{"custom hook "} + role_name +
                                " install failed for module '" + point.spec.module +
                                "': " + std::string{hook_install_status_name(result.status)} +
                                (point.spec.forced ? ""
                                                   : " (declare forced = true to allow forced "
                                                     "relocation of an unsupported prologue)")};
    }
    role.installed = true;
  }

  void verify_image_identity(const PointState& point, const PeHeaders& pe) {
    if (!point.spec.image_identity.has_value()) {
      return;
    }
    const auto& expected = *point.spec.image_identity;
    if (pe.nt->FileHeader.TimeDateStamp != expected.timestamp ||
        pe.nt->OptionalHeader.CheckSum != expected.checksum ||
        pe.nt->OptionalHeader.SizeOfImage != expected.image_size) {
      throw CustomHookError{
          point.spec.module, CustomHookFailureRole::kPoint,
          CustomHookFailureReason::kImageIdentityMismatch,
          "custom hook module '" + point.spec.module +
              "' image identity does not match the identity recorded when its PDB symbols were "
              "resolved; re-bake the configuration so the RVAs match the loaded module"};
    }
  }

  [[nodiscard]] void* resolve_role_target(const PointState& point,
                                          const noleax::ipc::CustomHookRoleSpec& role,
                                          const PeHeaders& pe, CustomHookFailureRole failure_role) {
    const char* const role_name = custom_hook_role_name(failure_role);
    switch (role.locator) {
      case noleax::ipc::CustomHookLocator::kNone:
        return nullptr;
      case noleax::ipc::CustomHookLocator::kExport: {
        const ExportLookupResult lookup = find_export_rva(pe, role.export_name);
        if (lookup.status == ExportLookup::kForwarded) {
          throw CustomHookError{point.spec.module, failure_role,
                                CustomHookFailureReason::kForwardedExport,
                                std::string{"custom hook "} + role_name + " export '" +
                                    role.export_name + "' of module '" + point.spec.module +
                                    "' is a forwarded export; hook the forward target instead"};
        }
        if (lookup.status != ExportLookup::kFound) {
          throw CustomHookError{
              point.spec.module, failure_role, CustomHookFailureReason::kExportNotFound,
              std::string{"custom hook "} + role_name + " export '" + role.export_name +
                  "' was not found in module '" + point.spec.module + "'"};
        }
        return const_cast<std::byte*>(pe.base) + lookup.rva;
      }
      case noleax::ipc::CustomHookLocator::kRva:
        if (role.rva > std::numeric_limits<std::uint32_t>::max() ||
            !rva_is_executable(pe, static_cast<std::uint32_t>(role.rva))) {
          throw CustomHookError{point.spec.module, failure_role,
                                CustomHookFailureReason::kInvalidRva,
                                std::string{"custom hook "} + role_name +
                                    " RVA does not point into an executable section of module '" +
                                    point.spec.module + "'"};
        }
        return const_cast<std::byte*>(pe.base) + static_cast<std::size_t>(role.rva);
      case noleax::ipc::CustomHookLocator::kElfSymbol:
        throw CustomHookError{point.spec.module, failure_role, CustomHookFailureReason::kOther,
                              std::string{"custom hook "} + role_name +
                                  " ELF symbol locators are only supported on Linux (module '" +
                                  point.spec.module + "')"};
    }
    throw CustomHookError{point.spec.module, failure_role, CustomHookFailureReason::kOther,
                          std::string{"custom hook "} + role_name + " locator is not supported"};
  }

  [[nodiscard]] static CustomHookFailureReason install_failure_reason(
      HookInstallStatus status) noexcept {
    switch (status) {
      case HookInstallStatus::kWrongSignature:
        return CustomHookFailureReason::kWrongSignature;
      case HookInstallStatus::kBackendStopped:
      case HookInstallStatus::kTeardownPending:
        return CustomHookFailureReason::kBackendUnavailable;
      case HookInstallStatus::kInstalled:
      case HookInstallStatus::kInvalidArgument:
      case HookInstallStatus::kAlreadyInstalled:
      case HookInstallStatus::kAlreadyReplaced:
      case HookInstallStatus::kPolicyViolation:
      case HookInstallStatus::kWrongType:
      case HookInstallStatus::kMissingOriginal:
        return CustomHookFailureReason::kOther;
    }
    return CustomHookFailureReason::kOther;
  }

  [[nodiscard]] bool try_finish_teardown(std::uint32_t max_attempts) noexcept {
    bool all_retired = true;
    for (PointState& point : points_) {
      if (!point.teardown_pending || point.retired) {
        continue;
      }
      CustomHookSlot& slot = g_custom_hook_slots[point.slot_index];
      if (!slot.lifecycle.wait_for_quiescence(max_attempts)) {
        all_retired = false;
        continue;
      }
      for (RoleState* role : {&point.alloc, &point.realloc, &point.free}) {
        if (role->lease_acquired) {
          backend_->release_trampoline_lifetime_lease();
          role->lease_acquired = false;
        }
        role->installed = false;
      }
      point.retired = true;
    }
    if (!all_retired) {
      return false;
    }
    if (!backend_flush_complete_) {
      backend_flush_complete_ = backend_->flush(max_attempts);
    }
    if (!backend_flush_complete_) {
      return false;
    }
    // The lifecycle counters cannot see a thread between the restored jump and the entry
    // increment. Prove the replacement code section is empty before releasing the module
    // reference; on failure stay teardown-pending so a later flush can retry.
    if (!module_rendezvous_complete_) {
      if (any_point_ever_installed() &&
          !verify_replacement_evacuated(hook_code_region(replacement_module_base()),
                                        kDefaultRendezvousMaxAttempts)) {
        return false;
      }
      module_rendezvous_complete_ = true;
    }
    if (replacement_module_referenced_) {
      note_agent_module_reference_released();
      static_cast<void>(FreeLibrary(replacement_module_handle_));
      replacement_module_handle_ = nullptr;
      replacement_module_referenced_ = false;
    }
    for (PointState& point : points_) {
      point.installed = false;
    }
    return true;
  }

  [[nodiscard]] bool any_point_ever_installed() const noexcept {
    return std::any_of(points_.begin(), points_.end(), [](const PointState& point) {
      return point.teardown_pending || point.installed;
    });
  }

  void abandon_pending_teardown() noexcept {
    for (PointState& point : points_) {
      if (!point.teardown_pending || point.retired) {
        continue;
      }
      g_custom_hook_slots[point.slot_index].lifecycle.route_to_target();
      point.retired = true;
    }
    // Keep the trampoline leases, the guard TLS slot, and the module reference: an in-transit
    // thread can still execute the replacements, so their backing storage stays alive for the
    // process lifetime.
    guard_runtime_acquired_ = false;
  }

  HookBackend* backend_{nullptr};
  RtlHeapEventQueue* event_queue_{nullptr};
  std::uint16_t maximum_stack_depth_{0U};
  std::uint64_t minimum_capture_size_{0U};
  std::vector<PointState> points_;
  std::vector<noleax::trace::CustomHookDefinition> definitions_;
  bool guard_runtime_acquired_{false};
  bool replacement_module_referenced_{false};
  HMODULE replacement_module_handle_{nullptr};
  bool backend_flush_complete_{false};
  bool module_rendezvous_complete_{false};
};

CustomSymbolHooks::CustomSymbolHooks(HookBackend& backend, RtlHeapEventQueue& event_queue,
                                     std::vector<noleax::ipc::CustomHookSpec> hooks,
                                     std::uint16_t maximum_stack_depth,
                                     std::uint64_t minimum_capture_size)
    : implementation_{std::make_unique<Implementation>(
          backend, event_queue, std::move(hooks), maximum_stack_depth, minimum_capture_size)} {}

CustomSymbolHooks::~CustomSymbolHooks() = default;

std::vector<noleax::trace::CustomHookFailure> CustomSymbolHooks::install() {
  return implementation_->install();
}

bool CustomSymbolHooks::uninstall(std::uint32_t flush_attempts) noexcept {
  return implementation_->uninstall(flush_attempts);
}

bool CustomSymbolHooks::flush(std::uint32_t max_attempts) noexcept {
  return implementation_->flush(max_attempts);
}

bool CustomSymbolHooks::stop_recording(std::uint32_t max_attempts) noexcept {
  return implementation_->stop_recording(max_attempts);
}

bool CustomSymbolHooks::is_installed() const noexcept { return implementation_->is_installed(); }

bool CustomSymbolHooks::is_recording() const noexcept { return implementation_->is_recording(); }

std::uint64_t CustomSymbolHooks::recording_in_flight_count() const noexcept {
  return implementation_->recording_in_flight_count();
}

bool CustomSymbolHooks::has_pending_teardown() const noexcept {
  return implementation_->has_pending_teardown();
}

bool CustomSymbolHooks::replacement_module_is_referenced() const noexcept {
  return implementation_->replacement_module_is_referenced();
}

RtlHeapEventQueue& CustomSymbolHooks::event_queue() noexcept {
  return implementation_->event_queue();
}

const RtlHeapEventQueue& CustomSymbolHooks::event_queue() const noexcept {
  return implementation_->event_queue();
}

const std::vector<noleax::trace::CustomHookDefinition>& CustomSymbolHooks::definitions()
    const noexcept {
  return implementation_->definitions();
}

std::vector<CustomHookApiStatistics> CustomSymbolHooks::api_statistics() const noexcept {
  return implementation_->api_statistics();
}

std::vector<std::pair<noleax::trace::ApiId, std::uint64_t>>
CustomSymbolHooks::take_dropped_event_counts() noexcept {
  return implementation_->take_dropped_event_counts();
}

std::uint64_t CustomSymbolHooks::dropped_event_count() const noexcept {
  return implementation_->dropped_event_count();
}

std::uint64_t CustomSymbolHooks::recordable_call_count() const noexcept {
  return implementation_->recordable_call_count();
}

std::uint64_t CustomSymbolHooks::filtered_call_count() const noexcept {
  return implementation_->filtered_call_count();
}

}  // namespace noleax::agent::windows
