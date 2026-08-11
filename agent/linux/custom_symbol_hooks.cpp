// Linux custom symbol hooks (docs/CUSTOM_HOOKS.md, docs/LINUX_PORT_PLAN.md M7): generic
// System V AMD64 replacements that record user-declared third-party allocator entry points
// as heap events. Discipline mirrors the built-in GlibcHeapHooks adapter — per-point
// ReplacementLifecycle routing, guard classification, counters, trampoline leases,
// quiescence/rendezvous teardown, ".nlxhk" placement via external-inline replacements in
// namespace detail, and errno preservation — while the declaration model, per-point best
// effort install, and failure records follow the Windows CustomSymbolHooks.

#include "noleax/agent/linux/custom_symbol_hooks.hpp"

#include <fcntl.h>
#include <link.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/hook_section.hpp"
#include "noleax/agent/patch_rendezvous.hpp"
#include "noleax/agent/replacement_lifecycle.hpp"

namespace noleax::agent::linux {
namespace {

using noleax::ipc::CustomHookLocator;
using noleax::ipc::CustomHookRoleSpec;
using noleax::ipc::CustomHookSpec;
using noleax::trace::CustomHookDefinition;
using noleax::trace::CustomHookFailure;
using noleax::trace::CustomHookFailureReason;
using noleax::trace::CustomHookFailureRole;

inline constexpr std::size_t kPoolSize = LinuxCustomSymbolHooks::kMaximumHookPoints;
inline constexpr std::uint8_t kNoArgumentSlot = 0xFFU;
inline constexpr std::uint8_t kMaximumArgumentSlot = 7U;
inline constexpr auto kModulePollInterval = std::chrono::milliseconds{100};
// The on-disk ELF tables of a hook target are install-time inputs; cap them so a corrupt
// or hostile image degrades to a recorded point failure instead of a huge allocation.
inline constexpr std::uint64_t kMaximumDynamicSymbolCount = 1U << 20U;
inline constexpr std::uint64_t kMaximumDynamicStringSize = 16U << 20U;

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

// Install-time failure of one hook point (or one role of it); install() turns each into a
// trace::CustomHookFailure record and keeps going with the remaining points.
class CustomHookError final : public std::runtime_error {
 public:
  CustomHookError(std::string module, CustomHookFailureRole role, CustomHookFailureReason reason,
                  const std::string& detail)
      : std::runtime_error{detail}, module_{std::move(module)}, role_{role}, reason_{reason} {}

  [[nodiscard]] const std::string& module() const noexcept { return module_; }
  [[nodiscard]] CustomHookFailureRole role() const noexcept { return role_; }
  [[nodiscard]] CustomHookFailureReason reason() const noexcept { return reason_; }

 private:
  std::string module_;
  CustomHookFailureRole role_{CustomHookFailureRole::kPoint};
  CustomHookFailureReason reason_{CustomHookFailureReason::kOther};
};

}  // namespace

// Per-point descriptor block shared between the control path and the generic replacements:
// routing state, original trampolines, argument mapping, queue, and accounting. One code
// copy per role reads its context from the slot bound to its thunk at install time. The
// struct deliberately sits at namespace scope (like GlibcHeapHookChannelSet): the generic
// replacements in namespace detail take a pointer to it, and a no-linkage parameter type
// would make GCC emit those vague-linkage functions as local symbols in a plain ".nlxhk"
// section, which cannot mix with the COMDAT ".nlxhk" groups in one TU.
struct CustomHookSlot {
  ReplacementLifecycle lifecycle;
  OriginalTrampolineSlot alloc_trampoline{nullptr};
  OriginalTrampolineSlot realloc_trampoline{nullptr};
  OriginalTrampolineSlot free_trampoline{nullptr};
  std::atomic<void*> alloc_restored_target{nullptr};
  std::atomic<void*> realloc_restored_target{nullptr};
  std::atomic<void*> free_restored_target{nullptr};
  LinuxHeapEventQueue* event_queue{nullptr};
  std::uint32_t api_id{0U};
  std::uint8_t size_arg{0U};
  std::uint8_t ptr_arg{0U};
  std::uint8_t result_arg{kNoArgumentSlot};
  std::uint8_t count_arg{kNoArgumentSlot};
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
  std::atomic<std::uint64_t> filtered_calls{0U};
  std::atomic<std::uint64_t> dropped_events{0U};
};

namespace {

CustomHookSlot g_custom_hook_slots[kPoolSize];
// Slots are claimed monotonically and never recycled: a slot that ever hosted a hook may
// still be referenced by an in-transit thread after teardown, so reuse is only provably
// safe never.
std::atomic<std::size_t> g_custom_hook_next_slot{0U};

// The generic replacement signature: eight integer-class argument slots. Under the System
// V AMD64 ABI slots 0-5 arrive in rdi/rsi/rdx/rcx/r8/r9 and slots 6-7 in the entry stack
// slots [rsp+8] and [rsp+16], which the compiler materializes as the 7th/8th parameters;
// rax returns to the caller untouched through the result passthrough.
using GenericHookFunction = void* (*)(void*, void*, void*, void*, void*, void*, void*, void*);

static_assert(OriginalTrampolineSlot::is_always_lock_free);
static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
static_assert(decltype(g_custom_hook_next_slot)::is_always_lock_free);

[[noreturn]] void fail_broken_custom_route() noexcept { std::abort(); }

void increment_saturating(std::atomic<std::uint64_t>& value) noexcept {
  std::uint64_t current = value.load(std::memory_order_relaxed);
  while (current != std::numeric_limits<std::uint64_t>::max() &&
         !value.compare_exchange_weak(current, current + 1U, std::memory_order_relaxed,
                                      std::memory_order_relaxed)) {
  }
}

[[nodiscard]] GenericHookFunction load_custom_function(const std::atomic<void*>& slot) noexcept {
  void* const address = slot.load(std::memory_order_acquire);
  if (address == nullptr) {
    fail_broken_custom_route();
  }
  return reinterpret_cast<GenericHookFunction>(address);
}

[[nodiscard]] std::uint64_t argument_value(void* const* args, std::uint8_t index) noexcept {
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

[[nodiscard]] std::uint64_t monotonic_ticks_nanoseconds() noexcept {
  timespec value{};
  static_cast<void>(::clock_gettime(CLOCK_MONOTONIC, &value));
  return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000U +
         static_cast<std::uint64_t>(value.tv_nsec);
}

[[nodiscard]] std::uint64_t current_thread_id() noexcept {
  return static_cast<std::uint64_t>(::syscall(SYS_gettid));
}

struct CustomEventFields {
  LinuxHeapEventOperation operation;
  std::uint64_t requested_size;
  std::uint64_t count;
  std::uint64_t address;
  const void* result;  // nullptr on failure and for frees
  bool failed;
  int error_code;  // errno of the original call on failure, else 0
};

void emit_custom_event(CustomHookSlot& slot, const CustomEventFields& fields) noexcept {
  const std::uint16_t maximum_stack_depth = slot.maximum_stack_depth;
  const std::uint32_t api_id = slot.api_id;
  const std::uint64_t result_address =
      static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(fields.result));
  const std::uint32_t operation_result =
      fields.failed ? static_cast<std::uint32_t>(fields.error_code) : 0U;
  const bool queued = slot.event_queue->try_emplace(
      [&fields, maximum_stack_depth, api_id, result_address, operation_result](
          LinuxHeapEvent& event, std::uint64_t queue_sequence) noexcept {
        event = LinuxHeapEvent{};
        event.queue_sequence = queue_sequence;
        event.monotonic_ticks = monotonic_ticks_nanoseconds();
        event.thread_id = current_thread_id();
        event.requested_size = fields.requested_size;
        event.count = fields.count;
        event.result_address = result_address;
        event.address = fields.address;
        event.operation_result = operation_result;
        event.api_id = api_id;
        event.operation = fields.operation;
        event.status =
            fields.failed ? LinuxHeapEventStatus::kFailure : LinuxHeapEventStatus::kSuccess;
        capture_current_stack(event.stack, maximum_stack_depth, 2U);
      });
  if (!queued) {
    increment_saturating(slot.dropped_events);
  }
}

// The minimum-size filter is creation-side only and applies to successful calls: a failed
// allocation — including the calloc-kind product overflow, which is always a failure
// event — is never swallowed by the floor, while reallocate and free always record.
void record_custom_allocate(CustomHookSlot& slot, std::uint64_t size, std::uint64_t count,
                            void* result, bool size_valid, int original_errno) noexcept {
  const bool failed = !size_valid || result == nullptr;
  (failed ? slot.failed_calls : slot.successful_calls).fetch_add(1U, std::memory_order_relaxed);
  if (!failed && size < slot.minimum_capture_size) {
    increment_saturating(slot.filtered_calls);
    return;
  }
  // The writer requires failure events to carry a nonzero result code; a third-party
  // allocator that fails without setting errno reports ENOMEM rather than an invalid event.
  const int error_code = failed ? (original_errno != 0 ? original_errno : ENOMEM) : 0;
  emit_custom_event(slot, CustomEventFields{LinuxHeapEventOperation::kAllocate, size, count, 0U,
                                            failed ? nullptr : result, failed, error_code});
}

void record_custom_reallocate(CustomHookSlot& slot, void* address, std::uint64_t size, void* result,
                              int original_errno) noexcept {
  // realloc(p, 0) frees and returns nullptr on glibc: a success, not a failure.
  const bool failed = result == nullptr && size != 0U;
  (failed ? slot.failed_calls : slot.successful_calls).fetch_add(1U, std::memory_order_relaxed);
  const int error_code = failed ? (original_errno != 0 ? original_errno : ENOMEM) : 0;
  emit_custom_event(
      slot, CustomEventFields{LinuxHeapEventOperation::kReallocate, size, 0U,
                              static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(address)),
                              failed ? nullptr : result, failed, error_code});
}

void record_custom_free(CustomHookSlot& slot, void* address,
                        std::uint64_t /*freed_size*/) noexcept {
  // A declared free_size_arg is read by the replacement but intentionally not carried on
  // the wire: the trace FreeEvent has no size field and the writer applies the built-in
  // kFree invariant (requested_size == 0) to custom events (docs/CUSTOM_HOOKS.md §10.4).
  slot.successful_calls.fetch_add(1U, std::memory_order_relaxed);
  emit_custom_event(
      slot, CustomEventFields{LinuxHeapEventOperation::kFree, 0U, 0U,
                              static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(address)),
                              nullptr, false, 0});
}

}  // namespace

// The replacement bodies stay in ".nlxhk" so the patch rendezvous covers the uncounted
// window before each lifecycle entry; the helpers they call after entering are counted and
// stay outside the section. They are not noexcept and carry no try/catch, the Linux
// counterpart of the Windows SEH __finally discipline, and every route calls the original
// (or the restored target) exactly once with rax passed back to the caller untouched. On
// ELF they must be external-linkage inline functions: GCC gives inline functions a
// linkonce ".nlxhk" group, which is the only kind that can share the section with the
// inline gate/lifecycle helpers without a section type conflict (plain and linkonce
// ".nlxhk" symbols cannot mix in one TU). Because a compiled replacement cannot receive
// its hook point's identity through a register, each point binds one fixed thunk per role
// from the 32-slot pool; the thunk forwards its slot to the shared implementation (the
// same anchor-pool shape as the Windows custom_symbol_hooks.cpp, sized by
// ipc::kMaximumCustomHooks).

namespace detail {

NOLEAX_HOOK_SECTION_PUSH

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* custom_alloc_impl(CustomHookSlot* slot, void* a0, void* a1,
                                                         void* a2, void* a3, void* a4, void* a5,
                                                         void* a6, void* a7) {
  const ReplacementRoute route = slot->lifecycle.enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_custom_function(slot->alloc_restored_target)(a0, a1, a2, a3, a4, a5, a6, a7);
  } else {
    const GenericHookFunction original = load_custom_function(slot->alloc_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      note_custom_call(*slot, entry_kind);
    }
    result = original(a0, a1, a2, a3, a4, a5, a6, a7);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      void* const args[8U] = {a0, a1, a2, a3, a4, a5, a6, a7};
      std::uint64_t size = 0U;
      std::uint64_t count = 0U;
      bool size_valid = true;
      if (slot->calloc) {
        count = argument_value(args, slot->count_arg);
        const std::uint64_t element = argument_value(args, slot->size_arg);
        if (count != 0U && element > std::numeric_limits<std::uint64_t>::max() / count) {
          // The declared product overflows: record a failure event with a zero size.
          size_valid = false;
        } else {
          size = count * element;
        }
      } else {
        size = argument_value(args, slot->size_arg);
      }
      void* result_pointer = result;
      if (slot->result_arg != kNoArgumentSlot) {
        result_pointer = *static_cast<void**>(args[slot->result_arg]);
      }
      record_custom_allocate(*slot, size, count, result_pointer, size_valid, original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  slot->lifecycle.leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* custom_realloc_impl(CustomHookSlot* slot, void* a0, void* a1,
                                                           void* a2, void* a3, void* a4, void* a5,
                                                           void* a6, void* a7) {
  const ReplacementRoute route = slot->lifecycle.enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_custom_function(slot->realloc_restored_target)(a0, a1, a2, a3, a4, a5, a6, a7);
  } else {
    const GenericHookFunction original = load_custom_function(slot->realloc_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      note_custom_call(*slot, entry_kind);
    }
    result = original(a0, a1, a2, a3, a4, a5, a6, a7);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      void* const args[8U] = {a0, a1, a2, a3, a4, a5, a6, a7};
      const std::uint64_t size = argument_value(args, slot->size_arg);
      void* result_pointer = result;
      if (slot->result_arg != kNoArgumentSlot) {
        result_pointer = *static_cast<void**>(args[slot->result_arg]);
      }
      record_custom_reallocate(*slot, args[slot->ptr_arg], size, result_pointer, original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  slot->lifecycle.leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* custom_free_impl(CustomHookSlot* slot, void* a0, void* a1,
                                                        void* a2, void* a3, void* a4, void* a5,
                                                        void* a6, void* a7) {
  const ReplacementRoute route = slot->lifecycle.enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_custom_function(slot->free_restored_target)(a0, a1, a2, a3, a4, a5, a6, a7);
  } else {
    const GenericHookFunction original = load_custom_function(slot->free_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      note_custom_call(*slot, entry_kind);
    }
    result = original(a0, a1, a2, a3, a4, a5, a6, a7);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      void* const args[8U] = {a0, a1, a2, a3, a4, a5, a6, a7};
      const std::uint64_t freed_size =
          slot->free_size_arg != kNoArgumentSlot ? argument_value(args, slot->free_size_arg) : 0U;
      record_custom_free(*slot, args[slot->ptr_arg], freed_size);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  slot->lifecycle.leave_unscoped(route);
  return result;
}

#define NLXHK_CUSTOM_ALLOC_THUNK(index)                                                    \
  NOLEAX_HOOK_SECTION                                                                      \
  __attribute__((noinline)) inline void* custom_alloc_thunk_##index(                       \
      void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7) {    \
    return custom_alloc_impl(&g_custom_hook_slots[index], a0, a1, a2, a3, a4, a5, a6, a7); \
  }

#define NLXHK_CUSTOM_REALLOC_THUNK(index)                                                    \
  NOLEAX_HOOK_SECTION                                                                        \
  __attribute__((noinline)) inline void* custom_realloc_thunk_##index(                       \
      void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7) {      \
    return custom_realloc_impl(&g_custom_hook_slots[index], a0, a1, a2, a3, a4, a5, a6, a7); \
  }

#define NLXHK_CUSTOM_FREE_THUNK(index)                                                    \
  NOLEAX_HOOK_SECTION                                                                     \
  __attribute__((noinline)) inline void* custom_free_thunk_##index(                       \
      void* a0, void* a1, void* a2, void* a3, void* a4, void* a5, void* a6, void* a7) {   \
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

NOLEAX_HOOK_SECTION_POP

}  // namespace detail

namespace {

#define NLXHK_CUSTOM_ALLOC_THUNK_ENTRY(index) &detail::custom_alloc_thunk_##index,
#define NLXHK_CUSTOM_REALLOC_THUNK_ENTRY(index) &detail::custom_realloc_thunk_##index,
#define NLXHK_CUSTOM_FREE_THUNK_ENTRY(index) &detail::custom_free_thunk_##index,

const std::array<GenericHookFunction, kPoolSize> kAllocThunks{
    NLXHK_CUSTOM_SLOT_NUMBERS(NLXHK_CUSTOM_ALLOC_THUNK_ENTRY)};
const std::array<GenericHookFunction, kPoolSize> kReallocThunks{
    NLXHK_CUSTOM_SLOT_NUMBERS(NLXHK_CUSTOM_REALLOC_THUNK_ENTRY)};
const std::array<GenericHookFunction, kPoolSize> kFreeThunks{
    NLXHK_CUSTOM_SLOT_NUMBERS(NLXHK_CUSTOM_FREE_THUNK_ENTRY)};

[[nodiscard]] void* replacement_module_base() noexcept {
  return reinterpret_cast<void*>(&detail::custom_alloc_impl);
}

// One loaded module as seen through /proc/self/maps: the lowest mapping start (the runtime
// anchor for symbol offsets), its on-disk path, and the executable ranges of that path.
struct ModuleMapping {
  std::uint64_t base{0U};
  std::string path;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> executable_ranges;
};

[[nodiscard]] std::string_view path_basename(std::string_view path) noexcept {
  const std::size_t slash = path.find_last_of('/');
  return slash == std::string_view::npos ? path : path.substr(slash + 1U);
}

[[nodiscard]] std::uint64_t parse_hex_u64(std::string_view token, bool& ok) noexcept {
  std::uint64_t value = 0U;
  const auto result = std::from_chars(token.data(), token.data() + token.size(), value, 16);
  ok = result.ec == std::errc{} && result.ptr == token.data() + token.size();
  return value;
}

// One maps line: "<start>-<end> <perms> <offset> <dev> <inode> <path>". The path may be
// absent (anonymous mappings) and may itself contain spaces, so it is the rest of the line
// after the fifth field.
void note_maps_line(std::string_view line, const std::string& wanted_basename,
                    std::optional<ModuleMapping>& mapping) {
  const std::size_t dash = line.find('-');
  if (dash == std::string_view::npos) {
    return;
  }
  const std::size_t range_end = line.find(' ', dash + 1U);
  if (range_end == std::string_view::npos) {
    return;
  }
  bool start_ok = false;
  bool end_ok = false;
  const std::uint64_t start = parse_hex_u64(line.substr(0U, dash), start_ok);
  const std::uint64_t end = parse_hex_u64(line.substr(dash + 1U, range_end - dash - 1U), end_ok);
  if (!start_ok || !end_ok || end <= start) {
    return;
  }
  const std::size_t perms_end = line.find(' ', range_end + 1U);
  if (perms_end == std::string_view::npos) {
    return;
  }
  const std::string_view perms = line.substr(range_end + 1U, perms_end - range_end - 1U);
  // Skip the offset, device, and inode fields; the path is the rest of the line.
  std::size_t path_begin = perms_end + 1U;
  for (int skipped = 0; skipped < 3; ++skipped) {
    const std::size_t space = line.find(' ', path_begin);
    if (space == std::string_view::npos) {
      return;
    }
    path_begin = space + 1U;
  }
  while (path_begin < line.size() && line[path_begin] == ' ') {
    ++path_begin;
  }
  const std::string_view path = line.substr(path_begin);
  if (path.empty() || path.ends_with(" (deleted)")) {
    return;
  }
  if (path_basename(path) != wanted_basename) {
    return;
  }
  if (mapping.has_value() && mapping->path != path) {
    // Two loaded modules sharing a basename: the first match wins, like a loader search.
    return;
  }
  if (!mapping.has_value()) {
    mapping = ModuleMapping{};
    mapping->base = start;
    mapping->path = std::string{path};
  }
  mapping->base = (std::min)(mapping->base, start);
  if (perms.find('x') != std::string_view::npos) {
    mapping->executable_ranges.emplace_back(start, end);
  }
}

[[nodiscard]] std::optional<ModuleMapping> find_module_mapping(const std::string& module_basename) {
  const int fd = ::open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return std::nullopt;
  }
  std::string contents;
  std::array<char, 16'384U> buffer{};
  for (;;) {
    const ssize_t count = ::read(fd, buffer.data(), buffer.size());
    if (count <= 0) {
      break;
    }
    contents.append(buffer.data(), static_cast<std::size_t>(count));
  }
  ::close(fd);

  std::optional<ModuleMapping> mapping;
  std::size_t line_begin = 0U;
  while (line_begin < contents.size()) {
    const std::size_t newline = contents.find('\n', line_begin);
    const std::size_t line_end = newline == std::string::npos ? contents.size() : newline;
    note_maps_line(std::string_view{contents}.substr(line_begin, line_end - line_begin),
                   module_basename, mapping);
    if (newline == std::string::npos) {
      break;
    }
    line_begin = newline + 1U;
  }
  return mapping;
}

// Polls for the module at the fixed 100 ms granularity until wait_module_ms expires; a
// module that never shows up fails the whole point (none of its roles can resolve).
[[nodiscard]] ModuleMapping wait_for_module(const CustomHookSpec& spec) {
  const std::string module_basename{path_basename(spec.module)};
  std::optional<ModuleMapping> mapping = find_module_mapping(module_basename);
  if (mapping.has_value()) {
    return *mapping;
  }
  if (spec.wait_module_ms == 0U) {
    throw CustomHookError{spec.module, CustomHookFailureRole::kPoint,
                          CustomHookFailureReason::kModuleNotLoaded,
                          "custom hook module '" + spec.module + "' is not loaded"};
  }
  const auto wait =
      std::chrono::milliseconds{static_cast<std::chrono::milliseconds::rep>(spec.wait_module_ms)};
  const auto deadline = std::chrono::steady_clock::now() + wait;
  for (;;) {
    std::this_thread::sleep_for(kModulePollInterval);
    mapping = find_module_mapping(module_basename);
    if (mapping.has_value()) {
      return *mapping;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      throw CustomHookError{spec.module, CustomHookFailureRole::kPoint,
                            CustomHookFailureReason::kModuleNotLoaded,
                            "custom hook module '" + spec.module + "' did not load within " +
                                std::to_string(wait.count()) + " ms"};
    }
  }
}

struct OpenedFile {
  int descriptor{-1};
  ~OpenedFile() {
    if (descriptor >= 0) {
      ::close(descriptor);
    }
  }
};

[[nodiscard]] bool read_file_at(int fd, void* buffer, std::size_t size,
                                std::uint64_t offset) noexcept {
  return ::pread(fd, buffer, size, static_cast<off_t>(offset)) == static_cast<ssize_t>(size);
}

// The on-disk ELF layout needed to resolve an export: the lowest PT_LOAD virtual address
// (symbol values are link-time vaddrs; the runtime address is the maps base plus the
// symbol's offset above it) and the file bounds of .dynsym with its string table.
struct ElfModuleLayout {
  std::uint64_t min_load_vaddr{0U};
  std::uint64_t dynsym_offset{0U};
  std::uint64_t dynsym_size{0U};
  std::uint64_t dynstr_offset{0U};
  std::uint64_t dynstr_size{0U};
};

[[noreturn]] void throw_invalid_module_elf(const std::string& module, const std::string& path) {
  throw CustomHookError{
      module, CustomHookFailureRole::kPoint, CustomHookFailureReason::kOther,
      "custom hook module '" + module + "' at '" + path + "' is not a readable x86-64 ELF image"};
}

// Self-contained minimal ELF reader (no external dependencies; the agent must not link the
// analyzer). Runs at install time on the file backing the loaded module.
[[nodiscard]] ElfModuleLayout parse_elf_layout(int fd, const std::string& module,
                                               const std::string& path) {
  Elf64_Ehdr header;
  if (!read_file_at(fd, &header, sizeof(header), 0U) ||
      std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 || header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_machine != EM_X86_64 ||
      (header.e_type != ET_DYN && header.e_type != ET_EXEC) || header.e_phoff == 0U ||
      header.e_phnum == 0U || header.e_phnum >= 4096U || header.e_phentsize != sizeof(Elf64_Phdr) ||
      header.e_shoff == 0U || header.e_shnum == 0U || header.e_shnum >= 4096U ||
      header.e_shentsize != sizeof(Elf64_Shdr)) {
    throw_invalid_module_elf(module, path);
  }

  std::vector<Elf64_Phdr> segments(header.e_phnum);
  if (!read_file_at(fd, segments.data(), segments.size() * sizeof(Elf64_Phdr), header.e_phoff)) {
    throw_invalid_module_elf(module, path);
  }
  ElfModuleLayout layout;
  layout.min_load_vaddr = std::numeric_limits<std::uint64_t>::max();
  for (const Elf64_Phdr& segment : segments) {
    if (segment.p_type == PT_LOAD) {
      layout.min_load_vaddr =
          (std::min)(layout.min_load_vaddr, static_cast<std::uint64_t>(segment.p_vaddr));
    }
  }
  if (layout.min_load_vaddr == std::numeric_limits<std::uint64_t>::max()) {
    throw_invalid_module_elf(module, path);
  }

  std::vector<Elf64_Shdr> sections(header.e_shnum);
  if (!read_file_at(fd, sections.data(), sections.size() * sizeof(Elf64_Shdr), header.e_shoff)) {
    throw_invalid_module_elf(module, path);
  }
  bool found = false;
  for (const Elf64_Shdr& section : sections) {
    if (section.sh_type != SHT_DYNSYM) {
      continue;
    }
    if (section.sh_link >= sections.size() || sections[section.sh_link].sh_type != SHT_STRTAB ||
        section.sh_size > kMaximumDynamicSymbolCount * sizeof(Elf64_Sym) ||
        sections[section.sh_link].sh_size > kMaximumDynamicStringSize) {
      throw_invalid_module_elf(module, path);
    }
    layout.dynsym_offset = section.sh_offset;
    layout.dynsym_size = section.sh_size;
    layout.dynstr_offset = sections[section.sh_link].sh_offset;
    layout.dynstr_size = sections[section.sh_link].sh_size;
    found = true;
    break;
  }
  if (!found) {
    throw CustomHookError{
        module, CustomHookFailureRole::kPoint, CustomHookFailureReason::kOther,
        "custom hook module '" + module + "' at '" + path + "' has no dynamic symbol table"};
  }
  return layout;
}

[[nodiscard]] bool symbol_name_matches(const char* strings, std::uint64_t strings_size,
                                       std::uint32_t name_offset,
                                       std::string_view wanted) noexcept {
  if (name_offset >= strings_size) {
    return false;
  }
  const std::uint64_t available = strings_size - name_offset;
  if (wanted.size() + 1U > available) {
    return false;
  }
  return std::memcmp(strings + name_offset, wanted.data(), wanted.size()) == 0 &&
         strings[static_cast<std::uint64_t>(name_offset) + wanted.size()] == '\0';
}

enum class ExportLookup : std::uint8_t {
  kFound,
  kNotFound,
  kWrongType,
};

// Linear scan of the module's .dynsym for the export name. A defined non-function symbol
// (object, TLS, IFUNC resolver) is rejected rather than hooked at a wrong address.
[[nodiscard]] ExportLookup find_export_value(int fd, const ElfModuleLayout& layout,
                                             std::string_view name, std::uint64_t& value) {
  const std::size_t symbol_count = static_cast<std::size_t>(layout.dynsym_size / sizeof(Elf64_Sym));
  std::vector<Elf64_Sym> symbols(symbol_count);
  if (!read_file_at(fd, symbols.data(), symbols.size() * sizeof(Elf64_Sym), layout.dynsym_offset)) {
    return ExportLookup::kNotFound;
  }
  std::vector<char> strings(static_cast<std::size_t>(layout.dynstr_size));
  if (!read_file_at(fd, strings.data(), strings.size(), layout.dynstr_offset)) {
    return ExportLookup::kNotFound;
  }
  for (const Elf64_Sym& symbol : symbols) {
    if (ELF64_ST_BIND(symbol.st_info) == STB_LOCAL ||
        !symbol_name_matches(strings.data(), layout.dynstr_size, symbol.st_name, name)) {
      continue;
    }
    if (symbol.st_shndx == SHN_UNDEF || symbol.st_value == 0U) {
      return ExportLookup::kNotFound;
    }
    const unsigned char type = ELF64_ST_TYPE(symbol.st_info);
    if (type != STT_FUNC && type != STT_NOTYPE) {
      return ExportLookup::kWrongType;
    }
    value = symbol.st_value;
    return ExportLookup::kFound;
  }
  return ExportLookup::kNotFound;
}

[[nodiscard]] bool inside_executable_range(const ModuleMapping& mapping,
                                           std::uint64_t address) noexcept {
  for (const auto& range : mapping.executable_ranges) {
    if (address >= range.first && address < range.second) {
      return true;
    }
  }
  return false;
}

void validate_point_spec(const CustomHookSpec& spec) {
  // The controller validates the declaration; the agent re-checks the pieces the generic
  // replacements dereference so a hand-rolled StartCaptureRequest fails closed per point.
  if (spec.alloc.locator == CustomHookLocator::kNone ||
      spec.free.locator == CustomHookLocator::kNone) {
    throw CustomHookError{
        spec.module, CustomHookFailureRole::kPoint, CustomHookFailureReason::kOther,
        "custom hook point '" + spec.module + "' requires an alloc and a free role"};
  }
  const bool argument_out_of_range =
      spec.size_arg > kMaximumArgumentSlot || spec.ptr_arg > kMaximumArgumentSlot ||
      (spec.result_arg.has_value() && *spec.result_arg > kMaximumArgumentSlot) ||
      (spec.count_arg.has_value() && *spec.count_arg > kMaximumArgumentSlot) ||
      (spec.free_size_arg.has_value() && *spec.free_size_arg > kMaximumArgumentSlot);
  if (argument_out_of_range) {
    throw CustomHookError{
        spec.module, CustomHookFailureRole::kPoint, CustomHookFailureReason::kOther,
        "custom hook point '" + spec.module + "' declares an argument position outside 0-7"};
  }
  if (spec.calloc && !spec.count_arg.has_value()) {
    throw CustomHookError{
        spec.module, CustomHookFailureRole::kPoint, CustomHookFailureReason::kOther,
        "custom hook point '" + spec.module + "' declares the calloc kind without count_arg"};
  }
}

}  // namespace

class LinuxCustomSymbolHooks::Implementation final {
 public:
  Implementation(HookBackend& backend, LinuxHeapEventQueue& shared_queue,
                 std::vector<CustomHookSpec> specs, std::uint16_t maximum_stack_depth,
                 std::uint64_t minimum_capture_size)
      : backend_{&backend},
        event_queue_{&shared_queue},
        maximum_stack_depth_{maximum_stack_depth},
        minimum_capture_size_{minimum_capture_size} {
    if (specs.empty() || specs.size() > kPoolSize) {
      throw std::invalid_argument{"custom symbol hooks require between 1 and 32 hook points"};
    }
    if (maximum_stack_depth > kMaximumCapturedStackDepth) {
      throw std::invalid_argument{"maximum stack depth exceeds the fixed event capacity"};
    }
    CapturedStack preflight_stack;
    capture_current_stack(preflight_stack, maximum_stack_depth_);
    if (maximum_stack_depth_ != 0U && !stack_capture_succeeded(preflight_stack)) {
      throw HookBackendError{"_Unwind_Backtrace preflight failed"};
    }
    if (!acquire_hook_guard_runtime()) {
      throw HookBackendError{"the hook guard runtime is unavailable"};
    }
    guard_runtime_acquired_ = true;
    points_.reserve(specs.size());
    definitions_.reserve(specs.size());
    noleax::trace::ApiId api_id = noleax::trace::kCustomHookApiIdBase;
    for (auto& spec : specs) {
      const std::size_t slot_index =
          g_custom_hook_next_slot.fetch_add(1U, std::memory_order_acq_rel);
      if (slot_index >= kPoolSize) {
        throw HookBackendError{"the custom hook replacement slot pool is exhausted"};
      }
      PointState point;
      point.spec = std::move(spec);
      point.slot_index = slot_index;
      point.api_id = api_id;
      point.alloc.spec = point.spec.alloc;
      point.realloc.spec = point.spec.realloc;
      point.free.spec = point.spec.free;
      points_.push_back(std::move(point));
      CustomHookDefinition definition;
      definition.api_id = api_id;
      definition.module_name = points_.back().spec.module;
      definition.label = points_.back().spec.label;
      definitions_.push_back(std::move(definition));
      ++api_id;
    }
  }

  ~Implementation() {
    if (any_point_live()) {
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

  bool install() {
    const InternalThreadScope internal_thread;
    if (install_pass_ran_) {
      return false;
    }
    install_pass_ran_ = true;
    for (PointState& point : points_) {
      try {
        install_point(point);
      } catch (const CustomHookError& error) {
        // install_point leaves a failed point fully reverted. Record the failure and keep
        // installing the remaining points: one bad declaration must not silence the rest
        // of the capture (the failure surfaces through the trace completeness issue).
        failures_.push_back(
            CustomHookFailure{error.module(), error.role(), error.reason(), error.what()});
      }
    }
    return true;
  }

  [[nodiscard]] bool stop_recording(std::uint32_t max_yields) noexcept {
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
              max_yields)) {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] bool uninstall(std::uint32_t max_yields) noexcept {
    const InternalThreadScope internal_thread;
    for (PointState& point : points_) {
      if (!point.installed || point.teardown_pending) {
        continue;
      }
      CustomHookSlot& slot = g_custom_hook_slots[point.slot_index];
      slot.lifecycle.stop_recording();
      point.teardown_pending = true;
      // Never let Hoox flush here: revert first, publish the restored-target route, then
      // wait for replacement quiescence before releasing the trampoline lifetime leases.
      for (RoleState* role : {&point.alloc, &point.realloc, &point.free}) {
        if (role->installed) {
          static_cast<void>(backend_->uninstall(role->target, 0U));
        }
      }
      slot.lifecycle.route_to_target();
    }
    return try_finish_teardown(max_yields);
  }

  [[nodiscard]] bool flush(std::uint32_t max_yields) noexcept {
    if (any_point_live()) {
      return false;
    }
    return try_finish_teardown(max_yields);
  }

  [[nodiscard]] bool any_point_live() const noexcept {
    return std::any_of(points_.begin(), points_.end(), [](const PointState& point) {
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

  [[nodiscard]] std::size_t point_count() const noexcept { return points_.size(); }

  [[nodiscard]] noleax::trace::ApiId point_api_id(std::size_t point_index) const noexcept {
    return points_[point_index].api_id;
  }

  [[nodiscard]] LinuxCustomHookApiCounters counters(std::size_t point_index) const noexcept {
    const CustomHookSlot& slot = g_custom_hook_slots[points_[point_index].slot_index];
    LinuxCustomHookApiCounters snapshot;
    snapshot.replacement_calls = slot.replacement_calls.load(std::memory_order_relaxed);
    snapshot.recordable_calls = slot.recordable_calls.load(std::memory_order_relaxed);
    snapshot.recursive_calls = slot.recursive_calls.load(std::memory_order_relaxed);
    snapshot.internal_calls = slot.internal_calls.load(std::memory_order_relaxed);
    snapshot.successful_calls = slot.successful_calls.load(std::memory_order_relaxed);
    snapshot.failed_calls = slot.failed_calls.load(std::memory_order_relaxed);
    snapshot.filtered_calls = slot.filtered_calls.load(std::memory_order_relaxed);
    snapshot.dropped_events = slot.dropped_events.load(std::memory_order_relaxed);
    return snapshot;
  }

  [[nodiscard]] const std::vector<CustomHookDefinition>& definitions() const noexcept {
    return definitions_;
  }

  [[nodiscard]] const std::vector<CustomHookFailure>& failures() const noexcept {
    return failures_;
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
    CustomHookRoleSpec spec;
    void* target{nullptr};
    bool installed{false};
    bool lease_acquired{false};
  };

  struct PointState {
    CustomHookSpec spec;
    std::size_t slot_index{0U};
    noleax::trace::ApiId api_id{0U};
    RoleState alloc;
    RoleState realloc;
    RoleState free;
    bool installed{false};
    bool teardown_pending{false};
    bool retired{false};
  };

  void install_point(PointState& point) {
    validate_point_spec(point.spec);
    const ModuleMapping mapping = wait_for_module(point.spec);

    // The on-disk ELF is only needed to resolve export names; an RVA-only point skips the
    // parse, so a module whose file disappeared after loading can still host RVA hooks.
    OpenedFile module_file;
    ElfModuleLayout layout;
    const bool needs_symbols = point.alloc.spec.locator == CustomHookLocator::kExport ||
                               point.realloc.spec.locator == CustomHookLocator::kExport ||
                               point.free.spec.locator == CustomHookLocator::kExport;
    if (needs_symbols) {
      module_file.descriptor = ::open(mapping.path.c_str(), O_RDONLY | O_CLOEXEC);
      if (module_file.descriptor < 0) {
        throw CustomHookError{point.spec.module, CustomHookFailureRole::kPoint,
                              CustomHookFailureReason::kOther,
                              "custom hook module '" + point.spec.module +
                                  "' cannot be read from '" + mapping.path + "'"};
      }
      layout = parse_elf_layout(module_file.descriptor, point.spec.module, mapping.path);
    }
    point.alloc.target =
        resolve_role_target(point, point.alloc.spec, mapping, module_file.descriptor, layout,
                            CustomHookFailureRole::kAlloc);
    point.realloc.target =
        resolve_role_target(point, point.realloc.spec, mapping, module_file.descriptor, layout,
                            CustomHookFailureRole::kRealloc);
    point.free.target = resolve_role_target(point, point.free.spec, mapping, module_file.descriptor,
                                            layout, CustomHookFailureRole::kFree);

    CustomHookSlot& slot = g_custom_hook_slots[point.slot_index];
    slot.event_queue = event_queue_;
    slot.api_id = point.api_id;
    slot.size_arg = point.spec.size_arg;
    slot.ptr_arg = point.spec.ptr_arg;
    slot.result_arg = point.spec.result_arg.value_or(kNoArgumentSlot);
    slot.count_arg = point.spec.count_arg.value_or(kNoArgumentSlot);
    slot.free_size_arg = point.spec.free_size_arg.value_or(kNoArgumentSlot);
    slot.calloc = point.spec.calloc;
    slot.maximum_stack_depth = maximum_stack_depth_;
    slot.minimum_capture_size = minimum_capture_size_;
    slot.lifecycle.start_recording();
    try {
      install_role(point, point.alloc, slot.alloc_trampoline, slot.alloc_restored_target,
                   kAllocThunks[point.slot_index], CustomHookFailureRole::kAlloc);
      if (point.realloc.spec.locator != CustomHookLocator::kNone) {
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
                    std::atomic<void*>& restored_slot, GenericHookFunction thunk,
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

  [[nodiscard]] void* resolve_role_target(const PointState& point, const CustomHookRoleSpec& role,
                                          const ModuleMapping& mapping, int module_fd,
                                          const ElfModuleLayout& layout,
                                          CustomHookFailureRole failure_role) {
    const char* const role_name = custom_hook_role_name(failure_role);
    switch (role.locator) {
      case CustomHookLocator::kNone:
        return nullptr;
      case CustomHookLocator::kExport: {
        std::uint64_t value = 0U;
        const ExportLookup lookup = find_export_value(module_fd, layout, role.export_name, value);
        if (lookup == ExportLookup::kWrongType) {
          throw CustomHookError{point.spec.module, failure_role, CustomHookFailureReason::kOther,
                                std::string{"custom hook "} + role_name + " export '" +
                                    role.export_name + "' of module '" + point.spec.module +
                                    "' is not a function symbol"};
        }
        if (lookup != ExportLookup::kFound) {
          throw CustomHookError{
              point.spec.module, failure_role, CustomHookFailureReason::kExportNotFound,
              std::string{"custom hook "} + role_name + " export '" + role.export_name +
                  "' was not found in module '" + point.spec.module + "'"};
        }
        if (value < layout.min_load_vaddr ||
            value - layout.min_load_vaddr >
                std::numeric_limits<std::uint64_t>::max() - mapping.base) {
          throw CustomHookError{point.spec.module, failure_role, CustomHookFailureReason::kOther,
                                std::string{"custom hook "} + role_name + " export '" +
                                    role.export_name + "' of module '" + point.spec.module +
                                    "' resolves outside the loaded image"};
        }
        const std::uint64_t address = mapping.base + (value - layout.min_load_vaddr);
        if (!inside_executable_range(mapping, address)) {
          throw CustomHookError{point.spec.module, failure_role, CustomHookFailureReason::kOther,
                                std::string{"custom hook "} + role_name + " export '" +
                                    role.export_name + "' of module '" + point.spec.module +
                                    "' does not resolve into an executable mapping"};
        }
        return reinterpret_cast<void*>(static_cast<std::uintptr_t>(address));
      }
      case CustomHookLocator::kRva:
        if (role.rva > std::numeric_limits<std::uint64_t>::max() - mapping.base ||
            !inside_executable_range(mapping, mapping.base + role.rva)) {
          throw CustomHookError{point.spec.module, failure_role,
                                CustomHookFailureReason::kInvalidRva,
                                std::string{"custom hook "} + role_name +
                                    " RVA does not point into an executable mapping of module '" +
                                    point.spec.module + "'"};
        }
        return reinterpret_cast<void*>(static_cast<std::uintptr_t>(mapping.base + role.rva));
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

  [[nodiscard]] bool try_finish_teardown(std::uint32_t max_yields) noexcept {
    bool all_retired = true;
    for (PointState& point : points_) {
      if (!point.teardown_pending || point.retired) {
        continue;
      }
      CustomHookSlot& slot = g_custom_hook_slots[point.slot_index];
      if (!slot.lifecycle.wait_for_quiescence(max_yields)) {
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
      backend_flush_complete_ = backend_->flush(max_yields);
    }
    if (!backend_flush_complete_) {
      return false;
    }
    // The lifecycle counters cannot see a thread between a target's restored bytes and the
    // replacement's entry increment. All replacements share this module's ".nlxhk" section,
    // so one evacuation proof covers every point; on failure stay teardown-pending and let
    // a later flush retry.
    if (!module_rendezvous_complete_) {
      if (any_point_ever_installed() &&
          !verify_replacement_evacuated(hook_code_region(replacement_module_base()),
                                        kDefaultRendezvousMaxAttempts)) {
        return false;
      }
      module_rendezvous_complete_ = true;
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
    // Keep the trampoline leases and the guard reference: an in-transit thread can still
    // execute the replacements, so their backing storage stays alive for the process
    // lifetime. The slots live in process-lifetime storage already, and the shared event
    // queue is owned by the caller.
    guard_runtime_acquired_ = false;
  }

  HookBackend* backend_{nullptr};
  LinuxHeapEventQueue* event_queue_{nullptr};
  std::uint16_t maximum_stack_depth_{0U};
  std::uint64_t minimum_capture_size_{0U};
  std::vector<PointState> points_;
  std::vector<CustomHookDefinition> definitions_;
  std::vector<CustomHookFailure> failures_;
  bool install_pass_ran_{false};
  bool guard_runtime_acquired_{false};
  bool backend_flush_complete_{false};
  bool module_rendezvous_complete_{false};
};

LinuxCustomSymbolHooks::LinuxCustomSymbolHooks(HookBackend& backend,
                                               LinuxHeapEventQueue& shared_queue,
                                               std::vector<CustomHookSpec> specs,
                                               std::uint16_t maximum_stack_depth,
                                               std::uint64_t minimum_capture_size)
    : implementation_{std::make_unique<Implementation>(
          backend, shared_queue, std::move(specs), maximum_stack_depth, minimum_capture_size)} {}

LinuxCustomSymbolHooks::~LinuxCustomSymbolHooks() = default;

bool LinuxCustomSymbolHooks::install() { return implementation_->install(); }

bool LinuxCustomSymbolHooks::stop_recording(std::uint32_t max_yields) noexcept {
  return implementation_->stop_recording(max_yields);
}

bool LinuxCustomSymbolHooks::uninstall(std::uint32_t max_yields) noexcept {
  return implementation_->uninstall(max_yields);
}

bool LinuxCustomSymbolHooks::flush(std::uint32_t max_yields) noexcept {
  return implementation_->flush(max_yields);
}

bool LinuxCustomSymbolHooks::is_installed() const noexcept {
  return implementation_->any_point_live();
}

bool LinuxCustomSymbolHooks::is_recording() const noexcept {
  return implementation_->is_recording();
}

bool LinuxCustomSymbolHooks::has_pending_teardown() const noexcept {
  return implementation_->has_pending_teardown();
}

std::uint64_t LinuxCustomSymbolHooks::recording_in_flight_count() const noexcept {
  return implementation_->recording_in_flight_count();
}

std::size_t LinuxCustomSymbolHooks::point_count() const noexcept {
  return implementation_->point_count();
}

noleax::trace::ApiId LinuxCustomSymbolHooks::point_api_id(std::size_t point_index) const noexcept {
  return implementation_->point_api_id(point_index);
}

LinuxCustomHookApiCounters LinuxCustomSymbolHooks::counters(
    std::size_t point_index) const noexcept {
  return implementation_->counters(point_index);
}

const std::vector<noleax::trace::CustomHookDefinition>& LinuxCustomSymbolHooks::definitions()
    const noexcept {
  return implementation_->definitions();
}

const std::vector<noleax::trace::CustomHookFailure>& LinuxCustomSymbolHooks::failures()
    const noexcept {
  return implementation_->failures();
}

std::uint64_t LinuxCustomSymbolHooks::dropped_event_count() const noexcept {
  return implementation_->dropped_event_count();
}

std::uint64_t LinuxCustomSymbolHooks::recordable_call_count() const noexcept {
  return implementation_->recordable_call_count();
}

std::uint64_t LinuxCustomSymbolHooks::filtered_call_count() const noexcept {
  return implementation_->filtered_call_count();
}

}  // namespace noleax::agent::linux
