#include "noleax/agent/linux/glibc_heap_hooks.hpp"

#include <dlfcn.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/hook_section.hpp"
#include "noleax/agent/patch_rendezvous.hpp"
#include "noleax/agent/replacement_lifecycle.hpp"

namespace noleax::agent::linux {

struct GlibcHeapHookChannelState {
  void reset_quiescent() noexcept {
    original_trampoline.store(nullptr, std::memory_order_relaxed);
    replacement_calls.store(0U, std::memory_order_relaxed);
    recordable_calls.store(0U, std::memory_order_relaxed);
    recursive_calls.store(0U, std::memory_order_relaxed);
    internal_calls.store(0U, std::memory_order_relaxed);
    successful_calls.store(0U, std::memory_order_relaxed);
    failed_calls.store(0U, std::memory_order_relaxed);
    filtered_calls.store(0U, std::memory_order_relaxed);
    dropped_events.store(0U, std::memory_order_relaxed);
  }

  OriginalTrampolineSlot original_trampoline{nullptr};
  std::atomic<std::uint64_t> replacement_calls{0U};
  std::atomic<std::uint64_t> recordable_calls{0U};
  std::atomic<std::uint64_t> recursive_calls{0U};
  std::atomic<std::uint64_t> internal_calls{0U};
  std::atomic<std::uint64_t> successful_calls{0U};
  std::atomic<std::uint64_t> failed_calls{0U};
  std::atomic<std::uint64_t> filtered_calls{0U};
  std::atomic<std::uint64_t> dropped_events{0U};
};

// Hot-path state for the whole profile, owned by GlibcHeapHooks and published to the
// replacements through active_channel_set before any target is patched. The event queue
// pointer and the capture parameters are plain fields: they are written before
// publication and never mutated while a replacement can run.
struct GlibcHeapHookChannelSet {
  explicit GlibcHeapHookChannelSet(LinuxHeapEventQueue& queue) : event_queue{&queue} {}

  void reset_quiescent() noexcept {
    for (GlibcHeapHookChannelState& channel : channels) {
      channel.reset_quiescent();
    }
  }

  std::array<GlibcHeapHookChannelState, GlibcHeapHooks::kChannelCount> channels{};
  LinuxHeapEventQueue* event_queue;
  std::uint16_t maximum_stack_depth{0U};
  std::uint64_t minimum_capture_size{0U};
};

namespace {

using MallocFunction = void* (*)(std::size_t);
using CallocFunction = void* (*)(std::size_t, std::size_t);
using ReallocFunction = void* (*)(void*, std::size_t);
using FreeFunction = void (*)(void*);
using PosixMemalignFunction = int (*)(void**, std::size_t, std::size_t);
using AlignedAllocFunction = void* (*)(std::size_t, std::size_t);
using MemalignFunction = void* (*)(std::size_t, std::size_t);
using ReallocarrayFunction = void* (*)(void*, std::size_t, std::size_t);

constexpr std::size_t kMallocChannel = static_cast<std::size_t>(LinuxLogicalHookApi::kMalloc);
constexpr std::size_t kCallocChannel = static_cast<std::size_t>(LinuxLogicalHookApi::kCalloc);
constexpr std::size_t kReallocChannel = static_cast<std::size_t>(LinuxLogicalHookApi::kRealloc);
constexpr std::size_t kFreeChannel = static_cast<std::size_t>(LinuxLogicalHookApi::kFree);
constexpr std::size_t kPosixMemalignChannel =
    static_cast<std::size_t>(LinuxLogicalHookApi::kPosixMemalign);
constexpr std::size_t kAlignedAllocChannel =
    static_cast<std::size_t>(LinuxLogicalHookApi::kAlignedAlloc);
constexpr std::size_t kMemalignChannel = static_cast<std::size_t>(LinuxLogicalHookApi::kMemalign);
constexpr std::size_t kReallocarrayChannel =
    static_cast<std::size_t>(LinuxLogicalHookApi::kReallocarray);
constexpr std::size_t kChannelCount = GlibcHeapHooks::kChannelCount;

// One lifecycle per channel, mirroring the per-API adapters on the Windows side. The
// lifecycles are process-wide: an abandoned teardown can leave a counted replacement
// able to enter them until the process exits.
std::array<ReplacementLifecycle, kChannelCount> channel_lifecycles;
std::atomic<GlibcHeapHookChannelSet*> active_channel_set{nullptr};
std::array<std::atomic<void*>, kChannelCount> restored_targets{};
std::atomic<GlibcHeapHooks*> active_owner{nullptr};
std::atomic<bool> installation_retired{false};

static_assert(OriginalTrampolineSlot::is_always_lock_free);
static_assert(std::atomic<std::uint64_t>::is_always_lock_free);
static_assert(decltype(active_channel_set)::is_always_lock_free);

[[noreturn]] void fail_broken_replacement_route() noexcept { std::abort(); }

void increment_saturating(std::atomic<std::uint64_t>& value) noexcept {
  std::uint64_t current = value.load(std::memory_order_relaxed);
  while (current != std::numeric_limits<std::uint64_t>::max() &&
         !value.compare_exchange_weak(current, current + 1U, std::memory_order_relaxed,
                                      std::memory_order_relaxed)) {
  }
}

template <typename Function>
[[nodiscard]] Function load_function(const std::atomic<void*>& slot) noexcept {
  void* const address = slot.load(std::memory_order_acquire);
  if (address == nullptr) {
    fail_broken_replacement_route();
  }
  return reinterpret_cast<Function>(address);
}

void release_owner(GlibcHeapHooks* owner, bool clear_channel_set) noexcept {
  if (clear_channel_set) {
    active_channel_set.store(nullptr, std::memory_order_release);
  }
  GlibcHeapHooks* expected = owner;
  static_cast<void>(active_owner.compare_exchange_strong(
      expected, nullptr, std::memory_order_release, std::memory_order_relaxed));
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

void note_entry_kind(GlibcHeapHookChannelState& channel, HookEntryKind entry_kind) noexcept {
  switch (entry_kind) {
    case HookEntryKind::kOutermost:
      channel.recordable_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
    case HookEntryKind::kRecursive:
      channel.recursive_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
    case HookEntryKind::kInternalThread:
      channel.internal_calls.fetch_add(1U, std::memory_order_relaxed);
      break;
  }
}

struct EventFields {
  noleax::trace::ApiId api_id;
  LinuxHeapEventOperation operation;
  std::uint64_t requested_size;
  std::uint64_t count;
  std::uint64_t alignment;
  std::uint64_t address;
  void* result;
  bool failed;
  int error_code;  // errno of the original call (posix_memalign: its return code)
};

void emit_event(GlibcHeapHookChannelSet& set, GlibcHeapHookChannelState& channel,
                const EventFields& fields) noexcept {
  const std::uint16_t maximum_stack_depth = set.maximum_stack_depth;
  const std::uint64_t result_address =
      static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(fields.result));
  const std::uint32_t operation_result =
      fields.failed ? static_cast<std::uint32_t>(fields.error_code) : 0U;
  const bool queued = set.event_queue->try_emplace(
      [&fields, maximum_stack_depth, result_address, operation_result](
          LinuxHeapEvent& event, std::uint64_t queue_sequence) noexcept {
        event = LinuxHeapEvent{};
        event.queue_sequence = queue_sequence;
        event.monotonic_ticks = monotonic_ticks_nanoseconds();
        event.thread_id = current_thread_id();
        event.requested_size = fields.requested_size;
        event.count = fields.count;
        event.alignment = fields.alignment;
        event.result_address = result_address;
        event.address = fields.address;
        event.operation_result = operation_result;
        event.api_id = fields.api_id;
        event.operation = fields.operation;
        event.status =
            fields.failed ? LinuxHeapEventStatus::kFailure : LinuxHeapEventStatus::kSuccess;
        capture_current_stack(event.stack, maximum_stack_depth, 2U);
      });
  if (!queued) {
    increment_saturating(channel.dropped_events);
  }
}

void note_call_outcome(GlibcHeapHookChannelState& channel, bool failed) noexcept {
  (failed ? channel.failed_calls : channel.successful_calls)
      .fetch_add(1U, std::memory_order_relaxed);
}

// The minimum-size filter is creation-side only: allocate operations below the floor are
// counted as filtered without an event, while reallocate and free always record.
void record_allocate(GlibcHeapHookChannelSet& set, GlibcHeapHookChannelState& channel,
                     noleax::trace::ApiId api_id, std::uint64_t requested_size, std::uint64_t count,
                     std::uint64_t alignment, void* result, bool failed, int error_code) noexcept {
  note_call_outcome(channel, failed);
  if (requested_size < set.minimum_capture_size) {
    increment_saturating(channel.filtered_calls);
    return;
  }
  emit_event(set, channel,
             EventFields{api_id, LinuxHeapEventOperation::kAllocate, requested_size, count,
                         alignment, 0U, result, failed, error_code});
}

void record_reallocate(GlibcHeapHookChannelSet& set, GlibcHeapHookChannelState& channel,
                       noleax::trace::ApiId api_id, void* address, std::uint64_t requested_size,
                       std::uint64_t count, void* result, bool failed, int error_code) noexcept {
  note_call_outcome(channel, failed);
  emit_event(set, channel,
             EventFields{api_id, LinuxHeapEventOperation::kReallocate, requested_size, count, 0U,
                         static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(address)),
                         result, failed, error_code});
}

void record_free(GlibcHeapHookChannelSet& set, GlibcHeapHookChannelState& channel,
                 noleax::trace::ApiId api_id, void* address) noexcept {
  note_call_outcome(channel, false);
  emit_event(set, channel,
             EventFields{api_id, LinuxHeapEventOperation::kFree, 0U, 0U, 0U,
                         static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(address)),
                         nullptr, false, 0});
}

}  // namespace

// The replacement bodies stay in ".nlxhk" so the patch rendezvous covers the uncounted
// window before each lifecycle entry. They are not noexcept and carry no try/catch:
// glibc allocator entry points never raise C++ exceptions, so the leave calls below are
// the Linux counterpart of the Windows SEH __finally discipline. Every route calls the
// original (or the restored target) exactly once. On ELF they must be external-linkage
// inline functions: GCC gives inline functions a linkonce ".nlxhk" group, which is the
// only kind that can share the section with the inline gate/lifecycle helpers without a
// section type conflict (plain and linkonce ".nlxhk" symbols cannot mix in one TU).

namespace detail {

NOLEAX_HOOK_SECTION_PUSH

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* replacement_malloc(std::size_t size) {
  const ReplacementRoute route = channel_lifecycles[kMallocChannel].enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_function<MallocFunction>(restored_targets[kMallocChannel])(size);
  } else {
    GlibcHeapHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    GlibcHeapHookChannelState& channel = set->channels[kMallocChannel];
    const MallocFunction original = load_function<MallocFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    result = original(size);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      record_allocate(*set, channel, kMallocApiId, static_cast<std::uint64_t>(size), 0U, 0U, result,
                      result == nullptr, original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kMallocChannel].leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* replacement_calloc(std::size_t nmemb, std::size_t size) {
  const ReplacementRoute route = channel_lifecycles[kCallocChannel].enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_function<CallocFunction>(restored_targets[kCallocChannel])(nmemb, size);
  } else {
    GlibcHeapHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    GlibcHeapHookChannelState& channel = set->channels[kCallocChannel];
    const CallocFunction original = load_function<CallocFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    result = original(nmemb, size);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      // The product wraps on overflow: glibc fails the call, and the wrapped value is what
      // the writer needs to see. Do not clamp.
      record_allocate(*set, channel, kCallocApiId, static_cast<std::uint64_t>(nmemb * size),
                      static_cast<std::uint64_t>(nmemb), 0U, result, result == nullptr,
                      original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kCallocChannel].leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* replacement_realloc(void* pointer, std::size_t size) {
  const ReplacementRoute route = channel_lifecycles[kReallocChannel].enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_function<ReallocFunction>(restored_targets[kReallocChannel])(pointer, size);
  } else {
    GlibcHeapHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    GlibcHeapHookChannelState& channel = set->channels[kReallocChannel];
    const ReallocFunction original = load_function<ReallocFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    result = original(pointer, size);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      // realloc(p, 0) frees and returns nullptr on glibc: a success, not a failure.
      const bool failed = result == nullptr && size != 0U;
      record_reallocate(*set, channel, kReallocApiId, pointer, static_cast<std::uint64_t>(size), 0U,
                        result, failed, original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kReallocChannel].leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void replacement_free(void* pointer) {
  const ReplacementRoute route = channel_lifecycles[kFreeChannel].enter_unscoped();
  if (route == ReplacementRoute::kTarget) {
    load_function<FreeFunction>(restored_targets[kFreeChannel])(pointer);
  } else {
    GlibcHeapHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    GlibcHeapHookChannelState& channel = set->channels[kFreeChannel];
    const FreeFunction original = load_function<FreeFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    original(pointer);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      record_free(*set, channel, kFreeApiId, pointer);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kFreeChannel].leave_unscoped(route);
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline int replacement_posix_memalign(void** memptr,
                                                                std::size_t alignment,
                                                                std::size_t size) {
  const ReplacementRoute route = channel_lifecycles[kPosixMemalignChannel].enter_unscoped();
  int result = 0;
  if (route == ReplacementRoute::kTarget) {
    result = load_function<PosixMemalignFunction>(restored_targets[kPosixMemalignChannel])(
        memptr, alignment, size);
  } else {
    GlibcHeapHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    GlibcHeapHookChannelState& channel = set->channels[kPosixMemalignChannel];
    const PosixMemalignFunction original =
        load_function<PosixMemalignFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    result = original(memptr, alignment, size);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      // posix_memalign reports through its return code, not errno; the code doubles as the
      // event's operation_result. *memptr is only meaningful on success.
      const bool failed = result != 0;
      record_allocate(*set, channel, kPosixMemalignApiId, static_cast<std::uint64_t>(size), 0U,
                      static_cast<std::uint64_t>(alignment), failed ? nullptr : *memptr, failed,
                      result);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kPosixMemalignChannel].leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* replacement_aligned_alloc(std::size_t alignment,
                                                                 std::size_t size) {
  const ReplacementRoute route = channel_lifecycles[kAlignedAllocChannel].enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_function<AlignedAllocFunction>(restored_targets[kAlignedAllocChannel])(alignment,
                                                                                         size);
  } else {
    GlibcHeapHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    GlibcHeapHookChannelState& channel = set->channels[kAlignedAllocChannel];
    const AlignedAllocFunction original =
        load_function<AlignedAllocFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    result = original(alignment, size);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      record_allocate(*set, channel, kAlignedAllocApiId, static_cast<std::uint64_t>(size), 0U,
                      static_cast<std::uint64_t>(alignment), result, result == nullptr,
                      original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kAlignedAllocChannel].leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* replacement_memalign(std::size_t alignment,
                                                            std::size_t size) {
  const ReplacementRoute route = channel_lifecycles[kMemalignChannel].enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_function<MemalignFunction>(restored_targets[kMemalignChannel])(alignment, size);
  } else {
    GlibcHeapHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    GlibcHeapHookChannelState& channel = set->channels[kMemalignChannel];
    const MemalignFunction original = load_function<MemalignFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    result = original(alignment, size);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      record_allocate(*set, channel, kMemalignApiId, static_cast<std::uint64_t>(size), 0U,
                      static_cast<std::uint64_t>(alignment), result, result == nullptr,
                      original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kMemalignChannel].leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* replacement_reallocarray(void* pointer, std::size_t nmemb,
                                                                std::size_t size) {
  const ReplacementRoute route = channel_lifecycles[kReallocarrayChannel].enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_function<ReallocarrayFunction>(restored_targets[kReallocarrayChannel])(
        pointer, nmemb, size);
  } else {
    GlibcHeapHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    GlibcHeapHookChannelState& channel = set->channels[kReallocarrayChannel];
    const ReallocarrayFunction original =
        load_function<ReallocarrayFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    result = original(pointer, nmemb, size);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      // Same wrapped-product and zero-size rules as calloc/realloc. A glibc reallocarray
      // that reaches the public realloc through the PLT re-enters the realloc replacement
      // with the guard held; that inner call classifies as recursive and records nothing.
      const std::uint64_t requested_size = static_cast<std::uint64_t>(nmemb * size);
      const bool failed = result == nullptr && requested_size != 0U;
      record_reallocate(*set, channel, kReallocarrayApiId, pointer, requested_size,
                        static_cast<std::uint64_t>(nmemb), result, failed, original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kReallocarrayChannel].leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION_POP

}  // namespace detail

namespace {

const std::array<void*, kChannelCount> kReplacementAddresses{
    reinterpret_cast<void*>(&detail::replacement_malloc),
    reinterpret_cast<void*>(&detail::replacement_calloc),
    reinterpret_cast<void*>(&detail::replacement_realloc),
    reinterpret_cast<void*>(&detail::replacement_free),
    reinterpret_cast<void*>(&detail::replacement_posix_memalign),
    reinterpret_cast<void*>(&detail::replacement_aligned_alloc),
    reinterpret_cast<void*>(&detail::replacement_memalign),
    reinterpret_cast<void*>(&detail::replacement_reallocarray),
};

}  // namespace

GlibcHeapHooks::GlibcHeapHooks(HookBackend& backend, std::size_t event_queue_capacity,
                               std::uint16_t maximum_stack_depth,
                               std::uint64_t minimum_capture_size)
    : owned_event_queue_{std::make_unique<LinuxHeapEventQueue>(event_queue_capacity)},
      channel_set_{std::make_unique<GlibcHeapHookChannelSet>(*owned_event_queue_)},
      backend_{&backend},
      maximum_stack_depth_{maximum_stack_depth},
      minimum_capture_size_{minimum_capture_size} {
  if (maximum_stack_depth_ > kMaximumCapturedStackDepth) {
    throw HookBackendError{"maximum stack depth exceeds the fixed event capacity"};
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
  channel_set_->maximum_stack_depth = maximum_stack_depth_;
  channel_set_->minimum_capture_size = minimum_capture_size_;
}

GlibcHeapHooks::~GlibcHeapHooks() {
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

bool GlibcHeapHooks::install() {
  const InternalThreadScope internal_thread;
  if (state_ == State::kInstalled || state_ == State::kTeardownPending) {
    return false;
  }
  if (installation_retired.load(std::memory_order_acquire)) {
    return false;
  }
  GlibcHeapHooks* expected = nullptr;
  if (!active_owner.compare_exchange_strong(expected, this, std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
    return false;
  }

  void* const libc = ::dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
  if (libc == nullptr) {
    release_owner(this, true);
    return false;
  }
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    const LinuxHookRegistryEntry& entry = kLinuxHookRegistry[index];
    char name[64];
    if (entry.canonical_name.size() >= sizeof(name)) {
      static_cast<void>(::dlclose(libc));
      release_owner(this, true);
      return false;
    }
    std::memcpy(name, entry.canonical_name.data(), entry.canonical_name.size());
    name[entry.canonical_name.size()] = '\0';
    void* const address = ::dlsym(libc, name);
    if (address == nullptr) {
      static_cast<void>(::dlclose(libc));
      release_owner(this, true);
      return false;
    }
    targets_[index] = address;
  }

  if (!backend_->acquire_trampoline_lifetime_lease()) {
    static_cast<void>(::dlclose(libc));
    release_owner(this, true);
    return false;
  }
  trampoline_lease_acquired_ = true;

  // Publish every routing input before any target is patched; install_fast writes the
  // original trampoline slot before Hoox activates the replacement.
  channel_set_->reset_quiescent();
  owned_event_queue_->reset_quiescent();
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    restored_targets[index].store(targets_[index], std::memory_order_release);
  }
  active_channel_set.store(channel_set_.get(), std::memory_order_release);
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    channel_lifecycles[index].start_recording();
  }
  replacements_quiescent_ = false;
  backend_teardown_complete_ = false;
  state_ = State::kInstalled;

  std::size_t installed = 0U;
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    FastHookResult result;
    try {
      result = backend_->install_fast(targets_[index], kReplacementAddresses[index],
                                      &channel_set_->channels[index].original_trampoline);
    } catch (...) {
      break;
    }
    if (!result.installed()) {
      break;
    }
    ++installed;
  }
  static_cast<void>(::dlclose(libc));

  if (installed != kChannelCount) {
    // Roll back whatever was activated through the same path a full uninstall uses.
    static_cast<void>(uninstall());
    return false;
  }
  installation_retired.store(true, std::memory_order_release);
  return true;
}

bool GlibcHeapHooks::stop_recording(QuiescenceDeadline deadline) noexcept {
  if (state_ != State::kInstalled) {
    return state_ == State::kInactive || state_ == State::kRetired;
  }
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    channel_lifecycles[index].stop_recording();
  }
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    if (!channel_lifecycles[index].wait_for_recording_quiescence(deadline)) {
      return false;
    }
  }
  return true;
}

bool GlibcHeapHooks::uninstall(QuiescenceDeadline deadline) noexcept {
  const InternalThreadScope internal_thread;
  if (state_ == State::kInactive || state_ == State::kRetired) {
    return true;
  }
  if (state_ == State::kTeardownPending) {
    return try_finish_teardown(deadline);
  }

  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    channel_lifecycles[index].stop_recording();
  }
  state_ = State::kTeardownPending;

  // Revert every physical target before waiting on any channel: the shared backend's
  // flush cannot finish a trampoline while another target of this profile is still
  // installed. The restored-target route then serves any thread that entered a
  // replacement just before its revert landed.
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    if (targets_[index] != nullptr) {
      static_cast<void>(backend_->uninstall(targets_[index], std::chrono::steady_clock::now()));
    }
    channel_lifecycles[index].route_to_target();
  }
  return try_finish_teardown(deadline);
}

bool GlibcHeapHooks::flush(QuiescenceDeadline deadline) noexcept {
  if (state_ == State::kInactive || state_ == State::kRetired) {
    return true;
  }
  if (state_ == State::kInstalled) {
    return false;
  }
  return try_finish_teardown(deadline);
}

bool GlibcHeapHooks::is_installed() const noexcept { return state_ == State::kInstalled; }

bool GlibcHeapHooks::is_recording() const noexcept {
  if (state_ != State::kInstalled) {
    return false;
  }
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    if (channel_lifecycles[index].route() == ReplacementRoute::kRecord) {
      return true;
    }
  }
  return false;
}

bool GlibcHeapHooks::has_pending_teardown() const noexcept {
  return state_ == State::kTeardownPending;
}

std::uint64_t GlibcHeapHooks::recording_in_flight_count() const noexcept {
  std::uint64_t total = 0U;
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    const std::uint64_t value = channel_lifecycles[index].recording_in_flight();
    total = value > std::numeric_limits<std::uint64_t>::max() - total
                ? std::numeric_limits<std::uint64_t>::max()
                : total + value;
  }
  return total;
}

GlibcHeapHookApiCounters GlibcHeapHooks::counters(LinuxLogicalHookApi api) const noexcept {
  const GlibcHeapHookChannelState& channel = channel_set_->channels[static_cast<std::size_t>(api)];
  GlibcHeapHookApiCounters snapshot;
  snapshot.replacement_calls = channel.replacement_calls.load(std::memory_order_relaxed);
  snapshot.recordable_calls = channel.recordable_calls.load(std::memory_order_relaxed);
  snapshot.recursive_calls = channel.recursive_calls.load(std::memory_order_relaxed);
  snapshot.internal_calls = channel.internal_calls.load(std::memory_order_relaxed);
  snapshot.successful_calls = channel.successful_calls.load(std::memory_order_relaxed);
  snapshot.failed_calls = channel.failed_calls.load(std::memory_order_relaxed);
  snapshot.filtered_calls = channel.filtered_calls.load(std::memory_order_relaxed);
  snapshot.dropped_events = channel.dropped_events.load(std::memory_order_relaxed);
  return snapshot;
}

LinuxHeapEventQueue& GlibcHeapHooks::event_queue() noexcept { return *owned_event_queue_; }

const LinuxHeapEventQueue& GlibcHeapHooks::event_queue() const noexcept {
  return *owned_event_queue_;
}

std::uint16_t GlibcHeapHooks::maximum_stack_depth() const noexcept { return maximum_stack_depth_; }

std::uint64_t GlibcHeapHooks::minimum_capture_size() const noexcept {
  return minimum_capture_size_;
}

void* GlibcHeapHooks::target_address(LinuxLogicalHookApi api) const noexcept {
  return targets_[static_cast<std::size_t>(api)];
}

bool GlibcHeapHooks::try_finish_teardown(QuiescenceDeadline deadline) noexcept {
  if (!replacements_quiescent_) {
    for (std::size_t index = 0U; index < kChannelCount; ++index) {
      if (!channel_lifecycles[index].wait_for_quiescence(deadline)) {
        return false;
      }
    }
    replacements_quiescent_ = true;
    if (trampoline_lease_acquired_) {
      backend_->release_trampoline_lifetime_lease();
      trampoline_lease_acquired_ = false;
    }
  }
  if (!backend_teardown_complete_) {
    backend_teardown_complete_ = backend_->flush(deadline);
  }
  if (!backend_teardown_complete_) {
    return false;
  }
  // The lifecycle counters cannot see a thread between a target's restored bytes and the
  // replacement's entry increment. All eight replacements share this module's ".nlxhk"
  // section, so one evacuation proof covers every channel; on failure stay
  // teardown-pending and let a later flush retry.
  if (!verify_replacement_evacuated(hook_code_region(kReplacementAddresses[0]),
                                    kDefaultRendezvousMaxAttempts)) {
    return false;
  }
  finish_teardown();
  return true;
}

void GlibcHeapHooks::finish_teardown() noexcept {
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    channel_set_->channels[index].original_trampoline.store(nullptr, std::memory_order_release);
  }
  state_ = State::kRetired;
  installation_retired.store(false, std::memory_order_release);
  release_owner(this, true);
}

void GlibcHeapHooks::abandon_pending_teardown() noexcept {
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    channel_lifecycles[index].route_to_target();
  }
  if (trampoline_lease_acquired_) {
    // A counted replacement may still read the channel set and its original trampoline
    // slots. Transfer the set, the queue, and the guard reference to process lifetime;
    // the retained backend lease keeps Hoox from flushing the trampolines those
    // replacements still call.
    static_cast<void>(channel_set_.release());
    static_cast<void>(owned_event_queue_.release());
    guard_runtime_acquired_ = false;
    release_owner(this, false);
  } else {
    release_owner(this, true);
  }
  state_ = State::kRetired;
}

}  // namespace noleax::agent::linux
