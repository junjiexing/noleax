// mremap and the MREMAP_* flags are GNU extensions; glibc exposes them only under
// _GNU_SOURCE. The g++ driver predefines it; the guard covers a bare cc1plus invocation and
// must precede every system header.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "noleax/agent/linux/virtual_memory_hooks.hpp"

#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/hook_section.hpp"
#include "noleax/agent/linux/agent_memory.hpp"
#include "noleax/agent/patch_rendezvous.hpp"
#include "noleax/agent/replacement_lifecycle.hpp"

namespace noleax::agent::linux {

struct VirtualMemoryHookChannelState {
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
    paired_records.store(0U, std::memory_order_relaxed);
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
  std::atomic<std::uint64_t> paired_records{0U};
};

// Hot-path state for the whole profile, owned by VirtualMemoryHooks and published to the
// replacements through active_channel_set before any target is patched. The event queue
// pointer and the capture parameters are plain fields: they are written before publication
// and never mutated while a replacement can run. The queue is owned here unless the
// shared-queue constructor borrowed one, in which case owned_event_queue stays null (the
// NtMemoryHookState pattern from agent/windows/nt_memory_hooks.cpp).
struct VirtualMemoryHookChannelSet {
  explicit VirtualMemoryHookChannelSet(std::size_t event_queue_capacity)
      : owned_event_queue{make_linux_heap_event_queue(event_queue_capacity)},
        event_queue{owned_event_queue.get()} {}

  explicit VirtualMemoryHookChannelSet(LinuxHeapEventQueue& shared_queue)
      : event_queue{&shared_queue} {}

  void reset_quiescent() noexcept {
    for (VirtualMemoryHookChannelState& channel : channels) {
      channel.reset_quiescent();
    }
  }

  std::array<VirtualMemoryHookChannelState, VirtualMemoryHooks::kChannelCount> channels{};
  std::unique_ptr<LinuxHeapEventQueue> owned_event_queue;
  LinuxHeapEventQueue* event_queue;
  std::uint16_t maximum_stack_depth{0U};
  std::uint64_t minimum_capture_size{0U};
};

namespace {

using MmapFunction = void* (*)(void*, std::size_t, int, int, int, off_t);
using MunmapFunction = int (*)(void*, std::size_t);
using MremapFunction = void* (*)(void*, std::size_t, std::size_t, int, ...);

constexpr std::size_t kRegistryBase = kGlibcHeapHookCount;
constexpr std::size_t kMmapChannel =
    static_cast<std::size_t>(LinuxLogicalHookApi::kMmap) - kRegistryBase;
constexpr std::size_t kMunmapChannel =
    static_cast<std::size_t>(LinuxLogicalHookApi::kMunmap) - kRegistryBase;
constexpr std::size_t kMremapChannel =
    static_cast<std::size_t>(LinuxLogicalHookApi::kMremap) - kRegistryBase;
constexpr std::size_t kChannelCount = VirtualMemoryHooks::kChannelCount;

// One lifecycle per channel, mirroring the per-API adapters on the Windows side. The
// lifecycles are process-wide: an abandoned teardown can leave a counted replacement
// able to enter them until the process exits.
std::array<ReplacementLifecycle, kChannelCount> channel_lifecycles;
std::atomic<VirtualMemoryHookChannelSet*> active_channel_set{nullptr};
std::array<std::atomic<void*>, kChannelCount> restored_targets{};
std::atomic<VirtualMemoryHooks*> active_owner{nullptr};
std::atomic<bool> installation_retired{false};

// Process-global VM completion counter (docs/TRACE_WRITER.md §VM interval model): every
// recorded mmap/munmap/mremap takes the next value immediately after the libc call returns
// and before any queueing, so the writer orders same-address generations by syscall
// completion instead of queue arrival. A thread preempted between the call and the fetch_add
// can still swap with a competitor, but that window is a handful of instructions versus the
// whole queueing path; queue order alone was unusable for same-address matching.
std::atomic<std::uint64_t> vm_completion_sequence{0U};

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

void release_owner(VirtualMemoryHooks* owner, bool clear_channel_set) noexcept {
  if (clear_channel_set) {
    active_channel_set.store(nullptr, std::memory_order_release);
  }
  VirtualMemoryHooks* expected = owner;
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

void note_entry_kind(VirtualMemoryHookChannelState& channel, HookEntryKind entry_kind) noexcept {
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
  std::uint64_t requested_address;
  std::uint64_t requested_size;
  std::uint64_t count;
  std::uint64_t alignment;
  std::uint64_t address;
  std::uint64_t protection;
  std::uint64_t map_flags;
  std::uint64_t section_handle;
  std::uint64_t section_offset;
  std::uint64_t completion_sequence;
  void* result;
  bool failed;
  int error_code;  // errno of the original call
};

[[nodiscard]] bool emit_event(VirtualMemoryHookChannelSet& set,
                              VirtualMemoryHookChannelState& channel,
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
        event.requested_address = fields.requested_address;
        event.requested_size = fields.requested_size;
        event.count = fields.count;
        event.alignment = fields.alignment;
        event.result_address = result_address;
        event.address = fields.address;
        event.protection = fields.protection;
        event.map_flags = fields.map_flags;
        event.section_handle = fields.section_handle;
        event.section_offset = fields.section_offset;
        event.completion_sequence = fields.completion_sequence;
        event.operation_result = operation_result;
        event.api_id = fields.api_id;
        event.operation = fields.operation;
        event.status =
            fields.failed ? LinuxHeapEventStatus::kFailure : LinuxHeapEventStatus::kSuccess;
        capture_current_stack(event.stack, maximum_stack_depth, 1U);
      });
  if (!queued) {
    increment_saturating(channel.dropped_events);
  }
  return queued;
}

void note_call_outcome(VirtualMemoryHookChannelState& channel, bool failed) noexcept {
  (failed ? channel.failed_calls : channel.successful_calls)
      .fetch_add(1U, std::memory_order_relaxed);
}

[[nodiscard]] std::uint64_t as_u64(const void* pointer) noexcept {
  return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(pointer));
}

// int arguments are zero-extended into the 64-bit event fields so a high sign bit never
// bleeds into the upper half.
[[nodiscard]] std::uint64_t zero_extended(int value) noexcept {
  return static_cast<std::uint64_t>(static_cast<std::uint32_t>(value));
}

// The minimum-size filter is creation-side only: an mmap below the floor is counted as
// filtered without an event, while munmap and mremap always record.
void record_vm_allocate(VirtualMemoryHookChannelSet& set, VirtualMemoryHookChannelState& channel,
                        const void* requested_address, std::uint64_t requested_size, int protection,
                        int flags, int fd, std::uint64_t section_offset, void* result,
                        int error_code) noexcept {
  const std::uint64_t completion_sequence =
      vm_completion_sequence.fetch_add(1U, std::memory_order_relaxed) + 1U;
  const bool failed = result == MAP_FAILED;
  note_call_outcome(channel, failed);
  if (requested_size < set.minimum_capture_size) {
    increment_saturating(channel.filtered_calls);
    return;
  }
  // Anonymous mappings carry fd -1, recorded as UINT64_MAX so the writer can tell them
  // apart from a real descriptor zero.
  const std::uint64_t section_handle =
      fd == -1 ? std::numeric_limits<std::uint64_t>::max() : static_cast<std::uint64_t>(fd);
  static_cast<void>(emit_event(
      set, channel,
      EventFields{kMmapApiId, LinuxHeapEventOperation::kVmAllocate, as_u64(requested_address),
                  requested_size, 0U, 0U, 0U, zero_extended(protection), zero_extended(flags),
                  section_handle, section_offset, completion_sequence, failed ? nullptr : result,
                  failed, error_code}));
}

void record_vm_unmap(VirtualMemoryHookChannelSet& set, VirtualMemoryHookChannelState& channel,
                     const void* address, std::uint64_t requested_size, int result,
                     int error_code) noexcept {
  const std::uint64_t completion_sequence =
      vm_completion_sequence.fetch_add(1U, std::memory_order_relaxed) + 1U;
  const bool failed = result == -1;
  note_call_outcome(channel, failed);
  static_cast<void>(emit_event(set, channel,
                               EventFields{kMunmapApiId, LinuxHeapEventOperation::kVmUnmap, 0U,
                                           requested_size, 0U, 0U, as_u64(address), 0U, 0U, 0U, 0U,
                                           completion_sequence, nullptr, failed, error_code}));
}

void record_vm_remap(VirtualMemoryHookChannelSet& set, VirtualMemoryHookChannelState& channel,
                     const void* old_address, std::uint64_t old_size, std::uint64_t new_size,
                     int flags, const void* requested_new_address, void* result,
                     int error_code) noexcept {
  const std::uint64_t completion_sequence =
      vm_completion_sequence.fetch_add(1U, std::memory_order_relaxed) + 1U;
  const bool failed = result == MAP_FAILED;
  note_call_outcome(channel, failed);
  const bool queued = emit_event(
      set, channel,
      EventFields{kMremapApiId, LinuxHeapEventOperation::kVmRemap, 0U, old_size, new_size,
                  as_u64(requested_new_address), as_u64(old_address), 0U, zero_extended(flags), 0U,
                  0U, completion_sequence, failed ? nullptr : result, failed, error_code});
  // A successful move makes the writer emit at least a VmFree+VmAllocate record pair for
  // this one call (the interval model may add eviction/trim records on top, which the
  // writer accounts itself). Keep the wire-space counter so the statistics reconciliation
  // sees the pair — but only when the event actually queued: a dropped call emits no
  // records, so counting its pair here would break the written+filtered+dropped == observed
  // conservation.
  if (queued && !failed && result != old_address) {
    channel.paired_records.fetch_add(1U, std::memory_order_relaxed);
  }
}

}  // namespace

// The replacement bodies stay in ".nlxhk" so the patch rendezvous covers the uncounted
// window before each lifecycle entry. They are not noexcept and carry no try/catch:
// glibc virtual-memory entry points never raise C++ exceptions, so the leave calls below
// are the Linux counterpart of the Windows SEH __finally discipline. Every route calls the
// original (or the restored target) exactly once. On ELF they must be external-linkage
// inline functions: GCC gives inline functions a linkonce ".nlxhk" group, which is the
// only kind that can share the section with the inline gate/lifecycle helpers without a
// section type conflict (plain and linkonce ".nlxhk" symbols cannot mix in one TU).

namespace detail {

NOLEAX_HOOK_SECTION_PUSH

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* replacement_mmap(void* address, std::size_t length,
                                                        int protection, int flags, int fd,
                                                        off_t offset) {
  const ReplacementRoute route = channel_lifecycles[kMmapChannel].enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_function<MmapFunction>(restored_targets[kMmapChannel])(
        address, length, protection, flags, fd, offset);
  } else {
    VirtualMemoryHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    VirtualMemoryHookChannelState& channel = set->channels[kMmapChannel];
    const MmapFunction original = load_function<MmapFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    result = original(address, length, protection, flags, fd, offset);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      record_vm_allocate(*set, channel, address, static_cast<std::uint64_t>(length), protection,
                         flags, fd, static_cast<std::uint64_t>(offset), result, original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kMmapChannel].leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline int replacement_munmap(void* address, std::size_t length) {
  const ReplacementRoute route = channel_lifecycles[kMunmapChannel].enter_unscoped();
  int result = 0;
  if (route == ReplacementRoute::kTarget) {
    result = load_function<MunmapFunction>(restored_targets[kMunmapChannel])(address, length);
  } else {
    VirtualMemoryHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    VirtualMemoryHookChannelState& channel = set->channels[kMunmapChannel];
    const MunmapFunction original = load_function<MunmapFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    result = original(address, length);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      record_vm_unmap(*set, channel, address, static_cast<std::uint64_t>(length), result,
                      original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kMunmapChannel].leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION
__attribute__((noinline)) inline void* replacement_mremap(void* old_address, std::size_t old_size,
                                                          std::size_t new_size, int flags, ...) {
  // The glibc wrapper declares mremap variadic; callers pass new_address only together with
  // MREMAP_FIXED. glibc fetches the slot whenever MREMAP_MAYMOVE is set, so the forward to
  // the original does the same (the kernel ignores it without MREMAP_FIXED), but the event
  // records it only when MREMAP_FIXED makes it semantically real — a MAYMOVE-only call has
  // no fifth argument and reading it would record garbage.
  void* requested_new_address = nullptr;
  if ((flags & MREMAP_MAYMOVE) != 0) {
    va_list arguments;
    va_start(arguments, flags);
    requested_new_address = va_arg(arguments, void*);
    va_end(arguments);
  }
  void* const recorded_new_address = (flags & MREMAP_FIXED) != 0 ? requested_new_address : nullptr;
  const ReplacementRoute route = channel_lifecycles[kMremapChannel].enter_unscoped();
  void* result = nullptr;
  if (route == ReplacementRoute::kTarget) {
    result = load_function<MremapFunction>(restored_targets[kMremapChannel])(
        old_address, old_size, new_size, flags, requested_new_address);
  } else {
    VirtualMemoryHookChannelSet* const set = active_channel_set.load(std::memory_order_acquire);
    if (set == nullptr) {
      fail_broken_replacement_route();
    }
    VirtualMemoryHookChannelState& channel = set->channels[kMremapChannel];
    const MremapFunction original = load_function<MremapFunction>(channel.original_trampoline);
    const HookEntryKind entry_kind = enter_hook_invocation_unscoped();
    if (route == ReplacementRoute::kRecord) {
      channel.replacement_calls.fetch_add(1U, std::memory_order_relaxed);
      note_entry_kind(channel, entry_kind);
    }
    result = original(old_address, old_size, new_size, flags, requested_new_address);
    const int original_errno = errno;
    if (route == ReplacementRoute::kRecord && entry_kind == HookEntryKind::kOutermost) {
      record_vm_remap(*set, channel, old_address, static_cast<std::uint64_t>(old_size),
                      static_cast<std::uint64_t>(new_size), flags, recorded_new_address, result,
                      original_errno);
    }
    errno = original_errno;
    leave_hook_invocation_unscoped();
  }
  channel_lifecycles[kMremapChannel].leave_unscoped(route);
  return result;
}

NOLEAX_HOOK_SECTION_POP

}  // namespace detail

namespace {

const std::array<void*, kChannelCount> kReplacementAddresses{
    reinterpret_cast<void*>(&detail::replacement_mmap),
    reinterpret_cast<void*>(&detail::replacement_munmap),
    reinterpret_cast<void*>(&detail::replacement_mremap),
};

}  // namespace

VirtualMemoryHooks::VirtualMemoryHooks(HookBackend& backend, std::size_t event_queue_capacity,
                                       std::uint16_t maximum_stack_depth,
                                       std::uint64_t minimum_capture_size)
    : channel_set_{std::make_unique<VirtualMemoryHookChannelSet>(event_queue_capacity)},
      backend_{&backend},
      maximum_stack_depth_{maximum_stack_depth},
      minimum_capture_size_{minimum_capture_size} {
  initialize();
}

VirtualMemoryHooks::VirtualMemoryHooks(HookBackend& backend, LinuxHeapEventQueue& shared_queue,
                                       std::uint16_t maximum_stack_depth,
                                       std::uint64_t minimum_capture_size)
    : channel_set_{std::make_unique<VirtualMemoryHookChannelSet>(shared_queue)},
      backend_{&backend},
      maximum_stack_depth_{maximum_stack_depth},
      minimum_capture_size_{minimum_capture_size} {
  initialize();
}

void VirtualMemoryHooks::initialize() {
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

VirtualMemoryHooks::~VirtualMemoryHooks() {
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

bool VirtualMemoryHooks::install() {
  const InternalThreadScope internal_thread;
  if (state_ == State::kInstalled || state_ == State::kTeardownPending) {
    return false;
  }
  if (installation_retired.load(std::memory_order_acquire)) {
    return false;
  }
  VirtualMemoryHooks* expected = nullptr;
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
    const LinuxHookRegistryEntry& entry = kLinuxHookRegistry[kRegistryBase + index];
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
  // mmap64 resolves to the same address as mmap on x86-64 glibc (off_t is already 64-bit);
  // hooking it separately would double-install the same target and fail already-replaced,
  // so the registry covers mmap only and mmap64 callers are recorded through it.

  if (!backend_->acquire_trampoline_lifetime_lease()) {
    static_cast<void>(::dlclose(libc));
    release_owner(this, true);
    return false;
  }
  trampoline_lease_acquired_ = true;

  // Publish every routing input before any target is patched; install_fast writes the
  // original trampoline slot before Hoox activates the replacement. A shared queue belongs
  // to another profile: it is never reset here, the owner coordinates that.
  channel_set_->reset_quiescent();
  if (channel_set_->owned_event_queue != nullptr) {
    channel_set_->owned_event_queue->reset_quiescent();
  }
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

bool VirtualMemoryHooks::stop_recording(QuiescenceDeadline deadline) noexcept {
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

bool VirtualMemoryHooks::uninstall(QuiescenceDeadline deadline) noexcept {
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

bool VirtualMemoryHooks::flush(QuiescenceDeadline deadline) noexcept {
  if (state_ == State::kInactive || state_ == State::kRetired) {
    return true;
  }
  if (state_ == State::kInstalled) {
    return false;
  }
  return try_finish_teardown(deadline);
}

bool VirtualMemoryHooks::is_installed() const noexcept { return state_ == State::kInstalled; }

bool VirtualMemoryHooks::is_recording() const noexcept {
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

bool VirtualMemoryHooks::has_pending_teardown() const noexcept {
  return state_ == State::kTeardownPending;
}

std::uint64_t VirtualMemoryHooks::recording_in_flight_count() const noexcept {
  std::uint64_t total = 0U;
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    const std::uint64_t value = channel_lifecycles[index].recording_in_flight();
    total = value > std::numeric_limits<std::uint64_t>::max() - total
                ? std::numeric_limits<std::uint64_t>::max()
                : total + value;
  }
  return total;
}

VirtualMemoryHookApiCounters VirtualMemoryHooks::counters(LinuxLogicalHookApi api) const noexcept {
  const VirtualMemoryHookChannelState& channel =
      channel_set_->channels[static_cast<std::size_t>(api) - kRegistryBase];
  VirtualMemoryHookApiCounters snapshot;
  snapshot.replacement_calls = channel.replacement_calls.load(std::memory_order_relaxed);
  snapshot.recordable_calls = channel.recordable_calls.load(std::memory_order_relaxed);
  snapshot.recursive_calls = channel.recursive_calls.load(std::memory_order_relaxed);
  snapshot.internal_calls = channel.internal_calls.load(std::memory_order_relaxed);
  snapshot.successful_calls = channel.successful_calls.load(std::memory_order_relaxed);
  snapshot.failed_calls = channel.failed_calls.load(std::memory_order_relaxed);
  snapshot.filtered_calls = channel.filtered_calls.load(std::memory_order_relaxed);
  snapshot.dropped_events = channel.dropped_events.load(std::memory_order_relaxed);
  snapshot.paired_records = channel.paired_records.load(std::memory_order_relaxed);
  return snapshot;
}

LinuxHeapEventQueue& VirtualMemoryHooks::event_queue() noexcept {
  return *channel_set_->event_queue;
}

const LinuxHeapEventQueue& VirtualMemoryHooks::event_queue() const noexcept {
  return *channel_set_->event_queue;
}

std::uint16_t VirtualMemoryHooks::maximum_stack_depth() const noexcept {
  return maximum_stack_depth_;
}

std::uint64_t VirtualMemoryHooks::minimum_capture_size() const noexcept {
  return minimum_capture_size_;
}

void* VirtualMemoryHooks::target_address(LinuxLogicalHookApi api) const noexcept {
  return targets_[static_cast<std::size_t>(api) - kRegistryBase];
}

bool VirtualMemoryHooks::try_finish_teardown(QuiescenceDeadline deadline) noexcept {
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
  // replacement's entry increment. All three replacements share this module's ".nlxhk"
  // section, so one evacuation proof covers every channel; on failure stay
  // teardown-pending and let a later flush retry.
  if (!verify_replacement_evacuated(hook_code_region(kReplacementAddresses[0]),
                                    kDefaultRendezvousMaxAttempts)) {
    return false;
  }
  finish_teardown();
  return true;
}

void VirtualMemoryHooks::finish_teardown() noexcept {
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    channel_set_->channels[index].original_trampoline.store(nullptr, std::memory_order_release);
  }
  state_ = State::kRetired;
  installation_retired.store(false, std::memory_order_release);
  release_owner(this, true);
}

void VirtualMemoryHooks::abandon_pending_teardown() noexcept {
  for (std::size_t index = 0U; index < kChannelCount; ++index) {
    channel_lifecycles[index].route_to_target();
  }
  if (trampoline_lease_acquired_) {
    // A counted replacement may still read the channel set and its original trampoline
    // slots. Transfer the set — and with it the queue when this profile owns one — plus the
    // guard reference to process lifetime; the retained backend lease keeps Hoox from
    // flushing the trampolines those replacements still call.
    static_cast<void>(channel_set_.release());
    guard_runtime_acquired_ = false;
    release_owner(this, false);
  } else {
    release_owner(this, true);
  }
  state_ = State::kRetired;
}

}  // namespace noleax::agent::linux
