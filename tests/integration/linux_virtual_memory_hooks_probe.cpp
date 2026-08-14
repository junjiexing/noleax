// End-to-end probe for the linux-virtual-memory profile (docs/LINUX_PORT_PLAN.md M4):
// installs VirtualMemoryHooks on this process's own glibc virtual-memory entry points and
// proves the adapter contract in-process — event field mapping (anonymous versus
// file-backed section handle/offset, the mremap requested-new-address slot), errno
// preservation, the creation-side minimum-size filter, counter conservation,
// stop/uninstall silence, and multi-threaded churn.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <thread>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/agent/linux/hook_registry.hpp"
#include "noleax/agent/linux/stack_capture.hpp"
#include "noleax/agent/linux/virtual_memory_hooks.hpp"

namespace {

using noleax::agent::linux::LinuxHeapEvent;
using noleax::agent::linux::LinuxHeapEventOperation;
using noleax::agent::linux::LinuxHeapEventQueue;
using noleax::agent::linux::LinuxHeapEventStatus;
using noleax::agent::linux::LinuxLogicalHookApi;
using noleax::agent::linux::stack_capture_succeeded;
using noleax::agent::linux::VirtualMemoryHookApiCounters;
using noleax::agent::linux::VirtualMemoryHooks;

constexpr std::uint64_t kAnonymousSectionHandle = std::numeric_limits<std::uint64_t>::max();

unsigned check_failures = 0;

void check(bool condition, const char* message) {
  if (!condition) {
    std::printf("FAIL: %s\n", message);
    ++check_failures;
  }
}

std::size_t drain_events(LinuxHeapEventQueue& queue, std::vector<LinuxHeapEvent>& out) {
  LinuxHeapEvent event;
  const std::size_t before = out.size();
  while (queue.try_pop(event)) {
    out.push_back(event);
  }
  return out.size() - before;
}

struct ExpectedEvent {
  std::uint32_t api_id;
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
  std::uint64_t result_address;
  LinuxHeapEventStatus status;
  std::uint32_t operation_result;
};

std::uint64_t as_u64(const void* pointer) {
  return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(pointer));
}

void verify_event(const LinuxHeapEvent& event, const ExpectedEvent& expected,
                  std::uint64_t expected_sequence, std::uint64_t main_thread_id,
                  std::uint16_t stack_depth) {
  if (event.api_id != expected.api_id || event.operation != expected.operation ||
      event.requested_address != expected.requested_address ||
      event.requested_size != expected.requested_size || event.count != expected.count ||
      event.alignment != expected.alignment || event.address != expected.address ||
      event.protection != expected.protection || event.map_flags != expected.map_flags ||
      event.section_handle != expected.section_handle ||
      event.section_offset != expected.section_offset ||
      event.result_address != expected.result_address || event.status != expected.status ||
      event.operation_result != expected.operation_result) {
    std::printf(
        "FAIL: event seq=%llu api=%u op=%u req_addr=%llu size=%llu count=%llu align=%llu "
        "addr=%llu prot=%llu flags=%llu handle=%llu off=%llu result=%llu status=%u "
        "op_result=%u\n",
        static_cast<unsigned long long>(event.queue_sequence), static_cast<unsigned>(event.api_id),
        static_cast<unsigned>(event.operation),
        static_cast<unsigned long long>(event.requested_address),
        static_cast<unsigned long long>(event.requested_size),
        static_cast<unsigned long long>(event.count),
        static_cast<unsigned long long>(event.alignment),
        static_cast<unsigned long long>(event.address),
        static_cast<unsigned long long>(event.protection),
        static_cast<unsigned long long>(event.map_flags),
        static_cast<unsigned long long>(event.section_handle),
        static_cast<unsigned long long>(event.section_offset),
        static_cast<unsigned long long>(event.result_address), static_cast<unsigned>(event.status),
        static_cast<unsigned>(event.operation_result));
    ++check_failures;
    return;
  }
  check(event.queue_sequence == expected_sequence, "queue sequence is not contiguous from 1");
  check(event.thread_id == main_thread_id, "event thread id matches the caller thread");
  check(event.monotonic_ticks != 0U, "event carries monotonic ticks");
  check(event.completion_sequence != 0U, "VM event carries a completion sequence");
  check(event.stack.requested_depth == stack_depth, "event stack requested depth");
  check(stack_capture_succeeded(event.stack), "event stack captured");
  check(event.stack.frame_count <= stack_depth, "event stack depth within the requested limit");
}

void verify_scripted_phase(const std::vector<LinuxHeapEvent>& events, const ExpectedEvent* expected,
                           std::size_t count, std::uint64_t first_sequence,
                           std::uint64_t main_thread_id, std::uint16_t stack_depth) {
  std::uint64_t previous_ticks = 0U;
  std::uint64_t previous_completion = 0U;
  for (std::size_t index = 0U; index < count; ++index) {
    verify_event(events[index], expected[index], first_sequence + static_cast<std::uint64_t>(index),
                 main_thread_id, stack_depth);
    check(events[index].monotonic_ticks >= previous_ticks, "monotonic ticks are non-decreasing");
    previous_ticks = events[index].monotonic_ticks;
    // Single-threaded scripted phases complete syscalls in call order.
    check(events[index].completion_sequence > previous_completion,
          "completion sequences strictly increase within a scripted phase");
    previous_completion = events[index].completion_sequence;
  }
}

struct ChurnResult {
  std::uint64_t operations{0U};
};

void churn_worker(std::uint64_t seed, std::uint64_t iterations, ChurnResult* result) {
  std::uint64_t state = seed;
  for (std::uint64_t i = 0U; i < iterations; ++i) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    const std::size_t size = 0x1000U * (1U + static_cast<std::size_t>((state >> 33U) % 4U));
    void* const pointer =
        ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pointer != MAP_FAILED) {
      static_cast<unsigned char*>(pointer)[0] = static_cast<unsigned char>(i);
      static_cast<unsigned char*>(pointer)[size - 1U] = static_cast<unsigned char>(state);
      static_cast<void>(::munmap(pointer, size));
      ++result->operations;
    }
  }
}

}  // namespace

int main() {
  // Warm up stdio and the virtual-memory path before any hook goes live; everything between
  // install and the final drain must stay free of incidental mmap traffic on this thread.
  std::printf("linux_virtual_memory_hooks_probe\n");
  {
    void* const warm =
        ::mmap(nullptr, 0x1000U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (warm != MAP_FAILED) {
      static_cast<void>(::munmap(warm, 0x1000U));
    }
  }

  constexpr std::size_t kQueueCapacity = 1024U;
  constexpr std::uint16_t kStackDepth = 32U;
  constexpr std::uint64_t kMinCaptureSize = 256U;
  constexpr std::size_t kPhaseACount = 9U;
  constexpr std::size_t kPhaseDCount = 5U;
  constexpr std::size_t kBigSize = 0x800000U;      // 8 MiB
  constexpr std::size_t kBiggerSize = 0x1000000U;  // 16 MiB

  std::vector<LinuxHeapEvent> events_a;
  std::vector<LinuxHeapEvent> events_d;
  std::vector<LinuxHeapEvent> events_b;
  std::vector<LinuxHeapEvent> events_c;
  events_a.reserve(64U);
  events_d.reserve(16U);
  events_b.reserve(2048U);
  events_c.reserve(16U);

  // The file-backed case: plant a marker at the mapped offset before install so the
  // scripted phase issues no fd bookkeeping of its own.
  char temp_path[] = "/tmp/noleax_vm_probe_XXXXXX";
  const int temp_fd = ::mkstemp(temp_path);
  check(temp_fd >= 0, "mkstemp creates the backing file");
  if (temp_fd < 0) {
    return 1;
  }
  static_cast<void>(::unlink(temp_path));
  check(::ftruncate(temp_fd, static_cast<off_t>(kBigSize)) == 0, "ftruncate grows the file");
  const std::array<unsigned char, 16> marker{0x4eU, 0x4fU, 0x4cU, 0x45U, 0x41U, 0x58U,
                                             0x2dU, 0x56U, 0x4dU, 0x2dU, 0x70U, 0x72U,
                                             0x6fU, 0x62U, 0x65U, 0x21U};
  const ssize_t written = ::pwrite(temp_fd, marker.data(), marker.size(), 0x1000);
  check(written == static_cast<ssize_t>(marker.size()), "pwrite plants the marker");

  noleax::agent::HookBackend backend;
  VirtualMemoryHooks hooks{backend, kQueueCapacity, kStackDepth, kMinCaptureSize};

  // The shared-queue constructor borrows the queue instead of owning one; it cannot install
  // while another profile owns the channels, but the queue identity is provable up front.
  {
    VirtualMemoryHooks shared{backend, hooks.event_queue(), kStackDepth, kMinCaptureSize};
    check(&shared.event_queue() == &hooks.event_queue(),
          "shared-queue constructor borrows the owner queue");
  }

  if (!hooks.install()) {
    std::printf("FAIL: VirtualMemoryHooks::install\n");
    return 1;
  }
  check(hooks.is_installed(), "profile is installed");
  check(hooks.is_recording(), "profile is recording after install");

  const std::uint64_t main_tid = static_cast<std::uint64_t>(::syscall(SYS_gettid));

  // Counter baseline: install-time bookkeeping (dlopen/dlsym) classifies as internal, so
  // the exact scripted assertions below run on deltas from this snapshot.
  std::array<VirtualMemoryHookApiCounters, 3> baseline{};
  for (std::size_t index = 0U; index < baseline.size(); ++index) {
    baseline[index] = hooks.counters(
        static_cast<LinuxLogicalHookApi>(noleax::agent::linux::kGlibcHeapHookCount + index));
  }

  // ---- scripted sequence (phase A) ----
  // Every successful mapping is written (or read) before it is unmapped; the accesses also
  // prove the hooked path returns usable memory. Base addresses are captured as integers
  // immediately: the expectation table must not dereference an unmapped range.
  errno = EDOM;
  void* const a1 =
      ::mmap(nullptr, 0x2000U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  const int errno_after_a1 = errno;
  check(a1 != MAP_FAILED, "anonymous mmap succeeds");
  check(errno_after_a1 == EDOM, "errno preserved across a successful mmap");
  std::memset(a1, 0x11, 0x2000U);
  check(::munmap(a1, 0x2000U) == 0, "anonymous munmap succeeds");

  void* const small =
      ::mmap(nullptr, 64U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  check(small != MAP_FAILED, "below-floor mmap still succeeds");
  check(::munmap(small, 64U) == 0, "below-floor munmap succeeds");

  void* const a2 = ::mmap(nullptr, 0x3000U, PROT_READ, MAP_PRIVATE, temp_fd, 0x1000);
  check(a2 != MAP_FAILED, "file-backed mmap succeeds");
  check(std::memcmp(a2, marker.data(), marker.size()) == 0,
        "file-backed mapping exposes the file contents");
  check(::munmap(a2, 0x3000U) == 0, "file-backed munmap succeeds");

  void* const a3 =
      ::mmap(nullptr, 0x1000U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  check(a3 != MAP_FAILED, "remap source mmap succeeds");
  std::memset(a3, 0x5a, 0x1000U);
  errno = EDOM;
  void* const a4 = ::mremap(a3, 0x1000U, 0x4000U, MREMAP_MAYMOVE);
  const int errno_after_remap = errno;
  check(a4 != MAP_FAILED, "mremap growth succeeds");
  check(errno_after_remap == EDOM, "errno preserved across a successful mremap");
  bool grow_preserved = true;
  for (std::size_t i = 0U; i < 0x1000U; ++i) {
    grow_preserved = grow_preserved && static_cast<const unsigned char*>(a4)[i] == 0x5aU;
  }
  check(grow_preserved, "mremap growth preserves the old contents");

  static_cast<void>(::close(temp_fd));
  errno = 0;
  void* const bad = ::mmap(nullptr, 0x1000U, PROT_READ, MAP_SHARED, temp_fd, 0);
  const int errno_after_bad = errno;
  check(bad == MAP_FAILED, "mmap on a closed descriptor fails");
  check(errno_after_bad == EBADF, "errno after the bad-fd mmap is EBADF");

  check(::munmap(a4, 0x4000U) == 0, "grown mapping munmap succeeds");

  const std::size_t drained_a = drain_events(hooks.event_queue(), events_a);

  // ---- mremap move (phase D) ----
  // A big anonymous mapping is grown with MREMAP_MAYMOVE (the event carries the old and new
  // base), then moved to a reserved destination with MREMAP_FIXED (the event's alignment
  // field carries the requested new address). Contents must survive both remaps.
  void* const big =
      ::mmap(nullptr, kBigSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  check(big != MAP_FAILED, "big mmap succeeds");
  for (std::size_t page = 0U; page < kBigSize / 0x1000U; ++page) {
    static_cast<unsigned char*>(big)[page * 0x1000U] = static_cast<unsigned char>(page);
  }
  void* const grown = ::mremap(big, kBigSize, kBiggerSize, MREMAP_MAYMOVE);
  check(grown != MAP_FAILED, "big mremap growth succeeds");
  void* const dest = ::mmap(nullptr, kBiggerSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  check(dest != MAP_FAILED, "move destination reservation succeeds");
  void* const moved =
      ::mremap(grown, kBiggerSize, kBiggerSize, MREMAP_MAYMOVE | MREMAP_FIXED, dest);
  check(moved == dest, "MREMAP_FIXED move lands on the requested address");
  bool move_preserved = moved == dest;
  if (move_preserved) {
    for (std::size_t page = 0U; page < kBigSize / 0x1000U; ++page) {
      move_preserved = move_preserved && static_cast<const unsigned char*>(moved)[page * 0x1000U] ==
                                             static_cast<unsigned char>(page);
    }
  }
  check(move_preserved, "contents survive the MAYMOVE growth and the FIXED move");
  check(::munmap(moved, kBiggerSize) == 0, "moved mapping munmap succeeds");

  const std::size_t drained_d = drain_events(hooks.event_queue(), events_d);

  std::array<VirtualMemoryHookApiCounters, 3> scripted{};
  for (std::size_t index = 0U; index < scripted.size(); ++index) {
    scripted[index] = hooks.counters(
        static_cast<LinuxLogicalHookApi>(noleax::agent::linux::kGlibcHeapHookCount + index));
  }

  // ---- multi-threaded churn (phase B) ----
  constexpr std::uint64_t kChurnIterations = 500U;
  std::array<ChurnResult, 4> churn_results{};
  {
    std::array<std::thread, 4> workers;
    for (std::size_t index = 0U; index < workers.size(); ++index) {
      workers[index] = std::thread{churn_worker, 0x9e3779b97f4a7c15ULL * (index + 1U),
                                   kChurnIterations, &churn_results[index]};
    }
    for (std::thread& worker : workers) {
      worker.join();
    }
  }
  const std::size_t drained_b = drain_events(hooks.event_queue(), events_b);

  std::array<VirtualMemoryHookApiCounters, 3> pre_stop{};
  for (std::size_t index = 0U; index < pre_stop.size(); ++index) {
    pre_stop[index] = hooks.counters(
        static_cast<LinuxLogicalHookApi>(noleax::agent::linux::kGlibcHeapHookCount + index));
  }

  check(hooks.stop_recording(), "stop_recording");
  check(!hooks.is_recording(), "profile is not recording after stop_recording");

  // kOriginal routing: mappings still work, nothing is counted or queued.
  {
    void* const quiet =
        ::mmap(nullptr, 0x2000U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(quiet != MAP_FAILED, "mmap still works after stop_recording");
    std::memset(quiet, 0xee, 0x2000U);
    check(::munmap(quiet, 0x2000U) == 0, "munmap still works after stop_recording");
  }
  const std::size_t drained_c = drain_events(hooks.event_queue(), events_c);

  std::array<VirtualMemoryHookApiCounters, 3> post_stop{};
  for (std::size_t index = 0U; index < post_stop.size(); ++index) {
    post_stop[index] = hooks.counters(
        static_cast<LinuxLogicalHookApi>(noleax::agent::linux::kGlibcHeapHookCount + index));
  }

  check(hooks.uninstall(), "uninstall");
  check(!hooks.is_installed(), "profile is uninstalled");

  // Post-uninstall: the original entry points are fully restored.
  {
    void* const after =
        ::mmap(nullptr, 0x1000U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(after != MAP_FAILED, "post-uninstall mmap succeeds");
    std::memset(after, 0x5a, 0x1000U);
    check(::munmap(after, 0x1000U) == 0, "post-uninstall munmap succeeds");
  }
  const std::size_t drained_post = drain_events(hooks.event_queue(), events_c);

  // ---- verification ----

  check(drained_a == kPhaseACount, "phase A event count");
  check(drained_d == kPhaseDCount, "phase D event count");
  check(drained_c == 0U, "no events after stop_recording");
  check(drained_post == 0U, "no events after uninstall");
  check(drained_b != 0U, "churn produced events");

  if (drained_a == kPhaseACount) {
    const std::array<ExpectedEvent, kPhaseACount> expected{{
        // Anonymous mmap + munmap; the 64-byte mmap was filtered, its munmap was not.
        {18U, LinuxHeapEventOperation::kVmAllocate, 0U, 0x2000U, 0U, 0U, 0U, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS, kAnonymousSectionHandle, 0U, as_u64(a1),
         LinuxHeapEventStatus::kSuccess, 0U},
        {19U, LinuxHeapEventOperation::kVmUnmap, 0U, 0x2000U, 0U, 0U, as_u64(a1), 0U, 0U, 0U, 0U,
         0U, LinuxHeapEventStatus::kSuccess, 0U},
        {19U, LinuxHeapEventOperation::kVmUnmap, 0U, 64U, 0U, 0U, as_u64(small), 0U, 0U, 0U, 0U, 0U,
         LinuxHeapEventStatus::kSuccess, 0U},
        // File-backed mapping: the descriptor and offset are recorded verbatim.
        {18U, LinuxHeapEventOperation::kVmAllocate, 0U, 0x3000U, 0U, 0U, 0U, PROT_READ, MAP_PRIVATE,
         static_cast<std::uint64_t>(temp_fd), 0x1000U, as_u64(a2), LinuxHeapEventStatus::kSuccess,
         0U},
        {19U, LinuxHeapEventOperation::kVmUnmap, 0U, 0x3000U, 0U, 0U, as_u64(a2), 0U, 0U, 0U, 0U,
         0U, LinuxHeapEventStatus::kSuccess, 0U},
        // Remap source, the MAYMOVE growth, and the EBADF failure on the closed descriptor.
        {18U, LinuxHeapEventOperation::kVmAllocate, 0U, 0x1000U, 0U, 0U, 0U, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS, kAnonymousSectionHandle, 0U, as_u64(a3),
         LinuxHeapEventStatus::kSuccess, 0U},
        {20U, LinuxHeapEventOperation::kVmRemap, 0U, 0x1000U, 0x4000U, 0U, as_u64(a3), 0U,
         MREMAP_MAYMOVE, 0U, 0U, as_u64(a4), LinuxHeapEventStatus::kSuccess, 0U},
        {18U, LinuxHeapEventOperation::kVmAllocate, 0U, 0x1000U, 0U, 0U, 0U, PROT_READ, MAP_SHARED,
         static_cast<std::uint64_t>(temp_fd), 0U, 0U, LinuxHeapEventStatus::kFailure, EBADF},
        {19U, LinuxHeapEventOperation::kVmUnmap, 0U, 0x4000U, 0U, 0U, as_u64(a4), 0U, 0U, 0U, 0U,
         0U, LinuxHeapEventStatus::kSuccess, 0U},
    }};
    verify_scripted_phase(events_a, expected.data(), expected.size(), 1U, main_tid, kStackDepth);
  }

  if (drained_d == kPhaseDCount) {
    const std::array<ExpectedEvent, kPhaseDCount> expected{{
        {18U, LinuxHeapEventOperation::kVmAllocate, 0U, kBigSize, 0U, 0U, 0U,
         PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, kAnonymousSectionHandle, 0U,
         as_u64(big), LinuxHeapEventStatus::kSuccess, 0U},
        {20U, LinuxHeapEventOperation::kVmRemap, 0U, kBigSize, kBiggerSize, 0U, as_u64(big), 0U,
         MREMAP_MAYMOVE, 0U, 0U, as_u64(grown), LinuxHeapEventStatus::kSuccess, 0U},
        {18U, LinuxHeapEventOperation::kVmAllocate, 0U, kBiggerSize, 0U, 0U, 0U, PROT_NONE,
         MAP_PRIVATE | MAP_ANONYMOUS, kAnonymousSectionHandle, 0U, as_u64(dest),
         LinuxHeapEventStatus::kSuccess, 0U},
        {20U, LinuxHeapEventOperation::kVmRemap, 0U, kBiggerSize, kBiggerSize, as_u64(dest),
         as_u64(grown), 0U, MREMAP_MAYMOVE | MREMAP_FIXED, 0U, 0U, as_u64(moved),
         LinuxHeapEventStatus::kSuccess, 0U},
        {19U, LinuxHeapEventOperation::kVmUnmap, 0U, kBiggerSize, 0U, 0U, as_u64(moved), 0U, 0U, 0U,
         0U, 0U, LinuxHeapEventStatus::kSuccess, 0U},
    }};
    verify_scripted_phase(events_d, expected.data(), expected.size(),
                          static_cast<std::uint64_t>(kPhaseACount) + 1U, main_tid, kStackDepth);
  }

  // Exact scripted-phase counter deltas (baseline was taken right after install).
  struct ExpectedCounters {
    LinuxLogicalHookApi api;
    std::uint64_t recordable;
    std::uint64_t successful;
    std::uint64_t failed;
    std::uint64_t filtered;
  };
  constexpr std::array<ExpectedCounters, 3> expected_scripted{{
      {LinuxLogicalHookApi::kMmap, 7U, 6U, 1U, 1U},
      {LinuxLogicalHookApi::kMunmap, 5U, 5U, 0U, 0U},
      {LinuxLogicalHookApi::kMremap, 3U, 3U, 0U, 0U},
  }};
  for (const ExpectedCounters& entry : expected_scripted) {
    const auto index =
        static_cast<std::size_t>(entry.api) - noleax::agent::linux::kGlibcHeapHookCount;
    const VirtualMemoryHookApiCounters delta{
        scripted[index].replacement_calls - baseline[index].replacement_calls,
        scripted[index].recordable_calls - baseline[index].recordable_calls,
        scripted[index].recursive_calls - baseline[index].recursive_calls,
        scripted[index].internal_calls - baseline[index].internal_calls,
        scripted[index].successful_calls - baseline[index].successful_calls,
        scripted[index].failed_calls - baseline[index].failed_calls,
        scripted[index].filtered_calls - baseline[index].filtered_calls,
        scripted[index].dropped_events - baseline[index].dropped_events,
    };
    check(delta.recordable_calls == entry.recordable, "scripted recordable call count");
    check(delta.successful_calls == entry.successful, "scripted successful call count");
    check(delta.failed_calls == entry.failed, "scripted failed call count");
    check(delta.filtered_calls == entry.filtered, "scripted filtered call count");
    check(delta.dropped_events == 0U, "no drops during the scripted phases");
    check(delta.internal_calls == 0U, "no internal calls during the scripted phases");
    check(delta.replacement_calls ==
              delta.recordable_calls + delta.recursive_calls + delta.internal_calls,
          "scripted replacement calls classify exactly");
  }

  // Conservation invariants over the whole capture, per API:
  //   replacement_calls == recordable + recursive + internal
  //   recordable_calls  == successful + failed
  //   recordable_calls  == events + filtered + dropped
  std::array<std::uint64_t, 3> drained_per_api{};
  const std::array<std::vector<LinuxHeapEvent>*, 4> phases{
      {&events_a, &events_d, &events_b, &events_c}};
  for (const std::vector<LinuxHeapEvent>* phase : phases) {
    for (const LinuxHeapEvent& event : *phase) {
      for (std::size_t index = 0U; index < drained_per_api.size(); ++index) {
        if (event.api_id ==
            noleax::agent::linux::kLinuxHookRegistry[noleax::agent::linux::kGlibcHeapHookCount +
                                                     index]
                .api_id) {
          ++drained_per_api[index];
        }
      }
    }
  }
  std::uint64_t total_dropped = 0U;
  for (std::size_t index = 0U; index < post_stop.size(); ++index) {
    const VirtualMemoryHookApiCounters& counters = post_stop[index];
    check(counters.replacement_calls ==
              counters.recordable_calls + counters.recursive_calls + counters.internal_calls,
          "conservation: replacement calls classify exactly");
    check(counters.recordable_calls == counters.successful_calls + counters.failed_calls,
          "conservation: recordable == successful + failed");
    check(counters.recordable_calls ==
              drained_per_api[index] + counters.filtered_calls + counters.dropped_events,
          "conservation: recordable == events + filtered + dropped");
    total_dropped += counters.dropped_events;
  }
  check(total_dropped != 0U, "churn exercised the queue-full drop path");

  std::uint64_t churn_operations = 0U;
  for (const ChurnResult& result : churn_results) {
    churn_operations += result.operations;
  }
  check(churn_operations != 0U, "churn workers completed operations");

  // stop_recording must freeze every counter: the kOriginal route neither counts nor queues.
  for (std::size_t index = 0U; index < post_stop.size(); ++index) {
    check(post_stop[index] == pre_stop[index], "counters are frozen after stop_recording");
  }

  static_cast<void>(backend.shutdown());

  std::printf(
      "linux-virtual-memory probe: events A=%zu D=%zu B=%zu, churn ops=%llu, dropped=%llu, "
      "failures=%u\n",
      drained_a, drained_d, drained_b, static_cast<unsigned long long>(churn_operations),
      static_cast<unsigned long long>(total_dropped), check_failures);
  if (check_failures != 0U) {
    std::printf("FAIL\n");
    return 1;
  }
  std::printf("OK\n");
  return 0;
}
