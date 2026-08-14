// End-to-end probe for the linux-glibc-heap profile (docs/LINUX_PORT_PLAN.md M3): installs
// GlibcHeapHooks on this process's own glibc allocation entry points and proves the adapter
// contract in-process — event field mapping, errno preservation, recursion suppression,
// counter conservation, stop/uninstall silence, and multi-threaded churn.

#include <malloc.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/linux/agent_memory.hpp"
#include "noleax/agent/linux/glibc_heap_hooks.hpp"
#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/agent/linux/hook_registry.hpp"
#include "noleax/agent/linux/stack_capture.hpp"

namespace {

using noleax::agent::linux::GlibcHeapHookApiCounters;
using noleax::agent::linux::GlibcHeapHooks;
using noleax::agent::linux::LinuxHeapEvent;
using noleax::agent::linux::LinuxHeapEventOperation;
using noleax::agent::linux::LinuxHeapEventQueue;
using noleax::agent::linux::LinuxHeapEventStatus;
using noleax::agent::linux::LinuxLogicalHookApi;
using noleax::agent::linux::stack_capture_succeeded;

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
  std::uint64_t requested_size;
  std::uint64_t count;
  std::uint64_t alignment;
  std::uint64_t address;
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
      event.requested_size != expected.requested_size || event.count != expected.count ||
      event.alignment != expected.alignment || event.address != expected.address ||
      event.result_address != expected.result_address || event.status != expected.status ||
      event.operation_result != expected.operation_result) {
    std::printf(
        "FAIL: event seq=%llu api=%u op=%u size=%llu count=%llu align=%llu addr=%llu "
        "result=%llu status=%u op_result=%u\n",
        static_cast<unsigned long long>(event.queue_sequence), static_cast<unsigned>(event.api_id),
        static_cast<unsigned>(event.operation),
        static_cast<unsigned long long>(event.requested_size),
        static_cast<unsigned long long>(event.count),
        static_cast<unsigned long long>(event.alignment),
        static_cast<unsigned long long>(event.address),
        static_cast<unsigned long long>(event.result_address), static_cast<unsigned>(event.status),
        expected.operation_result);
    ++check_failures;
    return;
  }
  check(event.queue_sequence == expected_sequence, "queue sequence is not contiguous from 1");
  check(event.thread_id == main_thread_id, "event thread id matches the caller thread");
  check(event.monotonic_ticks != 0U, "event carries monotonic ticks");
  check(event.stack.requested_depth == stack_depth, "event stack requested depth");
  check(stack_capture_succeeded(event.stack), "event stack captured");
  check(event.stack.frame_count <= stack_depth, "event stack depth within the requested limit");
}

struct ChurnResult {
  std::uint64_t operations{0U};
};

void churn_worker(std::uint64_t seed, std::uint64_t iterations, ChurnResult* result) {
  std::uint64_t state = seed;
  void* pointer = nullptr;
  for (std::uint64_t i = 0U; i < iterations; ++i) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    const std::size_t size = static_cast<std::size_t>((state >> 33U) % 4096U) + 16U;
    switch (state % 5U) {
      case 0U:
        std::free(pointer);
        pointer = std::malloc(size);
        break;
      case 1U: {
        void* const next = std::realloc(pointer, size);
        if (next != nullptr) {
          pointer = next;
        }
        break;
      }
      case 2U:
        std::free(pointer);
        pointer = std::calloc(3U, size / 3U + 1U);
        break;
      case 3U:
        std::free(pointer);
        pointer = reallocarray(nullptr, 2U, size / 2U + 1U);
        break;
      default:
        std::free(pointer);
        pointer = nullptr;
        break;
    }
    if (pointer != nullptr) {
      static_cast<unsigned char*>(pointer)[0] = static_cast<unsigned char>(i);
      ++result->operations;
    }
  }
  std::free(pointer);
}

}  // namespace

int main() {
  // Warm up stdio and the allocator before any hook goes live; everything between install
  // and the final drain must stay free of incidental allocations on this thread.
  std::printf("linux_glibc_heap_hooks_probe\n");
  {
    void* const warm = std::malloc(128U);
    std::free(warm);
  }

  constexpr std::size_t kQueueCapacity = 1024U;
  constexpr std::uint16_t kStackDepth = 32U;
  constexpr std::uint64_t kMinCaptureSize = 256U;
  constexpr std::size_t kPhaseACount = 24U;

  std::vector<LinuxHeapEvent> events_a;
  std::vector<LinuxHeapEvent> events_r;
  std::vector<LinuxHeapEvent> events_b;
  std::vector<LinuxHeapEvent> events_c;
  events_a.reserve(64U);
  events_r.reserve(16U);
  events_b.reserve(2048U);
  events_c.reserve(16U);

  noleax::agent::HookBackend backend;
  GlibcHeapHooks hooks{backend, kQueueCapacity, kStackDepth, kMinCaptureSize};
  if (!hooks.install()) {
    std::printf("FAIL: GlibcHeapHooks::install\n");
    return 1;
  }
  check(hooks.is_installed(), "profile is installed");
  check(hooks.is_recording(), "profile is recording after install");

  const std::uint64_t main_tid = static_cast<std::uint64_t>(::syscall(SYS_gettid));

  // Counter baseline: install-time bookkeeping allocations count as internal calls, so the
  // exact scripted assertions below run on deltas from this snapshot.
  std::array<GlibcHeapHookApiCounters, 8> baseline{};
  for (std::size_t index = 0U; index < baseline.size(); ++index) {
    baseline[index] = hooks.counters(static_cast<LinuxLogicalHookApi>(index));
  }

  // Volatile sources keep the compiler from constant-folding the oversized requests (which
  // would trip -Walloc-size-larger-than) or eliminating the allocation calls. The volatile
  // function pointers block the realloc(NULL, n) -> malloc(n) and calloc foldings: the
  // scripted sequence must reach the exact public entry points it claims to exercise.
  volatile std::size_t huge_size = SIZE_MAX;
  volatile std::size_t huge_nmemb = 0x7fffffffffffffffU;
  void* (*volatile v_realloc)(void*, std::size_t) = &std::realloc;
  void* (*volatile v_calloc)(std::size_t, std::size_t) = &std::calloc;
  void (*volatile v_free)(void*) = &std::free;  // free(nullptr) would otherwise be deleted

  // ---- scripted sequence (phase A) ----
  // Every successful block is written before it is freed; the writes also prove the
  // hooked path returns usable memory. Returned pointers are captured as integers
  // immediately: the expectation table must not dereference or convert a pointer whose
  // block was already freed. Nothing here allocates besides the calls under test, so the
  // drained events must match the script exactly.
  errno = 0;
  void* const p1 = std::malloc(0x111U);
  const std::uint64_t a1 = as_u64(p1);
  std::memset(p1, 0x11, 0x111U);
  void* const p2 = std::malloc(64U);  // below the capture floor: filtered, no event
  const std::uint64_t a2 = as_u64(p2);
  std::memset(p2, 0x22, 64U);
  errno = 0;
  void* const p_fail = std::malloc(huge_size);
  const int errno_after_fail = errno;
  errno = EDOM;
  void* const p3 = std::malloc(0x900U);
  const std::uint64_t a3 = as_u64(p3);
  const int errno_after_success = errno;
  std::memset(p3, 0x33, 0x900U);
  void* const p4 = std::calloc(3U, 0x100U);
  const std::uint64_t a4 = as_u64(p4);
  bool calloc_zeroed = p4 != nullptr;
  if (p4 != nullptr) {
    const auto* const bytes = static_cast<const unsigned char*>(p4);
    for (std::size_t i = 0U; i < 3U * 0x100U; ++i) {
      calloc_zeroed = calloc_zeroed && bytes[i] == 0U;
    }
  }
  errno = 0;
  void* const p_overflow = v_calloc(huge_nmemb, 4U);
  const int errno_after_overflow = errno;
  void* const p5 = v_realloc(nullptr, 0x400U);
  const std::uint64_t a5 = as_u64(p5);
  std::memset(p5, 0xcd, 0x400U);
  void* const p6 = v_realloc(p5, 0x800U);
  const std::uint64_t a6 = as_u64(p6);
  std::memset(p6, 0xab, 0x800U);
  void* const p7 = v_realloc(p6, 0U);        // glibc frees p6 and returns nullptr
  void* const p8 = v_realloc(nullptr, 32U);  // reallocate is never size-filtered
  const std::uint64_t a8 = as_u64(p8);
  std::memset(p8, 0x88, 32U);
  v_free(nullptr);
  std::free(p1);
  std::free(p4);
  std::free(p2);
  std::free(p3);
  std::free(p8);
  void* pm = nullptr;
  errno = 0;
  const int pm_result = posix_memalign(&pm, 64U, 0x500U);
  const std::uint64_t am = as_u64(pm);
  std::memset(pm, 0x55, 0x500U);
  void* pm_bad = nullptr;
  errno = EDOM;
  const int pm_bad_result = posix_memalign(&pm_bad, 3U, 0x100U);
  const int errno_after_pm_bad = errno;
  void* const pa = aligned_alloc(128U, 0x600U);
  const std::uint64_t aa = as_u64(pa);
  std::memset(pa, 0x66, 0x600U);
  void* const pme = memalign(256U, 0x700U);
  const std::uint64_t ame = as_u64(pme);
  std::memset(pme, 0x77, 0x700U);
  void* const pr = reallocarray(nullptr, 4U, 0x100U);
  const std::uint64_t ar = as_u64(pr);
  std::memset(pr, 0x99, 0x400U);
  std::free(pm);
  std::free(pa);
  std::free(pme);
  std::free(pr);

  // The scripted calls must behave exactly as unhooked glibc calls.
  check(p1 != nullptr && p2 != nullptr && p3 != nullptr, "scripted mallocs succeed");
  check(p_fail == nullptr, "malloc(SIZE_MAX) fails");
  check(errno_after_fail == ENOMEM, "errno after failing malloc is ENOMEM");
  check(errno_after_success == EDOM, "errno preserved across a successful malloc");
  check(p4 != nullptr, "calloc succeeds");
  check(calloc_zeroed, "calloc result is zeroed");
  check(p_overflow == nullptr, "calloc overflow fails");
  check(errno_after_overflow == ENOMEM, "errno after calloc overflow is ENOMEM");
  check(p5 != nullptr && p6 != nullptr, "realloc grow succeeds");
  check(p7 == nullptr, "realloc(p, 0) returns nullptr");
  check(p8 != nullptr, "realloc(nullptr, 32) succeeds");
  check(pm_result == 0 && pm != nullptr, "posix_memalign succeeds");
  check(am % 64U == 0U, "posix_memalign result alignment");
  check(pm_bad_result == EINVAL, "posix_memalign bad alignment returns EINVAL");
  check(errno_after_pm_bad == EDOM, "errno preserved across failing posix_memalign");
  check(pa != nullptr && aa % 128U == 0U, "aligned_alloc result alignment");
  check(pme != nullptr && ame % 256U == 0U, "memalign result alignment");
  check(pr != nullptr, "reallocarray succeeds");

  const std::size_t drained_a = drain_events(hooks.event_queue(), events_a);

  // ---- recursion probe (phase R): one reallocarray call, one recorded event ----
  void* const pr2 = reallocarray(nullptr, 8U, 0x80U);
  const std::uint64_t ar2 = as_u64(pr2);
  check(pr2 != nullptr, "recursion-probe reallocarray succeeds");
  std::memset(pr2, 0x12, 0x400U);
  std::free(pr2);
  const std::size_t drained_r = drain_events(hooks.event_queue(), events_r);

  std::array<GlibcHeapHookApiCounters, 8> scripted{};
  for (std::size_t index = 0U; index < scripted.size(); ++index) {
    scripted[index] = hooks.counters(static_cast<LinuxLogicalHookApi>(index));
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

  // ---- H4 regression: agent mmap-region machinery never enters the heap event stream ----
  // The queue factory mmaps its slot ring (a syscall, not a heap call) and the resident
  // accounting runs on the agent's internal threads; under the internal-thread scope the
  // whole sequence — factory, page touches, registry snapshot, destruction — must record
  // nothing and count nothing recordable.
  {
    const noleax::agent::InternalThreadScope internal_scope;
    auto h4_queue = noleax::agent::linux::make_linux_heap_event_queue(16'384U);
    LinuxHeapEvent h4_event{};
    for (std::size_t index = 0U; index < 4'096U; ++index) {
      if (!h4_queue->try_push(h4_event)) {
        break;
      }
    }
    std::vector<noleax::trace::AgentMemoryCategorySample> categories;
    noleax::agent::linux::AgentMemoryRegistry::instance().snapshot(categories);
  }
  const std::size_t drained_h4 = drain_events(hooks.event_queue(), events_c);
  check(drained_h4 == 0U, "H4 mmap-region allocations stay out of the heap event stream");

  std::array<GlibcHeapHookApiCounters, 8> pre_stop{};
  for (std::size_t index = 0U; index < pre_stop.size(); ++index) {
    pre_stop[index] = hooks.counters(static_cast<LinuxLogicalHookApi>(index));
  }

  check(hooks.stop_recording(), "stop_recording");
  check(!hooks.is_recording(), "profile is not recording after stop_recording");

  // kOriginal routing: allocations still work, nothing is counted or queued.
  {
    void* const quiet = std::malloc(512U);
    std::memset(quiet, 0xee, 512U);
    std::free(quiet);
  }
  const std::size_t drained_c = drain_events(hooks.event_queue(), events_c);

  std::array<GlibcHeapHookApiCounters, 8> post_stop{};
  for (std::size_t index = 0U; index < post_stop.size(); ++index) {
    post_stop[index] = hooks.counters(static_cast<LinuxLogicalHookApi>(index));
  }

  check(hooks.uninstall(), "uninstall");
  check(!hooks.is_installed(), "profile is uninstalled");

  // Post-uninstall: the original entry points are fully restored.
  {
    void* const after = std::malloc(256U);
    check(after != nullptr, "post-uninstall malloc succeeds");
    std::memset(after, 0x5a, 256U);
    void* const grown = std::realloc(after, 1024U);
    check(grown != nullptr, "post-uninstall realloc succeeds");
    std::free(grown);
  }
  const std::size_t drained_d = drain_events(hooks.event_queue(), events_c);

  // ---- verification ----

  check(drained_a == kPhaseACount, "phase A event count");
  check(drained_r == 2U, "phase R event count: reallocarray plus its free");
  check(drained_c == 0U, "no events after stop_recording");
  check(drained_d == 0U, "no events after uninstall");
  check(drained_b != 0U, "churn produced events");

  if (drained_a == kPhaseACount) {
    const std::array<ExpectedEvent, kPhaseACount> expected{{
        // malloc(0x111), malloc(SIZE_MAX) failure, malloc(0x900); malloc(64) was filtered.
        {10U, LinuxHeapEventOperation::kAllocate, 0x111U, 0U, 0U, 0U, a1,
         LinuxHeapEventStatus::kSuccess, 0U},
        {10U, LinuxHeapEventOperation::kAllocate, SIZE_MAX, 0U, 0U, 0U, 0U,
         LinuxHeapEventStatus::kFailure, ENOMEM},
        {10U, LinuxHeapEventOperation::kAllocate, 0x900U, 0U, 0U, 0U, a3,
         LinuxHeapEventStatus::kSuccess, 0U},
        // calloc(3, 0x100), then the overflowing calloc with its wrapped product.
        {11U, LinuxHeapEventOperation::kAllocate, 0x300U, 3U, 0U, 0U, a4,
         LinuxHeapEventStatus::kSuccess, 0U},
        {11U, LinuxHeapEventOperation::kAllocate, 0xfffffffffffffffcU, 0x7fffffffffffffffU, 0U, 0U,
         0U, LinuxHeapEventStatus::kFailure, ENOMEM},
        // realloc(NULL, 0x400), grow, realloc(p, 0), and the unfiltered small realloc.
        {12U, LinuxHeapEventOperation::kReallocate, 0x400U, 0U, 0U, 0U, a5,
         LinuxHeapEventStatus::kSuccess, 0U},
        {12U, LinuxHeapEventOperation::kReallocate, 0x800U, 0U, 0U, a5, a6,
         LinuxHeapEventStatus::kSuccess, 0U},
        {12U, LinuxHeapEventOperation::kReallocate, 0U, 0U, 0U, a6, 0U,
         LinuxHeapEventStatus::kSuccess, 0U},
        {12U, LinuxHeapEventOperation::kReallocate, 32U, 0U, 0U, 0U, a8,
         LinuxHeapEventStatus::kSuccess, 0U},
        // free(NULL) and the five frees in call order.
        {13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, 0U, 0U, LinuxHeapEventStatus::kSuccess,
         0U},
        {13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, a1, 0U, LinuxHeapEventStatus::kSuccess,
         0U},
        {13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, a4, 0U, LinuxHeapEventStatus::kSuccess,
         0U},
        {13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, a2, 0U, LinuxHeapEventStatus::kSuccess,
         0U},
        {13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, a3, 0U, LinuxHeapEventStatus::kSuccess,
         0U},
        {13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, a8, 0U, LinuxHeapEventStatus::kSuccess,
         0U},
        // posix_memalign success and its EINVAL failure (result address stays zero).
        {14U, LinuxHeapEventOperation::kAllocate, 0x500U, 0U, 64U, 0U, am,
         LinuxHeapEventStatus::kSuccess, 0U},
        {14U, LinuxHeapEventOperation::kAllocate, 0x100U, 0U, 3U, 0U, 0U,
         LinuxHeapEventStatus::kFailure, EINVAL},
        {15U, LinuxHeapEventOperation::kAllocate, 0x600U, 0U, 128U, 0U, aa,
         LinuxHeapEventStatus::kSuccess, 0U},
        {16U, LinuxHeapEventOperation::kAllocate, 0x700U, 0U, 256U, 0U, ame,
         LinuxHeapEventStatus::kSuccess, 0U},
        // reallocarray(NULL, 4, 0x100) and the four trailing frees.
        {17U, LinuxHeapEventOperation::kReallocate, 0x400U, 4U, 0U, 0U, ar,
         LinuxHeapEventStatus::kSuccess, 0U},
        {13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, am, 0U, LinuxHeapEventStatus::kSuccess,
         0U},
        {13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, aa, 0U, LinuxHeapEventStatus::kSuccess,
         0U},
        {13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, ame, 0U, LinuxHeapEventStatus::kSuccess,
         0U},
        {13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, ar, 0U, LinuxHeapEventStatus::kSuccess,
         0U},
    }};
    std::uint64_t previous_ticks = 0U;
    for (std::size_t index = 0U; index < events_a.size(); ++index) {
      verify_event(events_a[index], expected[index], static_cast<std::uint64_t>(index) + 1U,
                   main_tid, kStackDepth);
      check(events_a[index].monotonic_ticks >= previous_ticks,
            "monotonic ticks are non-decreasing");
      previous_ticks = events_a[index].monotonic_ticks;
    }
  }

  // The recursion probe: exactly one reallocarray event and one free event, sequences
  // continuing from phase A. A glibc reallocarray reaching the public realloc through the
  // PLT re-enters the realloc replacement with the guard held; that inner call classifies
  // as recursive and must not produce a second event.
  if (drained_r == 2U) {
    const ExpectedEvent expected_reallocarray{
        17U, LinuxHeapEventOperation::kReallocate, 0x400U, 8U, 0U, 0U,
        ar2, LinuxHeapEventStatus::kSuccess,       0U};
    const ExpectedEvent expected_free{13U, LinuxHeapEventOperation::kFree, 0U, 0U, 0U, ar2,
                                      0U,  LinuxHeapEventStatus::kSuccess, 0U};
    verify_event(events_r[0], expected_reallocarray, static_cast<std::uint64_t>(kPhaseACount) + 1U,
                 main_tid, kStackDepth);
    verify_event(events_r[1], expected_free, static_cast<std::uint64_t>(kPhaseACount) + 2U,
                 main_tid, kStackDepth);
  }

  // Exact scripted-phase counter deltas (baseline was taken right after install).
  struct ExpectedCounters {
    LinuxLogicalHookApi api;
    std::uint64_t recordable;
    std::uint64_t successful;
    std::uint64_t failed;
    std::uint64_t filtered;
  };
  constexpr std::array<ExpectedCounters, 8> expected_scripted{{
      {LinuxLogicalHookApi::kMalloc, 4U, 3U, 1U, 1U},
      {LinuxLogicalHookApi::kCalloc, 2U, 1U, 1U, 0U},
      {LinuxLogicalHookApi::kRealloc, 4U, 4U, 0U, 0U},
      {LinuxLogicalHookApi::kFree, 11U, 11U, 0U, 0U},
      {LinuxLogicalHookApi::kPosixMemalign, 2U, 1U, 1U, 0U},
      {LinuxLogicalHookApi::kAlignedAlloc, 1U, 1U, 0U, 0U},
      {LinuxLogicalHookApi::kMemalign, 1U, 1U, 0U, 0U},
      {LinuxLogicalHookApi::kReallocarray, 2U, 2U, 0U, 0U},
  }};
  for (const ExpectedCounters& entry : expected_scripted) {
    const auto index = static_cast<std::size_t>(entry.api);
    const GlibcHeapHookApiCounters delta{
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
    check(delta.dropped_events == 0U, "no drops during the scripted phase");
    check(delta.internal_calls == 0U, "no internal calls during the scripted phase");
    check(delta.replacement_calls ==
              delta.recordable_calls + delta.recursive_calls + delta.internal_calls,
          "scripted replacement calls classify exactly");
  }

  // Conservation invariants over the whole capture, per API:
  //   replacement_calls == recordable + recursive + internal
  //   recordable_calls  == successful + failed
  //   recordable_calls  == events + filtered + dropped
  std::array<std::uint64_t, 8> drained_per_api{};
  const std::array<std::vector<LinuxHeapEvent>*, 4> phases{
      {&events_a, &events_r, &events_b, &events_c}};
  for (const std::vector<LinuxHeapEvent>* phase : phases) {
    for (const LinuxHeapEvent& event : *phase) {
      for (std::size_t index = 0U; index < drained_per_api.size(); ++index) {
        if (event.api_id == noleax::agent::linux::kLinuxHookRegistry[index].api_id) {
          ++drained_per_api[index];
        }
      }
    }
  }
  std::uint64_t total_dropped = 0U;
  for (std::size_t index = 0U; index < post_stop.size(); ++index) {
    const GlibcHeapHookApiCounters& counters = post_stop[index];
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
      "linux-glibc-heap probe: events A=%zu R=%zu B=%zu, churn ops=%llu, dropped=%llu, "
      "failures=%u\n",
      drained_a, drained_r, drained_b, static_cast<unsigned long long>(churn_operations),
      static_cast<unsigned long long>(total_dropped), check_failures);
  if (check_failures != 0U) {
    std::printf("FAIL\n");
    return 1;
  }
  std::printf("OK\n");
  return 0;
}
