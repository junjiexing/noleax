#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/windows/rtl_free_heap_hook.hpp"

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID address);

constexpr DWORD kLastErrorSentinel = 0xa1510001U;
constexpr ULONG kUnusualFlags = 0xffffffffU;
constexpr std::uint16_t kStackDepth = 16U;

enum class Case : std::uint8_t {
  kValid,
  kNullAddress,
  kNullHeap,
  kUnusualFlags,
};

struct Observation {
  PVOID heap{nullptr};
  PVOID address{nullptr};
  ULONG flags{0U};
  BOOLEAN result{FALSE};
  DWORD exception_status{0U};
  DWORD last_error{ERROR_SUCCESS};
  bool returned{false};
};

[[nodiscard]] LONG capture_exception(EXCEPTION_POINTERS* pointers, DWORD* status) noexcept {
  if (pointers != nullptr && pointers->ExceptionRecord != nullptr && status != nullptr) {
    *status = pointers->ExceptionRecord->ExceptionCode;
  }
  return EXCEPTION_EXECUTE_HANDLER;
}

[[nodiscard]] Observation invoke(RtlFreeHeapFunction free_heap, PVOID heap, ULONG flags,
                                 PVOID address) noexcept {
  Observation observation;
  observation.heap = heap;
  observation.address = address;
  observation.flags = flags;
  SetLastError(kLastErrorSentinel);
  __try {
    observation.result = free_heap(heap, flags, address);
    observation.returned = true;
  } __except (capture_exception(GetExceptionInformation(), &observation.exception_status)) {
  }
  observation.last_error = GetLastError();
  return observation;
}

[[nodiscard]] Observation run_case(Case test_case, RtlAllocateHeapFunction allocate,
                                   RtlFreeHeapFunction free_heap, PVOID process_heap) noexcept {
  PVOID heap = process_heap;
  PVOID address = nullptr;
  ULONG flags = 0U;
  if (test_case == Case::kValid || test_case == Case::kUnusualFlags) {
    address = allocate(process_heap, 0U, 64U);
  }
  if (test_case == Case::kNullHeap) {
    heap = nullptr;
  }
  if (test_case == Case::kUnusualFlags) {
    flags = kUnusualFlags;
  }

  return invoke(free_heap, heap, flags, address);
}

[[nodiscard]] bool same_contract(const Observation& baseline, const Observation& hooked) noexcept {
  return baseline.returned == hooked.returned && baseline.result == hooked.result &&
         baseline.exception_status == hooked.exception_status &&
         baseline.last_error == hooked.last_error;
}

void print_observation(const char* phase, std::size_t index,
                       const Observation& observation) noexcept {
  std::fprintf(stderr,
               "RtlFreeHeap %s case %zu: heap=%p address=%p flags=0x%08lx returned=%u "
               "result=%u exception=0x%08lx last_error=0x%08lx\n",
               phase, index, observation.heap, observation.address,
               static_cast<unsigned long>(observation.flags), observation.returned ? 1U : 0U,
               static_cast<unsigned>(observation.result),
               static_cast<unsigned long>(observation.exception_status),
               static_cast<unsigned long>(observation.last_error));
}

[[nodiscard]] bool finish_uninstall(noleax::agent::windows::RtlFreeHeapHook& hook) noexcept {
  auto status = hook.uninstall(std::chrono::steady_clock::now());
  if (status == noleax::agent::HookUninstallStatus::kTeardownPending && hook.flush()) {
    status = noleax::agent::HookUninstallStatus::kUninstalled;
  }
  return status == noleax::agent::HookUninstallStatus::kUninstalled;
}

[[nodiscard]] bool event_matches(const noleax::agent::windows::RtlFreeHeapEvent& event,
                                 const Observation& observation) noexcept {
  using noleax::agent::windows::RtlFreeHeapEventStatus;
  const auto expected_status =
      observation.exception_status != 0U
          ? RtlFreeHeapEventStatus::kException
          : (observation.result == FALSE ? RtlFreeHeapEventStatus::kFailure
                                         : RtlFreeHeapEventStatus::kSuccess);
  return event.operation == noleax::agent::windows::RtlHeapEventOperation::kFree &&
         event.heap_handle ==
             static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(observation.heap)) &&
         event.address ==
             static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(observation.address)) &&
         event.flags == observation.flags && event.status == expected_status &&
         event.raw_result == static_cast<std::uint64_t>(observation.result) &&
         event.requested_size == 0U && event.result_address == 0U &&
         event.exception_status == observation.exception_status;
}

}  // namespace

int main() {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const PVOID process_heap = GetProcessHeap();
  const auto allocate =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  const auto free_heap =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  if (process_heap == nullptr || allocate == nullptr || free_heap == nullptr) {
    return 2;
  }

  constexpr std::array cases{Case::kValid, Case::kNullAddress, Case::kNullHeap,
                             Case::kUnusualFlags};
  std::array<Observation, cases.size()> baseline{};
  for (std::size_t index = 0U; index < cases.size(); ++index) {
    baseline[index] = run_case(cases[index], allocate, free_heap, process_heap);
    const bool completed = baseline[index].returned && baseline[index].exception_status == 0U;
    const bool raised = !baseline[index].returned && baseline[index].exception_status != 0U;
    if ((!completed && !raised) || baseline[index].last_error != kLastErrorSentinel) {
      print_observation("baseline", index, baseline[index]);
      return 3;
    }
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlFreeHeapHook hook{backend, 64U, kStackDepth};
  const auto installed = hook.install();
  if (!installed.installed()) {
    return 4;
  }

  std::uint64_t previous_sequence = 0U;
  noleax::agent::windows::RtlFreeHeapEvent discarded;
  while (hook.try_dequeue_event(discarded)) {
    previous_sequence = discarded.queue_sequence;
  }
  static_cast<void>(hook.take_dropped_event_count());

  const std::uint64_t calls_before = hook.call_count();
  const std::uint64_t recordable_before = hook.recordable_call_count();
  const std::uint64_t recursive_before = hook.recursive_call_count();
  const std::uint64_t internal_before = hook.internal_call_count();
  const std::uint64_t successful_before = hook.successful_call_count();
  const std::uint64_t failed_before = hook.failed_call_count();
  const std::uint64_t exceptional_before = hook.exceptional_call_count();

  std::array<Observation, cases.size()> hooked{};
  std::uint64_t expected_successes = 0U;
  std::uint64_t expected_exceptions = 0U;
  for (std::size_t index = 0U; index < cases.size(); ++index) {
    hooked[index] = run_case(cases[index], allocate, free_heap, process_heap);
    if (!same_contract(baseline[index], hooked[index])) {
      print_observation("baseline", index, baseline[index]);
      print_observation("hooked", index, hooked[index]);
      return 5;
    }
    expected_successes += hooked[index].result == FALSE ? 0U : 1U;
    expected_exceptions += hooked[index].exception_status == 0U ? 0U : 1U;
  }

  PVOID recursive_allocation = allocate(process_heap, 0U, 80U);
  PVOID internal_allocation = allocate(process_heap, 0U, 96U);
  if (recursive_allocation == nullptr || internal_allocation == nullptr) {
    return 6;
  }
  Observation recursive;
  {
    const noleax::agent::HookInvocationGuard simulated_outer_hook;
    recursive = invoke(free_heap, process_heap, 0U, recursive_allocation);
  }
  Observation internal;
  {
    const noleax::agent::InternalThreadScope internal_thread;
    internal = invoke(free_heap, process_heap, 0U, internal_allocation);
  }
  if (!recursive.returned || recursive.result == FALSE ||
      recursive.last_error != baseline[0].last_error || !internal.returned ||
      internal.result == FALSE || internal.last_error != baseline[0].last_error ||
      noleax::agent::current_hook_depth() != 0U || noleax::agent::current_thread_is_internal()) {
    print_observation("recursive", cases.size(), recursive);
    print_observation("internal", cases.size() + 1U, internal);
    return 7;
  }

  std::array<bool, cases.size()> found{};
  std::uint64_t dequeued = 0U;
  noleax::agent::windows::RtlFreeHeapEvent event;
  while (hook.try_dequeue_event(event)) {
    if (event.queue_sequence != previous_sequence + 1U || event.monotonic_ticks == 0U ||
        event.thread_id == 0U ||
        event.stack.method !=
            noleax::agent::windows::StackCaptureMethod::kRtlCaptureStackBackTrace ||
        event.stack.requested_depth != kStackDepth) {
      return 8;
    }
    const bool exceptional_stack_valid =
        event.status == noleax::agent::windows::RtlFreeHeapEventStatus::kException &&
        event.stack.frame_count == 0U &&
        event.stack.status == noleax::agent::windows::StackCaptureStatus::kFailed;
    const bool normal_stack_valid =
        event.status != noleax::agent::windows::RtlFreeHeapEventStatus::kException &&
        noleax::agent::windows::stack_capture_succeeded(event.stack);
    if (!exceptional_stack_valid && !normal_stack_valid) {
      return 8;
    }
    previous_sequence = event.queue_sequence;
    ++dequeued;
    bool matched = false;
    for (std::size_t index = 0U; index < hooked.size(); ++index) {
      if (!found[index] && event_matches(event, hooked[index])) {
        found[index] = true;
        matched = true;
        break;
      }
    }
    if (!matched) {
      return 9;
    }
  }

  const std::uint64_t expected_failures = cases.size() - expected_successes;
  bool all_found = dequeued == cases.size();
  for (const bool value : found) {
    all_found &= value;
  }
  const bool counters_valid =
      hook.call_count() == calls_before + cases.size() + 2U &&
      hook.recordable_call_count() == recordable_before + cases.size() &&
      hook.recursive_call_count() == recursive_before + 1U &&
      hook.internal_call_count() == internal_before + 1U &&
      hook.successful_call_count() == successful_before + expected_successes &&
      hook.failed_call_count() == failed_before + expected_failures &&
      hook.exceptional_call_count() == exceptional_before + expected_exceptions &&
      hook.dropped_event_count() == 0U;

  const bool uninstalled = finish_uninstall(hook);
  const bool shutdown = backend.shutdown();
  if (!all_found || !counters_valid || !uninstalled || !shutdown) {
    std::fprintf(stderr,
                 "RtlFreeHeap contract failed: events=%llu calls=%llu recordable=%llu "
                 "recursive=%llu internal=%llu success=%llu failure=%llu dropped=%llu\n",
                 static_cast<unsigned long long>(dequeued),
                 static_cast<unsigned long long>(hook.call_count()),
                 static_cast<unsigned long long>(hook.recordable_call_count()),
                 static_cast<unsigned long long>(hook.recursive_call_count()),
                 static_cast<unsigned long long>(hook.internal_call_count()),
                 static_cast<unsigned long long>(hook.successful_call_count()),
                 static_cast<unsigned long long>(hook.failed_call_count()),
                 static_cast<unsigned long long>(hook.dropped_event_count()));
    return 10;
  }

  std::printf(
      "status=ok cases=4 outermost=4 recursive=1 internal=1 exceptions=%llu last_error=%lu\n",
      static_cast<unsigned long long>(expected_exceptions),
      static_cast<unsigned long>(kLastErrorSentinel));
  return 0;
}
