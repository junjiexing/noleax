#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/windows/rtl_reallocate_heap_hook.hpp"

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlReAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, PVOID address,
                                                SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID address);

constexpr DWORD kLastErrorSentinel = 0xa1520001U;
constexpr std::uint16_t kStackDepth = 16U;
constexpr SIZE_T kImpossibleSize =
    (std::numeric_limits<SIZE_T>::max)() - static_cast<SIZE_T>(65'535U);
constexpr std::byte kPattern{0x5a};

enum class Case : std::uint8_t {
  kInPlaceShrink,
  kZeroSize,
  kFailure,
  kGrow,
};

struct Observation {
  PVOID heap{nullptr};
  PVOID old_address{nullptr};
  PVOID result{nullptr};
  SIZE_T requested_size{0U};
  ULONG flags{0U};
  DWORD exception_status{0U};
  DWORD last_error{ERROR_SUCCESS};
  bool returned{false};
  bool content_valid{false};
  bool result_equals_old{false};
};

class TestHeap final {
 public:
  TestHeap() noexcept : handle_{HeapCreate(0U, 0U, 0U)} {}
  ~TestHeap() {
    if (handle_ != nullptr) {
      static_cast<void>(HeapDestroy(handle_));
    }
  }

  TestHeap(const TestHeap&) = delete;
  TestHeap& operator=(const TestHeap&) = delete;

  [[nodiscard]] PVOID get() const noexcept { return handle_; }

 private:
  HANDLE handle_{nullptr};
};

[[nodiscard]] LONG capture_exception(EXCEPTION_POINTERS* pointers, DWORD* status) noexcept {
  if (pointers != nullptr && pointers->ExceptionRecord != nullptr && status != nullptr) {
    *status = pointers->ExceptionRecord->ExceptionCode;
  }
  return EXCEPTION_EXECUTE_HANDLER;
}

[[nodiscard]] Observation invoke(RtlReAllocateHeapFunction reallocate, PVOID heap, ULONG flags,
                                 PVOID address, SIZE_T size) noexcept {
  Observation observation;
  observation.heap = heap;
  observation.old_address = address;
  observation.requested_size = size;
  observation.flags = flags;
  SetLastError(kLastErrorSentinel);
  __try {
    observation.result = reallocate(heap, flags, address, size);
    observation.returned = true;
  } __except (capture_exception(GetExceptionInformation(), &observation.exception_status)) {
  }
  observation.last_error = GetLastError();
  observation.result_equals_old = observation.result == address;
  return observation;
}

[[nodiscard]] bool has_pattern(const void* address, std::size_t count) noexcept {
  if (address == nullptr) {
    return false;
  }
  const auto* bytes = static_cast<const std::byte*>(address);
  for (std::size_t index = 0U; index < count; ++index) {
    if (bytes[index] != kPattern) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] Observation run_case(Case test_case, RtlAllocateHeapFunction allocate,
                                   RtlReAllocateHeapFunction reallocate,
                                   RtlFreeHeapFunction free_heap, PVOID heap) noexcept {
  constexpr SIZE_T kOriginalSize = 256U;
  PVOID address = allocate(heap, 0U, kOriginalSize);
  if (address == nullptr) {
    return {};
  }
  std::memset(address, std::to_integer<int>(kPattern), kOriginalSize);

  ULONG flags = 0U;
  SIZE_T requested_size = 8'192U;
  switch (test_case) {
    case Case::kInPlaceShrink:
      flags = HEAP_REALLOC_IN_PLACE_ONLY;
      requested_size = 128U;
      break;
    case Case::kZeroSize:
      requested_size = 0U;
      break;
    case Case::kFailure:
      requested_size = kImpossibleSize;
      break;
    case Case::kGrow:
      break;
  }

  Observation observation = invoke(reallocate, heap, flags, address, requested_size);
  if (observation.returned && observation.exception_status == 0U) {
    if (observation.result != nullptr) {
      observation.content_valid = requested_size == 0U || has_pattern(observation.result, 64U);
      static_cast<void>(free_heap(heap, 0U, observation.result));
    } else {
      observation.content_valid = has_pattern(address, 64U);
      static_cast<void>(free_heap(heap, 0U, address));
    }
  }
  return observation;
}

[[nodiscard]] bool same_contract(Case test_case, const Observation& baseline,
                                 const Observation& hooked) noexcept {
  const bool stable_result_shape =
      (baseline.result == nullptr) == (hooked.result == nullptr) &&
      (test_case == Case::kGrow || baseline.result_equals_old == hooked.result_equals_old);
  return baseline.returned == hooked.returned &&
         baseline.exception_status == hooked.exception_status &&
         baseline.last_error == hooked.last_error && stable_result_shape &&
         baseline.content_valid && hooked.content_valid;
}

void print_observation(const char* phase, std::size_t index,
                       const Observation& observation) noexcept {
  std::fprintf(stderr,
               "RtlReAllocateHeap %s case %zu: old=%p result=%p size=%llu flags=0x%08lx "
               "returned=%u exception=0x%08lx last_error=0x%08lx content=%u same=%u\n",
               phase, index, observation.old_address, observation.result,
               static_cast<unsigned long long>(observation.requested_size),
               static_cast<unsigned long>(observation.flags), observation.returned ? 1U : 0U,
               static_cast<unsigned long>(observation.exception_status),
               static_cast<unsigned long>(observation.last_error),
               observation.content_valid ? 1U : 0U, observation.result_equals_old ? 1U : 0U);
}

[[nodiscard]] bool finish_uninstall(noleax::agent::windows::RtlReAllocateHeapHook& hook) noexcept {
  auto status = hook.uninstall(std::chrono::steady_clock::now());
  if (status == noleax::agent::HookUninstallStatus::kTeardownPending && hook.flush()) {
    status = noleax::agent::HookUninstallStatus::kUninstalled;
  }
  return status == noleax::agent::HookUninstallStatus::kUninstalled;
}

[[nodiscard]] bool event_matches(const noleax::agent::windows::RtlReAllocateHeapEvent& event,
                                 const Observation& observation) noexcept {
  using noleax::agent::windows::RtlReAllocateHeapEventStatus;
  const auto expected_status =
      observation.exception_status != 0U
          ? RtlReAllocateHeapEventStatus::kException
          : (observation.result == nullptr ? RtlReAllocateHeapEventStatus::kFailure
                                           : RtlReAllocateHeapEventStatus::kSuccess);
  return event.operation == noleax::agent::windows::RtlHeapEventOperation::kReallocate &&
         event.heap_handle ==
             static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(observation.heap)) &&
         event.address == static_cast<std::uint64_t>(
                              reinterpret_cast<std::uintptr_t>(observation.old_address)) &&
         event.result_address ==
             static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(observation.result)) &&
         event.requested_size == static_cast<std::uint64_t>(observation.requested_size) &&
         event.flags == observation.flags && event.status == expected_status &&
         event.raw_result == 0U && event.exception_status == observation.exception_status;
}

}  // namespace

int main() {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const TestHeap test_heap;
  const PVOID process_heap = test_heap.get();
  const auto allocate =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  const auto reallocate =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlReAllocateHeapFunction>(GetProcAddress(ntdll, "RtlReAllocateHeap"));
  const auto free_heap =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  if (process_heap == nullptr || allocate == nullptr || reallocate == nullptr ||
      free_heap == nullptr) {
    return 2;
  }

  constexpr std::array cases{Case::kInPlaceShrink, Case::kZeroSize, Case::kFailure, Case::kGrow};
  std::array<Observation, cases.size()> baseline{};
  for (std::size_t index = 0U; index < cases.size(); ++index) {
    baseline[index] = run_case(cases[index], allocate, reallocate, free_heap, process_heap);
    const bool expected_failure = cases[index] == Case::kFailure;
    const bool valid = baseline[index].returned && baseline[index].exception_status == 0U &&
                       baseline[index].content_valid &&
                       (expected_failure == (baseline[index].result == nullptr));
    if (!valid || (cases[index] == Case::kInPlaceShrink && !baseline[index].result_equals_old)) {
      print_observation("baseline", index, baseline[index]);
      return 3;
    }
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlReAllocateHeapHook hook{backend, 128U, kStackDepth};
  if (!hook.install().installed()) {
    return 4;
  }

  std::uint64_t previous_sequence = 0U;
  noleax::agent::windows::RtlReAllocateHeapEvent discarded;
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

  std::array<Observation, cases.size()> hooked{};
  std::uint64_t expected_successes = 0U;
  for (std::size_t index = 0U; index < cases.size(); ++index) {
    hooked[index] = run_case(cases[index], allocate, reallocate, free_heap, process_heap);
    if (!same_contract(cases[index], baseline[index], hooked[index])) {
      print_observation("baseline", index, baseline[index]);
      print_observation("hooked", index, hooked[index]);
      return 5;
    }
    expected_successes += hooked[index].result == nullptr ? 0U : 1U;
  }

  std::array<Observation, 32U> movement_attempts{};
  std::size_t movement_count = 0U;
  bool observed_move = false;
  while (movement_count < movement_attempts.size() && !observed_move) {
    const SIZE_T original_size = 64U + movement_count;
    PVOID address = allocate(process_heap, 0U, original_size);
    PVOID blocker = allocate(process_heap, 0U, 4'096U);
    if (address == nullptr || blocker == nullptr) {
      return 6;
    }
    std::memset(address, std::to_integer<int>(kPattern), original_size);
    const SIZE_T new_size = 1U * 1024U * 1024U + movement_count * 4'096U;
    Observation& attempt = movement_attempts[movement_count++];
    attempt = invoke(reallocate, process_heap, 0U, address, new_size);
    attempt.content_valid = attempt.result != nullptr && has_pattern(attempt.result, original_size);
    observed_move = attempt.result != nullptr && !attempt.result_equals_old;
    if (attempt.result != nullptr) {
      static_cast<void>(free_heap(process_heap, 0U, attempt.result));
    } else {
      static_cast<void>(free_heap(process_heap, 0U, address));
    }
    static_cast<void>(free_heap(process_heap, 0U, blocker));
    if (!attempt.returned || attempt.exception_status != 0U || attempt.result == nullptr ||
        !attempt.content_valid || attempt.last_error != kLastErrorSentinel) {
      print_observation("move", movement_count - 1U, attempt);
      return 6;
    }
    ++expected_successes;
  }
  if (!observed_move) {
    return 6;
  }

  PVOID recursive_address = allocate(process_heap, 0U, 128U);
  PVOID internal_address = allocate(process_heap, 0U, 128U);
  if (recursive_address == nullptr || internal_address == nullptr) {
    return 7;
  }
  Observation recursive;
  {
    const noleax::agent::HookInvocationGuard simulated_outer_hook;
    recursive = invoke(reallocate, process_heap, 0U, recursive_address, 192U);
  }
  Observation internal;
  {
    const noleax::agent::InternalThreadScope internal_thread;
    internal = invoke(reallocate, process_heap, 0U, internal_address, 224U);
  }
  if (recursive.result == nullptr || internal.result == nullptr ||
      recursive.last_error != kLastErrorSentinel || internal.last_error != kLastErrorSentinel ||
      noleax::agent::current_hook_depth() != 0U || noleax::agent::current_thread_is_internal()) {
    return 7;
  }
  static_cast<void>(free_heap(process_heap, 0U, recursive.result));
  static_cast<void>(free_heap(process_heap, 0U, internal.result));

  std::array<bool, cases.size()> found{};
  std::array<bool, movement_attempts.size()> movement_found{};
  std::uint64_t dequeued = 0U;
  noleax::agent::windows::RtlReAllocateHeapEvent event;
  while (hook.try_dequeue_event(event)) {
    if (event.queue_sequence != previous_sequence + 1U || event.monotonic_ticks == 0U ||
        event.thread_id == 0U ||
        event.stack.method !=
            noleax::agent::windows::StackCaptureMethod::kRtlCaptureStackBackTrace ||
        event.stack.requested_depth != kStackDepth ||
        !noleax::agent::windows::stack_capture_succeeded(event.stack)) {
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
    for (std::size_t index = 0U; !matched && index < movement_count; ++index) {
      if (!movement_found[index] && event_matches(event, movement_attempts[index])) {
        movement_found[index] = true;
        matched = true;
      }
    }
    if (!matched) {
      return 9;
    }
  }

  bool all_found = dequeued == cases.size() + movement_count;
  for (const bool value : found) {
    all_found &= value;
  }
  for (std::size_t index = 0U; index < movement_count; ++index) {
    all_found &= movement_found[index];
  }
  const std::uint64_t expected_recordable = cases.size() + movement_count;
  const std::uint64_t expected_failures = expected_recordable - expected_successes;
  const bool counters_valid =
      hook.call_count() == calls_before + expected_recordable + 2U &&
      hook.recordable_call_count() == recordable_before + expected_recordable &&
      hook.recursive_call_count() == recursive_before + 1U &&
      hook.internal_call_count() == internal_before + 1U &&
      hook.successful_call_count() == successful_before + expected_successes &&
      hook.failed_call_count() == failed_before + expected_failures &&
      hook.dropped_event_count() == 0U;

  const bool uninstalled = finish_uninstall(hook);
  const bool shutdown = backend.shutdown();
  if (!all_found || !counters_valid || !uninstalled || !shutdown) {
    std::fprintf(stderr,
                 "RtlReAllocateHeap contract failed: events=%llu expected=%llu calls=%llu "
                 "recordable=%llu recursive=%llu internal=%llu success=%llu failure=%llu\n",
                 static_cast<unsigned long long>(dequeued),
                 static_cast<unsigned long long>(expected_recordable),
                 static_cast<unsigned long long>(hook.call_count()),
                 static_cast<unsigned long long>(hook.recordable_call_count()),
                 static_cast<unsigned long long>(hook.recursive_call_count()),
                 static_cast<unsigned long long>(hook.internal_call_count()),
                 static_cast<unsigned long long>(hook.successful_call_count()),
                 static_cast<unsigned long long>(hook.failed_call_count()));
    return 10;
  }

  std::printf("status=ok cases=4 move=1 outermost=%llu recursive=1 internal=1 last_error=%lu\n",
              static_cast<unsigned long long>(expected_recordable),
              static_cast<unsigned long>(kLastErrorSentinel));
  return 0;
}
