#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID allocation);

constexpr ULONG kExceptionFlags = HEAP_GENERATE_EXCEPTIONS;
constexpr DWORD kLastErrorSentinel = 0xa1490001U;
constexpr SIZE_T kImpossibleSize =
    (std::numeric_limits<SIZE_T>::max)() - static_cast<SIZE_T>(65'535U);

struct ExceptionObservation {
  std::array<ULONG_PTR, EXCEPTION_MAXIMUM_PARAMETERS> parameters{};
  PVOID result{nullptr};
  DWORD exception_status{0U};
  DWORD exception_flags{0U};
  DWORD last_error{ERROR_SUCCESS};
  DWORD parameter_count{0U};
  bool returned{false};
};

[[nodiscard]] LONG capture_exception(EXCEPTION_POINTERS* pointers,
                                     ExceptionObservation* observation) noexcept {
  if (pointers == nullptr || pointers->ExceptionRecord == nullptr || observation == nullptr) {
    return EXCEPTION_EXECUTE_HANDLER;
  }
  const EXCEPTION_RECORD& record = *pointers->ExceptionRecord;
  observation->exception_status = record.ExceptionCode;
  observation->exception_flags = record.ExceptionFlags;
  observation->parameter_count =
      (std::min)(record.NumberParameters, static_cast<DWORD>(EXCEPTION_MAXIMUM_PARAMETERS));
  for (DWORD index = 0U; index < observation->parameter_count; ++index) {
    observation->parameters[index] = record.ExceptionInformation[index];
  }
  return EXCEPTION_EXECUTE_HANDLER;
}

[[nodiscard]] ExceptionObservation invoke_exceptional_allocation(RtlAllocateHeapFunction allocate,
                                                                 PVOID heap) noexcept {
  ExceptionObservation observation;
  SetLastError(kLastErrorSentinel);
  __try {
    observation.result = allocate(heap, kExceptionFlags, kImpossibleSize);
    observation.returned = true;
  } __except (capture_exception(GetExceptionInformation(), &observation)) {
  }
  observation.last_error = GetLastError();
  return observation;
}

[[nodiscard]] bool same_exception(const ExceptionObservation& left,
                                  const ExceptionObservation& right) noexcept {
  if (left.returned || right.returned || left.exception_status == 0U ||
      left.exception_status != right.exception_status ||
      left.exception_flags != right.exception_flags ||
      left.parameter_count != right.parameter_count || left.last_error != right.last_error) {
    return false;
  }
  for (DWORD index = 0U; index < left.parameter_count; ++index) {
    if (left.parameters[index] != right.parameters[index]) {
      return false;
    }
  }
  return true;
}

}  // namespace

int main() {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const HANDLE heap = GetProcessHeap();
  const auto allocate =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  const auto free_heap =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  if (heap == nullptr || allocate == nullptr || free_heap == nullptr) {
    return 2;
  }

  const ExceptionObservation baseline = invoke_exceptional_allocation(allocate, heap);
  if (baseline.returned || baseline.exception_status == 0U) {
    std::fprintf(stderr, "baseline HEAP_GENERATE_EXCEPTIONS call did not raise\n");
    return 3;
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlAllocateHeapHook hook{backend, 64U, 0U};
  const auto installed = hook.install();
  if (!installed.installed()) {
    return 4;
  }

  noleax::agent::windows::RtlAllocateHeapEvent discarded;
  while (hook.try_dequeue_event(discarded)) {
  }
  static_cast<void>(hook.take_dropped_event_count());

  const std::uint64_t recordable_before = hook.recordable_call_count();
  const std::uint64_t failed_before = hook.failed_call_count();
  const std::uint64_t exceptional_before = hook.exceptional_call_count();
  const ExceptionObservation hooked = invoke_exceptional_allocation(allocate, heap);

  bool found_exception_event = false;
  noleax::agent::windows::RtlAllocateHeapEvent event;
  while (hook.try_dequeue_event(event)) {
    if (event.status == noleax::agent::windows::RtlAllocateHeapEventStatus::kException &&
        event.exception_status == hooked.exception_status && event.flags == kExceptionFlags &&
        event.requested_size == static_cast<std::uint64_t>(kImpossibleSize) &&
        event.heap_handle == static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(heap)) &&
        event.result_address == 0U) {
      found_exception_event = true;
    }
  }

  const bool exception_state_valid =
      same_exception(baseline, hooked) && hook.recordable_call_count() == recordable_before + 1U &&
      hook.failed_call_count() == failed_before + 1U &&
      hook.exceptional_call_count() == exceptional_before + 1U &&
      hook.replacement_in_flight_count() == 0U && noleax::agent::current_hook_depth() == 0U &&
      found_exception_event;

  const std::uint64_t successful_before = hook.successful_call_count();
  const std::uint64_t normal_recordable_before = hook.recordable_call_count();
  void* const normal = allocate(heap, 0U, 96U);
  const bool normal_valid =
      normal != nullptr && hook.successful_call_count() == successful_before + 1U &&
      hook.recordable_call_count() == normal_recordable_before + 1U &&
      hook.replacement_in_flight_count() == 0U && noleax::agent::current_hook_depth() == 0U;
  if (normal != nullptr) {
    static_cast<void>(free_heap(heap, 0U, normal));
  }

  auto uninstall_status = hook.uninstall(0U);
  if (uninstall_status == noleax::agent::HookUninstallStatus::kTeardownPending &&
      hook.flush(100'000U)) {
    uninstall_status = noleax::agent::HookUninstallStatus::kUninstalled;
  }
  const bool shutdown = backend.shutdown();

  if (!exception_state_valid || !normal_valid ||
      uninstall_status != noleax::agent::HookUninstallStatus::kUninstalled || !shutdown) {
    std::fprintf(stderr,
                 "SEH contract failed: baseline=0x%08lx hooked=0x%08lx last_error=%lu/%lu "
                 "recordable=%llu failed=%llu exceptional=%llu in_flight=%llu depth=%u "
                 "event=%u normal=%u uninstall=%u shutdown=%u\n",
                 static_cast<unsigned long>(baseline.exception_status),
                 static_cast<unsigned long>(hooked.exception_status),
                 static_cast<unsigned long>(baseline.last_error),
                 static_cast<unsigned long>(hooked.last_error),
                 static_cast<unsigned long long>(hook.recordable_call_count()),
                 static_cast<unsigned long long>(hook.failed_call_count()),
                 static_cast<unsigned long long>(hook.exceptional_call_count()),
                 static_cast<unsigned long long>(hook.replacement_in_flight_count()),
                 noleax::agent::current_hook_depth(), found_exception_event ? 1U : 0U,
                 normal_valid ? 1U : 0U, static_cast<unsigned int>(uninstall_status),
                 shutdown ? 1U : 0U);
    return 5;
  }

  std::printf("status=ok exception=0x%08lx last_error=%lu event=1 cleanup=1\n",
              static_cast<unsigned long>(hooked.exception_status),
              static_cast<unsigned long>(hooked.last_error));
  return 0;
}
