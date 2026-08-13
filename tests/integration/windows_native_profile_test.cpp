#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <stdexcept>
#include <variant>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/hook_registry.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_trace_writer.hpp"
#include "noleax/agent/windows/windows_memory_hooks.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/trace/event.hpp"

namespace {

using RtlCreateHeapFunction = PVOID(NTAPI*)(ULONG flags, PVOID heap_base, SIZE_T reserve_size,
                                            SIZE_T commit_size, PVOID lock, PVOID parameters);
using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlReAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, PVOID address,
                                                SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID address);
using RtlDestroyHeapFunction = PVOID(NTAPI*)(PVOID heap);
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

constexpr SIZE_T kPageSize = 4096U;
constexpr SIZE_T kMinimumCaptureSize = 64U * 1024U;
constexpr SIZE_T kLargeSize = 128U * 1024U;
constexpr std::size_t kWorkerCount = 4U;
constexpr std::size_t kChurnCount = 16U;

struct NativeFunctions {
  RtlCreateHeapFunction create_heap{nullptr};
  RtlAllocateHeapFunction allocate_heap{nullptr};
  RtlReAllocateHeapFunction reallocate_heap{nullptr};
  RtlFreeHeapFunction free_heap{nullptr};
  RtlDestroyHeapFunction destroy_heap{nullptr};
  NtAllocateVirtualMemoryFunction allocate_virtual_memory{nullptr};
  NtFreeVirtualMemoryFunction free_virtual_memory{nullptr};
  NtMapViewOfSectionFunction map_view{nullptr};
  NtUnmapViewOfSectionFunction unmap_view{nullptr};

  [[nodiscard]] bool complete() const noexcept {
    return create_heap != nullptr && allocate_heap != nullptr && reallocate_heap != nullptr &&
           free_heap != nullptr && destroy_heap != nullptr && allocate_virtual_memory != nullptr &&
           free_virtual_memory != nullptr && map_view != nullptr && unmap_view != nullptr;
  }
};

struct WorkerContext {
  const NativeFunctions* functions{nullptr};
  std::atomic<bool>* run{nullptr};
  PVOID process_heap{nullptr};
  std::atomic<std::uint64_t>* operations{nullptr};
};

[[nodiscard]] bool nt_success(NTSTATUS status) noexcept { return status >= 0; }

DWORD WINAPI churn_worker(void* parameter) noexcept {
  auto* const context = static_cast<WorkerContext*>(parameter);
  std::uint64_t iteration = 0U;
  while (context->run->load(std::memory_order_acquire)) {
    PVOID allocation =
        context->functions->allocate_heap(context->process_heap, 0U, kLargeSize + iteration % 97U);
    if (allocation != nullptr) {
      static_cast<void>(context->functions->free_heap(context->process_heap, 0U, allocation));
    }
    if ((iteration & 63U) == 0U) {
      PVOID base = nullptr;
      SIZE_T size = kLargeSize;
      if (nt_success(context->functions->allocate_virtual_memory(
              GetCurrentProcess(), &base, 0U, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
        SIZE_T release_size = 0U;
        static_cast<void>(context->functions->free_virtual_memory(GetCurrentProcess(), &base,
                                                                  &release_size, MEM_RELEASE));
      }
    }
    context->operations->fetch_add(1U, std::memory_order_relaxed);
    ++iteration;
    if ((iteration & 15U) == 0U) {
      Sleep(1U);
    }
  }
  return 0U;
}

DWORD WINAPI one_shot_worker(void* parameter) noexcept {
  auto* const context = static_cast<WorkerContext*>(parameter);
  PVOID allocation = context->functions->allocate_heap(context->process_heap, 0U, kLargeSize);
  if (allocation != nullptr) {
    static_cast<void>(context->functions->free_heap(context->process_heap, 0U, allocation));
  }
  context->operations->fetch_add(1U, std::memory_order_relaxed);
  return 0U;
}

[[nodiscard]] NativeFunctions resolve_functions() noexcept {
  NativeFunctions functions;
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    return functions;
  }
  functions.create_heap =
      reinterpret_cast<RtlCreateHeapFunction>(GetProcAddress(ntdll, "RtlCreateHeap"));
  functions.allocate_heap =
      reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  functions.reallocate_heap =
      reinterpret_cast<RtlReAllocateHeapFunction>(GetProcAddress(ntdll, "RtlReAllocateHeap"));
  functions.free_heap = reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  functions.destroy_heap =
      reinterpret_cast<RtlDestroyHeapFunction>(GetProcAddress(ntdll, "RtlDestroyHeap"));
  functions.allocate_virtual_memory = reinterpret_cast<NtAllocateVirtualMemoryFunction>(
      GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
  functions.free_virtual_memory =
      reinterpret_cast<NtFreeVirtualMemoryFunction>(GetProcAddress(ntdll, "NtFreeVirtualMemory"));
  functions.map_view =
      reinterpret_cast<NtMapViewOfSectionFunction>(GetProcAddress(ntdll, "NtMapViewOfSection"));
  functions.unmap_view =
      reinterpret_cast<NtUnmapViewOfSectionFunction>(GetProcAddress(ntdll, "NtUnmapViewOfSection"));
  return functions;
}

[[nodiscard]] noleax::trace::FileHeader make_file_header() {
  LARGE_INTEGER frequency{};
  LARGE_INTEGER origin{};
  if (QueryPerformanceFrequency(&frequency) == FALSE || QueryPerformanceCounter(&origin) == FALSE) {
    throw std::runtime_error{"QueryPerformanceCounter is unavailable"};
  }
  noleax::trace::FileHeader header;
  header.pointer_width = sizeof(void*);
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.session_id[0] = std::byte{0x57};
  header.monotonic_frequency = static_cast<std::uint64_t>(frequency.QuadPart);
  header.monotonic_origin = static_cast<std::uint64_t>(origin.QuadPart);
  return header;
}

[[nodiscard]] const noleax::trace::ApiStatistics* find_api_statistics(
    const noleax::trace::CaptureStatistics& statistics, noleax::trace::ApiId api_id) noexcept {
  for (const auto& api : statistics.per_api) {
    if (api.api_id == api_id) {
      return &api;
    }
  }
  return nullptr;
}

[[nodiscard]] std::array<std::uint64_t, 9U> recordable_counts(
    const noleax::agent::windows::WindowsMemoryHooks& hooks) noexcept {
  const auto* const heap = hooks.nt_heap_hooks();
  const auto* const virtual_memory = hooks.virtual_memory_hooks();
  const auto allocate = virtual_memory->allocate_statistics();
  const auto free = virtual_memory->free_statistics();
  const auto map = virtual_memory->map_statistics();
  const auto unmap = virtual_memory->unmap_statistics();
  return {
      heap->allocate_hook().recordable_call_count(),
      heap->free_hook().recordable_call_count(),
      heap->reallocate_hook().recordable_call_count(),
      heap->create_hook().recordable_call_count(),
      heap->destroy_hook().recordable_call_count(),
      allocate.recordable_calls,
      free.recordable_calls,
      map.recordable_calls,
      unmap.recordable_calls,
  };
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 2) {
    return 2;
  }
  const NativeFunctions functions = resolve_functions();
  const PVOID process_heap = GetProcessHeap();
  if (!functions.complete() || process_heap == nullptr) {
    std::fprintf(stderr,
                 "native function resolution failed: heap=%p create=%p allocate=%p realloc=%p "
                 "free=%p destroy=%p vm-allocate=%p vm-free=%p map=%p unmap=%p\n",
                 process_heap, reinterpret_cast<void*>(functions.create_heap),
                 reinterpret_cast<void*>(functions.allocate_heap),
                 reinterpret_cast<void*>(functions.reallocate_heap),
                 reinterpret_cast<void*>(functions.free_heap),
                 reinterpret_cast<void*>(functions.destroy_heap),
                 reinterpret_cast<void*>(functions.allocate_virtual_memory),
                 reinterpret_cast<void*>(functions.free_virtual_memory),
                 reinterpret_cast<void*>(functions.map_view),
                 reinterpret_cast<void*>(functions.unmap_view));
    return 3;
  }

  const HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0U,
                                            4U * kLargeSize, nullptr);
  if (section == nullptr) {
    return 4;
  }
  const std::filesystem::path output_path{argv[1]};
  std::ofstream output{output_path, std::ios::binary | std::ios::trunc};
  if (!output) {
    CloseHandle(section);
    return 5;
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::WindowsMemoryHookOptions hook_options;
  hook_options.profile = noleax::agent::windows::WindowsHookProfile::kNative;
  hook_options.event_queue_capacity = 32'768U;
  hook_options.maximum_stack_depth = 16U;
  hook_options.minimum_capture_size = kMinimumCaptureSize;
  noleax::agent::windows::WindowsMemoryHooks hooks{backend, hook_options};
  noleax::agent::windows::RtlAllocateHeapTraceWriterOptions writer_options;
  writer_options.flush_interval = std::chrono::milliseconds{5};
  writer_options.chunk_target_size = 8U * 1024U;
  writer_options.stack_dictionary_capacity = 1024U;
  writer_options.trace.max_file_size = 32U * 1024U * 1024U;
  noleax::agent::windows::RtlAllocateHeapTraceWriter writer{hooks, output, make_file_header(),
                                                            writer_options};
  if (!hooks.install().installed() || !hooks.is_installed() || !hooks.is_recording()) {
    return 6;
  }
  writer.begin_capture();
  bool early_finish_rejected = false;
  try {
    static_cast<void>(writer.finish());
  } catch (const std::logic_error&) {
    early_finish_rejected = true;
  }
  const bool early_uninstall_rejected = !hooks.uninstall(std::chrono::steady_clock::now());

  auto* const heap_hooks = hooks.nt_heap_hooks();
  auto* const virtual_memory_hooks = hooks.virtual_memory_hooks();
  if (heap_hooks == nullptr || virtual_memory_hooks == nullptr ||
      &heap_hooks->event_queue() != &hooks.event_queue() ||
      &virtual_memory_hooks->event_queue() != &hooks.event_queue() || !early_finish_rejected ||
      !early_uninstall_rejected) {
    return 7;
  }

  PVOID heap = functions.create_heap(HEAP_GROWABLE, nullptr, 0U, 0U, nullptr, nullptr);
  const std::uint64_t heap_filtered_before = heap_hooks->allocate_hook().filtered_call_count();
  PVOID small_heap = heap == nullptr ? nullptr : functions.allocate_heap(heap, 0U, 32U);
  const std::uint64_t heap_filtered_after = heap_hooks->allocate_hook().filtered_call_count();
  PVOID reallocated_heap =
      small_heap == nullptr ? nullptr : functions.reallocate_heap(heap, 0U, small_heap, 64U);
  const bool small_heap_freed =
      reallocated_heap != nullptr && functions.free_heap(heap, 0U, reallocated_heap) != FALSE;
  PVOID large_heap = heap == nullptr ? nullptr : functions.allocate_heap(heap, 0U, kLargeSize);
  const bool large_heap_freed =
      large_heap != nullptr && functions.free_heap(heap, 0U, large_heap) != FALSE;
  const bool heap_destroyed = heap != nullptr && functions.destroy_heap(heap) == nullptr;

  const auto vm_filtered_before = virtual_memory_hooks->allocate_statistics().filtered_calls;
  PVOID small_vm = nullptr;
  SIZE_T small_vm_size = kPageSize;
  const NTSTATUS small_vm_status = functions.allocate_virtual_memory(
      GetCurrentProcess(), &small_vm, 0U, &small_vm_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  const auto vm_filtered_after = virtual_memory_hooks->allocate_statistics().filtered_calls;
  SIZE_T small_release_size = 0U;
  const NTSTATUS small_vm_free = functions.free_virtual_memory(GetCurrentProcess(), &small_vm,
                                                               &small_release_size, MEM_RELEASE);
  PVOID large_vm = nullptr;
  SIZE_T large_vm_size = kLargeSize;
  const NTSTATUS large_vm_status = functions.allocate_virtual_memory(
      GetCurrentProcess(), &large_vm, 0U, &large_vm_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  SIZE_T large_release_size = 0U;
  const NTSTATUS large_vm_free = functions.free_virtual_memory(GetCurrentProcess(), &large_vm,
                                                               &large_release_size, MEM_RELEASE);

  const auto map_filtered_before = virtual_memory_hooks->map_statistics().filtered_calls;
  PVOID small_view = nullptr;
  SIZE_T small_view_size = kPageSize;
  const NTSTATUS small_map = functions.map_view(section, GetCurrentProcess(), &small_view, 0U, 0U,
                                                nullptr, &small_view_size, 2U, 0U, PAGE_READWRITE);
  const auto map_filtered_after = virtual_memory_hooks->map_statistics().filtered_calls;
  const NTSTATUS small_unmap = functions.unmap_view(GetCurrentProcess(), small_view);
  PVOID large_view = nullptr;
  SIZE_T large_view_size = kLargeSize;
  const NTSTATUS large_map = functions.map_view(section, GetCurrentProcess(), &large_view, 0U, 0U,
                                                nullptr, &large_view_size, 2U, 0U, PAGE_READWRITE);
  const NTSTATUS large_unmap = functions.unmap_view(GetCurrentProcess(), large_view);

  const bool deterministic_calls_valid =
      heap != nullptr && small_heap != nullptr && reallocated_heap != nullptr && small_heap_freed &&
      large_heap != nullptr && large_heap_freed && heap_destroyed && nt_success(small_vm_status) &&
      nt_success(small_vm_free) && nt_success(large_vm_status) && nt_success(large_vm_free) &&
      nt_success(small_map) && nt_success(small_unmap) && nt_success(large_map) &&
      nt_success(large_unmap) && heap_filtered_after == heap_filtered_before + 1U &&
      vm_filtered_after == vm_filtered_before + 1U &&
      map_filtered_after == map_filtered_before + 1U;
  if (!deterministic_calls_valid) {
    return 8;
  }

  std::atomic<bool> run{true};
  std::atomic<std::uint64_t> operations{0U};
  WorkerContext context{&functions, &run, process_heap, &operations};
  std::array<HANDLE, kWorkerCount> workers{};
  for (HANDLE& worker : workers) {
    worker = CreateThread(nullptr, 0U, churn_worker, &context, 0U, nullptr);
    if (worker == nullptr) {
      run.store(false, std::memory_order_release);
      return 9;
    }
  }
  Sleep(30U);
  const bool recording_stopped = hooks.stop_recording();
  const auto stopped_counts = recordable_counts(hooks);
  Sleep(20U);

  for (std::size_t index = 0U; index < kChurnCount; ++index) {
    const HANDLE thread = CreateThread(nullptr, 0U, one_shot_worker, &context, 0U, nullptr);
    if (thread == nullptr || WaitForSingleObject(thread, 30'000U) != WAIT_OBJECT_0) {
      run.store(false, std::memory_order_release);
      return 10;
    }
    CloseHandle(thread);
  }
  const auto churned_counts = recordable_counts(hooks);
  const bool counts_stable = stopped_counts == churned_counts;
  const auto writer_result = writer.finish();
  const bool writer_stopped_before_revert = !writer.is_running() && hooks.is_installed();

  run.store(false, std::memory_order_release);
  const DWORD wait_result =
      WaitForMultipleObjects(static_cast<DWORD>(workers.size()), workers.data(), TRUE, 30'000U);
  for (const HANDLE worker : workers) {
    CloseHandle(worker);
  }
  const bool workers_stopped = wait_result == WAIT_OBJECT_0;
  const bool physically_uninstalled = hooks.uninstall();
  const bool backend_stopped = backend.shutdown();
  output.close();
  const bool section_closed = CloseHandle(section) != FALSE;

  if (!recording_stopped || hooks.is_recording() || hooks.recording_in_flight_count() != 0U ||
      !counts_stable || !writer_stopped_before_revert || !workers_stopped ||
      !physically_uninstalled || !backend_stopped || !section_closed || !output ||
      operations.load(std::memory_order_relaxed) == 0U ||
      writer_result.status != noleax::agent::windows::RtlAllocateHeapTraceWriterStatus::kComplete ||
      writer_result.queue_dropped_events != 0U || writer_result.trace_dropped_events != 0U) {
    std::fprintf(stderr,
                 "native profile shutdown failed: logical=%u recording=%u inflight=%llu stable=%u "
                 "writer-first=%u workers=%u uninstall=%u backend=%u section=%u output=%u ops=%llu "
                 "status=%u queue=%llu trace=%llu error=%s\n",
                 recording_stopped ? 1U : 0U, hooks.is_recording() ? 1U : 0U,
                 static_cast<unsigned long long>(hooks.recording_in_flight_count()),
                 counts_stable ? 1U : 0U, writer_stopped_before_revert ? 1U : 0U,
                 workers_stopped ? 1U : 0U, physically_uninstalled ? 1U : 0U,
                 backend_stopped ? 1U : 0U, section_closed ? 1U : 0U, output ? 1U : 0U,
                 static_cast<unsigned long long>(operations.load(std::memory_order_relaxed)),
                 static_cast<unsigned int>(writer_result.status),
                 static_cast<unsigned long long>(writer_result.queue_dropped_events),
                 static_cast<unsigned long long>(writer_result.trace_dropped_events),
                 writer_result.error_message.c_str());
    return 11;
  }

  std::ifstream input{output_path, std::ios::binary};
  if (!input) {
    return 12;
  }
  std::array<bool, 10U> observed_api{};
  noleax::analyzer::GenerationTracker generations;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_event = [&observed_api, &generations](const noleax::trace::Event& event) {
    generations.observe(event);
    if (event.header.api_id < observed_api.size()) {
      observed_api[event.header.api_id] = true;
    }
  };
  const auto parsed = noleax::analyzer::analyze_event_stream(input, callbacks);

  bool all_apis_observed = true;
  for (std::size_t api_id = 1U; api_id < observed_api.size(); ++api_id) {
    all_apis_observed &= observed_api[api_id];
  }
  bool per_api_counts_match = writer_result.statistics.per_api.size() == 9U;
  std::uint64_t filtered_total = 0U;
  for (std::size_t index = 0U; index < stopped_counts.size(); ++index) {
    const auto* const statistics = find_api_statistics(
        writer_result.statistics, static_cast<noleax::trace::ApiId>(index + 1U));
    per_api_counts_match &= statistics != nullptr &&
                            statistics->observed_calls == stopped_counts[index] &&
                            statistics->dropped_events == 0U;
    if (statistics != nullptr) {
      filtered_total += statistics->filtered_before_queue;
    }
  }
  const auto* const heap_allocate_statistics =
      find_api_statistics(writer_result.statistics, noleax::agent::windows::kRtlAllocateHeapApiId);
  const auto* const vm_allocate_statistics = find_api_statistics(
      writer_result.statistics, noleax::agent::windows::kNtAllocateVirtualMemoryApiId);
  const auto* const map_statistics = find_api_statistics(
      writer_result.statistics, noleax::agent::windows::kNtMapViewOfSectionApiId);
  const bool filtering_valid = heap_allocate_statistics != nullptr &&
                               vm_allocate_statistics != nullptr && map_statistics != nullptr &&
                               heap_allocate_statistics->filtered_before_queue != 0U &&
                               vm_allocate_statistics->filtered_before_queue != 0U &&
                               map_statistics->filtered_before_queue != 0U &&
                               writer_result.statistics.filtered_before_queue == filtered_total;
  const std::uint64_t expected_events = writer_result.statistics.observed_calls -
                                        writer_result.statistics.filtered_before_queue -
                                        writer_result.statistics.dropped_events;
  const bool trace_valid = all_apis_observed && per_api_counts_match && filtering_valid &&
                           parsed.event_count == expected_events &&
                           parsed.statistics == writer_result.statistics &&
                           parsed.end_of_trace.has_value() && parsed.end_of_trace->normal_stop &&
                           !parsed.completeness.has(noleax::trace::CompletenessIssue::kEventLoss);
  if (!trace_valid) {
    std::fprintf(stderr,
                 "native profile trace failed: events=%llu expected=%llu observed=%llu "
                 "filtered=%llu apis=%u counts=%u filter=%u stats=%u end=%u\n",
                 static_cast<unsigned long long>(parsed.event_count),
                 static_cast<unsigned long long>(expected_events),
                 static_cast<unsigned long long>(writer_result.statistics.observed_calls),
                 static_cast<unsigned long long>(writer_result.statistics.filtered_before_queue),
                 all_apis_observed ? 1U : 0U, per_api_counts_match ? 1U : 0U,
                 filtering_valid ? 1U : 0U, parsed.statistics == writer_result.statistics ? 1U : 0U,
                 parsed.end_of_trace.has_value() ? 1U : 0U);
    return 13;
  }

  std::printf(
      "status=ok profile=windows-native apis=9 events=%llu filtered=%llu stable=1 "
      "writer-before-revert=1 operations=%llu\n",
      static_cast<unsigned long long>(parsed.event_count),
      static_cast<unsigned long long>(writer_result.statistics.filtered_before_queue),
      static_cast<unsigned long long>(operations.load(std::memory_order_relaxed)));
  return 0;
}
