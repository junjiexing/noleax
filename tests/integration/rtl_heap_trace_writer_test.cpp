#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "noleax/agent/windows/rtl_heap_trace_writer.hpp"

#include <windows.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"
#include "noleax/agent/windows/rtl_free_heap_hook.hpp"
#include "noleax/agent/windows/rtl_heap_hooks.hpp"
#include "noleax/agent/windows/rtl_reallocate_heap_hook.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/trace/event.hpp"

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlCreateHeapFunction = PVOID(NTAPI*)(ULONG flags, PVOID heap_base, SIZE_T reserve_size,
                                            SIZE_T commit_size, PVOID lock, PVOID parameters);
using RtlReAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, PVOID address,
                                                SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID address);
using RtlDestroyHeapFunction = PVOID(NTAPI*)(PVOID heap);

constexpr SIZE_T kMatchedSize = 12'345U;
constexpr SIZE_T kOutstandingSize = 23'457U;
constexpr SIZE_T kCrossThreadSize = 34'569U;
constexpr SIZE_T kInPlaceOriginalSize = 45'671U;
constexpr SIZE_T kInPlaceNewSize = 44'321U;
constexpr SIZE_T kFailureOriginalSize = 56'783U;
constexpr SIZE_T kCrossReallocateOriginalSize = 67'891U;
constexpr SIZE_T kCrossReallocateNewSize = 79'013U;
constexpr SIZE_T kZeroOriginalSize = 81'127U;
constexpr SIZE_T kPreexistingNewSize = 91'229U;
constexpr SIZE_T kDestroyedWithHeapSize = 102'451U;
constexpr SIZE_T kFreedBeforeHeapDestroySize = 113'671U;
constexpr std::uint32_t kHeapReuseAttempts = 64U;
constexpr SIZE_T kImpossibleSize =
    (std::numeric_limits<SIZE_T>::max)() - static_cast<SIZE_T>(65'535U);

struct ThreadFreeContext {
  RtlFreeHeapFunction free_heap{nullptr};
  PVOID heap{nullptr};
  PVOID address{nullptr};
  BOOLEAN result{FALSE};
};

struct ThreadReallocateContext {
  RtlReAllocateHeapFunction reallocate{nullptr};
  PVOID heap{nullptr};
  PVOID address{nullptr};
  SIZE_T size{0U};
  PVOID result{nullptr};
  DWORD thread_id{0U};
};

DWORD WINAPI free_on_thread(void* parameter) noexcept {
  auto* const context = static_cast<ThreadFreeContext*>(parameter);
  context->result = context->free_heap(context->heap, 0U, context->address);
  return context->result == FALSE ? 1U : 0U;
}

DWORD WINAPI reallocate_on_thread(void* parameter) noexcept {
  auto* const context = static_cast<ThreadReallocateContext*>(parameter);
  context->thread_id = GetCurrentThreadId();
  context->result = context->reallocate(context->heap, 0U, context->address, context->size);
  return context->result == nullptr ? 1U : 0U;
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
  header.session_id[0] = std::byte{0x51};
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

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 2) {
    return 2;
  }
  const std::filesystem::path output_path{argv[1]};
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const PVOID process_heap = GetProcessHeap();
  const auto allocate =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  const auto create =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlCreateHeapFunction>(GetProcAddress(ntdll, "RtlCreateHeap"));
  const auto free_heap =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  const auto reallocate =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlReAllocateHeapFunction>(GetProcAddress(ntdll, "RtlReAllocateHeap"));
  const auto destroy =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlDestroyHeapFunction>(GetProcAddress(ntdll, "RtlDestroyHeap"));
  if (process_heap == nullptr || create == nullptr || allocate == nullptr ||
      reallocate == nullptr || free_heap == nullptr || destroy == nullptr) {
    std::fprintf(stderr,
                 "Rtl heap entry resolution failed: ntdll=%p heap=%p alloc=%p realloc=%p "
                 "free=%p create=%p destroy=%p\n",
                 static_cast<void*>(ntdll), process_heap, reinterpret_cast<void*>(allocate),
                 reinterpret_cast<void*>(reallocate), reinterpret_cast<void*>(free_heap),
                 reinterpret_cast<void*>(create), reinterpret_cast<void*>(destroy));
    return 3;
  }
  PVOID preexisting = allocate(process_heap, 0U, 4'093U);
  if (preexisting == nullptr) {
    return 4;
  }

  std::ofstream output{output_path, std::ios::binary | std::ios::trunc};
  if (!output) {
    return 5;
  }
  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlHeapHooks hooks{backend, 32'768U, 16U};
  auto& create_hook = hooks.create_hook();
  auto& allocate_hook = hooks.allocate_hook();
  auto& reallocate_hook = hooks.reallocate_hook();
  auto& free_hook = hooks.free_hook();
  auto& destroy_hook = hooks.destroy_hook();

  {
    noleax::agent::windows::RtlCreateHeapHook separate_create{backend, 16U, 0U};
    noleax::agent::windows::RtlAllocateHeapHook separate_allocate{backend, 16U, 0U};
    noleax::agent::windows::RtlReAllocateHeapHook separate_reallocate{backend, 16U, 0U};
    noleax::agent::windows::RtlFreeHeapHook separate_free{backend, 16U, 0U};
    noleax::agent::windows::RtlDestroyHeapHook separate_destroy{backend, 16U, 0U};
    std::ostringstream discarded;
    bool rejected = false;
    try {
      noleax::agent::windows::RtlHeapTraceWriter invalid_writer{
          separate_create,  separate_allocate, separate_reallocate, separate_free,
          separate_destroy, discarded,         make_file_header()};
    } catch (const std::invalid_argument&) {
      rejected = true;
    }
    if (!rejected) {
      return 6;
    }
  }

  noleax::agent::windows::RtlHeapTraceWriterOptions options;
  options.flush_interval = std::chrono::milliseconds{5};
  options.chunk_target_size = 4U * 1024U;
  options.stack_dictionary_capacity = 256U;
  options.trace.max_file_size = 16U * 1024U * 1024U;
  noleax::agent::windows::RtlHeapTraceWriter writer{
      create_hook,  allocate_hook, reallocate_hook,    free_hook,
      destroy_hook, output,        make_file_header(), options};

  const auto installed = hooks.install();
  if (!installed.installed()) {
    return 8;
  }
  writer.begin_capture();

  PVOID first_heap = create(HEAP_GROWABLE, nullptr, 0U, 0U, nullptr, nullptr);
  PVOID second_heap = create(HEAP_GROWABLE, nullptr, 0U, 0U, nullptr, nullptr);
  if (first_heap == nullptr || second_heap == nullptr || first_heap == second_heap) {
    return 91;
  }
  PVOID destroyed_with_heap = allocate(first_heap, 0U, kDestroyedWithHeapSize);
  PVOID freed_before_heap_destroy = allocate(second_heap, 0U, kFreedBeforeHeapDestroySize);
  const PVOID first_destroy_result = destroy(first_heap);
  const BOOLEAN second_free_result = free_heap(second_heap, 0U, freed_before_heap_destroy);
  const PVOID second_destroy_result = destroy(second_heap);
  if (destroyed_with_heap == nullptr || freed_before_heap_destroy == nullptr ||
      first_destroy_result != nullptr || second_free_result == FALSE ||
      second_destroy_result != nullptr) {
    std::fprintf(stderr, "heap lifecycle setup failed: allocations=%p/%p destroy=%p/%p free=%u\n",
                 destroyed_with_heap, freed_before_heap_destroy, first_destroy_result,
                 second_destroy_result, static_cast<unsigned int>(second_free_result));
    return 92;
  }

  std::array<std::uintptr_t, static_cast<std::size_t>(kHeapReuseAttempts) + 2U>
      runtime_heap_handles{};
  std::size_t runtime_heap_handle_count = 0U;
  runtime_heap_handles[runtime_heap_handle_count++] = reinterpret_cast<std::uintptr_t>(first_heap);
  runtime_heap_handles[runtime_heap_handle_count++] = reinterpret_cast<std::uintptr_t>(second_heap);
  bool runtime_handle_reused = false;
  for (std::uint32_t attempt = 0U; attempt < kHeapReuseAttempts; ++attempt) {
    PVOID heap = create(HEAP_GROWABLE, nullptr, 0U, 0U, nullptr, nullptr);
    if (heap == nullptr) {
      return 93;
    }
    const std::uintptr_t raw_heap = reinterpret_cast<std::uintptr_t>(heap);
    for (std::size_t index = 0U; index < runtime_heap_handle_count; ++index) {
      runtime_handle_reused |= runtime_heap_handles[index] == raw_heap;
    }
    runtime_heap_handles[runtime_heap_handle_count++] = raw_heap;
    if (destroy(heap) != nullptr) {
      return 94;
    }
  }
  if (!runtime_handle_reused) {
    return 95;
  }

  PVOID matched = allocate(process_heap, 0U, kMatchedSize);
  PVOID outstanding = allocate(process_heap, 0U, kOutstandingSize);
  PVOID cross_thread = allocate(process_heap, 0U, kCrossThreadSize);
  PVOID in_place = allocate(process_heap, 0U, kInPlaceOriginalSize);
  PVOID failure_source = allocate(process_heap, 0U, kFailureOriginalSize);
  PVOID cross_reallocate = allocate(process_heap, 0U, kCrossReallocateOriginalSize);
  PVOID zero_source = allocate(process_heap, 0U, kZeroOriginalSize);
  if (matched == nullptr || outstanding == nullptr || cross_thread == nullptr ||
      in_place == nullptr || failure_source == nullptr || cross_reallocate == nullptr ||
      zero_source == nullptr) {
    return 9;
  }
  if (free_heap(process_heap, 0U, matched) == FALSE) {
    return 10;
  }

  ThreadFreeContext thread_context{free_heap, process_heap, cross_thread, FALSE};
  const HANDLE thread = CreateThread(nullptr, 0U, &free_on_thread, &thread_context, 0U, nullptr);
  if (thread == nullptr) {
    return 11;
  }
  const DWORD wait_status = WaitForSingleObject(thread, 30'000U);
  DWORD thread_exit = 1U;
  const bool thread_completed =
      wait_status == WAIT_OBJECT_0 && GetExitCodeThread(thread, &thread_exit) != FALSE;
  CloseHandle(thread);
  if (!thread_completed || thread_exit != 0U || thread_context.result == FALSE) {
    return 12;
  }

  PVOID in_place_result =
      reallocate(process_heap, HEAP_REALLOC_IN_PLACE_ONLY, in_place, kInPlaceNewSize);
  PVOID failure_result = reallocate(process_heap, 0U, failure_source, kImpossibleSize);
  PVOID zero_result = reallocate(process_heap, 0U, zero_source, 0U);
  PVOID preexisting_result = reallocate(process_heap, 0U, preexisting, kPreexistingNewSize);
  ThreadReallocateContext reallocate_context{
      reallocate, process_heap, cross_reallocate, kCrossReallocateNewSize, nullptr, 0U};
  const HANDLE reallocate_thread =
      CreateThread(nullptr, 0U, &reallocate_on_thread, &reallocate_context, 0U, nullptr);
  if (reallocate_thread == nullptr) {
    return 13;
  }
  const DWORD reallocate_wait = WaitForSingleObject(reallocate_thread, 30'000U);
  DWORD reallocate_exit = 1U;
  const bool reallocate_completed = reallocate_wait == WAIT_OBJECT_0 &&
                                    GetExitCodeThread(reallocate_thread, &reallocate_exit) != FALSE;
  CloseHandle(reallocate_thread);
  if (!reallocate_completed || reallocate_exit != 0U || in_place_result != in_place ||
      failure_result != nullptr || zero_result == nullptr || preexisting_result == nullptr ||
      reallocate_context.result == nullptr ||
      free_heap(process_heap, 0U, in_place_result) == FALSE ||
      free_heap(process_heap, 0U, failure_source) == FALSE ||
      free_heap(process_heap, 0U, zero_result) == FALSE ||
      free_heap(process_heap, 0U, preexisting_result) == FALSE ||
      free_heap(process_heap, 0U, reallocate_context.result) == FALSE ||
      free_heap(process_heap, 0U, nullptr) == FALSE) {
    return 13;
  }
  Sleep(50U);

  const bool hooks_uninstalled = hooks.uninstall();
  const auto writer_result = writer.finish();
  const bool shutdown = backend.shutdown();
  output.close();
  if (!hooks_uninstalled || !shutdown || !output ||
      writer_result.status != noleax::agent::windows::RtlHeapTraceWriterStatus::kComplete ||
      writer_result.queue_dropped_events != 0U || writer_result.trace_dropped_events != 0U) {
    return 14;
  }

  static_cast<void>(free_heap(process_heap, 0U, outstanding));

  std::ifstream input{output_path, std::ios::binary};
  if (!input) {
    return 15;
  }
  std::vector<noleax::trace::Event> events;
  std::uint64_t heap_destroyed_generation_count = 0U;
  noleax::analyzer::GenerationCallbacks generation_callbacks;
  generation_callbacks.on_ended = [&heap_destroyed_generation_count](
                                      const noleax::analyzer::MemoryGeneration& generation,
                                      noleax::analyzer::GenerationEndReason reason,
                                      const noleax::trace::Event&) {
    if (reason == noleax::analyzer::GenerationEndReason::kHeapDestroyed &&
        generation.size == kDestroyedWithHeapSize) {
      ++heap_destroyed_generation_count;
    }
  };
  noleax::analyzer::GenerationTracker tracker{generation_callbacks};
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_event = [&events, &tracker](const noleax::trace::Event& event) {
    tracker.observe(event);
    events.push_back(event);
  };
  const noleax::analyzer::EventStreamResult parsed =
      noleax::analyzer::analyze_event_stream(input, callbacks);

  std::optional<noleax::trace::AllocationId> matched_id;
  std::optional<noleax::trace::AllocationId> outstanding_id;
  std::optional<noleax::trace::AllocationId> cross_thread_id;
  std::optional<noleax::trace::AllocationId> in_place_old_id;
  std::optional<noleax::trace::AllocationId> failure_old_id;
  std::optional<noleax::trace::AllocationId> cross_reallocate_old_id;
  std::optional<noleax::trace::AllocationId> zero_old_id;
  std::optional<noleax::trace::AllocationId> in_place_new_id;
  std::optional<noleax::trace::AllocationId> cross_reallocate_new_id;
  std::optional<noleax::trace::AllocationId> zero_new_id;
  std::optional<noleax::trace::AllocationId> preexisting_new_id;
  bool matched_free = false;
  bool cross_thread_free = false;
  bool preexisting_free = false;
  bool null_free = false;
  bool in_place_reallocation = false;
  bool failed_reallocation = false;
  bool cross_thread_reallocation = false;
  bool zero_reallocation = false;
  bool preexisting_reallocation = false;
  bool destroyed_heap_allocation_associated = false;
  bool second_heap_allocation_associated = false;
  bool heap_destroy_ids_match = true;
  bool heap_ids_unique = true;
  std::uint64_t heap_create_events = 0U;
  std::uint64_t heap_destroy_events = 0U;
  std::unordered_map<std::uint64_t, std::vector<noleax::trace::HeapId>> heap_ids_by_handle;
  std::unordered_map<std::uint64_t, noleax::trace::HeapId> active_heap_ids;
  std::unordered_set<std::uint64_t> all_heap_ids;
  for (const auto& event : events) {
    if (const auto* create_event = std::get_if<noleax::trace::HeapCreateEvent>(&event.payload)) {
      ++heap_create_events;
      heap_ids_unique &= create_event->heap_id.is_valid() &&
                         all_heap_ids.insert(create_event->heap_id.value()).second;
      heap_ids_by_handle[create_event->heap_handle].push_back(create_event->heap_id);
      active_heap_ids.insert_or_assign(create_event->heap_handle, create_event->heap_id);
      continue;
    }
    if (const auto* destroy_event = std::get_if<noleax::trace::HeapDestroyEvent>(&event.payload)) {
      ++heap_destroy_events;
      const auto active = active_heap_ids.find(destroy_event->heap_handle);
      heap_destroy_ids_match &= event.header.status == noleax::trace::EventStatus::kSuccess &&
                                destroy_event->raw_result == 0U &&
                                active != active_heap_ids.end() &&
                                active->second == destroy_event->heap_id;
      if (active != active_heap_ids.end()) {
        active_heap_ids.erase(active);
      }
      continue;
    }
    if (const auto* allocation = std::get_if<noleax::trace::AllocationEvent>(&event.payload)) {
      if (allocation->requested_size == kMatchedSize) {
        matched_id = allocation->allocation_id;
      } else if (allocation->requested_size == kOutstandingSize) {
        outstanding_id = allocation->allocation_id;
      } else if (allocation->requested_size == kCrossThreadSize) {
        cross_thread_id = allocation->allocation_id;
      } else if (allocation->requested_size == kInPlaceOriginalSize) {
        in_place_old_id = allocation->allocation_id;
      } else if (allocation->requested_size == kFailureOriginalSize) {
        failure_old_id = allocation->allocation_id;
      } else if (allocation->requested_size == kCrossReallocateOriginalSize) {
        cross_reallocate_old_id = allocation->allocation_id;
      } else if (allocation->requested_size == kZeroOriginalSize) {
        zero_old_id = allocation->allocation_id;
      } else if (allocation->requested_size == kDestroyedWithHeapSize) {
        const auto active = active_heap_ids.find(allocation->heap_handle);
        destroyed_heap_allocation_associated =
            allocation->heap_handle ==
                static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(first_heap)) &&
            active != active_heap_ids.end() && allocation->heap_id == active->second;
      } else if (allocation->requested_size == kFreedBeforeHeapDestroySize) {
        const auto active = active_heap_ids.find(allocation->heap_handle);
        second_heap_allocation_associated =
            allocation->heap_handle ==
                static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(second_heap)) &&
            active != active_heap_ids.end() && allocation->heap_id == active->second;
      }
      continue;
    }
    if (const auto* reallocation = std::get_if<noleax::trace::ReallocationEvent>(&event.payload)) {
      if (reallocation->requested_size == kInPlaceNewSize && in_place_old_id.has_value()) {
        in_place_new_id = reallocation->new_allocation_id;
        in_place_reallocation =
            event.header.status == noleax::trace::EventStatus::kSuccess &&
            reallocation->old_allocation_id == *in_place_old_id &&
            reallocation->effect == noleax::trace::ReallocationEffect::kNewGeneration &&
            reallocation->old_address == reallocation->result_address &&
            reallocation->new_allocation_id != reallocation->old_allocation_id;
      } else if (reallocation->requested_size == kImpossibleSize && failure_old_id.has_value()) {
        failed_reallocation =
            event.header.status == noleax::trace::EventStatus::kFailure &&
            reallocation->old_allocation_id == *failure_old_id &&
            reallocation->effect == noleax::trace::ReallocationEffect::kNoChange &&
            reallocation->result_address == 0U && !reallocation->new_allocation_id;
      } else if (reallocation->requested_size == kCrossReallocateNewSize &&
                 cross_reallocate_old_id.has_value()) {
        cross_reallocate_new_id = reallocation->new_allocation_id;
        cross_thread_reallocation =
            event.header.status == noleax::trace::EventStatus::kSuccess &&
            event.header.thread_id == reallocate_context.thread_id &&
            reallocation->old_allocation_id == *cross_reallocate_old_id &&
            reallocation->effect == noleax::trace::ReallocationEffect::kNewGeneration;
      } else if (reallocation->requested_size == 0U && zero_old_id.has_value()) {
        zero_new_id = reallocation->new_allocation_id;
        zero_reallocation =
            event.header.status == noleax::trace::EventStatus::kSuccess &&
            reallocation->old_allocation_id == *zero_old_id &&
            reallocation->effect == noleax::trace::ReallocationEffect::kNewGeneration;
      } else if (reallocation->requested_size == kPreexistingNewSize) {
        preexisting_new_id = reallocation->new_allocation_id;
        preexisting_reallocation =
            event.header.status == noleax::trace::EventStatus::kPreexisting &&
            !reallocation->old_allocation_id && reallocation->new_allocation_id.is_valid() &&
            reallocation->effect == noleax::trace::ReallocationEffect::kNewGeneration;
      }
      continue;
    }
    const auto* free_event = std::get_if<noleax::trace::FreeEvent>(&event.payload);
    if (free_event == nullptr) {
      continue;
    }
    if (matched_id.has_value() &&
        free_event->address ==
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(matched))) {
      matched_free |= event.header.status == noleax::trace::EventStatus::kSuccess &&
                      free_event->allocation_id == *matched_id;
    } else if (cross_thread_id.has_value() &&
               free_event->address ==
                   static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(cross_thread))) {
      cross_thread_free |= event.header.status == noleax::trace::EventStatus::kSuccess &&
                           free_event->allocation_id == *cross_thread_id;
    } else if (free_event->address ==
               static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(preexisting_result))) {
      preexisting_free |= preexisting_new_id.has_value() &&
                          event.header.status == noleax::trace::EventStatus::kSuccess &&
                          free_event->allocation_id == *preexisting_new_id;
    } else if (free_event->address == 0U) {
      null_free |= event.header.status == noleax::trace::EventStatus::kUnmatched &&
                   !free_event->allocation_id;
    }
  }

  const auto* allocate_statistics =
      find_api_statistics(writer_result.statistics, noleax::agent::windows::kRtlAllocateHeapApiId);
  const auto* free_statistics =
      find_api_statistics(writer_result.statistics, noleax::agent::windows::kRtlFreeHeapApiId);
  const auto* reallocate_statistics = find_api_statistics(
      writer_result.statistics, noleax::agent::windows::kRtlReAllocateHeapApiId);
  const auto* create_statistics =
      find_api_statistics(writer_result.statistics, noleax::agent::windows::kRtlCreateHeapApiId);
  const auto* destroy_statistics =
      find_api_statistics(writer_result.statistics, noleax::agent::windows::kRtlDestroyHeapApiId);
  bool trace_handle_reused = false;
  for (const auto& [handle, heap_ids] : heap_ids_by_handle) {
    static_cast<void>(handle);
    trace_handle_reused |= heap_ids.size() > 1U;
  }
  const bool heap_generations_valid =
      runtime_handle_reused && trace_handle_reused && heap_ids_unique && heap_destroy_ids_match &&
      active_heap_ids.empty() && destroyed_heap_allocation_associated &&
      second_heap_allocation_associated && heap_destroyed_generation_count == 1U &&
      heap_create_events == static_cast<std::uint64_t>(kHeapReuseAttempts) + 2U &&
      heap_destroy_events == heap_create_events;
  const bool generations_valid =
      matched_id.has_value() && matched_id->is_valid() && outstanding_id.has_value() &&
      outstanding_id->is_valid() && cross_thread_id.has_value() && cross_thread_id->is_valid() &&
      *matched_id != *outstanding_id && *matched_id != *cross_thread_id &&
      *outstanding_id != *cross_thread_id && tracker.find_allocation(*matched_id) == nullptr &&
      tracker.find_allocation(*cross_thread_id) == nullptr &&
      tracker.find_allocation(*outstanding_id) != nullptr && in_place_old_id.has_value() &&
      failure_old_id.has_value() && cross_reallocate_old_id.has_value() &&
      zero_old_id.has_value() && in_place_new_id.has_value() &&
      cross_reallocate_new_id.has_value() && zero_new_id.has_value() &&
      preexisting_new_id.has_value() && tracker.find_allocation(*in_place_old_id) == nullptr &&
      tracker.find_allocation(*failure_old_id) == nullptr &&
      tracker.find_allocation(*cross_reallocate_old_id) == nullptr &&
      tracker.find_allocation(*zero_old_id) == nullptr &&
      tracker.find_allocation(*in_place_new_id) == nullptr &&
      tracker.find_allocation(*cross_reallocate_new_id) == nullptr &&
      tracker.find_allocation(*zero_new_id) == nullptr &&
      tracker.find_allocation(*preexisting_new_id) == nullptr && tracker.live_count() == 1U;
  const bool statistics_valid =
      allocate_statistics != nullptr && reallocate_statistics != nullptr &&
      free_statistics != nullptr && create_statistics != nullptr && destroy_statistics != nullptr &&
      allocate_statistics->observed_calls >= 3U && free_statistics->observed_calls >= 4U &&
      reallocate_statistics->observed_calls >= 5U &&
      create_statistics->observed_calls == heap_create_events &&
      destroy_statistics->observed_calls == heap_destroy_events &&
      allocate_statistics->dropped_events == 0U && reallocate_statistics->dropped_events == 0U &&
      free_statistics->dropped_events == 0U && create_statistics->dropped_events == 0U &&
      destroy_statistics->dropped_events == 0U &&
      writer_result.statistics.observed_calls == events.size() &&
      parsed.event_count == writer_result.statistics.observed_calls &&
      parsed.statistics == writer_result.statistics && parsed.end_of_trace.has_value() &&
      !parsed.completeness.has(noleax::trace::CompletenessIssue::kEventLoss);
  if (!matched_free || !cross_thread_free || !preexisting_free || !null_free ||
      !in_place_reallocation || !failed_reallocation || !cross_thread_reallocation ||
      !zero_reallocation || !preexisting_reallocation || !heap_generations_valid ||
      !generations_valid || !statistics_valid) {
    std::fprintf(stderr,
                 "combined trace failed: events=%llu alloc=%llu realloc=%llu free=%llu "
                 "matched=%u cross=%u preexisting=%u null=%u inplace=%u failed=%u "
                 "cross-realloc=%u zero=%u preexisting-realloc=%u heaps=%u generations=%u "
                 "stats=%u create=%llu destroy=%llu heap-ended=%llu\n",
                 static_cast<unsigned long long>(events.size()),
                 static_cast<unsigned long long>(
                     allocate_statistics == nullptr ? 0U : allocate_statistics->observed_calls),
                 static_cast<unsigned long long>(
                     reallocate_statistics == nullptr ? 0U : reallocate_statistics->observed_calls),
                 static_cast<unsigned long long>(
                     free_statistics == nullptr ? 0U : free_statistics->observed_calls),
                 matched_free ? 1U : 0U, cross_thread_free ? 1U : 0U, preexisting_free ? 1U : 0U,
                 null_free ? 1U : 0U, in_place_reallocation ? 1U : 0U,
                 failed_reallocation ? 1U : 0U, cross_thread_reallocation ? 1U : 0U,
                 zero_reallocation ? 1U : 0U, preexisting_reallocation ? 1U : 0U,
                 heap_generations_valid ? 1U : 0U, generations_valid ? 1U : 0U,
                 statistics_valid ? 1U : 0U, static_cast<unsigned long long>(heap_create_events),
                 static_cast<unsigned long long>(heap_destroy_events),
                 static_cast<unsigned long long>(heap_destroyed_generation_count));
    return 16;
  }

  std::printf(
      "status=ok events=%llu alloc-free=1 realloc=5 cross-thread=1 preexisting=1 "
      "unmatched=1 live=1 heap-generations=1 handle-reuse=1\n",
      static_cast<unsigned long long>(events.size()));
  return 0;
}
