#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "noleax/agent/windows/rtl_heap_trace_writer.hpp"

#include <windows.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"
#include "noleax/agent/windows/rtl_free_heap_hook.hpp"
#include "noleax/agent/windows/rtl_heap_hooks.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/trace/event.hpp"

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID address);

constexpr SIZE_T kMatchedSize = 12'345U;
constexpr SIZE_T kOutstandingSize = 23'457U;
constexpr SIZE_T kCrossThreadSize = 34'569U;

struct ThreadFreeContext {
  RtlFreeHeapFunction free_heap{nullptr};
  PVOID heap{nullptr};
  PVOID address{nullptr};
  BOOLEAN result{FALSE};
};

DWORD WINAPI free_on_thread(void* parameter) noexcept {
  auto* const context = static_cast<ThreadFreeContext*>(parameter);
  context->result = context->free_heap(context->heap, 0U, context->address);
  return context->result == FALSE ? 1U : 0U;
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
  const auto free_heap =
      ntdll == nullptr
          ? nullptr
          : reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  if (process_heap == nullptr || allocate == nullptr || free_heap == nullptr) {
    std::fprintf(stderr, "Rtl heap entry resolution failed: ntdll=%p heap=%p alloc=%p free=%p\n",
                 static_cast<void*>(ntdll), process_heap, reinterpret_cast<void*>(allocate),
                 reinterpret_cast<void*>(free_heap));
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
  auto& allocate_hook = hooks.allocate_hook();
  auto& free_hook = hooks.free_hook();

  {
    noleax::agent::windows::RtlAllocateHeapHook separate_allocate{backend, 16U, 0U};
    noleax::agent::windows::RtlFreeHeapHook separate_free{backend, 16U, 0U};
    std::ostringstream discarded;
    bool rejected = false;
    try {
      noleax::agent::windows::RtlHeapTraceWriter invalid_writer{separate_allocate, separate_free,
                                                                discarded, make_file_header()};
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
  noleax::agent::windows::RtlHeapTraceWriter writer{allocate_hook, free_hook, output,
                                                    make_file_header(), options};

  const auto installed = hooks.install();
  if (!installed.installed()) {
    return 8;
  }
  writer.begin_capture();

  PVOID matched = allocate(process_heap, 0U, kMatchedSize);
  PVOID outstanding = allocate(process_heap, 0U, kOutstandingSize);
  PVOID cross_thread = allocate(process_heap, 0U, kCrossThreadSize);
  if (matched == nullptr || outstanding == nullptr || cross_thread == nullptr) {
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

  if (free_heap(process_heap, 0U, preexisting) == FALSE ||
      free_heap(process_heap, 0U, nullptr) == FALSE) {
    return 13;
  }
  Sleep(50U);

  const bool hooks_uninstalled = hooks.uninstall(100'000U);
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
  noleax::analyzer::GenerationTracker tracker;
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
  bool matched_free = false;
  bool cross_thread_free = false;
  bool preexisting_free = false;
  bool null_free = false;
  for (const auto& event : events) {
    if (const auto* allocation = std::get_if<noleax::trace::AllocationEvent>(&event.payload)) {
      if (allocation->requested_size == kMatchedSize) {
        matched_id = allocation->allocation_id;
      } else if (allocation->requested_size == kOutstandingSize) {
        outstanding_id = allocation->allocation_id;
      } else if (allocation->requested_size == kCrossThreadSize) {
        cross_thread_id = allocation->allocation_id;
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
               static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(preexisting))) {
      preexisting_free |= event.header.status == noleax::trace::EventStatus::kPreexisting &&
                          !free_event->allocation_id;
    } else if (free_event->address == 0U) {
      null_free |= event.header.status == noleax::trace::EventStatus::kUnmatched &&
                   !free_event->allocation_id;
    }
  }

  const auto* allocate_statistics =
      find_api_statistics(writer_result.statistics, noleax::agent::windows::kRtlAllocateHeapApiId);
  const auto* free_statistics =
      find_api_statistics(writer_result.statistics, noleax::agent::windows::kRtlFreeHeapApiId);
  const bool generations_valid =
      matched_id.has_value() && matched_id->is_valid() && outstanding_id.has_value() &&
      outstanding_id->is_valid() && cross_thread_id.has_value() && cross_thread_id->is_valid() &&
      *matched_id != *outstanding_id && *matched_id != *cross_thread_id &&
      *outstanding_id != *cross_thread_id && tracker.find_allocation(*matched_id) == nullptr &&
      tracker.find_allocation(*cross_thread_id) == nullptr &&
      tracker.find_allocation(*outstanding_id) != nullptr;
  const bool statistics_valid =
      allocate_statistics != nullptr && free_statistics != nullptr &&
      allocate_statistics->observed_calls >= 3U && free_statistics->observed_calls >= 4U &&
      allocate_statistics->dropped_events == 0U && free_statistics->dropped_events == 0U &&
      writer_result.statistics.observed_calls == events.size() &&
      parsed.event_count == writer_result.statistics.observed_calls &&
      parsed.statistics == writer_result.statistics && parsed.end_of_trace.has_value() &&
      !parsed.completeness.has(noleax::trace::CompletenessIssue::kEventLoss);
  if (!matched_free || !cross_thread_free || !preexisting_free || !null_free ||
      !generations_valid || !statistics_valid) {
    std::fprintf(stderr,
                 "combined trace failed: events=%llu alloc=%llu free=%llu matched=%u cross=%u "
                 "preexisting=%u null=%u generations=%u stats=%u\n",
                 static_cast<unsigned long long>(events.size()),
                 static_cast<unsigned long long>(
                     allocate_statistics == nullptr ? 0U : allocate_statistics->observed_calls),
                 static_cast<unsigned long long>(
                     free_statistics == nullptr ? 0U : free_statistics->observed_calls),
                 matched_free ? 1U : 0U, cross_thread_free ? 1U : 0U, preexisting_free ? 1U : 0U,
                 null_free ? 1U : 0U, generations_valid ? 1U : 0U, statistics_valid ? 1U : 0U);
    return 16;
  }

  std::printf("status=ok events=%llu matched=1 cross-thread=1 preexisting=1 unmatched=1 live=1\n",
              static_cast<unsigned long long>(events.size()));
  return 0;
}
