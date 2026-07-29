#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "noleax/agent/windows/rtl_allocate_heap_trace_writer.hpp"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <limits>
#include <string_view>
#include <unordered_set>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_hook.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/wire_format.hpp"

#if defined(_MSC_VER)
#define NOLEAX_TEST_NOINLINE __declspec(noinline)
#else
#define NOLEAX_TEST_NOINLINE __attribute__((noinline))
#endif

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID address);

struct ParsedTrace {
  noleax::analyzer::EventStreamResult result;
  std::uint64_t events_with_stacks{0U};
  std::uint64_t successful_allocations{0U};
  bool unknown_stack_reference{false};
  bool saw_queue_full{false};
  bool saw_trace_full{false};
};

enum class TestMode : std::uint8_t {
  kEmpty,
  kNormal,
  kQueueLimit,
  kFileLimit,
};

[[nodiscard]] const char* mode_name(TestMode mode) noexcept {
  switch (mode) {
    case TestMode::kEmpty:
      return "empty";
    case TestMode::kNormal:
      return "normal";
    case TestMode::kQueueLimit:
      return "queue-limit";
    case TestMode::kFileLimit:
      return "file-limit";
  }
  return "unknown";
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
  header.session_id[0] = std::byte{0xA7};
  header.monotonic_frequency = static_cast<std::uint64_t>(frequency.QuadPart);
  header.monotonic_origin = static_cast<std::uint64_t>(origin.QuadPart);
  return header;
}

NOLEAX_TEST_NOINLINE bool run_allocations(RtlAllocateHeapFunction allocate,
                                          RtlFreeHeapFunction free_heap, HANDLE heap,
                                          std::uint32_t iterations) noexcept {
  for (std::uint32_t iteration = 0U; iteration < iterations; ++iteration) {
    const SIZE_T size = 16U + iteration % 240U;
    void* const allocation = allocate(heap, 0U, size);
    if (allocation == nullptr) {
      return false;
    }
    static_cast<std::byte*>(allocation)[0] = static_cast<std::byte>(iteration & 0xFFU);
    if (free_heap(heap, 0U, allocation) == FALSE) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool finish_uninstall(noleax::agent::windows::RtlAllocateHeapHook& hook) noexcept {
  auto status = hook.uninstall();
  if (status == noleax::agent::HookUninstallStatus::kTeardownPending && hook.flush()) {
    status = noleax::agent::HookUninstallStatus::kUninstalled;
  }
  return status == noleax::agent::HookUninstallStatus::kUninstalled;
}

[[nodiscard]] ParsedTrace parse_trace(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  if (!input) {
    throw std::runtime_error{"cannot reopen trace output"};
  }
  std::unordered_set<std::uint64_t> stack_ids;
  ParsedTrace parsed;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_stack_definition = [&stack_ids](const noleax::trace::StackDefinition& definition) {
    stack_ids.insert(definition.stack_id.value());
  };
  callbacks.on_event = [&parsed, &stack_ids](const noleax::trace::Event& event) {
    if (event.header.stack_id) {
      ++parsed.events_with_stacks;
      parsed.unknown_stack_reference |= !stack_ids.contains(event.header.stack_id.value());
    }
    if (event.header.status == noleax::trace::EventStatus::kSuccess) {
      const auto* allocation = std::get_if<noleax::trace::AllocationEvent>(&event.payload);
      if (allocation != nullptr && allocation->allocation_id) {
        ++parsed.successful_allocations;
      }
    }
  };
  callbacks.on_loss = [&parsed](const noleax::trace::LossRecord& loss) {
    parsed.saw_queue_full |= loss.reason == noleax::trace::LossReason::kQueueFull;
    parsed.saw_trace_full |= loss.reason == noleax::trace::LossReason::kTraceFull;
  };
  parsed.result = noleax::analyzer::analyze_event_stream(input, callbacks);
  return parsed;
}

[[nodiscard]] int run_empty_test(const std::filesystem::path& output_path) {
  std::ofstream output{output_path, std::ios::binary | std::ios::trunc};
  if (!output) {
    return 30;
  }
  noleax::agent::HookBackend backend;
  noleax::agent::windows::RtlAllocateHeapHook hook{backend, 16U, 16U};
  noleax::agent::windows::RtlAllocateHeapTraceWriter writer{hook, output, make_file_header()};
  const auto writer_result = writer.finish();
  const auto repeated_result = writer.finish();
  if (!backend.shutdown()) {
    return 31;
  }
  output.close();
  if (!output) {
    return 32;
  }

  const ParsedTrace parsed = parse_trace(output_path);
  const std::uint64_t file_size = std::filesystem::file_size(output_path);
  if (writer_result.status != noleax::agent::windows::RtlAllocateHeapTraceWriterStatus::kComplete ||
      writer_result.bytes_written != file_size ||
      repeated_result.bytes_written != writer_result.bytes_written ||
      writer_result.statistics.observed_calls != 0U || parsed.result.event_count != 0U ||
      parsed.result.stack_definition_count != 0U || !writer_result.statistics_written ||
      !writer_result.end_of_trace_written || !parsed.result.statistics.has_value() ||
      !parsed.result.end_of_trace.has_value() ||
      parsed.result.completeness.has(noleax::trace::CompletenessIssue::kEventLoss)) {
    return 33;
  }
  std::printf("status=ok mode=empty bytes=%llu events=0 dropped=0 unique_stacks=0\n",
              static_cast<unsigned long long>(file_size));
  return 0;
}

[[nodiscard]] int run_test(TestMode mode, const std::filesystem::path& output_path) {
  const bool queue_limit = mode == TestMode::kQueueLimit;
  const bool file_limit = mode == TestMode::kFileLimit;
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const HANDLE heap = GetProcessHeap();
  if (ntdll == nullptr || heap == nullptr) {
    return 10;
  }
  const auto allocate =
      reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  const auto free_heap =
      reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  if (allocate == nullptr || free_heap == nullptr) {
    return 11;
  }

  std::ofstream output{output_path, std::ios::binary | std::ios::trunc};
  if (!output) {
    return 12;
  }

  noleax::agent::HookBackend backend;
  const std::size_t queue_capacity = queue_limit ? 2U : (file_limit ? 32'768U : 16'384U);
  noleax::agent::windows::RtlAllocateHeapHook hook{backend, queue_capacity, 16U};
  noleax::agent::windows::RtlAllocateHeapTraceWriterOptions options;
  options.compression =
      file_limit ? noleax::trace::CompressionCodec::kNone : noleax::trace::CompressionCodec::kLz4;
  options.flush_interval = std::chrono::milliseconds{5};
  options.chunk_target_size = 1024U;
  options.stack_dictionary_capacity = 64U;
  options.trace.max_file_size = file_limit ? 8U * 1024U : 8U * 1024U * 1024U;
  options.trace.max_uncompressed_chunk_size = 64U * 1024U;
  options.trace.max_stored_chunk_size = 128U * 1024U;
  noleax::agent::windows::RtlAllocateHeapTraceWriter writer{hook, output, make_file_header(),
                                                            options};

  const auto install = hook.install();
  if (!install.installed()) {
    return 13;
  }
  writer.begin_capture();
  try {
    static_cast<void>(writer.finish());
    return 14;
  } catch (const std::logic_error&) {
  }
  const std::uint32_t iterations = file_limit || queue_limit ? 20'000U : 1'000U;
  if (!run_allocations(allocate, free_heap, heap, iterations)) {
    return 15;
  }
  // Keep the hook active while the internal writer drains and compresses at least one batch.
  // This verifies that any heap work performed by that thread is classified as internal.
  Sleep(50U);
  if (!finish_uninstall(hook)) {
    return 16;
  }
  const std::uint64_t internal_calls = hook.internal_call_count();
  const auto writer_result = writer.finish();
  if (!backend.shutdown()) {
    return 17;
  }
  output.close();
  if (!output) {
    return 18;
  }

  const std::uint64_t file_size = std::filesystem::file_size(output_path);
  if (file_size != writer_result.bytes_written || file_size > options.trace.max_file_size ||
      writer_result.statistics.observed_calls < iterations || internal_calls == 0U) {
    std::fprintf(stderr,
                 "trace writer accounting failed: status=%u file=%llu reported=%llu "
                 "observed=%llu expected-at-least=%u internal=%llu dropped=%llu\n",
                 static_cast<unsigned int>(writer_result.status),
                 static_cast<unsigned long long>(file_size),
                 static_cast<unsigned long long>(writer_result.bytes_written),
                 static_cast<unsigned long long>(writer_result.statistics.observed_calls),
                 iterations, static_cast<unsigned long long>(internal_calls),
                 static_cast<unsigned long long>(writer_result.statistics.dropped_events));
    return 19;
  }
  const ParsedTrace parsed = parse_trace(output_path);
  if (parsed.unknown_stack_reference ||
      (mode == TestMode::kNormal && parsed.successful_allocations < iterations) ||
      ((file_limit || queue_limit) && parsed.successful_allocations == 0U) ||
      parsed.result.event_count !=
          writer_result.statistics.observed_calls - writer_result.statistics.dropped_events) {
    std::fprintf(stderr,
                 "parsed trace accounting failed: events=%llu successful=%llu observed=%llu "
                 "dropped=%llu unknown-stack=%u\n",
                 static_cast<unsigned long long>(parsed.result.event_count),
                 static_cast<unsigned long long>(parsed.successful_allocations),
                 static_cast<unsigned long long>(writer_result.statistics.observed_calls),
                 static_cast<unsigned long long>(writer_result.statistics.dropped_events),
                 parsed.unknown_stack_reference ? 1U : 0U);
    return 20;
  }

  if (mode == TestMode::kNormal) {
    if (writer_result.status !=
            noleax::agent::windows::RtlAllocateHeapTraceWriterStatus::kComplete ||
        writer_result.statistics.dropped_events != 0U ||
        writer_result.statistics.unique_stacks == 0U ||
        writer_result.statistics.reused_stacks == 0U || parsed.events_with_stacks == 0U ||
        !writer_result.statistics_written || !writer_result.end_of_trace_written ||
        !parsed.result.statistics.has_value() || !parsed.result.end_of_trace.has_value() ||
        parsed.result.stack_definition_count != writer_result.statistics.unique_stacks) {
      return 21;
    }
  } else if (mode == TestMode::kQueueLimit) {
    if (writer_result.status !=
            noleax::agent::windows::RtlAllocateHeapTraceWriterStatus::kComplete ||
        writer_result.queue_dropped_events == 0U ||
        writer_result.statistics.dropped_events != writer_result.queue_dropped_events ||
        writer_result.trace_dropped_events != 0U || !parsed.saw_queue_full ||
        parsed.saw_trace_full || !writer_result.statistics_written ||
        !writer_result.end_of_trace_written ||
        !parsed.result.completeness.has(noleax::trace::CompletenessIssue::kEventLoss) ||
        parsed.result.stack_definition_count != writer_result.statistics.unique_stacks) {
      return 22;
    }
  } else if (writer_result.status !=
                 noleax::agent::windows::RtlAllocateHeapTraceWriterStatus::kFileLimit ||
             writer_result.trace_dropped_events == 0U || writer_result.queue_dropped_events != 0U ||
             !parsed.saw_trace_full || parsed.saw_queue_full || !writer_result.statistics_written ||
             !writer_result.end_of_trace_written ||
             !parsed.result.completeness.has(noleax::trace::CompletenessIssue::kEventLoss)) {
    return 23;
  }

  std::printf("status=ok mode=%s bytes=%llu events=%llu dropped=%llu unique_stacks=%llu\n",
              mode_name(mode), static_cast<unsigned long long>(writer_result.bytes_written),
              static_cast<unsigned long long>(parsed.result.event_count),
              static_cast<unsigned long long>(writer_result.statistics.dropped_events),
              static_cast<unsigned long long>(writer_result.statistics.unique_stacks));
  return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 3) {
    std::fprintf(
        stderr,
        "usage: rtl-heap-trace-writer-test <empty|normal|queue-limit|file-limit> <output>\n");
    return 2;
  }
  const std::string_view mode{argv[1]};
  TestMode parsed_mode = TestMode::kEmpty;
  if (mode == "normal") {
    parsed_mode = TestMode::kNormal;
  } else if (mode == "queue-limit") {
    parsed_mode = TestMode::kQueueLimit;
  } else if (mode == "file-limit") {
    parsed_mode = TestMode::kFileLimit;
  } else if (mode != "empty") {
    return 3;
  }
  try {
    if (parsed_mode == TestMode::kEmpty) {
      return run_empty_test(std::filesystem::path{argv[2]});
    }
    return run_test(parsed_mode, std::filesystem::path{argv[2]});
  } catch (const std::exception& error) {
    std::fprintf(stderr, "trace writer test failed: %s\n", error.what());
    return 4;
  }
}

#undef NOLEAX_TEST_NOINLINE
