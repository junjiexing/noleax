#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "noleax/agent/windows/nt_virtual_memory_trace_writer.hpp"

#include <windows.h>
#include <winternl.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/nt_memory_hooks.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/trace/event.hpp"

namespace {

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

[[nodiscard]] bool nt_success(NTSTATUS status) noexcept { return status >= 0; }

[[nodiscard]] NTSTATUS allocate(NtAllocateVirtualMemoryFunction function, HANDLE process,
                                PVOID& base, SIZE_T& size, ULONG type) {
  return function(process, &base, 0U, &size, type, PAGE_READWRITE);
}

[[nodiscard]] NTSTATUS free_memory(NtFreeVirtualMemoryFunction function, HANDLE process,
                                   PVOID& base, SIZE_T& size, ULONG type) {
  return function(process, &base, &size, type);
}

[[nodiscard]] NTSTATUS map_section(NtMapViewOfSectionFunction function, HANDLE section,
                                   HANDLE process, PVOID& base, SIZE_T& size,
                                   PLARGE_INTEGER offset = nullptr,
                                   ULONG protection = PAGE_READWRITE) {
  return function(section, process, &base, 0U, 0U, offset, &size, 2U, 0U, protection);
}

[[nodiscard]] NTSTATUS unmap_section(NtUnmapViewOfSectionFunction function, HANDLE process,
                                     PVOID base) {
  return function(process, base);
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
  header.session_id[0] = std::byte{0x54};
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

[[nodiscard]] bool start_suspended_child(PROCESS_INFORMATION& process) {
  std::vector<wchar_t> path(32'768U, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0U || length >= path.size()) {
    return false;
  }
  const std::wstring command_text =
      L"\"" + std::wstring{path.data(), length} + L"\" --remote-child";
  std::vector<wchar_t> command(command_text.begin(), command_text.end());
  command.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  return CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr,
                        nullptr, &startup, &process) != FALSE;
}

[[nodiscard]] bool stop_child(PROCESS_INFORMATION& process) noexcept {
  const bool terminated = TerminateProcess(process.hProcess, 0U) != FALSE;
  const DWORD wait = WaitForSingleObject(process.hProcess, 30'000U);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return terminated && wait == WAIT_OBJECT_0;
}

[[nodiscard]] int run_unmatched_view_case(const std::filesystem::path& output_path,
                                          NtUnmapViewOfSectionFunction unmap_function) {
  const HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0U,
                                            4U * kPageSize, nullptr);
  PVOID view =
      section == nullptr ? nullptr : MapViewOfFile(section, FILE_MAP_READ, 0U, 0U, kPageSize);
  if (section == nullptr || view == nullptr) {
    return 20;
  }

  std::ofstream output{output_path, std::ios::binary | std::ios::trunc};
  if (!output) {
    return 21;
  }
  noleax::agent::HookBackend backend;
  noleax::agent::windows::NtMemoryHooks hooks{backend, 1024U, 8U};
  noleax::agent::windows::NtVirtualMemoryTraceWriterOptions options;
  options.capture_scope = {false, false};
  options.flush_interval = std::chrono::milliseconds{5};
  options.trace.max_file_size = 4U * 1024U * 1024U;
  noleax::agent::windows::NtVirtualMemoryTraceWriter writer{hooks, output, make_file_header(),
                                                            options};
  if (!hooks.install().installed()) {
    return 22;
  }
  writer.begin_capture();
  const NTSTATUS unmapped = unmap_section(unmap_function, GetCurrentProcess(), view);
  Sleep(25U);
  const bool uninstalled = hooks.uninstall();
  const auto writer_result = writer.finish();
  const bool shutdown = backend.shutdown();
  output.close();
  const bool section_closed = CloseHandle(section) != FALSE;
  if (!nt_success(unmapped) || !uninstalled || !shutdown || !section_closed || !output ||
      writer_result.status != noleax::agent::windows::NtVirtualMemoryTraceWriterStatus::kComplete) {
    return 23;
  }

  std::ifstream input{output_path, std::ios::binary};
  bool saw_unmatched = false;
  noleax::analyzer::EventStreamCallbacks callbacks;
  callbacks.on_event = [&saw_unmatched, view](const noleax::trace::Event& event) {
    const auto* unmap = std::get_if<noleax::trace::UnmapEvent>(&event.payload);
    saw_unmatched |= unmap != nullptr && unmap->base == reinterpret_cast<std::uintptr_t>(view) &&
                     event.header.status == noleax::trace::EventStatus::kUnmatched &&
                     !unmap->mapping_id;
  };
  const auto parsed = noleax::analyzer::analyze_event_stream(input, callbacks);
  if (!saw_unmatched || parsed.statistics != writer_result.statistics ||
      !parsed.end_of_trace.has_value()) {
    return 24;
  }
  std::printf("status=ok unmatched=1 events=%llu\n",
              static_cast<unsigned long long>(parsed.event_count));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::string{argv[1]} == "--remote-child") {
    Sleep(30'000U);
    return 0;
  }
  const bool unmatched_mode = argc == 3 && std::string{argv[1]} == "--unmatched";
  if (argc != 2 && !unmatched_mode) {
    return 2;
  }

  const std::filesystem::path output_path{unmatched_mode ? argv[2] : argv[1]};
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto allocate_function = ntdll == nullptr
                                     ? nullptr
                                     : reinterpret_cast<NtAllocateVirtualMemoryFunction>(
                                           GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
  const auto free_function = ntdll == nullptr ? nullptr
                                              : reinterpret_cast<NtFreeVirtualMemoryFunction>(
                                                    GetProcAddress(ntdll, "NtFreeVirtualMemory"));
  const auto map_function = ntdll == nullptr ? nullptr
                                             : reinterpret_cast<NtMapViewOfSectionFunction>(
                                                   GetProcAddress(ntdll, "NtMapViewOfSection"));
  const auto unmap_function = ntdll == nullptr ? nullptr
                                               : reinterpret_cast<NtUnmapViewOfSectionFunction>(
                                                     GetProcAddress(ntdll, "NtUnmapViewOfSection"));
  if (allocate_function == nullptr || free_function == nullptr || map_function == nullptr ||
      unmap_function == nullptr) {
    return 3;
  }
  if (unmatched_mode) {
    return run_unmatched_view_case(output_path, unmap_function);
  }

  PVOID preexisting = nullptr;
  SIZE_T preexisting_size = 3U * kPageSize;
  if (!nt_success(allocate(allocate_function, GetCurrentProcess(), preexisting, preexisting_size,
                           MEM_RESERVE))) {
    return 4;
  }
  const HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0U,
                                            16U * kPageSize, nullptr);
  PVOID preexisting_view =
      section == nullptr ? nullptr : MapViewOfFile(section, FILE_MAP_READ, 0U, 0U, 2U * kPageSize);
  if (section == nullptr || preexisting_view == nullptr) {
    return 4;
  }

  std::ofstream output{output_path, std::ios::binary | std::ios::trunc};
  if (!output) {
    return 5;
  }
  noleax::agent::HookBackend backend;
  noleax::agent::windows::NtMemoryHooks hooks{backend, 8192U, 16U};
  noleax::agent::windows::NtVirtualMemoryTraceWriterOptions options;
  options.flush_interval = std::chrono::milliseconds{5};
  options.chunk_target_size = 4U * 1024U;
  options.stack_dictionary_capacity = 256U;
  options.trace.max_file_size = 16U * 1024U * 1024U;
  noleax::agent::windows::NtVirtualMemoryTraceWriter writer{hooks, output, make_file_header(),
                                                            options};
  if (!hooks.install().installed()) {
    return 6;
  }
  writer.begin_capture();

  PVOID known = nullptr;
  SIZE_T known_size = 3U * kPageSize;
  const NTSTATUS known_reserve =
      allocate(allocate_function, GetCurrentProcess(), known, known_size, MEM_RESERVE);
  PVOID known_page = static_cast<PVOID>(static_cast<std::byte*>(known) + kPageSize);
  SIZE_T page_size = kPageSize;
  const NTSTATUS known_commit =
      allocate(allocate_function, GetCurrentProcess(), known_page, page_size, MEM_COMMIT);
  PVOID decommit_base = known_page;
  SIZE_T decommit_size = kPageSize;
  const NTSTATUS known_decommit =
      free_memory(free_function, GetCurrentProcess(), decommit_base, decommit_size, MEM_DECOMMIT);
  PVOID known_release_base = known;
  SIZE_T release_size = 0U;
  const NTSTATUS known_release = free_memory(free_function, GetCurrentProcess(), known_release_base,
                                             release_size, MEM_RELEASE);

  PVOID preexisting_page = static_cast<PVOID>(static_cast<std::byte*>(preexisting) + kPageSize);
  SIZE_T preexisting_page_size = kPageSize;
  const NTSTATUS preexisting_commit = allocate(allocate_function, GetCurrentProcess(),
                                               preexisting_page, preexisting_page_size, MEM_COMMIT);
  PVOID preexisting_release_base = preexisting;
  SIZE_T preexisting_release_size = 0U;
  const NTSTATUS preexisting_release =
      free_memory(free_function, GetCurrentProcess(), preexisting_release_base,
                  preexisting_release_size, MEM_RELEASE);

  PVOID outstanding = nullptr;
  SIZE_T outstanding_size = 2U * kPageSize;
  const NTSTATUS outstanding_status = allocate(allocate_function, GetCurrentProcess(), outstanding,
                                               outstanding_size, MEM_RESERVE | MEM_COMMIT);

  PVOID failure_base = nullptr;
  SIZE_T failure_size = 0U;
  const NTSTATUS failure_status =
      allocate(allocate_function, GetCurrentProcess(), failure_base, failure_size, MEM_RESERVE);

  PVOID known_view = nullptr;
  SIZE_T known_view_size = 3U * kPageSize;
  const NTSTATUS known_map =
      map_section(map_function, section, GetCurrentProcess(), known_view, known_view_size);
  PVOID known_view_interior =
      known_view == nullptr ? nullptr : static_cast<std::byte*>(known_view) + kPageSize;
  const NTSTATUS known_unmap =
      unmap_section(unmap_function, GetCurrentProcess(), known_view_interior);

  PVOID outstanding_view = nullptr;
  SIZE_T outstanding_view_size = 2U * kPageSize;
  const NTSTATUS outstanding_map = map_section(map_function, section, GetCurrentProcess(),
                                               outstanding_view, outstanding_view_size);

  const NTSTATUS preexisting_unmap =
      unmap_section(unmap_function, GetCurrentProcess(), preexisting_view);

  PVOID section_failure_base = nullptr;
  SIZE_T section_failure_size = kPageSize;
  const NTSTATUS section_failure = map_section(map_function, nullptr, GetCurrentProcess(),
                                               section_failure_base, section_failure_size);

  PVOID wrapper_view = MapViewOfFile(section, FILE_MAP_READ, 0U, 0U, kPageSize);
  const BOOL wrapper_unmapped = wrapper_view == nullptr ? FALSE : UnmapViewOfFile(wrapper_view);

  PROCESS_INFORMATION child{};
  PVOID remote = nullptr;
  SIZE_T remote_size = kPageSize;
  NTSTATUS remote_allocate = static_cast<NTSTATUS>(0xC0000001L);
  NTSTATUS remote_free = static_cast<NTSTATUS>(0xC0000001L);
  NTSTATUS remote_map = static_cast<NTSTATUS>(0xC0000001L);
  NTSTATUS remote_unmap = static_cast<NTSTATUS>(0xC0000001L);
  PVOID remote_view = nullptr;
  SIZE_T remote_view_size = kPageSize;
  bool child_stopped = false;
  DWORD child_process_id = 0U;
  if (start_suspended_child(child)) {
    child_process_id = child.dwProcessId;
    remote_allocate =
        allocate(allocate_function, child.hProcess, remote, remote_size, MEM_RESERVE | MEM_COMMIT);
    PVOID remote_release = remote;
    SIZE_T remote_release_size = 0U;
    remote_free = free_memory(free_function, child.hProcess, remote_release, remote_release_size,
                              MEM_RELEASE);
    remote_map = map_section(map_function, section, child.hProcess, remote_view, remote_view_size);
    remote_unmap = unmap_section(unmap_function, child.hProcess, remote_view);
    child_stopped = stop_child(child);
  }

  if (!nt_success(known_reserve) || !nt_success(known_commit) || !nt_success(known_decommit) ||
      !nt_success(known_release) || !nt_success(preexisting_commit) ||
      !nt_success(preexisting_release) || !nt_success(outstanding_status) ||
      nt_success(failure_status) || !nt_success(remote_allocate) || !nt_success(remote_free) ||
      !nt_success(known_map) || !nt_success(known_unmap) || !nt_success(outstanding_map) ||
      !nt_success(preexisting_unmap) || nt_success(section_failure) || wrapper_view == nullptr ||
      wrapper_unmapped == FALSE || !nt_success(remote_map) || !nt_success(remote_unmap) ||
      !child_stopped) {
    return 7;
  }

  Sleep(50U);
  const bool uninstalled = hooks.uninstall();
  const auto writer_result = writer.finish();
  const bool shutdown = backend.shutdown();
  output.close();

  PVOID outstanding_release = outstanding;
  SIZE_T outstanding_release_size = 0U;
  const bool outstanding_cleaned =
      nt_success(free_memory(free_function, GetCurrentProcess(), outstanding_release,
                             outstanding_release_size, MEM_RELEASE));
  const bool outstanding_view_cleaned =
      nt_success(unmap_section(unmap_function, GetCurrentProcess(), outstanding_view));
  const bool section_closed = CloseHandle(section) != FALSE;
  if (!uninstalled || !shutdown || !outstanding_cleaned || !outstanding_view_cleaned ||
      !section_closed || !output ||
      writer_result.status != noleax::agent::windows::NtVirtualMemoryTraceWriterStatus::kComplete ||
      writer_result.queue_dropped_events != 0U || writer_result.trace_dropped_events != 0U) {
    std::fprintf(stderr,
                 "NT VM writer shutdown failed: uninstall=%u shutdown=%u cleanup=%u output=%u "
                 "status=%u queue=%llu trace=%llu error=%s\n",
                 uninstalled ? 1U : 0U, shutdown ? 1U : 0U, outstanding_cleaned ? 1U : 0U,
                 output ? 1U : 0U, static_cast<unsigned int>(writer_result.status),
                 static_cast<unsigned long long>(writer_result.queue_dropped_events),
                 static_cast<unsigned long long>(writer_result.trace_dropped_events),
                 writer_result.error_message.c_str());
    return 8;
  }

  std::ifstream input{output_path, std::ios::binary};
  if (!input) {
    return 9;
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

  std::optional<noleax::trace::MappingId> known_id;
  std::optional<noleax::trace::MappingId> preexisting_id;
  std::optional<noleax::trace::MappingId> outstanding_id;
  std::optional<noleax::trace::MappingId> known_view_id;
  std::optional<noleax::trace::MappingId> outstanding_view_id;
  std::optional<noleax::trace::MappingId> wrapper_view_id;
  bool commit_reused_id = false;
  bool decommit_preserved_id = false;
  bool release_ended_id = false;
  bool preexisting_classified = false;
  bool preexisting_release_matched = false;
  bool failure_preserved = false;
  bool remote_allocate_classified = false;
  bool remote_free_classified = false;
  bool known_view_ended = false;
  bool preexisting_view_classified = false;
  bool section_failure_preserved = false;
  bool wrapper_view_ended = false;
  bool remote_map_classified = false;
  bool remote_unmap_classified = false;
  for (const auto& event : events) {
    if (const auto* allocation = std::get_if<noleax::trace::VmAllocateEvent>(&event.payload)) {
      if (allocation->target.scope == noleax::trace::ProcessMemoryScope::kRemoteProcess &&
          allocation->target.process_id == child_process_id) {
        remote_allocate_classified = !allocation->mapping_id;
      } else if (allocation->result_base == reinterpret_cast<std::uintptr_t>(known) &&
                 allocation->allocation_type == MEM_RESERVE) {
        known_id = allocation->mapping_id;
      } else if (allocation->result_base == reinterpret_cast<std::uintptr_t>(known_page) &&
                 allocation->allocation_type == MEM_COMMIT && known_id.has_value()) {
        commit_reused_id = allocation->mapping_id == *known_id;
      } else if (allocation->result_base == reinterpret_cast<std::uintptr_t>(preexisting_page)) {
        preexisting_id = allocation->mapping_id;
        preexisting_classified = event.header.status == noleax::trace::EventStatus::kPreexisting;
      } else if (allocation->result_base == reinterpret_cast<std::uintptr_t>(outstanding)) {
        outstanding_id = allocation->mapping_id;
      } else if (allocation->requested_size == 0U &&
                 event.header.status == noleax::trace::EventStatus::kFailure) {
        failure_preserved =
            event.header.system_error.domain == noleax::trace::SystemErrorDomain::kNtStatus &&
            event.header.system_error.code == static_cast<std::uint32_t>(failure_status);
      }
      continue;
    }
    const auto* free_event = std::get_if<noleax::trace::VmFreeEvent>(&event.payload);
    if (free_event != nullptr) {
      if (free_event->target.scope == noleax::trace::ProcessMemoryScope::kRemoteProcess &&
          free_event->target.process_id == child_process_id) {
        remote_free_classified = !free_event->mapping_id;
      } else if (free_event->base == reinterpret_cast<std::uintptr_t>(known_page) &&
                 free_event->free_type == MEM_DECOMMIT && known_id.has_value()) {
        decommit_preserved_id = free_event->mapping_id == *known_id;
      } else if (free_event->base == reinterpret_cast<std::uintptr_t>(known) &&
                 free_event->free_type == MEM_RELEASE && known_id.has_value()) {
        release_ended_id = free_event->mapping_id == *known_id;
      } else if (free_event->base == reinterpret_cast<std::uintptr_t>(preexisting) &&
                 preexisting_id.has_value()) {
        preexisting_release_matched = free_event->mapping_id == *preexisting_id;
      }
      continue;
    }

    const auto* mapping = std::get_if<noleax::trace::MapEvent>(&event.payload);
    if (mapping != nullptr) {
      if (mapping->target.scope == noleax::trace::ProcessMemoryScope::kRemoteProcess &&
          mapping->target.process_id == child_process_id &&
          mapping->result_base == reinterpret_cast<std::uintptr_t>(remote_view)) {
        remote_map_classified = !mapping->mapping_id;
      } else if (mapping->section_handle == reinterpret_cast<std::uintptr_t>(section) &&
                 mapping->view_size == known_view_size) {
        known_view_id = mapping->mapping_id;
      } else if (mapping->section_handle == reinterpret_cast<std::uintptr_t>(section) &&
                 mapping->view_size == outstanding_view_size) {
        outstanding_view_id = mapping->mapping_id;
      } else if (mapping->section_handle == reinterpret_cast<std::uintptr_t>(section) &&
                 mapping->view_size == kPageSize) {
        wrapper_view_id = mapping->mapping_id;
      } else if (event.header.status == noleax::trace::EventStatus::kFailure &&
                 mapping->section_handle == 0U) {
        section_failure_preserved =
            event.header.system_error.domain == noleax::trace::SystemErrorDomain::kNtStatus &&
            event.header.system_error.code == static_cast<std::uint32_t>(section_failure);
      }
      continue;
    }

    const auto* unmap = std::get_if<noleax::trace::UnmapEvent>(&event.payload);
    if (unmap == nullptr) {
      continue;
    }
    if (unmap->target.scope == noleax::trace::ProcessMemoryScope::kRemoteProcess &&
        unmap->target.process_id == child_process_id &&
        unmap->base == reinterpret_cast<std::uintptr_t>(remote_view)) {
      remote_unmap_classified = !unmap->mapping_id;
    } else if (known_view_id.has_value() && unmap->mapping_id == *known_view_id) {
      known_view_ended = unmap->base == reinterpret_cast<std::uintptr_t>(known_view);
    } else if (wrapper_view_id.has_value() && unmap->mapping_id == *wrapper_view_id) {
      wrapper_view_ended = unmap->base == reinterpret_cast<std::uintptr_t>(wrapper_view);
    } else if (unmap->base == reinterpret_cast<std::uintptr_t>(preexisting_view)) {
      preexisting_view_classified =
          event.header.status == noleax::trace::EventStatus::kPreexisting && !unmap->mapping_id;
    }
  }

  const auto* allocate_statistics = find_api_statistics(
      writer_result.statistics, noleax::agent::windows::kNtAllocateVirtualMemoryApiId);
  const auto* free_statistics = find_api_statistics(
      writer_result.statistics, noleax::agent::windows::kNtFreeVirtualMemoryApiId);
  const auto* map_statistics = find_api_statistics(
      writer_result.statistics, noleax::agent::windows::kNtMapViewOfSectionApiId);
  const auto* unmap_statistics = find_api_statistics(
      writer_result.statistics, noleax::agent::windows::kNtUnmapViewOfSectionApiId);
  const bool generations_valid =
      known_id.has_value() && preexisting_id.has_value() && outstanding_id.has_value() &&
      known_id->is_valid() && preexisting_id->is_valid() && outstanding_id->is_valid() &&
      tracker.find_mapping(*known_id) == nullptr &&
      tracker.find_mapping(*preexisting_id) == nullptr &&
      tracker.find_mapping(*outstanding_id) != nullptr && known_view_id.has_value() &&
      outstanding_view_id.has_value() && wrapper_view_id.has_value() &&
      tracker.find_mapping(*known_view_id) == nullptr &&
      tracker.find_mapping(*wrapper_view_id) == nullptr &&
      tracker.find_mapping(*outstanding_view_id) != nullptr && tracker.live_count() >= 2U;
  const bool statistics_valid =
      allocate_statistics != nullptr && free_statistics != nullptr && map_statistics != nullptr &&
      unmap_statistics != nullptr && allocate_statistics->dropped_events == 0U &&
      free_statistics->dropped_events == 0U && map_statistics->dropped_events == 0U &&
      unmap_statistics->dropped_events == 0U &&
      writer_result.statistics.observed_calls == events.size() &&
      parsed.event_count == writer_result.statistics.observed_calls &&
      parsed.statistics == writer_result.statistics && parsed.end_of_trace.has_value() &&
      !parsed.completeness.has(noleax::trace::CompletenessIssue::kEventLoss);
  if (!commit_reused_id || !decommit_preserved_id || !release_ended_id || !preexisting_classified ||
      !preexisting_release_matched || !failure_preserved || !remote_allocate_classified ||
      !remote_free_classified || !known_view_ended || !preexisting_view_classified ||
      !section_failure_preserved || !wrapper_view_ended || !remote_map_classified ||
      !remote_unmap_classified || !generations_valid || !statistics_valid) {
    for (const auto& event : events) {
      if (const auto* mapping = std::get_if<noleax::trace::MapEvent>(&event.payload)) {
        std::fprintf(stderr, "map id=%llu base=%llx size=%llu section=%llx scope=%u status=%u\n",
                     static_cast<unsigned long long>(mapping->mapping_id.value()),
                     static_cast<unsigned long long>(mapping->result_base),
                     static_cast<unsigned long long>(mapping->view_size),
                     static_cast<unsigned long long>(mapping->section_handle),
                     static_cast<unsigned int>(mapping->target.scope),
                     static_cast<unsigned int>(event.header.status));
      } else if (const auto* unmap = std::get_if<noleax::trace::UnmapEvent>(&event.payload)) {
        std::fprintf(stderr, "unmap id=%llu base=%llx scope=%u status=%u\n",
                     static_cast<unsigned long long>(unmap->mapping_id.value()),
                     static_cast<unsigned long long>(unmap->base),
                     static_cast<unsigned int>(unmap->target.scope),
                     static_cast<unsigned int>(event.header.status));
      }
    }
    std::fprintf(
        stderr,
        "NT VM trace failed: events=%llu commit=%u decommit=%u release=%u "
        "preexisting=%u/%u failure=%u remote=%u/%u generations=%u stats=%u "
        "section=%u/%u/%u wrapper=%u remote-section=%u/%u view-ids=%llu/%llu/%llu "
        "ids=%llu/%llu/%llu found=%u/%u/%u live=%llu\n",
        static_cast<unsigned long long>(events.size()), commit_reused_id ? 1U : 0U,
        decommit_preserved_id ? 1U : 0U, release_ended_id ? 1U : 0U,
        preexisting_classified ? 1U : 0U, preexisting_release_matched ? 1U : 0U,
        failure_preserved ? 1U : 0U, remote_allocate_classified ? 1U : 0U,
        remote_free_classified ? 1U : 0U, generations_valid ? 1U : 0U, statistics_valid ? 1U : 0U,
        known_view_ended ? 1U : 0U, preexisting_view_classified ? 1U : 0U,
        section_failure_preserved ? 1U : 0U, wrapper_view_ended ? 1U : 0U,
        remote_map_classified ? 1U : 0U, remote_unmap_classified ? 1U : 0U,
        static_cast<unsigned long long>(known_view_id.has_value() ? known_view_id->value() : 0U),
        static_cast<unsigned long long>(
            outstanding_view_id.has_value() ? outstanding_view_id->value() : 0U),
        static_cast<unsigned long long>(wrapper_view_id.has_value() ? wrapper_view_id->value()
                                                                    : 0U),
        static_cast<unsigned long long>(known_id.has_value() ? known_id->value() : 0U),
        static_cast<unsigned long long>(preexisting_id.has_value() ? preexisting_id->value() : 0U),
        static_cast<unsigned long long>(outstanding_id.has_value() ? outstanding_id->value() : 0U),
        known_id.has_value() && tracker.find_mapping(*known_id) != nullptr ? 1U : 0U,
        preexisting_id.has_value() && tracker.find_mapping(*preexisting_id) != nullptr ? 1U : 0U,
        outstanding_id.has_value() && tracker.find_mapping(*outstanding_id) != nullptr ? 1U : 0U,
        static_cast<unsigned long long>(tracker.live_count()));
    return 10;
  }

  std::printf(
      "status=ok events=%llu reserve=1 commit=1 decommit=1 release=1 "
      "preexisting=1 remote=1 outstanding=1\n",
      static_cast<unsigned long long>(events.size()));
  return 0;
}
