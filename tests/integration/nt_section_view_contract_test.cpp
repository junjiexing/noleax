#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/windows/nt_memory_hooks.hpp"

namespace {

using NtMapViewOfSectionFunction = NTSTATUS(NTAPI*)(HANDLE section, HANDLE process,
                                                    PVOID* base_address, ULONG_PTR zero_bits,
                                                    SIZE_T commit_size,
                                                    PLARGE_INTEGER section_offset,
                                                    PSIZE_T view_size, ULONG inherit_disposition,
                                                    ULONG allocation_type, ULONG protect);
using NtUnmapViewOfSectionFunction = NTSTATUS(NTAPI*)(HANDLE process, PVOID base_address);

constexpr DWORD kLastErrorSentinel = 0x51ec710aU;
constexpr ULONG kViewUnmap = 2U;
constexpr SIZE_T kPageSize = 4096U;
constexpr SIZE_T kAllocationGranularity = 64U * 1024U;

struct CallResult {
  NTSTATUS status{0};
  DWORD last_error{0U};
  PVOID base{nullptr};
  SIZE_T size{0U};
};

struct WorkloadSummary {
  std::array<std::uint32_t, 12U> statuses{};
  std::array<DWORD, 12U> last_errors{};
  std::array<std::uint64_t, 4U> sizes{};
  std::array<bool, 9U> outcomes{};

  bool operator==(const WorkloadSummary&) const = default;
};

struct WorkloadArtifacts {
  std::uint64_t pagefile_section{0U};
  std::uint64_t file_section{0U};
  PVOID writable_view{nullptr};
  PVOID readonly_view{nullptr};
  PVOID file_view{nullptr};
  PVOID wrapper_view{nullptr};
  PVOID remote_view{nullptr};
  SIZE_T writable_size{0U};
  SIZE_T readonly_size{0U};
  SIZE_T file_size{0U};
  DWORD remote_process_id{0U};
};

[[nodiscard]] bool nt_success(NTSTATUS status) noexcept { return status >= 0; }

[[nodiscard]] CallResult map_view(NtMapViewOfSectionFunction function, HANDLE section,
                                  HANDLE process, PVOID requested_base, SIZE_T requested_size,
                                  LARGE_INTEGER* section_offset, ULONG protect) {
  PVOID base = requested_base;
  SIZE_T size = requested_size;
  SetLastError(kLastErrorSentinel);
  const NTSTATUS status =
      function(section, process, &base, 0U, 0U, section_offset, &size, kViewUnmap, 0U, protect);
  return {status, GetLastError(), base, size};
}

[[nodiscard]] CallResult unmap_view(NtUnmapViewOfSectionFunction function, HANDLE process,
                                    PVOID base) {
  SetLastError(kLastErrorSentinel);
  const NTSTATUS status = function(process, base);
  return {status, GetLastError(), base, 0U};
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

class TemporaryFile final {
 public:
  TemporaryFile() {
    std::array<wchar_t, MAX_PATH + 1U> directory{};
    const DWORD directory_length =
        GetTempPathW(static_cast<DWORD>(directory.size()), directory.data());
    std::array<wchar_t, MAX_PATH + 1U> path{};
    if (directory_length == 0U || directory_length >= directory.size() ||
        GetTempFileNameW(directory.data(), L"nlx", 0U, path.data()) == 0U) {
      return;
    }
    path_ = path.data();
    handle_ =
        CreateFileW(path_.c_str(), GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (handle_ == INVALID_HANDLE_VALUE) {
      return;
    }
    LARGE_INTEGER size{};
    size.QuadPart = static_cast<LONGLONG>(3U * kAllocationGranularity);
    if (SetFilePointerEx(handle_, size, nullptr, FILE_BEGIN) == FALSE ||
        SetEndOfFile(handle_) == FALSE) {
      CloseHandle(handle_);
      handle_ = INVALID_HANDLE_VALUE;
    }
  }

  ~TemporaryFile() {
    if (handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(handle_);
    }
    if (!path_.empty()) {
      static_cast<void>(DeleteFileW(path_.c_str()));
    }
  }

  TemporaryFile(const TemporaryFile&) = delete;
  TemporaryFile& operator=(const TemporaryFile&) = delete;

  [[nodiscard]] HANDLE get() const noexcept { return handle_; }

 private:
  HANDLE handle_{INVALID_HANDLE_VALUE};
  std::filesystem::path path_;
};

[[nodiscard]] WorkloadSummary run_workload(NtMapViewOfSectionFunction map_function,
                                           NtUnmapViewOfSectionFunction unmap_function,
                                           WorkloadArtifacts& artifacts) {
  WorkloadSummary summary;
  std::size_t call = 0U;
  const HANDLE current = GetCurrentProcess();
  const HANDLE pagefile = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0U,
                                             4U * kAllocationGranularity, nullptr);
  TemporaryFile file;
  const HANDLE file_section =
      file.get() == INVALID_HANDLE_VALUE
          ? nullptr
          : CreateFileMappingW(file.get(), nullptr, PAGE_READWRITE, 0U, 0U, nullptr);
  artifacts.pagefile_section = reinterpret_cast<std::uintptr_t>(pagefile);
  artifacts.file_section = reinterpret_cast<std::uintptr_t>(file_section);

  const CallResult writable =
      map_view(map_function, pagefile, current, nullptr, 3U * kPageSize, nullptr, PAGE_READWRITE);
  artifacts.writable_view = writable.base;
  artifacts.writable_size = writable.size;
  summary.statuses[call] = static_cast<std::uint32_t>(writable.status);
  summary.last_errors[call++] = writable.last_error;
  summary.sizes[0] = writable.size;
  if (nt_success(writable.status) && writable.base != nullptr && writable.size >= 3U * kPageSize) {
    auto* bytes = static_cast<std::byte*>(writable.base);
    bytes[0] = std::byte{0x35};
    bytes[2U * kPageSize] = std::byte{0x53};
  }

  const CallResult readonly =
      map_view(map_function, pagefile, current, nullptr, kPageSize, nullptr, PAGE_READONLY);
  artifacts.readonly_view = readonly.base;
  artifacts.readonly_size = readonly.size;
  summary.statuses[call] = static_cast<std::uint32_t>(readonly.status);
  summary.last_errors[call++] = readonly.last_error;
  summary.sizes[1] = readonly.size;

  PVOID writable_interior =
      writable.base == nullptr ? nullptr : static_cast<std::byte*>(writable.base) + kPageSize;
  const CallResult writable_unmap = unmap_view(unmap_function, current, writable_interior);
  summary.statuses[call] = static_cast<std::uint32_t>(writable_unmap.status);
  summary.last_errors[call++] = writable_unmap.last_error;
  const CallResult readonly_unmap = unmap_view(unmap_function, current, readonly.base);
  summary.statuses[call] = static_cast<std::uint32_t>(readonly_unmap.status);
  summary.last_errors[call++] = readonly_unmap.last_error;
  const CallResult repeated_unmap = unmap_view(unmap_function, current, readonly.base);
  summary.statuses[call] = static_cast<std::uint32_t>(repeated_unmap.status);
  summary.last_errors[call++] = repeated_unmap.last_error;

  LARGE_INTEGER file_offset{};
  file_offset.QuadPart = static_cast<LONGLONG>(kAllocationGranularity);
  const CallResult file_mapping = map_view(map_function, file_section, current, nullptr,
                                           kPageSize + 123U, &file_offset, PAGE_READWRITE);
  artifacts.file_view = file_mapping.base;
  artifacts.file_size = file_mapping.size;
  summary.statuses[call] = static_cast<std::uint32_t>(file_mapping.status);
  summary.last_errors[call++] = file_mapping.last_error;
  summary.sizes[2] = file_mapping.size;
  const CallResult file_unmap = unmap_view(unmap_function, current, file_mapping.base);
  summary.statuses[call] = static_cast<std::uint32_t>(file_unmap.status);
  summary.last_errors[call++] = file_unmap.last_error;

  const CallResult invalid =
      map_view(map_function, nullptr, current, nullptr, kPageSize, nullptr, PAGE_READONLY);
  summary.statuses[call] = static_cast<std::uint32_t>(invalid.status);
  summary.last_errors[call++] = invalid.last_error;

  SetLastError(kLastErrorSentinel);
  PVOID wrapper =
      pagefile == nullptr ? nullptr : MapViewOfFile(pagefile, FILE_MAP_READ, 0U, 0U, kPageSize);
  const DWORD wrapper_map_error = GetLastError();
  artifacts.wrapper_view = wrapper;
  SetLastError(kLastErrorSentinel);
  const BOOL wrapper_unmapped = wrapper == nullptr ? FALSE : UnmapViewOfFile(wrapper);
  const DWORD wrapper_unmap_error = GetLastError();
  summary.statuses[call] = wrapper == nullptr ? 0U : 1U;
  summary.last_errors[call++] = wrapper_map_error;
  summary.statuses[call] = wrapper_unmapped == FALSE ? 0U : 1U;
  summary.last_errors[call++] = wrapper_unmap_error;

  PROCESS_INFORMATION child{};
  CallResult remote_mapping{static_cast<NTSTATUS>(0xC0000001L), GetLastError(), nullptr, 0U};
  CallResult remote_unmap{static_cast<NTSTATUS>(0xC0000001L), GetLastError(), nullptr, 0U};
  bool child_stopped = false;
  if (pagefile != nullptr && start_suspended_child(child)) {
    artifacts.remote_process_id = child.dwProcessId;
    remote_mapping = map_view(map_function, pagefile, child.hProcess, nullptr, kPageSize, nullptr,
                              PAGE_READWRITE);
    artifacts.remote_view = remote_mapping.base;
    remote_unmap = unmap_view(unmap_function, child.hProcess, remote_mapping.base);
    child_stopped = stop_child(child);
  }
  summary.statuses[call] = static_cast<std::uint32_t>(remote_mapping.status);
  summary.last_errors[call++] = remote_mapping.last_error;
  summary.statuses[call] = static_cast<std::uint32_t>(remote_unmap.status);
  summary.last_errors[call++] = remote_unmap.last_error;
  summary.sizes[3] = remote_mapping.size;

  summary.outcomes = {
      pagefile != nullptr && file_section != nullptr,
      nt_success(writable.status) && writable.base != nullptr && writable.size >= 3U * kPageSize,
      nt_success(readonly.status) && readonly.base != nullptr,
      nt_success(writable_unmap.status) && nt_success(readonly_unmap.status),
      !nt_success(repeated_unmap.status),
      nt_success(file_mapping.status) && file_mapping.base != nullptr &&
          file_mapping.size >= kPageSize + 123U && nt_success(file_unmap.status),
      !nt_success(invalid.status),
      wrapper != nullptr && wrapper_unmapped != FALSE,
      nt_success(remote_mapping.status) && remote_mapping.base != nullptr &&
          nt_success(remote_unmap.status) && child_stopped,
  };

  if (nt_success(writable.status) && !nt_success(writable_unmap.status)) {
    static_cast<void>(unmap_view(unmap_function, current, writable.base));
  }
  if (nt_success(readonly.status) && !nt_success(readonly_unmap.status)) {
    static_cast<void>(unmap_view(unmap_function, current, readonly.base));
  }
  if (nt_success(file_mapping.status) && !nt_success(file_unmap.status)) {
    static_cast<void>(unmap_view(unmap_function, current, file_mapping.base));
  }
  if (file_section != nullptr) {
    CloseHandle(file_section);
  }
  if (pagefile != nullptr) {
    CloseHandle(pagefile);
  }
  return summary;
}

[[nodiscard]] bool finish_uninstall(noleax::agent::windows::NtMemoryHooks& hooks) noexcept {
  if (hooks.uninstall(std::chrono::steady_clock::now())) {
    return true;
  }
  return hooks.flush() && hooks.uninstall(std::chrono::steady_clock::now());
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::string{argv[1]} == "--remote-child") {
    Sleep(30'000U);
    return 0;
  }
  if (argc != 1) {
    return 2;
  }

  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto map_function = ntdll == nullptr ? nullptr
                                             : reinterpret_cast<NtMapViewOfSectionFunction>(
                                                   GetProcAddress(ntdll, "NtMapViewOfSection"));
  const auto unmap_function = ntdll == nullptr ? nullptr
                                               : reinterpret_cast<NtUnmapViewOfSectionFunction>(
                                                     GetProcAddress(ntdll, "NtUnmapViewOfSection"));
  if (map_function == nullptr || unmap_function == nullptr) {
    return 3;
  }

  WorkloadArtifacts baseline_artifacts;
  const WorkloadSummary baseline = run_workload(map_function, unmap_function, baseline_artifacts);
  for (bool outcome : baseline.outcomes) {
    if (!outcome) {
      return 4;
    }
  }

  noleax::agent::HookBackend backend;
  noleax::agent::windows::NtMemoryHooks hooks{backend, 8192U, 16U};
  const auto installed = hooks.install();
  if (!installed.installed() || hooks.map_target_address() == nullptr ||
      hooks.unmap_target_address() == nullptr || hooks.unmap_ex_target_address() == nullptr) {
    return 5;
  }

  WorkloadArtifacts hooked_artifacts;
  const WorkloadSummary hooked = run_workload(map_function, unmap_function, hooked_artifacts);

  const auto map_before_recursive = hooks.map_statistics();
  PVOID recursive_view = nullptr;
  SIZE_T recursive_size = kPageSize;
  const HANDLE recursive_section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                                      0U, 2U * kPageSize, nullptr);
  if (recursive_section != nullptr) {
    const noleax::agent::HookInvocationGuard outer;
    static_cast<void>(map_function(recursive_section, GetCurrentProcess(), &recursive_view, 0U, 0U,
                                   nullptr, &recursive_size, kViewUnmap, 0U, PAGE_READWRITE));
    if (recursive_view != nullptr) {
      static_cast<void>(unmap_function(GetCurrentProcess(), recursive_view));
    }
  }
  const auto map_before_internal = hooks.map_statistics();
  PVOID internal_view = nullptr;
  SIZE_T internal_size = kPageSize;
  if (recursive_section != nullptr) {
    const noleax::agent::InternalThreadScope internal;
    static_cast<void>(map_function(recursive_section, GetCurrentProcess(), &internal_view, 0U, 0U,
                                   nullptr, &internal_size, kViewUnmap, 0U, PAGE_READWRITE));
    if (internal_view != nullptr) {
      static_cast<void>(unmap_function(GetCurrentProcess(), internal_view));
    }
    CloseHandle(recursive_section);
  }

  bool stacks_valid = true;
  bool saw_writable = false;
  bool saw_readonly = false;
  bool saw_file_offset = false;
  bool saw_interior_unmap = false;
  bool saw_repeat_failure = false;
  bool saw_invalid_map = false;
  bool saw_wrapper_map = false;
  bool saw_wrapper_unmap = false;
  bool saw_remote_map = false;
  bool saw_remote_unmap = false;
  std::array<std::uint64_t, 4U> event_counts{};
  noleax::agent::windows::NtVirtualMemoryEvent event;
  while (hooks.try_dequeue_event(event)) {
    stacks_valid &= noleax::agent::windows::stack_capture_succeeded(event.stack) ||
                    event.stack.status == noleax::agent::windows::StackCaptureStatus::kFailed;
    if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kVmAllocate) {
      ++event_counts[0];
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kVmFree) {
      ++event_counts[1];
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kSectionMap) {
      ++event_counts[2];
      saw_writable |= event.section_handle == hooked_artifacts.pagefile_section &&
                      event.result_address ==
                          reinterpret_cast<std::uintptr_t>(hooked_artifacts.writable_view) &&
                      event.raw_result == hooked_artifacts.writable_size &&
                      event.secondary_flags == PAGE_READWRITE &&
                      event.tertiary_flags == kViewUnmap &&
                      event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kSuccess;
      saw_readonly |= event.section_handle == hooked_artifacts.pagefile_section &&
                      event.result_address ==
                          reinterpret_cast<std::uintptr_t>(hooked_artifacts.readonly_view) &&
                      event.raw_result == hooked_artifacts.readonly_size &&
                      event.secondary_flags == PAGE_READONLY;
      saw_file_offset |=
          event.section_handle == hooked_artifacts.file_section &&
          event.result_address == reinterpret_cast<std::uintptr_t>(hooked_artifacts.file_view) &&
          event.section_offset == kAllocationGranularity &&
          event.raw_result == hooked_artifacts.file_size;
      saw_invalid_map |=
          event.section_handle == 0U &&
          event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kFailure &&
          static_cast<NTSTATUS>(event.operation_result) < 0;
      saw_wrapper_map |=
          event.result_address == reinterpret_cast<std::uintptr_t>(hooked_artifacts.wrapper_view) &&
          event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kSuccess;
      saw_remote_map |=
          event.result_address == reinterpret_cast<std::uintptr_t>(hooked_artifacts.remote_view) &&
          event.target_process_id == hooked_artifacts.remote_process_id &&
          event.target_process_id != GetCurrentProcessId();
    } else if (event.operation == noleax::agent::windows::RtlHeapEventOperation::kSectionUnmap) {
      ++event_counts[3];
      const std::uint64_t writable_interior =
          reinterpret_cast<std::uintptr_t>(hooked_artifacts.writable_view) + kPageSize;
      saw_interior_unmap |=
          event.address == writable_interior &&
          event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kSuccess;
      saw_repeat_failure |=
          event.address == reinterpret_cast<std::uintptr_t>(hooked_artifacts.readonly_view) &&
          event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kFailure;
      saw_wrapper_unmap |=
          event.address == reinterpret_cast<std::uintptr_t>(hooked_artifacts.wrapper_view) &&
          event.status == noleax::agent::windows::NtVirtualMemoryEventStatus::kSuccess;
      saw_remote_unmap |=
          event.address == reinterpret_cast<std::uintptr_t>(hooked_artifacts.remote_view) &&
          event.target_process_id == hooked_artifacts.remote_process_id &&
          event.target_process_id != GetCurrentProcessId();
    } else {
      stacks_valid = false;
    }
  }

  const auto allocate_statistics = hooks.allocate_statistics();
  const auto free_statistics = hooks.free_statistics();
  const auto map_statistics = hooks.map_statistics();
  const auto unmap_statistics = hooks.unmap_statistics();
  const bool counters_valid =
      allocate_statistics.recordable_calls ==
          event_counts[0] + allocate_statistics.dropped_events &&
      free_statistics.recordable_calls == event_counts[1] + free_statistics.dropped_events &&
      map_statistics.recordable_calls == event_counts[2] + map_statistics.dropped_events &&
      unmap_statistics.recordable_calls == event_counts[3] + unmap_statistics.dropped_events &&
      map_statistics.successful_calls + map_statistics.failed_calls ==
          map_statistics.recordable_calls &&
      unmap_statistics.successful_calls + unmap_statistics.failed_calls ==
          unmap_statistics.recordable_calls;
  const bool guard_valid =
      recursive_view != nullptr && internal_view != nullptr &&
      map_before_recursive.recursive_calls < map_before_internal.recursive_calls &&
      map_before_internal.recordable_calls == map_before_recursive.recordable_calls &&
      hooks.map_statistics().internal_calls > map_before_internal.internal_calls;
  const bool summary_matches = baseline == hooked;
  const bool uninstalled = finish_uninstall(hooks);
  const bool shutdown = backend.shutdown();

  if (!summary_matches || !counters_valid || !guard_valid || !stacks_valid || !saw_writable ||
      !saw_readonly || !saw_file_offset || !saw_interior_unmap || !saw_repeat_failure ||
      !saw_invalid_map || !saw_wrapper_map || !saw_wrapper_unmap || !saw_remote_map ||
      !saw_remote_unmap || !uninstalled || !shutdown) {
    std::fprintf(stderr,
                 "section contract failed: summary=%u counters=%u guard=%u stacks=%u "
                 "raw=%u%u%u%u%u%u wrapper=%u/%u remote=%u/%u events=%llu/%llu/%llu/%llu "
                 "uninstall=%u shutdown=%u\n",
                 summary_matches ? 1U : 0U, counters_valid ? 1U : 0U, guard_valid ? 1U : 0U,
                 stacks_valid ? 1U : 0U, saw_writable ? 1U : 0U, saw_readonly ? 1U : 0U,
                 saw_file_offset ? 1U : 0U, saw_interior_unmap ? 1U : 0U,
                 saw_repeat_failure ? 1U : 0U, saw_invalid_map ? 1U : 0U, saw_wrapper_map ? 1U : 0U,
                 saw_wrapper_unmap ? 1U : 0U, saw_remote_map ? 1U : 0U, saw_remote_unmap ? 1U : 0U,
                 static_cast<unsigned long long>(event_counts[0]),
                 static_cast<unsigned long long>(event_counts[1]),
                 static_cast<unsigned long long>(event_counts[2]),
                 static_cast<unsigned long long>(event_counts[3]), uninstalled ? 1U : 0U,
                 shutdown ? 1U : 0U);
    return 6;
  }

  std::printf(
      "status=ok pagefile=1 file=1 offset=1 multi-view=1 wrapper=1 remote=1 "
      "last-error=preserved events=%llu/%llu\n",
      static_cast<unsigned long long>(event_counts[2]),
      static_cast<unsigned long long>(event_counts[3]));
  return 0;
}
