#include "noleax/controller/windows/remote_injector.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: tlhelp32.h and psapi.h require Windows base types.
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
// clang-format on

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <string>

#include "noleax/agent/windows/bootstrap.hpp"
#include "noleax/controller/windows/process.hpp"
#include "noleax/ipc/windows/named_pipe.hpp"

namespace {

[[nodiscard]] bool module_loaded_by_memory(HANDLE process, const std::wstring& module_name) {
  SYSTEM_INFO system_info{};
  GetSystemInfo(&system_info);
  auto address = reinterpret_cast<std::uintptr_t>(system_info.lpMinimumApplicationAddress);
  const auto maximum = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);
  while (address < maximum) {
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQueryEx(process, std::bit_cast<const void*>(address), &memory, sizeof(memory)) !=
        sizeof(memory)) {
      return GetLastError() != ERROR_INVALID_PARAMETER;
    }
    const auto base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
    const auto allocation_base = reinterpret_cast<std::uintptr_t>(memory.AllocationBase);
    if (memory.State == MEM_COMMIT && memory.Type == MEM_IMAGE && base == allocation_base) {
      std::array<wchar_t, 32'768U> path{};
      const DWORD length = GetMappedFileNameW(process, memory.AllocationBase, path.data(),
                                              static_cast<DWORD>(path.size()));
      if (length != 0U && length < path.size()) {
        const std::filesystem::path image_path{std::wstring{path.data(), length}};
        if (_wcsicmp(image_path.filename().c_str(), module_name.c_str()) == 0) {
          return true;
        }
      }
    }
    if (memory.RegionSize == 0U ||
        memory.RegionSize > std::numeric_limits<std::uintptr_t>::max() - base) {
      return false;
    }
    const auto next = base + memory.RegionSize;
    if (next <= address) {
      return false;
    }
    address = next;
  }
  return false;
}

[[nodiscard]] bool module_loaded(HANDLE process, std::uint32_t process_id,
                                 const std::wstring& module_name) {
  HANDLE snapshot = INVALID_HANDLE_VALUE;
  for (std::uint32_t attempt = 0U; attempt < 8U; ++attempt) {
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
    if (snapshot != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) {
      break;
    }
  }
  if (snapshot == INVALID_HANDLE_VALUE) {
    return GetLastError() == ERROR_PARTIAL_COPY ? module_loaded_by_memory(process, module_name)
                                                : true;
  }
  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Module32FirstW(snapshot, &entry) == FALSE) {
    const DWORD error = GetLastError();
    static_cast<void>(CloseHandle(snapshot));
    if (error == ERROR_NO_MORE_FILES) {
      return false;
    }
    return error == ERROR_PARTIAL_COPY ? module_loaded_by_memory(process, module_name) : true;
  }
  do {
    if (_wcsicmp(entry.szModule, module_name.c_str()) == 0) {
      static_cast<void>(CloseHandle(snapshot));
      return true;
    }
    entry.dwSize = sizeof(entry);
  } while (Module32NextW(snapshot, &entry) != FALSE);
  const DWORD error = GetLastError();
  static_cast<void>(CloseHandle(snapshot));
  if (error == ERROR_NO_MORE_FILES) {
    return false;
  }
  return error == ERROR_PARTIAL_COPY ? module_loaded_by_memory(process, module_name) : true;
}

}  // namespace

int main(int argc, char* argv[]) {
  using namespace std::chrono_literals;
  if (argc != 4) {
    return 2;
  }
  const std::filesystem::path fixture = std::filesystem::absolute(argv[1]);
  const std::filesystem::path target = std::filesystem::absolute(argv[2]);
  const std::filesystem::path marker = std::filesystem::absolute(argv[3]);
  std::error_code error;
  static_cast<void>(std::filesystem::remove(marker, error));
  auto process = noleax::controller::windows::SuspendedProcess::create(
      target, {noleax::controller::windows::wide_to_utf8(marker.native()), "1000"},
      target.parent_path());

  std::array<std::byte, 16U> token{};
  token[0] = std::byte{0x42};
  const std::wstring pipe_name = noleax::ipc::windows::make_pipe_name(token);
  noleax::agent::windows::BootstrapParameters bootstrap;
  std::ranges::copy(pipe_name, bootstrap.pipe_name.begin());
  bootstrap.session_token = token;

  DWORD handles_before = 0U;
  DWORD handles_after = 0U;
  const bool queried_before = GetProcessHandleCount(GetCurrentProcess(), &handles_before) != FALSE;
  constexpr std::uint32_t kAttempts = 8U;
  bool rejected = true;
  bool unloaded = true;
  for (std::uint32_t attempt = 0U; attempt < kAttempts; ++attempt) {
    bool current_rejected = false;
    try {
      static_cast<void>(noleax::controller::windows::inject_remote_thread(
          process.process_handle(), process.process_id(), fixture, bootstrap, 5s));
    } catch (const noleax::controller::windows::InjectionError&) {
      current_rejected = true;
    }
    rejected = rejected && current_rejected;
    unloaded = unloaded && !module_loaded(static_cast<HANDLE>(process.process_handle()),
                                          process.process_id(), fixture.filename().native());
  }
  const bool queried_after = GetProcessHandleCount(GetCurrentProcess(), &handles_after) != FALSE;
  const bool handles_stable = queried_before && queried_after && handles_before == handles_after;
  const bool still_suspended =
      process.main_thread_is_suspended() && !std::filesystem::exists(marker) && !process.wait(0ms);
  process.terminate(0U);
  if (!rejected || !unloaded || !still_suspended || !handles_stable) {
    std::fprintf(stderr, "rollback failed: rejected=%u unloaded=%u suspended=%u handles=%lu/%lu\n",
                 rejected ? 1U : 0U, unloaded ? 1U : 0U, still_suspended ? 1U : 0U,
                 static_cast<unsigned long>(handles_before),
                 static_cast<unsigned long>(handles_after));
    return 3;
  }
  std::printf(
      "status=ok rollback=1 module-unloaded=1 main-suspended=1 attempts=8 handles-stable=1\n");
  return 0;
}
