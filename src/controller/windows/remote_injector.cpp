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
#include <cstdint>
#include <cwchar>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace noleax::controller::windows {
namespace {

class Handle final {
 public:
  explicit Handle(HANDLE value = nullptr) noexcept : value_{value} {}
  ~Handle() {
    if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
      static_cast<void>(CloseHandle(value_));
    }
  }

  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;

  Handle(Handle&& other) noexcept : value_{std::exchange(other.value_, nullptr)} {}
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
        static_cast<void>(CloseHandle(value_));
      }
      value_ = std::exchange(other.value_, nullptr);
    }
    return *this;
  }

  [[nodiscard]] HANDLE get() const noexcept { return value_; }
  [[nodiscard]] bool valid() const noexcept {
    return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
  }

 private:
  HANDLE value_{nullptr};
};

class RemoteMemory final {
 public:
  RemoteMemory(HANDLE process, std::size_t size) : process_{process}, size_{size} {
    address_ = VirtualAllocEx(process_, nullptr, size_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (address_ == nullptr) {
      const DWORD error = GetLastError();
      throw InjectionError{"VirtualAllocEx failed with Windows error " + std::to_string(error),
                           error};
    }
  }

  ~RemoteMemory() {
    if (address_ != nullptr && owned_) {
      static_cast<void>(VirtualFreeEx(process_, address_, 0U, MEM_RELEASE));
    }
  }

  RemoteMemory(const RemoteMemory&) = delete;
  RemoteMemory& operator=(const RemoteMemory&) = delete;

  [[nodiscard]] void* get() const noexcept { return address_; }
  void preserve_for_timed_out_remote_thread() noexcept { owned_ = false; }

  void protect(DWORD protection) {
    DWORD previous = 0U;
    if (VirtualProtectEx(process_, address_, size_, protection, &previous) == FALSE) {
      const DWORD error = GetLastError();
      throw InjectionError{"VirtualProtectEx failed with Windows error " + std::to_string(error),
                           error};
    }
    if (FlushInstructionCache(process_, address_, size_) == FALSE) {
      const DWORD error = GetLastError();
      throw InjectionError{
          "FlushInstructionCache failed with Windows error " + std::to_string(error), error};
    }
  }

  void write(const void* bytes, std::size_t size) { write_at(0U, bytes, size); }

  void write_at(std::size_t offset, const void* bytes, std::size_t size) {
    if (offset > size_ || size > size_ - offset) {
      throw InjectionError{"remote write exceeds its allocation", ERROR_BUFFER_OVERFLOW};
    }
    SIZE_T written = 0U;
    auto* destination = static_cast<std::byte*>(address_) + offset;
    if (WriteProcessMemory(process_, destination, bytes, size, &written) == FALSE ||
        written != size) {
      const DWORD error = GetLastError();
      throw InjectionError{"WriteProcessMemory failed with Windows error " + std::to_string(error),
                           error};
    }
  }

  void read(void* bytes, std::size_t size) const { read_at(0U, bytes, size); }

  void read_at(std::size_t offset, void* bytes, std::size_t size) const {
    if (offset > size_ || size > size_ - offset) {
      throw InjectionError{"remote read exceeds its allocation", ERROR_BUFFER_OVERFLOW};
    }
    SIZE_T read_size = 0U;
    const auto* source = static_cast<const std::byte*>(address_) + offset;
    if (ReadProcessMemory(process_, source, bytes, size, &read_size) == FALSE ||
        read_size != size) {
      const DWORD error = GetLastError();
      throw InjectionError{"ReadProcessMemory failed with Windows error " + std::to_string(error),
                           error};
    }
  }

 private:
  HANDLE process_{nullptr};
  void* address_{nullptr};
  std::size_t size_{0U};
  bool owned_{true};
};

struct RemoteModule {
  std::uintptr_t base{0U};
  std::wstring path;
};

[[noreturn]] void fail(const char* operation, DWORD error) {
  throw InjectionError{
      std::string{operation} + " failed with Windows error " + std::to_string(error), error};
}

[[nodiscard]] bool equal_case_insensitive(std::wstring_view left,
                                          std::wstring_view right) noexcept {
  return left.size() == right.size() && _wcsnicmp(left.data(), right.data(), left.size()) == 0;
}

[[nodiscard]] std::optional<RemoteModule> find_remote_module(std::uint32_t process_id,
                                                             std::wstring_view module_name) {
  Handle snapshot;
  for (std::uint32_t attempt = 0U; attempt < 8U; ++attempt) {
    snapshot =
        Handle{CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id)};
    if (snapshot.valid()) {
      break;
    }
    const DWORD error = GetLastError();
    if (error != ERROR_BAD_LENGTH) {
      fail("CreateToolhelp32Snapshot", error);
    }
    std::this_thread::yield();
  }
  if (!snapshot.valid()) {
    fail("CreateToolhelp32Snapshot", GetLastError());
  }

  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Module32FirstW(snapshot.get(), &entry) == FALSE) {
    const DWORD error = GetLastError();
    if (error == ERROR_NO_MORE_FILES) {
      return std::nullopt;
    }
    fail("Module32FirstW", error);
  }
  do {
    if (equal_case_insensitive(entry.szModule, module_name)) {
      return RemoteModule{reinterpret_cast<std::uintptr_t>(entry.modBaseAddr), entry.szExePath};
    }
    entry.dwSize = sizeof(entry);
  } while (Module32NextW(snapshot.get(), &entry) != FALSE);
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    fail("Module32NextW", GetLastError());
  }
  return std::nullopt;
}

[[nodiscard]] std::optional<RemoteModule> find_remote_image_by_memory(
    HANDLE process, std::wstring_view module_name) {
  SYSTEM_INFO system_info{};
  GetSystemInfo(&system_info);
  auto address = reinterpret_cast<std::uintptr_t>(system_info.lpMinimumApplicationAddress);
  const auto maximum = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);
  while (address < maximum) {
    MEMORY_BASIC_INFORMATION memory{};
    const SIZE_T queried =
        VirtualQueryEx(process, std::bit_cast<const void*>(address), &memory, sizeof(memory));
    if (queried != sizeof(memory)) {
      const DWORD error = GetLastError();
      if (error == ERROR_INVALID_PARAMETER) {
        break;
      }
      fail("VirtualQueryEx", error);
    }
    const auto base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
    const auto allocation_base = reinterpret_cast<std::uintptr_t>(memory.AllocationBase);
    if (memory.State == MEM_COMMIT && memory.Type == MEM_IMAGE && base == allocation_base) {
      std::wstring path(32'768U, L'\0');
      const DWORD size = GetMappedFileNameW(process, memory.AllocationBase, path.data(),
                                            static_cast<DWORD>(path.size()));
      if (size != 0U && size < path.size()) {
        path.resize(size);
        if (equal_case_insensitive(std::filesystem::path{path}.filename().native(), module_name)) {
          return RemoteModule{allocation_base, std::move(path)};
        }
      }
    }
    if (memory.RegionSize == 0U ||
        memory.RegionSize > std::numeric_limits<std::uintptr_t>::max() - base) {
      break;
    }
    const auto next = base + memory.RegionSize;
    if (next <= address) {
      break;
    }
    address = next;
  }
  return std::nullopt;
}

[[nodiscard]] std::optional<RemoteModule> find_remote_module_resilient(
    HANDLE process, std::uint32_t process_id, std::wstring_view module_name) {
  try {
    return find_remote_module(process_id, module_name);
  } catch (const InjectionError& error) {
    if (error.system_error() != ERROR_PARTIAL_COPY) {
      throw;
    }
    return find_remote_image_by_memory(process, module_name);
  }
}

[[nodiscard]] std::uintptr_t checked_remote_address(std::uintptr_t base, std::uintptr_t offset) {
  if (offset > std::numeric_limits<std::uintptr_t>::max() - base) {
    throw InjectionError{"remote procedure address overflows", ERROR_ARITHMETIC_OVERFLOW};
  }
  return base + offset;
}

[[nodiscard]] std::uintptr_t local_procedure_offset(HMODULE module, const char* name) {
  const FARPROC procedure = GetProcAddress(module, name);
  if (procedure == nullptr) {
    fail("GetProcAddress", GetLastError());
  }
  const auto module_address = reinterpret_cast<std::uintptr_t>(module);
  const auto procedure_address = reinterpret_cast<std::uintptr_t>(procedure);
  if (procedure_address < module_address) {
    throw InjectionError{"local procedure address precedes its module", ERROR_INVALID_ADDRESS};
  }
  return procedure_address - module_address;
}

struct RemoteThreadResult {
  std::uint32_t thread_id{0U};
  std::uint32_t exit_code{0U};
};

[[nodiscard]] RemoteThreadResult run_remote_thread(HANDLE process, std::uintptr_t procedure,
                                                   void* parameter,
                                                   std::chrono::milliseconds timeout,
                                                   RemoteMemory* parameter_memory,
                                                   RemoteMemory* procedure_memory = nullptr) {
  DWORD thread_id = 0U;
  const auto start = std::bit_cast<LPTHREAD_START_ROUTINE>(procedure);
  Handle thread{CreateRemoteThread(process, nullptr, 0U, start, parameter, 0U, &thread_id)};
  if (!thread.valid()) {
    fail("CreateRemoteThread", GetLastError());
  }
  const DWORD timeout_value = timeout.count() >= static_cast<long long>(INFINITE - 1U)
                                  ? INFINITE - 1U
                                  : static_cast<DWORD>((std::max)(timeout.count(), 1LL));
  const DWORD wait_result = WaitForSingleObject(thread.get(), timeout_value);
  if (wait_result == WAIT_TIMEOUT) {
    if (parameter_memory != nullptr) {
      parameter_memory->preserve_for_timed_out_remote_thread();
    }
    if (procedure_memory != nullptr) {
      procedure_memory->preserve_for_timed_out_remote_thread();
    }
    throw InjectionError{"remote thread timed out; its parameter allocation was retained",
                         WAIT_TIMEOUT};
  }
  if (wait_result != WAIT_OBJECT_0) {
    fail("WaitForSingleObject(remote thread)", GetLastError());
  }
  DWORD exit_code = 0U;
  if (GetExitCodeThread(thread.get(), &exit_code) == FALSE) {
    fail("GetExitCodeThread", GetLastError());
  }
  return {thread_id, exit_code};
}

[[nodiscard]] std::uintptr_t remote_ntdll_procedure(HANDLE process, std::uint32_t process_id,
                                                    const char* name) {
  const HMODULE local_ntdll = GetModuleHandleW(L"ntdll.dll");
  if (local_ntdll == nullptr) {
    fail("GetModuleHandleW(ntdll)", GetLastError());
  }
  const auto remote_ntdll = find_remote_module_resilient(process, process_id, L"ntdll.dll");
  if (!remote_ntdll.has_value()) {
    throw InjectionError{"target process does not contain ntdll.dll", ERROR_MOD_NOT_FOUND};
  }
  return checked_remote_address(remote_ntdll->base, local_procedure_offset(local_ntdll, name));
}

struct alignas(8) RemoteLdrLoadContext {
  std::uintptr_t ldr_load_dll{0U};
  std::uint16_t path_length{0U};
  std::uint16_t path_capacity{0U};
  std::uint32_t reserved{0U};
  std::uintptr_t path_buffer{0U};
  std::uintptr_t module_handle{0U};
};

static_assert(sizeof(RemoteLdrLoadContext) == 32U);
static_assert(offsetof(RemoteLdrLoadContext, path_length) == 8U);
static_assert(offsetof(RemoteLdrLoadContext, module_handle) == 24U);

struct LoadedRemoteModule {
  std::uintptr_t base{0U};
  std::uint32_t thread_id{0U};
};

[[nodiscard]] LoadedRemoteModule load_remote_library(HANDLE process, std::uint32_t process_id,
                                                     const std::wstring& path,
                                                     std::chrono::milliseconds timeout) {
  if constexpr (sizeof(void*) != 8U) {
    throw InjectionError{"the P6 remote loader currently requires x64", ERROR_NOT_SUPPORTED};
  }
  const std::size_t path_bytes = (path.size() + 1U) * sizeof(wchar_t);
  if (path_bytes > std::numeric_limits<std::uint16_t>::max()) {
    throw InjectionError{"agent path is too long for UNICODE_STRING", ERROR_FILENAME_EXCED_RANGE};
  }
  RemoteMemory context_memory{process, sizeof(RemoteLdrLoadContext) + path_bytes};
  RemoteLdrLoadContext context;
  context.ldr_load_dll = remote_ntdll_procedure(process, process_id, "LdrLoadDll");
  context.path_length = static_cast<std::uint16_t>(path.size() * sizeof(wchar_t));
  context.path_capacity = static_cast<std::uint16_t>(path_bytes);
  context.path_buffer = reinterpret_cast<std::uintptr_t>(context_memory.get()) + sizeof(context);
  context_memory.write(&context, sizeof(context));
  context_memory.write_at(sizeof(context), path.c_str(), path_bytes);

  // Windows x64 ABI stub:
  //   r10=ctx; reserve shadow space; LdrLoadDll(nullptr,nullptr,&ctx->unicode,&ctx->module).
  constexpr std::array<std::byte, 29U> kLdrLoadStub{
      std::byte{0x49}, std::byte{0x89}, std::byte{0xca}, std::byte{0x48}, std::byte{0x83},
      std::byte{0xec}, std::byte{0x28}, std::byte{0x33}, std::byte{0xc9}, std::byte{0x33},
      std::byte{0xd2}, std::byte{0x4d}, std::byte{0x8d}, std::byte{0x42}, std::byte{0x08},
      std::byte{0x4d}, std::byte{0x8d}, std::byte{0x4a}, std::byte{0x18}, std::byte{0x49},
      std::byte{0x8b}, std::byte{0x02}, std::byte{0xff}, std::byte{0xd0}, std::byte{0x48},
      std::byte{0x83}, std::byte{0xc4}, std::byte{0x28}, std::byte{0xc3}};
  RemoteMemory code_memory{process, kLdrLoadStub.size()};
  code_memory.write(kLdrLoadStub.data(), kLdrLoadStub.size());
  code_memory.protect(PAGE_EXECUTE_READ);
  const RemoteThreadResult loaded =
      run_remote_thread(process, reinterpret_cast<std::uintptr_t>(code_memory.get()),
                        context_memory.get(), timeout, &context_memory, &code_memory);
  if (static_cast<std::int32_t>(loaded.exit_code) < 0) {
    throw InjectionError{"LdrLoadDll failed with NTSTATUS " + std::to_string(loaded.exit_code),
                         loaded.exit_code};
  }
  context_memory.read(&context, sizeof(context));
  if (context.module_handle == 0U) {
    throw InjectionError{"LdrLoadDll succeeded without returning a module handle",
                         ERROR_MOD_NOT_FOUND};
  }
  return {context.module_handle, loaded.thread_id};
}

void try_unload_remote_module(HANDLE process, std::uint32_t process_id,
                              std::uintptr_t remote_module,
                              std::chrono::milliseconds timeout) noexcept {
  try {
    static_cast<void>(run_remote_thread(process,
                                        remote_ntdll_procedure(process, process_id, "LdrUnloadDll"),
                                        std::bit_cast<void*>(remote_module), timeout, nullptr));
  } catch (...) {
  }
}

}  // namespace

InjectionError::InjectionError(const std::string& message, std::uint32_t system_error)
    : std::runtime_error{message}, system_error_{system_error} {}

std::uint32_t InjectionError::system_error() const noexcept { return system_error_; }

InjectionResult inject_remote_thread(void* process_handle, std::uint32_t process_id,
                                     const std::filesystem::path& agent_path,
                                     const noleax::agent::windows::BootstrapParameters& bootstrap,
                                     std::chrono::milliseconds timeout) {
  const HANDLE process = static_cast<HANDLE>(process_handle);
  if (process == nullptr || process == INVALID_HANDLE_VALUE || process_id == 0U ||
      timeout <= std::chrono::milliseconds::zero()) {
    throw InjectionError{"remote injection parameters are invalid", ERROR_INVALID_PARAMETER};
  }
  if (!agent_path.is_absolute()) {
    throw InjectionError{"agent path must be absolute", ERROR_INVALID_PARAMETER};
  }
  std::error_code path_error;
  if (!std::filesystem::is_regular_file(agent_path, path_error) || path_error) {
    throw InjectionError{"agent DLL does not exist or is not a regular file", ERROR_FILE_NOT_FOUND};
  }
  if (bootstrap.structure_size != sizeof(bootstrap) ||
      bootstrap.version != noleax::agent::windows::kBootstrapVersion ||
      bootstrap.pipe_name.front() == L'\0' || bootstrap.pipe_name.back() != L'\0' ||
      bootstrap.connect_timeout_ms == 0U || bootstrap.reserved != 0U) {
    throw InjectionError{"agent bootstrap parameters are invalid", ERROR_INVALID_PARAMETER};
  }
  if (find_remote_module_resilient(process, process_id, agent_path.filename().native())
          .has_value()) {
    throw InjectionError{"an agent module with the same file name is already loaded",
                         ERROR_ALREADY_EXISTS};
  }

  const LoadedRemoteModule loaded =
      load_remote_library(process, process_id, agent_path.native(), timeout);
  const std::uintptr_t remote_agent_base = loaded.base;

  const HMODULE local_agent =
      LoadLibraryExW(agent_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
  if (local_agent == nullptr) {
    const DWORD error = GetLastError();
    try_unload_remote_module(process, process_id, remote_agent_base, timeout);
    fail("LoadLibraryExW(agent image)", error);
  }
  std::uintptr_t bootstrap_offset = 0U;
  try {
    bootstrap_offset = local_procedure_offset(local_agent, "noleax_agent_bootstrap");
  } catch (...) {
    static_cast<void>(FreeLibrary(local_agent));
    try_unload_remote_module(process, process_id, remote_agent_base, timeout);
    throw;
  }
  static_cast<void>(FreeLibrary(local_agent));

  RemoteMemory remote_bootstrap{process, sizeof(bootstrap)};
  remote_bootstrap.write(&bootstrap, sizeof(bootstrap));
  const RemoteThreadResult started =
      run_remote_thread(process, checked_remote_address(remote_agent_base, bootstrap_offset),
                        remote_bootstrap.get(), timeout, &remote_bootstrap);
  if (started.exit_code !=
      static_cast<std::uint32_t>(noleax::agent::windows::BootstrapResult::kSuccess)) {
    try_unload_remote_module(process, process_id, remote_agent_base, timeout);
    throw InjectionError{"agent bootstrap returned error " + std::to_string(started.exit_code),
                         ERROR_DLL_INIT_FAILED};
  }
  return {remote_agent_base, loaded.thread_id, started.thread_id};
}

}  // namespace noleax::controller::windows
