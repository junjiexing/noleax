#include "injection_common.hpp"

#include <algorithm>
#include <bit>
#include <cwchar>
#include <filesystem>
#include <limits>
#include <string>
#include <thread>

namespace noleax::controller::windows::injection {

RemoteMemory::RemoteMemory(HANDLE process, std::size_t size) : process_{process}, size_{size} {
  address_ = VirtualAllocEx(process_, nullptr, size_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (address_ == nullptr) {
    const DWORD error = GetLastError();
    throw InjectionError{"VirtualAllocEx failed with Windows error " + std::to_string(error),
                         error};
  }
}

RemoteMemory::~RemoteMemory() {
  if (address_ != nullptr && owned_) {
    static_cast<void>(VirtualFreeEx(process_, address_, 0U, MEM_RELEASE));
  }
}

void RemoteMemory::protect(DWORD protection) {
  DWORD previous = 0U;
  if (VirtualProtectEx(process_, address_, size_, protection, &previous) == FALSE) {
    const DWORD error = GetLastError();
    throw InjectionError{"VirtualProtectEx failed with Windows error " + std::to_string(error),
                         error};
  }
  if (FlushInstructionCache(process_, address_, size_) == FALSE) {
    const DWORD error = GetLastError();
    throw InjectionError{"FlushInstructionCache failed with Windows error " + std::to_string(error),
                         error};
  }
}

void RemoteMemory::write_at(std::size_t offset, const void* bytes, std::size_t size) {
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

void RemoteMemory::read_at(std::size_t offset, void* bytes, std::size_t size) const {
  if (offset > size_ || size > size_ - offset) {
    throw InjectionError{"remote read exceeds its allocation", ERROR_BUFFER_OVERFLOW};
  }
  SIZE_T read_size = 0U;
  const auto* source = static_cast<const std::byte*>(address_) + offset;
  if (ReadProcessMemory(process_, source, bytes, size, &read_size) == FALSE || read_size != size) {
    const DWORD error = GetLastError();
    throw InjectionError{"ReadProcessMemory failed with Windows error " + std::to_string(error),
                         error};
  }
}

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

[[nodiscard]] RemoteThreadResult run_remote_thread(HANDLE process, std::uintptr_t procedure,
                                                   void* parameter,
                                                   std::chrono::milliseconds timeout,
                                                   RemoteMemory* parameter_memory,
                                                   RemoteMemory* procedure_memory) {
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

[[nodiscard]] std::uint32_t remote_image_size(HANDLE process, std::uintptr_t image_base) {
  const auto read_remote = [process](std::uintptr_t address, void* bytes, std::size_t size,
                                     const char* what) {
    SIZE_T read_size = 0U;
    if (ReadProcessMemory(process, std::bit_cast<LPCVOID>(address), bytes, size, &read_size) ==
            FALSE ||
        read_size != size) {
      const DWORD error = GetLastError();
      throw InjectionError{std::string{"cannot read remote "} + what + " (Windows error " +
                               std::to_string(error) + ")",
                           error};
    }
  };
  std::uint32_t pe_offset = 0U;
  read_remote(image_base + 0x3cU, &pe_offset, sizeof(pe_offset), "PE header offset");
  if (pe_offset > 0x1000U) {
    throw InjectionError{"remote image has an implausible PE header offset", ERROR_BAD_EXE_FORMAT};
  }
  std::uint32_t signature = 0U;
  read_remote(checked_remote_address(image_base, pe_offset), &signature, sizeof(signature),
              "PE signature");
  if (signature != 0x0000'4550U) {  // "PE\0\0"
    throw InjectionError{"remote image does not contain a PE signature", ERROR_BAD_EXE_FORMAT};
  }
  constexpr std::uint32_t kSizeOfImageOffset = 4U + 20U + 56U;  // signature + COFF + PE32+ field
  std::uint32_t size_of_image = 0U;
  read_remote(checked_remote_address(image_base, pe_offset + kSizeOfImageOffset), &size_of_image,
              sizeof(size_of_image), "image size");
  if (size_of_image == 0U || size_of_image > 0x4000'0000U) {
    throw InjectionError{"remote image reports an implausible size", ERROR_BAD_EXE_FORMAT};
  }
  return size_of_image;
}

[[nodiscard]] std::uint32_t remote_entry_point_rva(HANDLE process, std::uintptr_t image_base) {
  const auto read_remote = [process](std::uintptr_t address, void* bytes, std::size_t size,
                                     const char* what) {
    SIZE_T read_size = 0U;
    if (ReadProcessMemory(process, std::bit_cast<LPCVOID>(address), bytes, size, &read_size) ==
            FALSE ||
        read_size != size) {
      const DWORD error = GetLastError();
      throw InjectionError{std::string{"cannot read remote "} + what + " (Windows error " +
                               std::to_string(error) + ")",
                           error};
    }
  };
  std::uint32_t pe_offset = 0U;
  read_remote(image_base + 0x3cU, &pe_offset, sizeof(pe_offset), "PE header offset");
  if (pe_offset > 0x1000U) {
    throw InjectionError{"remote image has an implausible PE header offset", ERROR_BAD_EXE_FORMAT};
  }
  std::uint32_t signature = 0U;
  read_remote(checked_remote_address(image_base, pe_offset), &signature, sizeof(signature),
              "PE signature");
  if (signature != 0x0000'4550U) {  // "PE\0\0"
    throw InjectionError{"remote image does not contain a PE signature", ERROR_BAD_EXE_FORMAT};
  }
  constexpr std::uint32_t kEntryPointOffset = 4U + 20U + 16U;  // signature + COFF + PE32+ field
  std::uint32_t entry_point_rva = 0U;
  read_remote(checked_remote_address(image_base, pe_offset + kEntryPointOffset), &entry_point_rva,
              sizeof(entry_point_rva), "entry point RVA");
  if (entry_point_rva == 0U) {
    throw InjectionError{"remote image does not have an entry point", ERROR_BAD_EXE_FORMAT};
  }
  return entry_point_rva;
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

}  // namespace noleax::controller::windows::injection
