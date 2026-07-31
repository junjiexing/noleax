#include "noleax/controller/windows/remote_injector.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <system_error>

#include "injection_common.hpp"

namespace noleax::controller::windows {
namespace {

using injection::RemoteMemory;
using injection::RemoteThreadResult;
using injection::checked_remote_address;
using injection::fail;
using injection::find_remote_module_resilient;
using injection::local_procedure_offset;
using injection::remote_ntdll_procedure;
using injection::run_remote_thread;
using injection::try_unload_remote_module;

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
