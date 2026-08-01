#include "noleax/controller/windows/entrypoint_injector.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

#include "injection_common.hpp"

namespace noleax::controller::windows {
namespace {

using injection::checked_remote_address;
using injection::fail;
using injection::find_remote_image_by_memory;
using injection::Handle;
using injection::local_procedure_offset;
using injection::remote_entry_point_rva;
using injection::remote_ntdll_procedure;
using injection::RemoteMemory;

// x64 bootstrap stub executed as the temporarily patched image entrypoint.
// Assembled with ml64 from the reference source recorded in
// docs/ENTRYPOINT_INJECTION.md; the byte sequence below is verified against
// that disassembly.
//
// Entry contract: rcx = EntryStubData. The stub saves the full register state
// (GP registers, XMM0-15, MXCSR, flags), bootstraps the agent, writes the
// original entry bytes back, flushes the instruction cache, restores every
// register except rax (repurposed as the final jump register) and jumps to
// the original entrypoint — a function start, so the indirect jump stays
// endbr64-compatible for CET/IBT targets.
constexpr std::array<std::byte, 608U> kEntryStub{
    std::byte{0x49}, std::byte{0xBC}, std::byte{0x88}, std::byte{0x77}, std::byte{0x66},
    std::byte{0x55}, std::byte{0x44}, std::byte{0x33}, std::byte{0x22}, std::byte{0x11},
    std::byte{0x9C}, std::byte{0x50}, std::byte{0x53}, std::byte{0x51}, std::byte{0x52},
    std::byte{0x56}, std::byte{0x57}, std::byte{0x55}, std::byte{0x41}, std::byte{0x50},
    std::byte{0x41}, std::byte{0x51}, std::byte{0x41}, std::byte{0x52}, std::byte{0x41},
    std::byte{0x53}, std::byte{0x41}, std::byte{0x54}, std::byte{0x41}, std::byte{0x55},
    std::byte{0x41}, std::byte{0x56}, std::byte{0x41}, std::byte{0x57}, std::byte{0x4C},
    std::byte{0x8B}, std::byte{0xF4}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F},
    std::byte{0x7F}, std::byte{0x44}, std::byte{0x24}, std::byte{0x70}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x8C}, std::byte{0x24},
    std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x94}, std::byte{0x24},
    std::byte{0x90}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x9C}, std::byte{0x24},
    std::byte{0xA0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xA4}, std::byte{0x24},
    std::byte{0xB0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xAC}, std::byte{0x24},
    std::byte{0xC0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xB4}, std::byte{0x24},
    std::byte{0xD0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xBC}, std::byte{0x24},
    std::byte{0xE0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x84}, std::byte{0x24},
    std::byte{0xF0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x8C}, std::byte{0x24},
    std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x94}, std::byte{0x24},
    std::byte{0x10}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x9C}, std::byte{0x24},
    std::byte{0x20}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xA4}, std::byte{0x24},
    std::byte{0x30}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xAC}, std::byte{0x24},
    std::byte{0x40}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xB4}, std::byte{0x24},
    std::byte{0x50}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xBC}, std::byte{0x24},
    std::byte{0x60}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x41},
    std::byte{0x0F}, std::byte{0xAE}, std::byte{0x9C}, std::byte{0x24}, std::byte{0x70},
    std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x83},
    std::byte{0xE4}, std::byte{0xF0}, std::byte{0x48}, std::byte{0x83}, std::byte{0xEC},
    std::byte{0x60}, std::byte{0x33}, std::byte{0xC9}, std::byte{0x33}, std::byte{0xD2},
    std::byte{0x4D}, std::byte{0x8D}, std::byte{0x44}, std::byte{0x24}, std::byte{0x10},
    std::byte{0x4D}, std::byte{0x8D}, std::byte{0x4C}, std::byte{0x24}, std::byte{0x20},
    std::byte{0x41}, std::byte{0xFF}, std::byte{0x54}, std::byte{0x24}, std::byte{0x08},
    std::byte{0x41}, std::byte{0x89}, std::byte{0x44}, std::byte{0x24}, std::byte{0x64},
    std::byte{0x41}, std::byte{0xC7}, std::byte{0x44}, std::byte{0x24}, std::byte{0x60},
    std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x85},
    std::byte{0xC0}, std::byte{0x78}, std::byte{0x67}, std::byte{0x49}, std::byte{0x8B},
    std::byte{0x44}, std::byte{0x24}, std::byte{0x20}, std::byte{0x48}, std::byte{0x85},
    std::byte{0xC0}, std::byte{0x74}, std::byte{0x5D}, std::byte{0x49}, std::byte{0x8D},
    std::byte{0x8C}, std::byte{0x24}, std::byte{0x78}, std::byte{0x01}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x49}, std::byte{0x8B}, std::byte{0x54}, std::byte{0x24},
    std::byte{0x28}, std::byte{0x48}, std::byte{0x03}, std::byte{0xD0}, std::byte{0xFF},
    std::byte{0xD2}, std::byte{0x41}, std::byte{0x89}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x68}, std::byte{0x41}, std::byte{0xC7}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x60}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x85}, std::byte{0xC0}, std::byte{0x75}, std::byte{0x39}, std::byte{0x41},
    std::byte{0xF6}, std::byte{0x44}, std::byte{0x24}, std::byte{0x58}, std::byte{0x01},
    std::byte{0x74}, std::byte{0x28}, std::byte{0x41}, std::byte{0xBD}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x08}, std::byte{0x49}, std::byte{0x8B},
    std::byte{0x5C}, std::byte{0x24}, std::byte{0x20}, std::byte{0x49}, std::byte{0x03},
    std::byte{0x5C}, std::byte{0x24}, std::byte{0x30}, std::byte{0xFF}, std::byte{0xD3},
    std::byte{0x84}, std::byte{0xC0}, std::byte{0x75}, std::byte{0x12}, std::byte{0xF3},
    std::byte{0x90}, std::byte{0x41}, std::byte{0xFF}, std::byte{0xCD}, std::byte{0x75},
    std::byte{0xF3}, std::byte{0x41}, std::byte{0xC7}, std::byte{0x44}, std::byte{0x24},
    std::byte{0x60}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0xEB}, std::byte{0x09}, std::byte{0x41}, std::byte{0xC7}, std::byte{0x44},
    std::byte{0x24}, std::byte{0x60}, std::byte{0x03}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}, std::byte{0xFC}, std::byte{0x49}, std::byte{0x8B}, std::byte{0x7C},
    std::byte{0x24}, std::byte{0x48}, std::byte{0x49}, std::byte{0x8D}, std::byte{0xB4},
    std::byte{0x24}, std::byte{0x98}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x49}, std::byte{0x8B}, std::byte{0x4C}, std::byte{0x24}, std::byte{0x50},
    std::byte{0xF3}, std::byte{0xA4}, std::byte{0x48}, std::byte{0xC7}, std::byte{0xC1},
    std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0x49},
    std::byte{0x8B}, std::byte{0x54}, std::byte{0x24}, std::byte{0x48}, std::byte{0x4D},
    std::byte{0x8B}, std::byte{0x44}, std::byte{0x24}, std::byte{0x50}, std::byte{0x41},
    std::byte{0xFF}, std::byte{0x54}, std::byte{0x24}, std::byte{0x38}, std::byte{0x41},
    std::byte{0xC7}, std::byte{0x44}, std::byte{0x24}, std::byte{0x6C}, std::byte{0x01},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x41}, std::byte{0x0F},
    std::byte{0xAE}, std::byte{0x94}, std::byte{0x24}, std::byte{0x70}, std::byte{0x01},
    std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F},
    std::byte{0x6F}, std::byte{0x44}, std::byte{0x24}, std::byte{0x70}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x8C}, std::byte{0x24},
    std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x94}, std::byte{0x24},
    std::byte{0x90}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x9C}, std::byte{0x24},
    std::byte{0xA0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xA4}, std::byte{0x24},
    std::byte{0xB0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xAC}, std::byte{0x24},
    std::byte{0xC0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xB4}, std::byte{0x24},
    std::byte{0xD0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xBC}, std::byte{0x24},
    std::byte{0xE0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x84}, std::byte{0x24},
    std::byte{0xF0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x8C}, std::byte{0x24},
    std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x94}, std::byte{0x24},
    std::byte{0x10}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x9C}, std::byte{0x24},
    std::byte{0x20}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xA4}, std::byte{0x24},
    std::byte{0x30}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xAC}, std::byte{0x24},
    std::byte{0x40}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xB4}, std::byte{0x24},
    std::byte{0x50}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xBC}, std::byte{0x24},
    std::byte{0x60}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49},
    std::byte{0x8B}, std::byte{0xE6}, std::byte{0x49}, std::byte{0x8B}, std::byte{0x44},
    std::byte{0x24}, std::byte{0x40}, std::byte{0x48}, std::byte{0x87}, std::byte{0x44},
    std::byte{0x24}, std::byte{0x70}, std::byte{0x41}, std::byte{0x5F}, std::byte{0x41},
    std::byte{0x5E}, std::byte{0x41}, std::byte{0x5D}, std::byte{0x41}, std::byte{0x5C},
    std::byte{0x41}, std::byte{0x5B}, std::byte{0x41}, std::byte{0x5A}, std::byte{0x41},
    std::byte{0x59}, std::byte{0x41}, std::byte{0x58}, std::byte{0x5D}, std::byte{0x5F},
    std::byte{0x5E}, std::byte{0x5A}, std::byte{0x59}, std::byte{0x5B}, std::byte{0x58},
    std::byte{0x9D}, std::byte{0xFF}, std::byte{0xE0},
};

struct alignas(8) EntryStubData {
  std::uint64_t magic{0U};
  std::uint64_t ldr_load_dll{0U};
  std::uint16_t path_length{0U};
  std::uint16_t path_capacity{0U};
  std::uint32_t path_reserved{0U};
  std::uint64_t path_buffer{0U};
  std::uint64_t module_handle{0U};
  std::uint64_t bootstrap_rva{0U};
  std::uint64_t ready_rva{0U};
  std::uint64_t flush_icache{0U};
  std::uint64_t entry_va{0U};
  std::uint64_t patch_va{0U};
  std::uint64_t patch_length{0U};
  std::uint64_t flags{0U};
  std::uint32_t stage{0U};
  std::int32_t ldr_status{0};
  std::uint32_t bootstrap_result{0U};
  std::uint32_t restored{0U};
  std::array<std::byte, 0x100U> xmm_save{};
  std::uint32_t mxcsr{0U};
  std::uint32_t mxcsr_pad{0U};
  noleax::agent::windows::BootstrapParameters params{};
  std::array<std::byte, 0x20U> original_bytes{};
  // The agent path (UTF-16, NUL terminated) follows immediately afterwards.
};

inline constexpr std::uint64_t kEntryMagic = 0x4E4C58455031ULL;  // "NLXEP1"
inline constexpr std::size_t kStubDataPointerOffset = 2U;        // imm64 of `mov r12,imm64`
inline constexpr std::uint32_t kStageLoaderReturned = 1U;
inline constexpr std::uint32_t kStageBootstrapReturned = 2U;
inline constexpr std::uint32_t kStageReady = 3U;
inline constexpr std::uint32_t kStageReadyTimeout = 4U;
inline constexpr std::uint64_t kFlagWaitForReady = 1U;
inline constexpr std::uint32_t kEndbr64 = 0xFA1E0FF3U;
inline constexpr std::size_t kEntryBackupSize = 0x20U;
inline constexpr std::size_t kJumpPatchSize = 12U;  // mov rax,imm64; jmp rax

static_assert(sizeof(EntryStubData) == 0x2B8U);
static_assert(offsetof(EntryStubData, stage) == 0x60U);
static_assert(offsetof(EntryStubData, ldr_status) == 0x64U);
static_assert(offsetof(EntryStubData, bootstrap_result) == 0x68U);
static_assert(offsetof(EntryStubData, restored) == 0x6CU);
static_assert(offsetof(EntryStubData, xmm_save) == 0x70U);
static_assert(offsetof(EntryStubData, mxcsr) == 0x170U);
static_assert(offsetof(EntryStubData, params) == 0x178U);
static_assert(offsetof(EntryStubData, original_bytes) == 0x298U);

struct EntryPatch {
  std::uintptr_t entry_va{0U};
  std::uintptr_t patch_va{0U};
  std::size_t patch_length{0U};
  DWORD original_protection{0U};
};

void protect_remote(HANDLE process, std::uintptr_t address, std::size_t size, DWORD protection,
                    DWORD* previous) {
  if (VirtualProtectEx(process, std::bit_cast<LPVOID>(address), size, protection, previous) ==
      FALSE) {
    fail("VirtualProtectEx(entry point)", GetLastError());
  }
}

void flush_remote(HANDLE process, std::uintptr_t address, std::size_t size) {
  if (FlushInstructionCache(process, std::bit_cast<LPCVOID>(address), size) == FALSE) {
    fail("FlushInstructionCache(entry point)", GetLastError());
  }
}

}  // namespace

std::uint32_t entrypoint_patch_offset(std::uint32_t first_entry_bytes) noexcept {
  return first_entry_bytes == kEndbr64 ? 4U : 0U;
}

class EntrypointInjection::Impl final {
 public:
  Impl(void* process_handle, std::uint32_t process_id, std::wstring_view image_file_name,
       const std::filesystem::path& agent_path,
       const noleax::agent::windows::BootstrapParameters& bootstrap)
      : process_{static_cast<HANDLE>(process_handle)}, process_id_{process_id} {
    if (process_ == nullptr || process_ == INVALID_HANDLE_VALUE || process_id_ == 0U ||
        image_file_name.empty()) {
      throw InjectionError{"entrypoint injection parameters are invalid", ERROR_INVALID_PARAMETER};
    }
    if (!agent_path.is_absolute()) {
      throw InjectionError{"agent path must be absolute", ERROR_INVALID_PARAMETER};
    }
    std::error_code path_error;
    if (!std::filesystem::is_regular_file(agent_path, path_error) || path_error) {
      throw InjectionError{"agent DLL does not exist or is not a regular file",
                           ERROR_FILE_NOT_FOUND};
    }
    const bool standalone = bootstrap.session_token == noleax::agent::windows::kStandaloneMagic;
    if (bootstrap.structure_size != sizeof(bootstrap) ||
        bootstrap.version != noleax::agent::windows::kBootstrapVersion ||
        bootstrap.pipe_name.front() == L'\0' || bootstrap.pipe_name.back() != L'\0' ||
        (!standalone &&
         (bootstrap.connect_timeout_ms == 0U || bootstrap.controller_process_id == 0U))) {
      throw InjectionError{"agent bootstrap parameters are invalid", ERROR_INVALID_PARAMETER};
    }
    if (injection::find_remote_module_resilient(process_, process_id_,
                                                agent_path.filename().native())
            .has_value()) {
      throw InjectionError{"an agent module with the same file name is already loaded",
                           ERROR_ALREADY_EXISTS};
    }

    // Resolve every address before touching the target memory. kernel32 is
    // not mapped yet in a freshly suspended process, so the flush goes
    // through ntdll!NtFlushInstructionCache (always present).
    const std::uintptr_t ldr_load_dll = remote_ntdll_procedure(process_, process_id_, "LdrLoadDll");
    const std::uintptr_t flush_icache =
        remote_ntdll_procedure(process_, process_id_, "NtFlushInstructionCache");
    const HMODULE local_agent =
        LoadLibraryExW(agent_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (local_agent == nullptr) {
      fail("LoadLibraryExW(agent image)", GetLastError());
    }
    std::uintptr_t bootstrap_rva = 0U;
    std::uintptr_t ready_rva = 0U;
    try {
      bootstrap_rva = local_procedure_offset(local_agent, "noleax_agent_bootstrap");
      ready_rva = local_procedure_offset(local_agent, "noleax_agent_capture_is_ready");
    } catch (...) {
      static_cast<void>(FreeLibrary(local_agent));
      throw;
    }
    static_cast<void>(FreeLibrary(local_agent));

    const auto image = find_remote_image_by_memory(process_, image_file_name);
    if (!image.has_value()) {
      throw InjectionError{"cannot locate the main image inside the target process",
                           ERROR_MOD_NOT_FOUND};
    }
    const std::uint32_t entry_rva = remote_entry_point_rva(process_, image->base);
    patch_.entry_va = checked_remote_address(image->base, entry_rva);

    // Back up the entry bytes and compute the patch position. An endbr64 must
    // stay intact so the loader's indirect entry call keeps passing IBT.
    std::array<std::byte, kEntryBackupSize> entry_bytes{};
    read_remote(patch_.entry_va, entry_bytes.data(), entry_bytes.size());
    std::uint32_t first_bytes = 0U;
    std::memcpy(&first_bytes, entry_bytes.data(), sizeof(first_bytes));
    const std::uint32_t patch_offset = entrypoint_patch_offset(first_bytes);
    patch_.patch_va = patch_.entry_va + patch_offset;
    patch_.patch_length = kJumpPatchSize;
    std::memcpy(original_bytes_.data(), entry_bytes.data() + patch_offset, kJumpPatchSize);

    const std::wstring& wide_path = agent_path.native();
    const std::size_t path_bytes = (wide_path.size() + 1U) * sizeof(wchar_t);
    if (path_bytes > std::numeric_limits<std::uint16_t>::max()) {
      throw InjectionError{"agent path is too long for UNICODE_STRING", ERROR_FILENAME_EXCED_RANGE};
    }

    write_stub(wide_path, ldr_load_dll, flush_icache, bootstrap_rva, ready_rva, bootstrap);
    apply_jump_patch();
  }

  ~Impl() { abort(); }

  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  [[nodiscard]] std::uintptr_t finish(std::chrono::milliseconds timeout) {
    const EntryStubData data = wait_for_restored(timeout);
    if (data.magic != kEntryMagic) {
      throw InjectionError{"entrypoint stub data was corrupted", ERROR_INVALID_DATA};
    }
    // The stub has written the original bytes back; prove it and re-apply the
    // original page protection.
    std::array<std::byte, kJumpPatchSize> current{};
    read_remote(patch_.patch_va, current.data(), current.size());
    if (current != original_bytes_) {
      throw InjectionError{"the target entry point was not restored to its original bytes",
                           ERROR_INVALID_STATE};
    }
    DWORD previous = 0U;
    protect_remote(process_, patch_.patch_va, patch_.patch_length, patch_.original_protection,
                   &previous);
    flush_remote(process_, patch_.patch_va, patch_.patch_length);
    restored_ = true;
    if (data.stage != kStageReady) {
      throw InjectionError{describe(data), ERROR_DLL_INIT_FAILED};
    }
    return data.module_handle;
  }

  [[nodiscard]] std::string describe_failure() const {
    EntryStubData data{};
    try {
      read_remote(data_base(), &data, sizeof(data));
    } catch (...) {
      return "the entrypoint stub did not report a stage";
    }
    return describe(data);
  }

  void abort() noexcept {
    if (restored_) {
      return;
    }
    // Best effort: the stub restores on its own, but when the launch is
    // being torn down anyway make sure the entry bytes are original.
    try {
      write_remote(patch_.patch_va, original_bytes_.data(), original_bytes_.size());
      std::uint32_t stub_restored = 0U;
      try {
        data_memory_->read_at(offsetof(EntryStubData, restored), &stub_restored,
                              sizeof(stub_restored));
      } catch (...) {
      }
      // Re-protecting to the original (read-execute) protection is only safe once the
      // stub finished its own restore: its rep-movsb needs the page writable, and if the
      // stub is still running, restoring protection now would crash it with an AV.
      if (stub_restored != 0U) {
        DWORD previous = 0U;
        protect_remote(process_, patch_.patch_va, patch_.patch_length, patch_.original_protection,
                       &previous);
        flush_remote(process_, patch_.patch_va, patch_.patch_length);
      }
      restored_ = true;
    } catch (...) {
    }
  }

 private:
  [[nodiscard]] std::uintptr_t data_base() const {
    return reinterpret_cast<std::uintptr_t>(data_memory_->get());
  }

  void read_remote(std::uintptr_t address, void* bytes, std::size_t size) const {
    SIZE_T read_size = 0U;
    if (ReadProcessMemory(process_, std::bit_cast<LPCVOID>(address), bytes, size, &read_size) ==
            FALSE ||
        read_size != size) {
      fail("ReadProcessMemory(entry point)", GetLastError());
    }
  }

  void write_remote(std::uintptr_t address, const void* bytes, std::size_t size) {
    SIZE_T written = 0U;
    if (WriteProcessMemory(process_, std::bit_cast<LPVOID>(address), bytes, size, &written) ==
            FALSE ||
        written != size) {
      fail("WriteProcessMemory(entry point)", GetLastError());
    }
  }

  void write_stub(const std::wstring& wide_path, std::uintptr_t ldr_load_dll,
                  std::uintptr_t flush_icache, std::uintptr_t bootstrap_rva,
                  std::uintptr_t ready_rva,
                  const noleax::agent::windows::BootstrapParameters& bootstrap) {
    const std::size_t path_bytes = (wide_path.size() + 1U) * sizeof(wchar_t);
    data_memory_ = std::make_unique<RemoteMemory>(process_, sizeof(EntryStubData) + path_bytes);
    EntryStubData data{};
    data.magic = kEntryMagic;
    data.ldr_load_dll = ldr_load_dll;
    data.path_length = static_cast<std::uint16_t>(wide_path.size() * sizeof(wchar_t));
    data.path_capacity = static_cast<std::uint16_t>(path_bytes);
    data.path_buffer = data_base() + sizeof(EntryStubData);
    data.bootstrap_rva = bootstrap_rva;
    data.ready_rva = ready_rva;
    data.flush_icache = flush_icache;
    data.entry_va = patch_.entry_va;
    data.patch_va = patch_.patch_va;
    data.patch_length = patch_.patch_length;
    data.flags = kFlagWaitForReady;
    data.params = bootstrap;
    std::memcpy(data.original_bytes.data(), original_bytes_.data(), original_bytes_.size());
    data_memory_->write(&data, sizeof(data));
    data_memory_->write_at(sizeof(data), wide_path.c_str(), path_bytes);

    code_memory_ = std::make_unique<RemoteMemory>(process_, kEntryStub.size());
    std::array<std::byte, kEntryStub.size()> code = kEntryStub;
    // The entrypoint provides no register argument, so the stub's first
    // instruction loads the data pointer as a patched immediate.
    static_assert(kStubDataPointerOffset + sizeof(std::uintptr_t) <= code.size());
    const auto data_address = data_base();
    std::memcpy(code.data() + kStubDataPointerOffset, &data_address, sizeof(data_address));
    code_memory_->write(code.data(), code.size());
    code_memory_->protect(PAGE_EXECUTE_READ);
  }

  void apply_jump_patch() {
    // mov rax,<stub>; jmp rax — 12 bytes written at the patch position.
    std::array<std::byte, kJumpPatchSize> patch{
        std::byte{0x48}, std::byte{0xB8}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0xFF}, std::byte{0xE0},
    };
    const auto stub_address = reinterpret_cast<std::uintptr_t>(code_memory_->get());
    std::memcpy(patch.data() + 2U, &stub_address, sizeof(stub_address));
    protect_remote(process_, patch_.patch_va, patch_.patch_length, PAGE_EXECUTE_READWRITE,
                   &patch_.original_protection);
    write_remote(patch_.patch_va, patch.data(), patch.size());
    flush_remote(process_, patch_.patch_va, patch_.patch_length);
  }

  [[nodiscard]] EntryStubData wait_for_restored(std::chrono::milliseconds timeout) const {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    EntryStubData data{};
    for (;;) {
      data_memory_->read_at(offsetof(EntryStubData, restored), &data.restored,
                            sizeof(data.restored));
      if (data.restored != 0U) {
        data_memory_->read(&data, sizeof(data));
        return data;
      }
      DWORD exit_code = 0U;
      if (GetExitCodeProcess(process_, &exit_code) == FALSE || exit_code != STILL_ACTIVE) {
        throw InjectionError{"the target process exited inside the entrypoint stub",
                             ERROR_PROCESS_ABORTED};
      }
      if (std::chrono::steady_clock::now() >= deadline) {
        throw InjectionError{"the entrypoint stub did not finish before the timeout", WAIT_TIMEOUT};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
  }

  [[nodiscard]] static std::string describe(const EntryStubData& data) {
    if (data.stage == kStageLoaderReturned) {
      return "entrypoint stub LdrLoadDll failed with NTSTATUS " + std::to_string(data.ldr_status);
    }
    if (data.stage == kStageBootstrapReturned) {
      return "entrypoint stub bootstrap returned error " + std::to_string(data.bootstrap_result);
    }
    if (data.stage == kStageReadyTimeout) {
      return "entrypoint stub capture did not become ready";
    }
    if (data.stage == kStageReady) {
      return "entrypoint stub completed";
    }
    return "entrypoint stub did not start";
  }

  HANDLE process_{nullptr};
  std::uint32_t process_id_{0U};
  EntryPatch patch_{};
  std::array<std::byte, kJumpPatchSize> original_bytes_{};
  std::unique_ptr<RemoteMemory> code_memory_;
  std::unique_ptr<RemoteMemory> data_memory_;
  bool restored_{false};
};

EntrypointInjection::EntrypointInjection(
    void* process_handle, std::uint32_t process_id, std::wstring_view image_file_name,
    const std::filesystem::path& agent_path,
    const noleax::agent::windows::BootstrapParameters& bootstrap)
    : impl_{std::make_unique<Impl>(process_handle, process_id, image_file_name, agent_path,
                                   bootstrap)} {}

EntrypointInjection::~EntrypointInjection() = default;

std::uintptr_t EntrypointInjection::finish(std::chrono::milliseconds timeout) {
  return impl_->finish(timeout);
}

std::string EntrypointInjection::describe_failure() const { return impl_->describe_failure(); }

void EntrypointInjection::abort() noexcept { impl_->abort(); }

}  // namespace noleax::controller::windows
