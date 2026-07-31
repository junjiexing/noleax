#pragma once

// Internal layout shared by the static PE patcher (P7C), the runtime
// bootstrap-parameter writer and tests. The offsets must match the reference
// stub assembly recorded in docs/STATIC_PE_PATCH.md; the byte template is
// produced from that assembly with ml64 and its two immediate fixup slots are
// patched per output image.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "noleax/agent/windows/bootstrap.hpp"

namespace noleax::controller::windows::pepatch {

inline constexpr std::size_t kStubCodeOffset = 0x000U;
inline constexpr std::size_t kParamsOffset = 0x500U;
inline constexpr std::size_t kMarkerOffset = 0x620U;
inline constexpr std::size_t kAgentNameOffset = 0x630U;
inline constexpr std::size_t kAgentNameCapacity = 0x80U;
inline constexpr std::size_t kBootstrapSymbolOffset = 0x6B0U;
inline constexpr std::size_t kBootstrapSymbolCapacity = 0x40U;
inline constexpr std::size_t kReadySymbolOffset = 0x6F0U;
inline constexpr std::size_t kReadySymbolCapacity = 0x40U;
inline constexpr std::size_t kHashKernelbaseOffset = 0x730U;
inline constexpr std::size_t kHashLoadLibraryOffset = 0x734U;
inline constexpr std::size_t kHashGetProcAddressOffset = 0x738U;
inline constexpr std::size_t kHashSleepOffset = 0x73CU;
inline constexpr std::size_t kHashNtdllOffset = 0x740U;
inline constexpr std::size_t kHashVirtualProtectOffset = 0x744U;
inline constexpr std::size_t kHashNtFlushOffset = 0x748U;
inline constexpr std::size_t kResultOffset = 0x74CU;
inline constexpr std::size_t kOriginalBytesOffset = 0x750U;
inline constexpr std::size_t kOldProtectOffset = 0x758U;
inline constexpr std::size_t kNtFlushSlotOffset = 0x760U;
inline constexpr std::size_t kPatchRvaOffset = 0x768U;
inline constexpr std::size_t kScratchOffset = 0x770U;
inline constexpr std::size_t kContentSize = 0x890U;

inline constexpr std::size_t kEntryPatchSize = 5U;  // direct `jmp rel32`

inline constexpr char kMarker[] = {'N', 'L', 'X', 'P', 'A', 'T', 'C', 'H', '0', '1'};
inline constexpr std::size_t kMarkerSize = sizeof(kMarker);

inline constexpr char kBootstrapSymbol[] = "noleax_agent_bootstrap";
inline constexpr char kReadySymbol[] = "noleax_agent_capture_is_ready";

// Immediate slots inside the stub template (verified against the assembly).
inline constexpr std::size_t kFixupSectionRvaOffset = 733U;
inline constexpr std::size_t kFixupEntryRvaOffset = 1041U;

// ror13 hash used by the stub for module and export resolution.
[[nodiscard]] constexpr std::uint32_t ror13(std::uint32_t value) noexcept {
  return (value >> 13U) | (value << 19U);
}

[[nodiscard]] constexpr std::uint32_t export_name_hash(std::string_view name) noexcept {
  std::uint32_t hash = 0U;
  for (const char character : name) {
    hash = ror13(hash) + static_cast<std::uint8_t>(character);
  }
  return hash;
}

[[nodiscard]] constexpr std::uint32_t module_name_hash(std::wstring_view name) noexcept {
  std::uint32_t hash = 0U;
  for (wchar_t character : name) {
    if (character >= L'A' && character <= L'Z') {
      character = static_cast<wchar_t>(character + 0x20U);
    }
    hash = ror13(hash) + static_cast<std::uint16_t>(character);
  }
  return hash;
}

inline constexpr std::uint32_t kKernelbaseHash = module_name_hash(L"kernelbase.dll");
inline constexpr std::uint32_t kNtdllHash = module_name_hash(L"ntdll.dll");
inline constexpr std::uint32_t kLoadLibraryHash = export_name_hash("LoadLibraryW");
inline constexpr std::uint32_t kGetProcAddressHash = export_name_hash("GetProcAddress");
inline constexpr std::uint32_t kSleepHash = export_name_hash("Sleep");
inline constexpr std::uint32_t kVirtualProtectHash = export_name_hash("VirtualProtect");
inline constexpr std::uint32_t kNtFlushInstructionCacheHash =
    export_name_hash("NtFlushInstructionCache");

// x64 position-independent bootstrap stub (1181 bytes), assembled with ml64
// from the reference source in docs/STATIC_PE_PATCH.md.
inline constexpr std::array<std::byte, 1203U> kStaticStub{
    std::byte{0x4C}, std::byte{0x8D}, std::byte{0x25}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49}, std::byte{0x83}, std::byte{0xEC}, std::byte{0x07}, std::byte{0x9C},
    std::byte{0x50}, std::byte{0x53}, std::byte{0x51}, std::byte{0x52}, std::byte{0x56}, std::byte{0x57}, std::byte{0x55}, std::byte{0x41}, std::byte{0x50}, std::byte{0x41}, std::byte{0x51}, std::byte{0x41},
    std::byte{0x52}, std::byte{0x41}, std::byte{0x53}, std::byte{0x41}, std::byte{0x54}, std::byte{0x41}, std::byte{0x55}, std::byte{0x41}, std::byte{0x56}, std::byte{0x41}, std::byte{0x57}, std::byte{0x4C},
    std::byte{0x8B}, std::byte{0xF4}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x84}, std::byte{0x24}, std::byte{0x70}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00},
    std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x8C}, std::byte{0x24}, std::byte{0x80}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41},
    std::byte{0x0F}, std::byte{0x7F}, std::byte{0x94}, std::byte{0x24}, std::byte{0x90}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F},
    std::byte{0x9C}, std::byte{0x24}, std::byte{0xA0}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xA4}, std::byte{0x24},
    std::byte{0xB0}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xAC}, std::byte{0x24}, std::byte{0xC0}, std::byte{0x07},
    std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xB4}, std::byte{0x24}, std::byte{0xD0}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00},
    std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xBC}, std::byte{0x24}, std::byte{0xE0}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45},
    std::byte{0x0F}, std::byte{0x7F}, std::byte{0x84}, std::byte{0x24}, std::byte{0xF0}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F},
    std::byte{0x8C}, std::byte{0x24}, std::byte{0x00}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x94}, std::byte{0x24},
    std::byte{0x10}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0x9C}, std::byte{0x24}, std::byte{0x20}, std::byte{0x08},
    std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xA4}, std::byte{0x24}, std::byte{0x30}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00},
    std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F}, std::byte{0xAC}, std::byte{0x24}, std::byte{0x40}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45},
    std::byte{0x0F}, std::byte{0x7F}, std::byte{0xB4}, std::byte{0x24}, std::byte{0x50}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x7F},
    std::byte{0xBC}, std::byte{0x24}, std::byte{0x60}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0x41}, std::byte{0x0F}, std::byte{0xAE}, std::byte{0x9C}, std::byte{0x24}, std::byte{0x70},
    std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x83}, std::byte{0xE4}, std::byte{0xF0}, std::byte{0x48}, std::byte{0x83}, std::byte{0xEC}, std::byte{0x60}, std::byte{0x65},
    std::byte{0x48}, std::byte{0x8B}, std::byte{0x04}, std::byte{0x25}, std::byte{0x60}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x40}, std::byte{0x18},
    std::byte{0x48}, std::byte{0x8D}, std::byte{0x48}, std::byte{0x10}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x11}, std::byte{0x45}, std::byte{0x33}, std::byte{0xED}, std::byte{0x33}, std::byte{0xED},
    std::byte{0x48}, std::byte{0x3B}, std::byte{0xD1}, std::byte{0x74}, std::byte{0x59}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x72}, std::byte{0x60}, std::byte{0x44}, std::byte{0x0F}, std::byte{0xB7},
    std::byte{0x42}, std::byte{0x58}, std::byte{0x33}, std::byte{0xFF}, std::byte{0x41}, std::byte{0xD1}, std::byte{0xE8}, std::byte{0x74}, std::byte{0x1E}, std::byte{0x0F}, std::byte{0xB7}, std::byte{0x06},
    std::byte{0x48}, std::byte{0x83}, std::byte{0xC6}, std::byte{0x02}, std::byte{0x44}, std::byte{0x8D}, std::byte{0x48}, std::byte{0xBF}, std::byte{0x41}, std::byte{0x83}, std::byte{0xF9}, std::byte{0x1A},
    std::byte{0x73}, std::byte{0x03}, std::byte{0x83}, std::byte{0xC0}, std::byte{0x20}, std::byte{0xC1}, std::byte{0xCF}, std::byte{0x0D}, std::byte{0x03}, std::byte{0xF8}, std::byte{0x41}, std::byte{0xFF},
    std::byte{0xC8}, std::byte{0x75}, std::byte{0xE2}, std::byte{0x41}, std::byte{0x3B}, std::byte{0xBC}, std::byte{0x24}, std::byte{0x30}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0x75},
    std::byte{0x06}, std::byte{0x4C}, std::byte{0x8B}, std::byte{0x6A}, std::byte{0x30}, std::byte{0xEB}, std::byte{0x0E}, std::byte{0x41}, std::byte{0x3B}, std::byte{0xBC}, std::byte{0x24}, std::byte{0x40},
    std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0x75}, std::byte{0x04}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x6A}, std::byte{0x30}, std::byte{0x48}, std::byte{0x8B}, std::byte{0x12},
    std::byte{0x4D}, std::byte{0x85}, std::byte{0xED}, std::byte{0x74}, std::byte{0xA7}, std::byte{0x48}, std::byte{0x85}, std::byte{0xED}, std::byte{0x74}, std::byte{0xA2}, std::byte{0x4D}, std::byte{0x85},
    std::byte{0xED}, std::byte{0x0F}, std::byte{0x84}, std::byte{0x4A}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x85}, std::byte{0xED}, std::byte{0x0F}, std::byte{0x84},
    std::byte{0x41}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49}, std::byte{0x89}, std::byte{0xAC}, std::byte{0x24}, std::byte{0x78}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x49}, std::byte{0x8B}, std::byte{0xDD}, std::byte{0x41}, std::byte{0x8B}, std::byte{0xBC}, std::byte{0x24}, std::byte{0x44}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xE8},
    std::byte{0xBE}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x85}, std::byte{0xC0}, std::byte{0x0F}, std::byte{0x84}, std::byte{0x2A}, std::byte{0x01}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x49}, std::byte{0x89}, std::byte{0x84}, std::byte{0x24}, std::byte{0x80}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x8B}, std::byte{0xDD},
    std::byte{0x41}, std::byte{0x8B}, std::byte{0xBC}, std::byte{0x24}, std::byte{0x48}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xE8}, std::byte{0x9D}, std::byte{0x02}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x48}, std::byte{0x85}, std::byte{0xC0}, std::byte{0x0F}, std::byte{0x84}, std::byte{0x09}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49}, std::byte{0x89},
    std::byte{0x84}, std::byte{0x24}, std::byte{0x60}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0x41}, std::byte{0x81}, std::byte{0xBC}, std::byte{0x24}, std::byte{0x00}, std::byte{0x05},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x20}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x0F}, std::byte{0x85}, std::byte{0xDE}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x41}, std::byte{0x83}, std::byte{0xBC}, std::byte{0x24}, std::byte{0x04}, std::byte{0x05}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x0F}, std::byte{0x85}, std::byte{0xCF},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x66}, std::byte{0x41}, std::byte{0x83}, std::byte{0xBC}, std::byte{0x24}, std::byte{0x08}, std::byte{0x05}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x0F}, std::byte{0x84}, std::byte{0xBF}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49}, std::byte{0x8B}, std::byte{0xDD}, std::byte{0x41}, std::byte{0x8B},
    std::byte{0xBC}, std::byte{0x24}, std::byte{0x34}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xE8}, std::byte{0x4B}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48},
    std::byte{0x85}, std::byte{0xC0}, std::byte{0x0F}, std::byte{0x84}, std::byte{0xC1}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x4C}, std::byte{0x8B}, std::byte{0xF8}, std::byte{0x49},
    std::byte{0x8B}, std::byte{0xDD}, std::byte{0x41}, std::byte{0x8B}, std::byte{0xBC}, std::byte{0x24}, std::byte{0x38}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xE8}, std::byte{0x2F},
    std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x85}, std::byte{0xC0}, std::byte{0x0F}, std::byte{0x84}, std::byte{0xA5}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x48}, std::byte{0x8B}, std::byte{0xE8}, std::byte{0x49}, std::byte{0x8B}, std::byte{0xDD}, std::byte{0x41}, std::byte{0x8B}, std::byte{0xBC}, std::byte{0x24}, std::byte{0x3C}, std::byte{0x07},
    std::byte{0x00}, std::byte{0x00}, std::byte{0xE8}, std::byte{0x13}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x85}, std::byte{0xC0}, std::byte{0x0F}, std::byte{0x84},
    std::byte{0x89}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x4C}, std::byte{0x8B}, std::byte{0xE8}, std::byte{0x49}, std::byte{0x8D}, std::byte{0x8C}, std::byte{0x24}, std::byte{0x30},
    std::byte{0x06}, std::byte{0x00}, std::byte{0x00}, std::byte{0x41}, std::byte{0xFF}, std::byte{0xD7}, std::byte{0x48}, std::byte{0x85}, std::byte{0xC0}, std::byte{0x74}, std::byte{0x7D}, std::byte{0x4C},
    std::byte{0x8B}, std::byte{0xF8}, std::byte{0x49}, std::byte{0x8B}, std::byte{0xCF}, std::byte{0x49}, std::byte{0x8D}, std::byte{0x94}, std::byte{0x24}, std::byte{0xB0}, std::byte{0x06}, std::byte{0x00},
    std::byte{0x00}, std::byte{0xFF}, std::byte{0xD5}, std::byte{0x48}, std::byte{0x85}, std::byte{0xC0}, std::byte{0x74}, std::byte{0x6F}, std::byte{0x49}, std::byte{0x8D}, std::byte{0x8C}, std::byte{0x24},
    std::byte{0x00}, std::byte{0x05}, std::byte{0x00}, std::byte{0x00}, std::byte{0xFF}, std::byte{0xD0}, std::byte{0x85}, std::byte{0xC0}, std::byte{0x75}, std::byte{0x68}, std::byte{0x49}, std::byte{0x8B},
    std::byte{0xCF}, std::byte{0x49}, std::byte{0x8D}, std::byte{0x94}, std::byte{0x24}, std::byte{0xF0}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00}, std::byte{0xFF}, std::byte{0xD5}, std::byte{0x48},
    std::byte{0x85}, std::byte{0xC0}, std::byte{0x74}, std::byte{0x4F}, std::byte{0x4C}, std::byte{0x8B}, std::byte{0xF8}, std::byte{0xBB}, std::byte{0xE8}, std::byte{0x03}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x41}, std::byte{0xFF}, std::byte{0xD7}, std::byte{0x84}, std::byte{0xC0}, std::byte{0x75}, std::byte{0x13}, std::byte{0xB9}, std::byte{0x0A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x41}, std::byte{0xFF}, std::byte{0xD5}, std::byte{0xFF}, std::byte{0xCB}, std::byte{0x75}, std::byte{0xED}, std::byte{0xB8}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0xEB}, std::byte{0x39}, std::byte{0x33}, std::byte{0xC0}, std::byte{0xEB}, std::byte{0x35}, std::byte{0xB8}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xEB},
    std::byte{0x2E}, std::byte{0xB8}, std::byte{0x02}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xE9}, std::byte{0xAC}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xB8},
    std::byte{0x03}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xE9}, std::byte{0xA2}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xB8}, std::byte{0x03}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x00}, std::byte{0xEB}, std::byte{0x13}, std::byte{0xB8}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xEB}, std::byte{0x0C}, std::byte{0xB8},
    std::byte{0x05}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xEB}, std::byte{0x05}, std::byte{0xB8}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x41},
    std::byte{0x89}, std::byte{0x84}, std::byte{0x24}, std::byte{0x4C}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0x49}, std::byte{0x8B}, std::byte{0xDC}, std::byte{0x48}, std::byte{0x81},
    std::byte{0xEB}, std::byte{0x11}, std::byte{0x11}, std::byte{0x11}, std::byte{0x11}, std::byte{0x48}, std::byte{0x8B}, std::byte{0xEB}, std::byte{0x49}, std::byte{0x03}, std::byte{0xAC}, std::byte{0x24},
    std::byte{0x68}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x8B}, std::byte{0xCD}, std::byte{0xBA}, std::byte{0x05}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x41}, std::byte{0xB8}, std::byte{0x40}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x4D}, std::byte{0x8D}, std::byte{0x8C}, std::byte{0x24}, std::byte{0x58}, std::byte{0x07},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x41}, std::byte{0xFF}, std::byte{0x94}, std::byte{0x24}, std::byte{0x80}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0xFC}, std::byte{0x48},
    std::byte{0x8B}, std::byte{0xFD}, std::byte{0x49}, std::byte{0x8D}, std::byte{0xB4}, std::byte{0x24}, std::byte{0x50}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xB9}, std::byte{0x05},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0xA4}, std::byte{0x48}, std::byte{0x8B}, std::byte{0xCD}, std::byte{0xBA}, std::byte{0x05}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x45}, std::byte{0x8B}, std::byte{0x84}, std::byte{0x24}, std::byte{0x58}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0x4D}, std::byte{0x8D}, std::byte{0x8C},
    std::byte{0x24}, std::byte{0x58}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0x41}, std::byte{0xFF}, std::byte{0x94}, std::byte{0x24}, std::byte{0x80}, std::byte{0x08}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x48}, std::byte{0xC7}, std::byte{0xC1}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0x48}, std::byte{0x8B}, std::byte{0xD5}, std::byte{0x41},
    std::byte{0xB8}, std::byte{0x05}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x41}, std::byte{0xFF}, std::byte{0x94}, std::byte{0x24}, std::byte{0x60}, std::byte{0x07}, std::byte{0x00},
    std::byte{0x00}, std::byte{0xEB}, std::byte{0x0C}, std::byte{0x41}, std::byte{0x89}, std::byte{0x84}, std::byte{0x24}, std::byte{0x4C}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3},
    std::byte{0x90}, std::byte{0xEB}, std::byte{0xFC}, std::byte{0x41}, std::byte{0x0F}, std::byte{0xAE}, std::byte{0x94}, std::byte{0x24}, std::byte{0x70}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00},
    std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x84}, std::byte{0x24}, std::byte{0x70}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41},
    std::byte{0x0F}, std::byte{0x6F}, std::byte{0x8C}, std::byte{0x24}, std::byte{0x80}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F},
    std::byte{0x94}, std::byte{0x24}, std::byte{0x90}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x9C}, std::byte{0x24},
    std::byte{0xA0}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xA4}, std::byte{0x24}, std::byte{0xB0}, std::byte{0x07},
    std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xAC}, std::byte{0x24}, std::byte{0xC0}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00},
    std::byte{0xF3}, std::byte{0x41}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xB4}, std::byte{0x24}, std::byte{0xD0}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x41},
    std::byte{0x0F}, std::byte{0x6F}, std::byte{0xBC}, std::byte{0x24}, std::byte{0xE0}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F},
    std::byte{0x84}, std::byte{0x24}, std::byte{0xF0}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x8C}, std::byte{0x24},
    std::byte{0x00}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x94}, std::byte{0x24}, std::byte{0x10}, std::byte{0x08},
    std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0x9C}, std::byte{0x24}, std::byte{0x20}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00},
    std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xA4}, std::byte{0x24}, std::byte{0x30}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45},
    std::byte{0x0F}, std::byte{0x6F}, std::byte{0xAC}, std::byte{0x24}, std::byte{0x40}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F},
    std::byte{0xB4}, std::byte{0x24}, std::byte{0x50}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0xF3}, std::byte{0x45}, std::byte{0x0F}, std::byte{0x6F}, std::byte{0xBC}, std::byte{0x24},
    std::byte{0x60}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0x48}, std::byte{0x8B}, std::byte{0xC3}, std::byte{0x48}, std::byte{0x05}, std::byte{0x22}, std::byte{0x22}, std::byte{0x22},
    std::byte{0x22}, std::byte{0x49}, std::byte{0x87}, std::byte{0x46}, std::byte{0x70}, std::byte{0x49}, std::byte{0x8B}, std::byte{0xE6}, std::byte{0x41}, std::byte{0x5F}, std::byte{0x41}, std::byte{0x5E},
    std::byte{0x41}, std::byte{0x5D}, std::byte{0x41}, std::byte{0x5C}, std::byte{0x41}, std::byte{0x5B}, std::byte{0x41}, std::byte{0x5A}, std::byte{0x41}, std::byte{0x59}, std::byte{0x41}, std::byte{0x58},
    std::byte{0x5D}, std::byte{0x5F}, std::byte{0x5E}, std::byte{0x5A}, std::byte{0x59}, std::byte{0x5B}, std::byte{0x58}, std::byte{0x9D}, std::byte{0xFF}, std::byte{0xE0}, std::byte{0x8B}, std::byte{0x43},
    std::byte{0x3C}, std::byte{0x4C}, std::byte{0x8D}, std::byte{0x04}, std::byte{0x03}, std::byte{0x41}, std::byte{0x8B}, std::byte{0x80}, std::byte{0x88}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x85}, std::byte{0xC0}, std::byte{0x74}, std::byte{0x68}, std::byte{0x4C}, std::byte{0x8D}, std::byte{0x0C}, std::byte{0x03}, std::byte{0x45}, std::byte{0x8B}, std::byte{0x51}, std::byte{0x18},
    std::byte{0x45}, std::byte{0x8B}, std::byte{0x59}, std::byte{0x20}, std::byte{0x4E}, std::byte{0x8D}, std::byte{0x1C}, std::byte{0x1B}, std::byte{0x33}, std::byte{0xC9}, std::byte{0x41}, std::byte{0x3B},
    std::byte{0xCA}, std::byte{0x73}, std::byte{0x51}, std::byte{0x41}, std::byte{0x8B}, std::byte{0x34}, std::byte{0x8B}, std::byte{0x48}, std::byte{0x8D}, std::byte{0x34}, std::byte{0x33}, std::byte{0x33},
    std::byte{0xD2}, std::byte{0x0F}, std::byte{0xB6}, std::byte{0x06}, std::byte{0x84}, std::byte{0xC0}, std::byte{0x74}, std::byte{0x0A}, std::byte{0xC1}, std::byte{0xCA}, std::byte{0x0D}, std::byte{0x03},
    std::byte{0xD0}, std::byte{0x48}, std::byte{0xFF}, std::byte{0xC6}, std::byte{0xEB}, std::byte{0xEF}, std::byte{0x3B}, std::byte{0xD7}, std::byte{0x74}, std::byte{0x04}, std::byte{0xFF}, std::byte{0xC1},
    std::byte{0xEB}, std::byte{0xD8}, std::byte{0x41}, std::byte{0x8B}, std::byte{0x41}, std::byte{0x24}, std::byte{0x48}, std::byte{0x8D}, std::byte{0x04}, std::byte{0x03}, std::byte{0x0F}, std::byte{0xB7},
    std::byte{0x0C}, std::byte{0x48}, std::byte{0x41}, std::byte{0x8B}, std::byte{0x41}, std::byte{0x1C}, std::byte{0x48}, std::byte{0x8D}, std::byte{0x04}, std::byte{0x03}, std::byte{0x8B}, std::byte{0x04},
    std::byte{0x88}, std::byte{0x8B}, std::byte{0xD0}, std::byte{0x41}, std::byte{0x2B}, std::byte{0x90}, std::byte{0x88}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x41}, std::byte{0x3B},
    std::byte{0x90}, std::byte{0x8C}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x72}, std::byte{0x05}, std::byte{0x48}, std::byte{0x8D}, std::byte{0x04}, std::byte{0x03}, std::byte{0xC3},
    std::byte{0x33}, std::byte{0xC0}, std::byte{0xC3},
};

static_assert(kFixupSectionRvaOffset + sizeof(std::uint32_t) <= kStaticStub.size());
static_assert(kFixupEntryRvaOffset + sizeof(std::uint32_t) <= kStaticStub.size());
static_assert(kStaticStub.size() <= kParamsOffset);
static_assert(kParamsOffset + sizeof(noleax::agent::windows::BootstrapParameters) <= kMarkerOffset);

}  // namespace noleax::controller::windows::pepatch
