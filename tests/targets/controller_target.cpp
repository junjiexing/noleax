#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <string_view>

namespace {

using CaptureIsReady = bool (*)() noexcept;

[[nodiscard]] std::uint32_t parse_duration(const wchar_t* value) noexcept {
  if (value == nullptr) {
    return 0U;
  }
  std::uint32_t result = 0U;
  const std::wstring text{value};
  for (const wchar_t character : text) {
    if (character < L'0' || character > L'9' ||
        result > (std::numeric_limits<std::uint32_t>::max() -
                  static_cast<std::uint32_t>(character - L'0')) /
                     10U) {
      return 0U;
    }
    result = result * 10U + static_cast<std::uint32_t>(character - L'0');
  }
  return result;
}

[[nodiscard]] bool write_marker(const wchar_t* path, bool capture_ready) noexcept {
  const HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  std::array<char, 128U> text{};
  const int length =
      std::snprintf(text.data(), text.size(), "pid=%lu ready=%u\n",
                    static_cast<unsigned long>(GetCurrentProcessId()), capture_ready ? 1U : 0U);
  DWORD written = 0U;
  const bool success =
      length > 0 && static_cast<std::size_t>(length) < text.size() &&
      WriteFile(file, text.data(), static_cast<DWORD>(length), &written, nullptr) != FALSE &&
      written == static_cast<DWORD>(length);
  static_cast<void>(CloseHandle(file));
  return success;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (argc != 3 && argc != 4) {
    return 2;
  }
  const std::uint32_t duration_ms = parse_duration(argv[2]);
  if (duration_ms == 0U) {
    return 3;
  }
  const bool expected_ready = argc == 3 || std::wstring_view{argv[3]} == L"1";
  const HMODULE agent = GetModuleHandleW(L"noleax-agent.dll");
  const auto is_ready = agent == nullptr ? nullptr
                                         : reinterpret_cast<CaptureIsReady>(GetProcAddress(
                                               agent, "noleax_agent_capture_is_ready"));
  const bool ready = is_ready != nullptr && is_ready();
  const HANDLE heap = GetProcessHeap();
  void* outstanding = HeapAlloc(heap, 0U, 128U * 1024U);
  if (!write_marker(argv[1], ready)) {
    if (outstanding != nullptr) {
      static_cast<void>(HeapFree(heap, 0U, outstanding));
    }
    return 4;
  }

  const ULONGLONG deadline = GetTickCount64() + duration_ms;
  std::uint64_t iteration = 0U;
  while (GetTickCount64() < deadline) {
    const SIZE_T size = 64U * 1024U + static_cast<SIZE_T>(iteration % 1024U);
    void* allocation = HeapAlloc(heap, 0U, size);
    if (allocation != nullptr) {
      allocation = HeapReAlloc(heap, 0U, allocation, size + 4096U);
      if (allocation != nullptr) {
        static_cast<void>(HeapFree(heap, 0U, allocation));
      }
    }
    void* pages = VirtualAlloc(nullptr, 128U * 1024U, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (pages != nullptr) {
      static_cast<void>(VirtualFree(pages, 0U, MEM_RELEASE));
    }
    ++iteration;
    Sleep(1U);
  }
  if (outstanding != nullptr) {
    static_cast<void>(HeapFree(heap, 0U, outstanding));
  }
  return ready == expected_ready ? 0 : 5;
}
