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
  for (const wchar_t character : std::wstring_view{value}) {
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

[[nodiscard]] bool capture_ready() noexcept {
  const HMODULE agent = GetModuleHandleW(L"noleax-agent.dll");
  if (agent == nullptr) {
    return false;
  }
  const auto function =
      reinterpret_cast<CaptureIsReady>(GetProcAddress(agent, "noleax_agent_capture_is_ready"));
  return function != nullptr && function();
}

[[nodiscard]] bool write_marker(const wchar_t* path, bool ready) noexcept {
  const HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  std::array<char, 128U> text{};
  const int length =
      std::snprintf(text.data(), text.size(), "pid=%lu ready=%u size=123457\n",
                    static_cast<unsigned long>(GetCurrentProcessId()), ready ? 1U : 0U);
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
  if (argc != 4) {
    return 2;
  }
  const std::uint32_t duration_ms = parse_duration(argv[2]);
  if (duration_ms == 0U) {
    return 3;
  }
  const bool attach_mode = std::wstring_view{argv[3]} == L"attach";
  if (!attach_mode && std::wstring_view{argv[3]} != L"launch") {
    return 4;
  }

  const HANDLE heap = GetProcessHeap();
  void* preexisting = attach_mode ? HeapAlloc(heap, 0U, 654'321U) : nullptr;
  bool ready = capture_ready();
  if (!write_marker(argv[1], ready)) {
    return 5;
  }
  const ULONGLONG deadline = GetTickCount64() + duration_ms;
  while (!ready && GetTickCount64() < deadline) {
    Sleep(1U);
    ready = capture_ready();
  }

  void* outstanding = nullptr;
  if (ready) {
    outstanding = HeapAlloc(heap, 0U, 123'457U);
    if (outstanding == nullptr || !write_marker(argv[1], true)) {
      return 6;
    }
  }
  while (GetTickCount64() < deadline) {
    void* transient = HeapAlloc(heap, 0U, 64U);
    if (transient != nullptr) {
      static_cast<void>(HeapFree(heap, 0U, transient));
    }
    Sleep(25U);
  }
  if (outstanding != nullptr) {
    static_cast<void>(HeapFree(heap, 0U, outstanding));
  }
  if (preexisting != nullptr) {
    static_cast<void>(HeapFree(heap, 0U, preexisting));
  }
  return ready ? 0 : 7;
}
