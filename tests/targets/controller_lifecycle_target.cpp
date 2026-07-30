#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <limits>
#include <string>
#include <thread>
#include <vector>

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

[[nodiscard]] bool write_marker(const wchar_t* path, bool ready) noexcept {
  const HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  std::array<char, 128U> text{};
  const int length =
      std::snprintf(text.data(), text.size(), "ready=%u threads=8\n", ready ? 1U : 0U);
  DWORD written = 0U;
  const bool success =
      length > 0 && static_cast<std::size_t>(length) < text.size() &&
      WriteFile(file, text.data(), static_cast<DWORD>(length), &written, nullptr) != FALSE &&
      written == static_cast<DWORD>(length);
  static_cast<void>(CloseHandle(file));
  return success;
}

void allocation_worker(ULONGLONG deadline, std::uint32_t worker_id,
                       const std::atomic<bool>& stop_requested) noexcept {
  const HANDLE heap = GetProcessHeap();
  std::uint64_t iteration = worker_id;
  while (!stop_requested.load(std::memory_order_relaxed) && GetTickCount64() < deadline) {
    const SIZE_T size = 64U + static_cast<SIZE_T>(iteration % 4096U);
    void* allocation = HeapAlloc(heap, 0U, size);
    if (allocation != nullptr) {
      void* resized = HeapReAlloc(heap, 0U, allocation, size + 128U);
      if (resized != nullptr) {
        allocation = resized;
      }
      static_cast<void>(HeapFree(heap, 0U, allocation));
    }
    if ((iteration & 0x3ffU) == 0U) {
      void* pages = VirtualAlloc(nullptr, 64U * 1024U, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
      if (pages != nullptr) {
        static_cast<void>(VirtualFree(pages, 0U, MEM_RELEASE));
      }
    }
    ++iteration;
  }
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
  const HMODULE agent = GetModuleHandleW(L"noleax-agent.dll");
  const auto is_ready = agent == nullptr ? nullptr
                                         : reinterpret_cast<CaptureIsReady>(GetProcAddress(
                                               agent, "noleax_agent_capture_is_ready"));
  const bool ready = is_ready != nullptr && is_ready();
  const ULONGLONG deadline = GetTickCount64() + duration_ms;
  std::atomic<bool> stop_requested{false};
  std::vector<std::thread> workers;
  workers.reserve(8U);
  for (std::uint32_t index = 0U; index < 8U; ++index) {
    workers.emplace_back(&allocation_worker, deadline, index, std::cref(stop_requested));
  }
  const bool marker_written = write_marker(argv[1], ready);
  while (GetTickCount64() < deadline && GetFileAttributesW(argv[3]) == INVALID_FILE_ATTRIBUTES) {
    Sleep(1U);
  }
  stop_requested.store(true, std::memory_order_relaxed);
  for (auto& worker : workers) {
    worker.join();
  }
  if (!marker_written) {
    return 4;
  }
  return ready ? 0 : 5;
}
