// Deterministic multi-threaded register workload target for thread-hijack
// context-restore tests.
//
// Usage: register_workload_target <digest-path> <iterations> [started-marker]
//
// Spawns four worker threads that run an assembly loop holding sentinels in
// every non-volatile GPR and XMM6-XMM15; any clobber (for example a botched
// hijack context restore) flips a per-thread error flag. The main thread
// additionally churns the heap so an attached capture observes events. The
// final FNV-1a digest over all thread results and error flags is written to
// <digest-path>; identical runs must produce identical digests whether or not
// an injection happened in between.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>

extern "C" std::uint64_t noleax_register_workload(std::uint64_t seed, std::uint32_t iterations,
                                                  std::uint32_t* error_flag);

namespace {

constexpr std::size_t kWorkerCount = 4U;
std::wstring g_crash_path;

[[nodiscard]] bool write_text(const wchar_t* path, const std::string& text) noexcept {
  const HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  DWORD written = 0U;
  const bool success =
      WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) != FALSE &&
      written == text.size();
  static_cast<void>(CloseHandle(file));
  return success;
}

LONG WINAPI crash_reporter(EXCEPTION_POINTERS* info) noexcept {
  if (info != nullptr && info->ExceptionRecord != nullptr && info->ContextRecord != nullptr) {
    char buffer[256];
    const int length =
        std::snprintf(buffer, sizeof(buffer),
                      "code=%08lx address=%p rip=%llx rcx=%llx r12=%llx rsp=%llx r8=%llx r9=%llx\n",
                      info->ExceptionRecord->ExceptionCode, info->ExceptionRecord->ExceptionAddress,
                      info->ContextRecord->Rip, info->ContextRecord->Rcx, info->ContextRecord->R12,
                      info->ContextRecord->Rsp, info->ContextRecord->R8, info->ContextRecord->R9);
    if (length > 0) {
      static_cast<void>(write_text(g_crash_path.c_str(), std::string{buffer, buffer + length}));
    }
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (argc < 3 || argc > 4) {
    return 2;
  }
  const std::uint32_t iterations = static_cast<std::uint32_t>(std::wcstoul(argv[2], nullptr, 10));
  if (iterations == 0U) {
    return 3;
  }
  g_crash_path = std::wstring{argv[1]} + L".crash";
  static_cast<void>(SetUnhandledExceptionFilter(&crash_reporter));

  std::array<std::uint64_t, kWorkerCount> results{};
  std::array<std::uint32_t, kWorkerCount> errors{};
  std::atomic<std::uint32_t> finished{0U};
  {
    std::array<std::thread, kWorkerCount> workers;
    for (std::size_t index = 0U; index < kWorkerCount; ++index) {
      workers[index] = std::thread{[index, iterations, &results, &errors, &finished] {
        results[index] = noleax_register_workload(0x9E3779B97F4A7C15ULL * (index + 1U), iterations,
                                                  &errors[index]);
        finished.fetch_add(1U, std::memory_order_release);
      }};
    }
    if (argc == 4 && !write_text(argv[3], "started=1\n")) {
      return 4;
    }
    const HANDLE heap = GetProcessHeap();
    while (finished.load(std::memory_order_acquire) != kWorkerCount) {
      void* allocation = HeapAlloc(heap, 0U, 48U * 1024U);
      if (allocation != nullptr) {
        allocation = HeapReAlloc(heap, 0U, allocation, 64U * 1024U);
        if (allocation != nullptr) {
          static_cast<void>(HeapFree(heap, 0U, allocation));
        }
      }
      void* pages = VirtualAlloc(nullptr, 64U * 1024U, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
      if (pages != nullptr) {
        static_cast<void>(VirtualFree(pages, 0U, MEM_RELEASE));
      }
      Sleep(1U);
    }
    for (auto& worker : workers) {
      worker.join();
    }
  }

  std::uint64_t digest = 1469598103934665603ULL;  // FNV-1a 64 offset basis
  const auto fold = [&digest](std::uint64_t value) {
    for (unsigned int shift = 0U; shift < 64U; shift += 8U) {
      digest ^= (value >> shift) & 0xFFU;
      digest *= 1099511628211ULL;
    }
  };
  for (std::size_t index = 0U; index < kWorkerCount; ++index) {
    fold(results[index]);
    fold(errors[index]);
  }

  std::array<char, 64U> text{};
  const int length = std::snprintf(text.data(), text.size(), "digest=%016llx\n",
                                   static_cast<unsigned long long>(digest));
  if (length <= 0 || !write_text(argv[1], std::string{text.data(), text.data() + length})) {
    return 5;
  }
  for (const std::uint32_t error : errors) {
    if (error != 0U) {
      return 6;  // a non-volatile register was clobbered during the run
    }
  }
  return 0;
}
