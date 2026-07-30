#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using CaptureIsReady = bool (*)() noexcept;

[[nodiscard]] bool capture_ready() noexcept {
  const HMODULE agent = GetModuleHandleW(L"noleax-agent.dll");
  if (agent == nullptr) {
    return false;
  }
  const auto function =
      reinterpret_cast<CaptureIsReady>(GetProcAddress(agent, "noleax_agent_capture_is_ready"));
  return function != nullptr && function();
}

[[nodiscard]] bool wait_for_capture(bool expected, std::chrono::seconds timeout) noexcept {
  const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout.count() * 1000);
  do {
    if (capture_ready() == expected) {
      return true;
    }
    Sleep(1U);
  } while (GetTickCount64() < deadline);
  return capture_ready() == expected;
}

template <typename Integer>
[[nodiscard]] bool parse_integer(std::wstring_view text, Integer minimum, Integer maximum,
                                 Integer& output) noexcept {
  Integer value{};
  if (text.empty()) {
    return false;
  }
  for (const wchar_t character : text) {
    if (character < L'0' || character > L'9') {
      return false;
    }
    const Integer digit = static_cast<Integer>(character - L'0');
    if (value > (maximum - digit) / 10U) {
      return false;
    }
    value = value * 10U + digit;
  }
  if (value < minimum) {
    return false;
  }
  output = value;
  return true;
}

struct ThreadResult {
  std::uint64_t checksum{0U};
  std::uint64_t requested_bytes{0U};
};

void run_workload(std::uint32_t thread_index, std::uint64_t iterations, ThreadResult& result,
                  std::atomic<bool>& failed) noexcept {
  const HANDLE heap = GetProcessHeap();
  std::uint64_t checksum = 14'695'981'039'346'656'037ULL ^ thread_index;
  std::uint64_t requested_bytes = 0U;
  for (std::uint64_t iteration = 0U; iteration < iterations; ++iteration) {
    const std::size_t size = static_cast<std::size_t>(
        32U + ((iteration * 131U + static_cast<std::uint64_t>(thread_index) * 977U) % 4'064U));
    auto* memory = static_cast<std::byte*>(HeapAlloc(heap, 0U, size));
    if (memory == nullptr) {
      failed.store(true, std::memory_order_relaxed);
      return;
    }
    requested_bytes += size;
    const std::size_t touched = (std::min)(size, std::size_t{256U});
    std::memset(memory, static_cast<int>((iteration + thread_index) & 0xffU), touched);
    memory[size - 1U] = static_cast<std::byte>((iteration >> 8U) & 0xffU);

    std::size_t final_size = size;
    if ((iteration & 3U) == 0U) {
      final_size = size + 97U;
      auto* replacement = static_cast<std::byte*>(HeapReAlloc(heap, 0U, memory, final_size));
      if (replacement == nullptr) {
        static_cast<void>(HeapFree(heap, 0U, memory));
        failed.store(true, std::memory_order_relaxed);
        return;
      }
      memory = replacement;
      requested_bytes += final_size;
      memory[final_size - 1U] = static_cast<std::byte>((iteration >> 8U) & 0xffU);
    }

    checksum ^= static_cast<std::uint64_t>(memory[0]);
    checksum *= 1'099'511'628'211ULL;
    checksum ^= static_cast<std::uint64_t>(memory[final_size - 1U]);
    if (HeapFree(heap, 0U, memory) == FALSE) {
      failed.store(true, std::memory_order_relaxed);
      return;
    }
  }
  result.checksum = checksum;
  result.requested_bytes = requested_bytes;
}

[[nodiscard]] bool write_report(const wchar_t* path, std::uint32_t threads,
                                std::uint64_t iterations, std::uint64_t elapsed_nanoseconds,
                                std::uint64_t checksum, std::uint64_t requested_bytes,
                                bool captured, bool capture_alive_at_end) {
  std::ofstream output{path, std::ios::binary | std::ios::trunc};
  if (!output) {
    return false;
  }
  const std::uint64_t reallocations_per_thread = (iterations + 3U) / 4U;
  const std::uint64_t operations =
      static_cast<std::uint64_t>(threads) * (iterations * 2U + reallocations_per_thread);
  output << "{\"schemaVersion\":1,\"status\":\"ok\",\"threads\":" << threads
         << ",\"iterationsPerThread\":" << iterations << ",\"operations\":" << operations
         << ",\"requestedBytes\":" << requested_bytes
         << ",\"elapsedNanoseconds\":" << elapsed_nanoseconds << ",\"checksum\":\"" << checksum
         << "\",\"captured\":" << (captured ? "true" : "false")
         << ",\"captureAliveAtEnd\":" << (capture_alive_at_end ? "true" : "false") << "}\n";
  return static_cast<bool>(output);
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (argc != 5) {
    return 2;
  }
  std::uint32_t threads = 0U;
  std::uint64_t iterations = 0U;
  if (!parse_integer<std::uint32_t>(argv[2], 1U, 64U, threads) ||
      !parse_integer<std::uint64_t>(argv[3], 1U, 10'000'000U, iterations)) {
    return 3;
  }
  const std::wstring_view mode{argv[4]};
  const bool captured = mode == L"captured";
  if (!captured && mode != L"baseline") {
    return 4;
  }
  if (captured && !wait_for_capture(true, std::chrono::seconds{15})) {
    return 5;
  }

  std::vector<ThreadResult> results(threads);
  std::vector<std::thread> workers;
  workers.reserve(threads);
  std::atomic<bool> failed{false};
  const auto started = std::chrono::steady_clock::now();
  for (std::uint32_t thread = 0U; thread < threads; ++thread) {
    workers.emplace_back(run_workload, thread, iterations, std::ref(results[thread]),
                         std::ref(failed));
  }
  for (auto& worker : workers) {
    worker.join();
  }
  const auto finished = std::chrono::steady_clock::now();
  const bool capture_alive_at_end = capture_ready();
  if (failed.load(std::memory_order_relaxed) || (captured && !capture_alive_at_end)) {
    return 6;
  }

  std::uint64_t checksum = 0U;
  std::uint64_t requested_bytes = 0U;
  for (const auto& result : results) {
    checksum ^= result.checksum;
    requested_bytes += result.requested_bytes;
  }
  const auto elapsed =
      std::chrono::duration_cast<std::chrono::nanoseconds>(finished - started).count();
  if (elapsed < 0 ||
      !write_report(argv[1], threads, iterations, static_cast<std::uint64_t>(elapsed), checksum,
                    requested_bytes, captured, capture_alive_at_end)) {
    return 7;
  }

  if (captured && !wait_for_capture(false, std::chrono::seconds{60})) {
    return 8;
  }
  if (captured) {
    // The agent clears readiness before it finishes writer drain and sends the stop reply.
    // Keep the process alive long enough for that control-plane handshake to complete.
    Sleep(1'000U);
  }
  return 0;
}
