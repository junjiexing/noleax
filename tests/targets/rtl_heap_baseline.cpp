#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

namespace {

using RtlAllocateHeapFunction = PVOID(NTAPI*)(PVOID heap, ULONG flags, SIZE_T size);
using RtlFreeHeapFunction = BOOLEAN(NTAPI*)(PVOID heap, ULONG flags, PVOID allocation);

constexpr std::uint32_t kMaximumThreads = 64U;
constexpr std::uint32_t kMaximumIterations = 1'000'000U;
constexpr std::uint32_t kMaximumRounds = 100U;
constexpr std::size_t kBatchSize = 32U;
constexpr std::uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

struct Options {
  std::uint32_t threads{8U};
  std::uint32_t iterations{20'000U};
  std::uint32_t rounds{2U};
  std::uint64_t seed{0x4e4f4c4541585034ULL};
};

enum class ParseResult : std::uint8_t {
  kSuccess,
  kHelp,
  kError,
};

enum class AllocationApi : std::uint8_t {
  kRtl,
  kWin32,
  kCrt,
};

struct NativeFunctions {
  RtlAllocateHeapFunction allocate{nullptr};
  RtlFreeHeapFunction free{nullptr};
};

struct Summary {
  std::uint64_t allocation_attempts{0U};
  std::uint64_t rtl_attempts{0U};
  std::uint64_t win32_attempts{0U};
  std::uint64_t crt_attempts{0U};
  std::uint64_t successful_allocations{0U};
  std::uint64_t expected_failures{0U};
  std::uint64_t frees{0U};
  std::uint64_t requested_bytes{0U};
  std::uint64_t zero_size_attempts{0U};
  std::uint64_t zero_verified_bytes{0U};
  std::uint64_t payload_verified_bytes{0U};
  std::uint64_t process_heap_attempts{0U};
  std::uint64_t explicit_heap_attempts{0U};
  std::uint64_t rtl_last_error_changes{0U};
  std::uint64_t win32_last_error_changes{0U};
  std::uint64_t rtl_last_error_hash{kFnvOffsetBasis};
  std::uint64_t win32_last_error_hash{kFnvOffsetBasis};
  std::uint64_t checksum{kFnvOffsetBasis};

  bool operator==(const Summary&) const = default;
};

struct WorkerResult {
  Summary summary;
  std::uint32_t failure_code{0U};
};

struct Block {
  PVOID allocation{nullptr};
  PVOID heap{nullptr};
  std::size_t size{0U};
  std::uint64_t token{0U};
  AllocationApi api{AllocationApi::kRtl};
};

[[nodiscard]] std::uint64_t splitmix64(std::uint64_t value) noexcept {
  value += 0x9e3779b97f4a7c15ULL;
  value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31U);
}

[[nodiscard]] std::uint64_t mix_hash(std::uint64_t hash, std::uint64_t value) noexcept {
  for (std::uint32_t index = 0U; index < 8U; ++index) {
    hash ^= (value >> (index * 8U)) & 0xffU;
    hash *= kFnvPrime;
  }
  return hash;
}

[[nodiscard]] std::uint8_t payload_byte(std::uint64_t token, std::size_t offset) noexcept {
  const auto offset_value = static_cast<std::uint64_t>(offset);
  return static_cast<std::uint8_t>(splitmix64(token + offset_value * 0x9e3779b97f4a7c15ULL));
}

[[nodiscard]] bool parse_unsigned(std::string_view text, std::uint64_t& result) noexcept {
  if (text.empty()) {
    return false;
  }
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result, 10);
  return error == std::errc{} && end == text.data() + text.size();
}

[[nodiscard]] bool parse_bounded(std::string_view text, std::uint32_t maximum,
                                 std::uint32_t& result) noexcept {
  std::uint64_t parsed = 0U;
  if (!parse_unsigned(text, parsed) || parsed == 0U || parsed > maximum) {
    return false;
  }
  result = static_cast<std::uint32_t>(parsed);
  return true;
}

void print_usage() {
  std::printf(
      "usage: noleax-rtl-heap-baseline [--threads N] [--iterations N] "
      "[--rounds N] [--seed N]\n");
}

[[nodiscard]] ParseResult parse_options(int argc, char* argv[], Options& options) {
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument{argv[index]};
    if (argument == "--help") {
      print_usage();
      return ParseResult::kHelp;
    }
    if (index + 1 >= argc) {
      std::fprintf(stderr, "missing value for %.*s\n", static_cast<int>(argument.size()),
                   argument.data());
      return ParseResult::kError;
    }
    const std::string_view value{argv[++index]};
    bool valid = false;
    if (argument == "--threads") {
      valid = parse_bounded(value, kMaximumThreads, options.threads);
    } else if (argument == "--iterations") {
      valid = parse_bounded(value, kMaximumIterations, options.iterations);
    } else if (argument == "--rounds") {
      valid = parse_bounded(value, kMaximumRounds, options.rounds);
    } else if (argument == "--seed") {
      valid = parse_unsigned(value, options.seed);
    } else {
      std::fprintf(stderr, "unknown option: %.*s\n", static_cast<int>(argument.size()),
                   argument.data());
      return ParseResult::kError;
    }
    if (!valid) {
      std::fprintf(stderr, "invalid value for %.*s\n", static_cast<int>(argument.size()),
                   argument.data());
      return ParseResult::kError;
    }
  }
  return ParseResult::kSuccess;
}

void count_api_attempt(Summary& summary, AllocationApi api) noexcept {
  ++summary.allocation_attempts;
  switch (api) {
    case AllocationApi::kRtl:
      ++summary.rtl_attempts;
      break;
    case AllocationApi::kWin32:
      ++summary.win32_attempts;
      break;
    case AllocationApi::kCrt:
      ++summary.crt_attempts;
      break;
  }
}

void record_last_error(Summary& summary, AllocationApi api, DWORD sentinel,
                       DWORD observed) noexcept {
  if (api == AllocationApi::kRtl) {
    summary.rtl_last_error_hash = mix_hash(summary.rtl_last_error_hash, observed);
    if (observed != sentinel) {
      ++summary.rtl_last_error_changes;
    }
  } else if (api == AllocationApi::kWin32) {
    summary.win32_last_error_hash = mix_hash(summary.win32_last_error_hash, observed);
    if (observed != sentinel) {
      ++summary.win32_last_error_changes;
    }
  }
}

[[nodiscard]] AllocationApi choose_api(std::uint32_t worker_index, std::uint32_t operation_index,
                                       std::uint64_t token) noexcept {
  if (operation_index % 257U == 0U) {
    return ((operation_index / 257U + worker_index) % 2U == 0U) ? AllocationApi::kRtl
                                                                : AllocationApi::kWin32;
  }
  return static_cast<AllocationApi>(token % 3U);
}

[[nodiscard]] std::size_t choose_size(std::uint32_t operation_index, std::uint64_t token) noexcept {
  if (operation_index % 257U == 0U) {
    return 0U;
  }
  if (operation_index % 1021U == 0U) {
    return 65'536U + static_cast<std::size_t>(token % 65'536U);
  }
  return 1U + static_cast<std::size_t>(token % 4096U);
}

[[nodiscard]] PVOID allocate_block(const NativeFunctions& functions, AllocationApi api, PVOID heap,
                                   std::size_t size, bool zero_memory, DWORD last_error_sentinel,
                                   Summary& summary) noexcept {
  count_api_attempt(summary, api);
  if (api != AllocationApi::kCrt) {
    if (heap == GetProcessHeap()) {
      ++summary.process_heap_attempts;
    } else {
      ++summary.explicit_heap_attempts;
    }
  }
  if (size == 0U) {
    ++summary.zero_size_attempts;
  }

  SetLastError(last_error_sentinel);
  PVOID allocation = nullptr;
  const ULONG flags = zero_memory ? HEAP_ZERO_MEMORY : 0U;
  switch (api) {
    case AllocationApi::kRtl:
      allocation = functions.allocate(heap, flags, size);
      break;
    case AllocationApi::kWin32:
      allocation = HeapAlloc(static_cast<HANDLE>(heap), flags, size);
      break;
    case AllocationApi::kCrt:
      allocation = zero_memory ? std::calloc(1U, size) : std::malloc(size);
      break;
  }
  if (api != AllocationApi::kCrt) {
    record_last_error(summary, api, last_error_sentinel, GetLastError());
  }
  return allocation;
}

[[nodiscard]] bool free_block(const NativeFunctions& functions, const Block& block) noexcept {
  switch (block.api) {
    case AllocationApi::kRtl:
      return functions.free(block.heap, 0U, block.allocation) != FALSE;
    case AllocationApi::kWin32:
      return HeapFree(static_cast<HANDLE>(block.heap), 0U, block.allocation) != FALSE;
    case AllocationApi::kCrt:
      std::free(block.allocation);
      return true;
  }
  return false;
}

void initialize_block(Block& block, bool zero_memory, Summary& summary,
                      std::uint32_t& failure_code) noexcept {
  auto* const bytes = static_cast<std::uint8_t*>(block.allocation);
  if (zero_memory) {
    for (std::size_t index = 0U; index < block.size; ++index) {
      if (bytes[index] != 0U && failure_code == 0U) {
        failure_code = 2U;
      }
    }
    summary.zero_verified_bytes += block.size;
  }
  for (std::size_t index = 0U; index < block.size; ++index) {
    bytes[index] = payload_byte(block.token, index);
  }
}

void verify_block(const Block& block, Summary& summary, std::uint32_t& failure_code) noexcept {
  const auto* const bytes = static_cast<const std::uint8_t*>(block.allocation);
  std::uint64_t payload_hash = kFnvOffsetBasis;
  for (std::size_t index = 0U; index < block.size; ++index) {
    const std::uint8_t expected = payload_byte(block.token, index);
    if (bytes[index] != expected && failure_code == 0U) {
      failure_code = 3U;
    }
    payload_hash ^= bytes[index];
    payload_hash *= kFnvPrime;
  }
  summary.payload_verified_bytes += block.size;
  summary.checksum = mix_hash(summary.checksum, static_cast<std::uint64_t>(block.api));
  summary.checksum = mix_hash(summary.checksum, block.size);
  summary.checksum = mix_hash(summary.checksum, block.token);
  summary.checksum = mix_hash(summary.checksum, payload_hash);
}

void run_expected_failures(const NativeFunctions& functions, std::uint32_t worker_index,
                           PVOID process_heap, Summary& summary,
                           std::uint32_t& failure_code) noexcept {
  constexpr std::size_t impossible_size = std::numeric_limits<std::size_t>::max() - 65'535U;
  constexpr std::array apis{AllocationApi::kRtl, AllocationApi::kWin32, AllocationApi::kCrt};
  for (const AllocationApi api : apis) {
    count_api_attempt(summary, api);
    if (api != AllocationApi::kCrt) {
      ++summary.process_heap_attempts;
    }
    const DWORD sentinel = 0xa1200000U | (worker_index << 8U) | static_cast<DWORD>(api);
    SetLastError(sentinel);
    PVOID allocation = nullptr;
    switch (api) {
      case AllocationApi::kRtl:
        allocation = functions.allocate(process_heap, 0U, impossible_size);
        break;
      case AllocationApi::kWin32:
        allocation = HeapAlloc(static_cast<HANDLE>(process_heap), 0U, impossible_size);
        break;
      case AllocationApi::kCrt:
        allocation = std::malloc(impossible_size);
        break;
    }
    if (api != AllocationApi::kCrt) {
      record_last_error(summary, api, sentinel, GetLastError());
    }
    if (allocation != nullptr) {
      Block block{allocation, process_heap, impossible_size, 0U, api};
      static_cast<void>(free_block(functions, block));
      if (failure_code == 0U) {
        failure_code = 4U;
      }
    } else {
      ++summary.expected_failures;
    }
    summary.checksum = mix_hash(summary.checksum, 0xf0000000U + static_cast<std::uint64_t>(api));
  }
}

[[nodiscard]] WorkerResult run_worker(const NativeFunctions& functions, const Options& options,
                                      std::uint32_t worker_index, PVOID process_heap,
                                      PVOID explicit_heap) noexcept {
  WorkerResult result;
  std::array<Block, kBatchSize> blocks{};
  std::uint32_t operation_index = 0U;

  while (operation_index < options.iterations) {
    std::size_t block_count = 0U;
    while (block_count < blocks.size() && operation_index < options.iterations) {
      const std::uint64_t token = splitmix64(
          options.seed ^ (static_cast<std::uint64_t>(worker_index) << 32U) ^ operation_index);
      const AllocationApi api = choose_api(worker_index, operation_index, token);
      std::size_t size = choose_size(operation_index, token);
      if (api == AllocationApi::kCrt && size == 0U) {
        size = 1U;
      }
      const bool zero_memory = size != 0U && ((token >> 9U) & 3U) == 0U;
      PVOID heap = ((token >> 8U) & 1U) == 0U ? process_heap : explicit_heap;
      if (api == AllocationApi::kCrt) {
        heap = nullptr;
      }
      const DWORD sentinel =
          0xa1100000U | (worker_index << 8U) | static_cast<DWORD>(operation_index & 0xffU);
      PVOID allocation =
          allocate_block(functions, api, heap, size, zero_memory, sentinel, result.summary);
      if (allocation == nullptr) {
        result.failure_code = 1U;
        break;
      }

      ++result.summary.successful_allocations;
      result.summary.requested_bytes += size;
      Block& block = blocks[block_count++];
      block = Block{allocation, heap, size, token, api};
      initialize_block(block, zero_memory, result.summary, result.failure_code);
      ++operation_index;
      if (result.failure_code != 0U) {
        break;
      }
    }

    while (block_count != 0U) {
      Block& block = blocks[--block_count];
      verify_block(block, result.summary, result.failure_code);
      if (free_block(functions, block)) {
        ++result.summary.frees;
      } else if (result.failure_code == 0U) {
        result.failure_code = 5U;
      }
      block = {};
    }
    if (result.failure_code != 0U) {
      return result;
    }
  }

  run_expected_failures(functions, worker_index, process_heap, result.summary, result.failure_code);
  return result;
}

void add_summary(Summary& aggregate, const Summary& worker, std::uint32_t worker_index) noexcept {
  aggregate.allocation_attempts += worker.allocation_attempts;
  aggregate.rtl_attempts += worker.rtl_attempts;
  aggregate.win32_attempts += worker.win32_attempts;
  aggregate.crt_attempts += worker.crt_attempts;
  aggregate.successful_allocations += worker.successful_allocations;
  aggregate.expected_failures += worker.expected_failures;
  aggregate.frees += worker.frees;
  aggregate.requested_bytes += worker.requested_bytes;
  aggregate.zero_size_attempts += worker.zero_size_attempts;
  aggregate.zero_verified_bytes += worker.zero_verified_bytes;
  aggregate.payload_verified_bytes += worker.payload_verified_bytes;
  aggregate.process_heap_attempts += worker.process_heap_attempts;
  aggregate.explicit_heap_attempts += worker.explicit_heap_attempts;
  aggregate.rtl_last_error_changes += worker.rtl_last_error_changes;
  aggregate.win32_last_error_changes += worker.win32_last_error_changes;
  aggregate.rtl_last_error_hash =
      mix_hash(aggregate.rtl_last_error_hash, worker.rtl_last_error_hash);
  aggregate.win32_last_error_hash =
      mix_hash(aggregate.win32_last_error_hash, worker.win32_last_error_hash);
  aggregate.checksum = mix_hash(aggregate.checksum, worker_index);
  aggregate.checksum = mix_hash(aggregate.checksum, worker.checksum);
}

[[nodiscard]] bool load_native_functions(NativeFunctions& functions) noexcept {
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) {
    return false;
  }
  functions.allocate =
      reinterpret_cast<RtlAllocateHeapFunction>(GetProcAddress(ntdll, "RtlAllocateHeap"));
  functions.free = reinterpret_cast<RtlFreeHeapFunction>(GetProcAddress(ntdll, "RtlFreeHeap"));
  return functions.allocate != nullptr && functions.free != nullptr;
}

[[nodiscard]] std::uint32_t run_round(const NativeFunctions& functions, const Options& options,
                                      Summary& summary) {
  const HANDLE process_heap = GetProcessHeap();
  const HANDLE explicit_heap = HeapCreate(0U, 0U, 0U);
  if (process_heap == nullptr || explicit_heap == nullptr) {
    return 10U;
  }

  std::vector<WorkerResult> results(options.threads);
  std::vector<std::thread> workers;
  workers.reserve(options.threads);
  std::atomic<bool> start{false};
  try {
    for (std::uint32_t index = 0U; index < options.threads; ++index) {
      workers.emplace_back([&, index] {
        while (!start.load(std::memory_order_acquire)) {
          std::this_thread::yield();
        }
        results[index] = run_worker(functions, options, index, process_heap, explicit_heap);
      });
    }
  } catch (...) {
    start.store(true, std::memory_order_release);
    for (auto& worker : workers) {
      worker.join();
    }
    static_cast<void>(HeapDestroy(explicit_heap));
    return 11U;
  }

  start.store(true, std::memory_order_release);
  for (auto& worker : workers) {
    worker.join();
  }

  std::uint32_t failure_code = 0U;
  for (std::uint32_t index = 0U; index < options.threads; ++index) {
    if (results[index].failure_code != 0U && failure_code == 0U) {
      failure_code = results[index].failure_code;
    }
    add_summary(summary, results[index].summary, index);
  }
  if (HeapDestroy(explicit_heap) == FALSE && failure_code == 0U) {
    failure_code = 12U;
  }
  return failure_code;
}

void print_summary(const Options& options, const Summary& summary) {
  std::printf(
      "status=ok version=1 threads=%u iterations=%u rounds=%u seed=0x%016llx "
      "attempts=%llu rtl=%llu win32=%llu crt=%llu successes=%llu expected_failures=%llu "
      "frees=%llu requested_bytes=%llu zero_size=%llu zero_verified_bytes=%llu "
      "payload_verified_bytes=%llu process_heap=%llu explicit_heap=%llu "
      "rtl_last_error_changes=%llu win32_last_error_changes=%llu "
      "rtl_last_error_hash=0x%016llx win32_last_error_hash=0x%016llx checksum=0x%016llx\n",
      options.threads, options.iterations, options.rounds,
      static_cast<unsigned long long>(options.seed),
      static_cast<unsigned long long>(summary.allocation_attempts),
      static_cast<unsigned long long>(summary.rtl_attempts),
      static_cast<unsigned long long>(summary.win32_attempts),
      static_cast<unsigned long long>(summary.crt_attempts),
      static_cast<unsigned long long>(summary.successful_allocations),
      static_cast<unsigned long long>(summary.expected_failures),
      static_cast<unsigned long long>(summary.frees),
      static_cast<unsigned long long>(summary.requested_bytes),
      static_cast<unsigned long long>(summary.zero_size_attempts),
      static_cast<unsigned long long>(summary.zero_verified_bytes),
      static_cast<unsigned long long>(summary.payload_verified_bytes),
      static_cast<unsigned long long>(summary.process_heap_attempts),
      static_cast<unsigned long long>(summary.explicit_heap_attempts),
      static_cast<unsigned long long>(summary.rtl_last_error_changes),
      static_cast<unsigned long long>(summary.win32_last_error_changes),
      static_cast<unsigned long long>(summary.rtl_last_error_hash),
      static_cast<unsigned long long>(summary.win32_last_error_hash),
      static_cast<unsigned long long>(summary.checksum));
}

[[nodiscard]] bool summary_is_valid(const Options& options, const Summary& summary) noexcept {
  const std::uint64_t normal_operations =
      static_cast<std::uint64_t>(options.threads) * options.iterations;
  const std::uint64_t failure_operations = static_cast<std::uint64_t>(options.threads) * 3U;
  return summary.allocation_attempts == normal_operations + failure_operations &&
         summary.rtl_attempts + summary.win32_attempts + summary.crt_attempts ==
             summary.allocation_attempts &&
         summary.successful_allocations == normal_operations &&
         summary.expected_failures == failure_operations && summary.frees == normal_operations &&
         summary.payload_verified_bytes == summary.requested_bytes &&
         summary.process_heap_attempts + summary.explicit_heap_attempts ==
             summary.rtl_attempts + summary.win32_attempts;
}

}  // namespace

int main(int argc, char* argv[]) {
  Options options;
  const ParseResult parse_result = parse_options(argc, argv, options);
  if (parse_result == ParseResult::kHelp) {
    return 0;
  }
  if (parse_result == ParseResult::kError) {
    print_usage();
    return 2;
  }

  NativeFunctions functions;
  if (!load_native_functions(functions)) {
    std::fprintf(stderr, "cannot resolve RtlAllocateHeap and RtlFreeHeap\n");
    return 3;
  }

  Summary baseline;
  for (std::uint32_t round = 0U; round < options.rounds; ++round) {
    Summary current;
    const std::uint32_t failure_code = run_round(functions, options, current);
    if (failure_code != 0U) {
      std::fprintf(stderr, "baseline round %u failed with code %u\n", round, failure_code);
      return 10 + static_cast<int>(failure_code);
    }
    if (round == 0U) {
      baseline = current;
    } else if (current != baseline) {
      std::fprintf(stderr, "baseline round %u produced a different deterministic summary\n", round);
      return 30;
    }
  }

  if (!summary_is_valid(options, baseline)) {
    std::fprintf(stderr, "baseline summary invariants failed\n");
    return 31;
  }
  print_summary(options, baseline);
  return 0;
}
