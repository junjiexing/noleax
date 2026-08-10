// Deterministic allocation workload for the Linux end-to-end capture test. The shape is
// deliberately simple so the analyzer output can be asserted exactly: a fixed number of
// paired allocations, a fixed set of never-freed (leaked) blocks, calloc/realloc/
// aligned-family coverage, and a multithreaded burst.

#include <malloc.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

namespace {

constexpr std::size_t kPairedCount = 400;
constexpr std::size_t kLeakedCount = 8;
constexpr std::size_t kLeakedSize = 4096;
constexpr std::size_t kThreadBurst = 250;

void paired_workload() {
  for (std::size_t index = 0; index < kPairedCount; ++index) {
    void* const block = std::malloc(64U + (index % 7U) * 128U);
    std::memset(block, 0x5a, 16U);
    std::free(block);
  }
}

void retained_workload(std::vector<void*>& retained) {
  for (std::size_t index = 0; index < kLeakedCount; ++index) {
    void* const block = std::calloc(1U, kLeakedSize + index * 512U);
    std::memset(block, 0x11, 8U);
    retained.push_back(block);
  }
}

void realloc_workload() {
  void* block = std::malloc(128U);
  for (std::size_t index = 0; index < 10U; ++index) {
    block = std::realloc(block, 256U + index * 256U);
    std::memset(block, 0x22, 8U);
  }
  std::free(block);
}

void aligned_workload() {
  void* block = nullptr;
  if (::posix_memalign(&block, 64U, 2048U) == 0) {
    std::memset(block, 0x33, 8U);
    std::free(block);
  }
  block = ::aligned_alloc(128U, 4096U);
  std::memset(block, 0x44, 8U);
  std::free(block);
  block = ::memalign(256U, 1024U);
  std::memset(block, 0x55, 8U);
  std::free(block);
}

void burst_worker() {
  for (std::size_t index = 0; index < kThreadBurst; ++index) {
    void* const block = std::malloc(96U + (index % 5U) * 64U);
    std::memset(block, 0x66, 8U);
    std::free(block);
  }
}

}  // namespace

int main() {
  std::vector<void*> retained;
  retained.reserve(kLeakedCount);

  paired_workload();
  retained_workload(retained);
  realloc_workload();
  aligned_workload();

  std::thread first{burst_worker};
  std::thread second{burst_worker};
  first.join();
  second.join();

  // Keep the retained blocks observable until exit so leaks mode sees them as outstanding.
  std::printf("workload done retained=%zu first=%p\n", retained.size(), retained.front());
  return 42;
}
