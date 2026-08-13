// Deterministic allocation workload for the Linux end-to-end capture test. Every pointer
// escapes through a volatile sink so -O2/-O3 cannot fold the calls away; the shape stays
// exactly assertable: a fixed number of paired allocations, a fixed set of never-freed
// blocks, realloc/aligned-family coverage, and a multithreaded burst.

#include <fcntl.h>
#include <malloc.h>
#include <sys/mman.h>

#include <atomic>
#include <chrono>
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

// Escape channel: once a pointer lands here, the allocation is observable and the
// compiler must materialize every call.
std::atomic<void*> escape_sink{nullptr};

template <typename T>
T* escape(T* pointer) {
  escape_sink.store(static_cast<void*>(pointer), std::memory_order_relaxed);
  return pointer;
}

void paired_workload() {
  for (std::size_t index = 0; index < kPairedCount; ++index) {
    void* const block = escape(std::malloc(64U + (index % 7U) * 128U));
    std::memset(block, 0x5a, 16U);
    std::free(block);
  }
}

void retained_workload(std::vector<void*>& retained) {
  for (std::size_t index = 0; index < kLeakedCount; ++index) {
    void* const block = escape(std::calloc(1U, kLeakedSize + index * 512U));
    std::memset(block, 0x11, 8U);
    retained.push_back(block);
  }
}

void realloc_workload() {
  void* block = escape(std::malloc(128U));
  for (std::size_t index = 0; index < 10U; ++index) {
    block = escape(std::realloc(block, 256U + index * 256U));
    std::memset(block, 0x22, 8U);
  }
  std::free(block);
}

void aligned_workload() {
  void* block = nullptr;
  if (::posix_memalign(&block, 64U, 2048U) == 0) {
    escape(block);
    std::memset(block, 0x33, 8U);
    std::free(block);
  }
  block = escape(::aligned_alloc(128U, 4096U));
  std::memset(block, 0x44, 8U);
  std::free(block);
  block = escape(::memalign(256U, 1024U));
  std::memset(block, 0x55, 8U);
  std::free(block);
}

void burst_worker() {
  for (std::size_t index = 0; index < kThreadBurst; ++index) {
    void* const block = escape(std::malloc(96U + (index % 5U) * 64U));
    std::memset(block, 0x66, 8U);
    std::free(block);
  }
}

void vm_workload() {
  // Anonymous mapping, grown in place or moved by mremap, then unmapped.
  void* region =
      ::mmap(nullptr, 64U * 1024U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (region == MAP_FAILED) {
    return;
  }
  escape(region);
  std::memset(region, 0x77, 4096U);
  region = ::mremap(region, 64U * 1024U, 256U * 1024U, MREMAP_MAYMOVE);
  if (region != MAP_FAILED) {
    escape(region);
    std::memset(region, 0x78, 4096U);
    ::munmap(region, 256U * 1024U);
  }

  // File-backed mapping: this source file read through a view.
  const int fd = ::open("/proc/self/exe", O_RDONLY);
  if (fd >= 0) {
    void* const view = ::mmap(nullptr, 8192U, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (view != MAP_FAILED) {
      escape(view);
      volatile unsigned char first_byte = *static_cast<unsigned char*>(view);
      static_cast<void>(first_byte);
      ::munmap(view, 8192U);
    }
  }
}

}  // namespace

// A trivially small "third-party allocator" for the custom-hook e2e: exported so the
// declaration can locate it by export name, and kept out of the built-in profile.
extern "C" __attribute__((visibility("default"))) void* my_alloc(std::size_t size) {
  auto* block = static_cast<std::byte*>(std::malloc(size + 16U));
  if (block == nullptr) {
    return nullptr;
  }
  std::memset(block, 0x4e, 16U);
  return block + 16U;
}

extern "C" __attribute__((visibility("default"))) void my_free(void* pointer) {
  if (pointer == nullptr) {
    return;
  }
  std::free(static_cast<std::byte*>(pointer) - 16U);
}

// A deliberately slow "allocator" pair for the drain-quiescence e2e (H1-A): the 500 ms
// sleep happens inside the hooked function, so a capture stop that lands mid-call finds
// the replacement in flight and must wait it out (or time out against a tiny budget).
// noinline+noipa keep the hooked entry points canonical (see CxxAllocator below).
extern "C" __attribute__((visibility("default"), noinline, noipa)) void* slow_alloc(
    std::size_t size) {
  std::this_thread::sleep_for(std::chrono::milliseconds{500});
  return std::malloc(size);
}

extern "C" __attribute__((visibility("default"), noinline, noipa)) void slow_free(void* pointer) {
  std::free(pointer);
}

// A C++ member allocator for the per-role custom-hook argument model: `this` occupies
// argument 0, so Malloc's size rides in argument 1, Realloc's pointer/size in arguments
// 1/2, and Free's pointer in argument 1. Out-of-line default-visibility definitions keep
// the mangled names in .dynsym (the target links with ENABLE_EXPORTS) as well as .symtab.
// noipa keeps the compiler from cloning or otherwise rerouting the hooked entry points
// (an ipa-cp constprop clone would bypass the patch on the canonical symbol).
class CxxAllocator {
 public:
  void* Malloc(std::size_t size, std::size_t alignment);
  void* Realloc(void* pointer, std::size_t size, std::size_t alignment);
  void Free(void* pointer);
};

__attribute__((noinline, noipa)) void* CxxAllocator::Malloc(std::size_t size,
                                                            std::size_t alignment) {
  static_cast<void>(alignment);  // the alignment parameter only shifts the argument slots
  return std::malloc(size);
}

__attribute__((noinline, noipa)) void* CxxAllocator::Realloc(void* pointer, std::size_t size,
                                                             std::size_t alignment) {
  static_cast<void>(alignment);
  return std::realloc(pointer, size);
}

__attribute__((noinline, noipa)) void CxxAllocator::Free(void* pointer) { std::free(pointer); }

// Hidden visibility: external linkage but absent from .dynsym, so only the .symtab lookup
// path (or a debug companion) can resolve these symbols.
__attribute__((noinline, noipa, visibility("hidden"))) void* hidden_alloc(std::size_t size) {
  return std::malloc(size);
}

__attribute__((noinline, noipa, visibility("hidden"))) void hidden_free(void* pointer) {
  std::free(pointer);
}

int main(int argc, char** argv) {
  // --slow-custom-alloc: one slow_alloc call whose 500 ms body spans the capture stop of
  // the drain-quiescence test. The block is retained until exit. The trailing cushion
  // keeps the process alive while the delayed drain finishes the writer, so the exit
  // hook never races an in-progress finalize.
  if (argc > 1 && std::strcmp(argv[1], "--slow-custom-alloc") == 0) {
    void* const block = escape(slow_alloc(2048U));
    std::this_thread::sleep_for(std::chrono::milliseconds{500});
    std::printf("slow workload done block=%p\n", block);
    return 42;
  }

  std::vector<void*> retained;
  retained.reserve(kLeakedCount);

  paired_workload();
  retained_workload(retained);
  realloc_workload();
  aligned_workload();
  vm_workload();

  // Two blocks through the custom allocator: visible to custom-hook captures and
  // retained until exit.
  retained.push_back(escape(my_alloc(2048U)));
  retained.push_back(escape(my_alloc(3072U)));

  // The C++ member allocator exercises the per-role argument mapping (`this` in argument
  // 0), the hidden pair the .symtab-only symbol lookup.
  CxxAllocator cxx_allocator;
  void* const cxx_block = escape(cxx_allocator.Malloc(1024U, 32U));
  std::memset(cxx_block, 0x6a, 16U);
  void* const cxx_grown = escape(cxx_allocator.Realloc(cxx_block, 1536U, 32U));
  std::memset(cxx_grown, 0x6b, 16U);
  cxx_allocator.Free(cxx_grown);
  void* const hidden_block = escape(hidden_alloc(512U));
  std::memset(hidden_block, 0x6c, 16U);
  hidden_free(hidden_block);

  std::thread first{burst_worker};
  std::thread second{burst_worker};
  first.join();
  second.join();

  // Keep the retained blocks observable until exit so leaks mode sees them as outstanding.
  std::printf("workload done retained=%zu first=%p\n", retained.size(), retained.front());
  return 42;
}
