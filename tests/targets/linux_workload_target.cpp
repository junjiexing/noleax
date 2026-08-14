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
#include <fstream>
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

// --vm-stress (H3): 64 threads hammering same-size mmap/munmap pairs, maximizing same-address
// reuse and queue-order/completion-order divergence. The trailing sleep keeps the process
// alive so a duration-bounded standalone capture finalizes mid-run.
int vm_stress_workload() {
  constexpr int kThreadCount = 64;
  constexpr int kIterations = 500;
  constexpr std::size_t kMappingSize = 64U * 1024U;
  std::atomic<int> ready{0};
  std::atomic<bool> go{false};
  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreadCount);
  for (int thread_index = 0; thread_index < kThreadCount; ++thread_index) {
    workers.emplace_back([&, thread_index] {
      ready.fetch_add(1, std::memory_order_release);
      while (!go.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      for (int iteration = 0; iteration < kIterations; ++iteration) {
        void* const mapping = ::mmap(nullptr, kMappingSize, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) {
          failures.fetch_add(1, std::memory_order_relaxed);
          continue;
        }
        std::memset(mapping, thread_index, 4096U);
        if (::munmap(mapping, kMappingSize) != 0) {
          failures.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }
  while (ready.load(std::memory_order_acquire) != kThreadCount) {
    std::this_thread::yield();
  }
  go.store(true, std::memory_order_release);
  for (std::thread& worker : workers) {
    worker.join();
  }
  // The standalone duration must finalize while the target remains alive.
  std::this_thread::sleep_for(std::chrono::seconds{5});
  return failures.load(std::memory_order_relaxed) == 0 ? 42 : 43;
}

// --vm-partials (H3): a deterministic, single-threaded partial-unmap fixture. Every mapping
// the fixture creates is reported as "touched <base>"; every generation that must still be
// outstanding at exit is reported as "expect <base> <bytes>" (the fixture's own ground
// truth). The report lands in the file named by NOLEAX_PARTIALS_REPORT; the integration
// test compares the analyzer's outstanding view against it.
int vm_partials_workload() {
  constexpr std::size_t kKiB = 1024U;
  constexpr std::size_t kMiB = 1024U * 1024U;
  struct Expected {
    std::uintptr_t base;
    std::uint64_t bytes;
  };
  std::vector<Expected> expected;
  std::vector<std::uintptr_t> touched;
  const auto as_u64 = [](const void* pointer) {
    return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(pointer));
  };
  const auto fail = [] {
    std::printf("vm-partials fixture syscall failed\n");
    return 43;
  };

  // A 4 MiB reservation carved into deterministic neighbours.
  void* const reservation =
      ::mmap(nullptr, 4U * kMiB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reservation == MAP_FAILED) {
    return fail();
  }
  const std::uint64_t base_r = as_u64(reservation);
  touched.push_back(base_r);
  escape(reservation);
  // Middle unmap: R splits into [R, R+1M) and [R+3M, R+4M).
  if (::munmap(reinterpret_cast<void*>(base_r + kMiB), 2U * kMiB) != 0) {
    return fail();
  }
  // B lands in the hole at a deterministic offset (MAP_FIXED_NOREPLACE).
  void* const mapping_b = ::mmap(reinterpret_cast<void*>(base_r + kMiB), 512U * kKiB,
                                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping_b == MAP_FAILED) {
    return fail();
  }
  const std::uint64_t base_b = as_u64(mapping_b);
  touched.push_back(base_b);
  escape(mapping_b);
  // One munmap spanning the R fragment tail and B's head: two generations, two records.
  if (::munmap(reinterpret_cast<void*>(base_r + 896U * kKiB),
               (base_b + 128U * kKiB) - (base_r + 896U * kKiB)) != 0) {
    return fail();
  }
  // Double unmap of B's freed head, and an unmap of the hole between B and R's tail.
  if (::munmap(mapping_b, 128U * kKiB) != 0) {
    return fail();
  }
  if (::munmap(reinterpret_cast<void*>(base_r + 2U * kMiB), 64U * kKiB) != 0) {
    return fail();
  }
  // MAP_FIXED overlap: E replaces the head of R's second fragment.
  void* const mapping_e =
      ::mmap(reinterpret_cast<void*>(base_r + 3U * kMiB + 64U * kKiB), 128U * kKiB,
             PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (mapping_e == MAP_FAILED) {
    return fail();
  }
  const std::uint64_t base_e = as_u64(mapping_e);
  touched.push_back(base_e);
  escape(mapping_e);
  // R keeps [R, R+896K) plus [R+3M, R+3M+64K) and [R+3M+192K, R+4M) around E;
  // B keeps [B+128K, B+512K).
  expected.push_back(Expected{base_r, 896U * kKiB + 64U * kKiB + (kMiB - 192U * kKiB)});
  expected.push_back(Expected{base_b, 384U * kKiB});
  expected.push_back(Expected{base_e, 128U * kKiB});

  // mremap: grow (maybe moving), shrink back, then a MREMAP_FIXED move onto a live mapping.
  void* growing =
      ::mmap(nullptr, 64U * kKiB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (growing == MAP_FAILED) {
    return fail();
  }
  touched.push_back(as_u64(growing));
  growing = ::mremap(growing, 64U * kKiB, 256U * kKiB, MREMAP_MAYMOVE);
  if (growing == MAP_FAILED) {
    return fail();
  }
  touched.push_back(as_u64(growing));
  growing = ::mremap(growing, 256U * kKiB, 64U * kKiB, MREMAP_MAYMOVE);
  if (growing == MAP_FAILED) {
    return fail();
  }
  touched.push_back(as_u64(growing));
  void* const fixed_target =
      ::mmap(nullptr, 64U * kKiB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (fixed_target == MAP_FAILED) {
    return fail();
  }
  touched.push_back(as_u64(fixed_target));
  void* const moved =
      ::mremap(growing, 64U * kKiB, 64U * kKiB, MREMAP_MAYMOVE | MREMAP_FIXED, fixed_target);
  if (moved == MAP_FAILED) {
    return fail();
  }
  if (moved != fixed_target) {
    return fail();
  }
  escape(moved);
  expected.push_back(Expected{as_u64(moved), 64U * kKiB});

  // A file-backed view of this executable: free only the prefix, leaving a partial view.
  const int fd = ::open("/proc/self/exe", O_RDONLY);
  if (fd < 0) {
    return fail();
  }
  void* const view = ::mmap(nullptr, 128U * kKiB, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (view == MAP_FAILED) {
    return fail();
  }
  touched.push_back(as_u64(view));
  escape(view);
  if (::munmap(view, 64U * kKiB) != 0) {
    return fail();
  }
  expected.push_back(Expected{as_u64(view), 64U * kKiB});

  if (const char* report_path = std::getenv("NOLEAX_PARTIALS_REPORT")) {
    std::ofstream report{report_path, std::ios::binary | std::ios::trunc};
    for (const Expected& entry : expected) {
      report << "expect " << std::hex << entry.base << std::dec << ' ' << entry.bytes << '\n';
    }
    for (const std::uintptr_t base : touched) {
      report << "touched " << std::hex << base << '\n';
    }
    report << "done\n";
    if (!report) {
      return fail();
    }
  }
  std::printf("vm-partials done expected=%zu\n", expected.size());
  return 42;
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
  // --vm-stress: 64 threads of same-size mmap/munmap pairs for the address-reuse stress
  // (H3); the process stays alive for a duration-bounded capture.
  if (argc == 2 && std::strcmp(argv[1], "--vm-stress") == 0) {
    return vm_stress_workload();
  }
  // --vm-partials: deterministic partial-unmap fixture with a ground-truth report (H3).
  if (argc == 2 && std::strcmp(argv[1], "--vm-partials") == 0) {
    return vm_partials_workload();
  }
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
