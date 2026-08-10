// POSIX hardening tests for the Hoox hook backend. The platform-neutral lifecycle contract
// lives in hook_backend_test.cpp; this file stresses the Linux-specific risks of the port
// (docs/LINUX_PORT_PLAN.md risk R1): patching real glibc text, concurrent execution during
// install/uninstall, repeated trampoline churn, and module reload cycles.

#include <dlfcn.h>
#include <malloc.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <vector>

#include "noleax/agent/hook_backend.hpp"

namespace {

using GetpidFunction = pid_t (*)() noexcept;

std::atomic<std::uint64_t> getpid_replacement_calls{0U};
GetpidFunction getpid_original = nullptr;

using FixtureFunction = std::uint64_t (*)(std::uint64_t, std::uint64_t) noexcept;

std::atomic<std::uint64_t> reload_replacement_calls{0U};
FixtureFunction reload_original = nullptr;

__attribute__((noinline)) pid_t getpid_replacement() noexcept {
  getpid_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return getpid_original();
}

__attribute__((noinline)) std::uint64_t reload_replacement(std::uint64_t left,
                                                           std::uint64_t right) noexcept {
  reload_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reload_original(left, right) ^ 0xffULL;
}

class LoadedLibc {
 public:
  LoadedLibc() : handle_{dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL)} {
    if (handle_ == nullptr) {
      throw std::runtime_error{"cannot open libc.so.6"};
    }
  }

  ~LoadedLibc() {
    if (handle_ != nullptr) {
      dlclose(handle_);
    }
  }

  LoadedLibc(const LoadedLibc&) = delete;
  LoadedLibc& operator=(const LoadedLibc&) = delete;

  [[nodiscard]] void* symbol(const char* name) const {
    void* const address = dlsym(handle_, name);
    if (address == nullptr) {
      throw std::runtime_error{"libc symbol is missing"};
    }
    return address;
  }

 private:
  void* handle_{nullptr};
};

// The linux-glibc-heap / linux-virtual-memory target set. Several of these have prologues
// shorter than the worst-case 16-byte far redirect (jump-only aliases, syscall stubs) and
// rely on Hoox's near-redirect fallback; pin the whole matrix so a Hoox regression or a
// glibc prologue change is caught here and not in production captures.

#define NOLEAX_MATRIX_SLOTS \
  X(malloc)                 \
  X(free)                   \
  X(calloc)                 \
  X(realloc)                \
  X(posix_memalign)         \
  X(aligned_alloc)          \
  X(memalign)               \
  X(valloc)                 \
  X(reallocarray)           \
  X(strdup)                 \
  X(munmap)

#define X(name) noleax::agent::OriginalTrampolineSlot matrix_##name##_slot{nullptr};
NOLEAX_MATRIX_SLOTS
#undef X

std::atomic<std::uint64_t> matrix_replacement_calls{0U};

// Escape hatch against allocation elision: a pointer stored here is no longer provably
// dead, so the compiler cannot fold the paired malloc/free in the matrix test away.
volatile void* opaque_sink = nullptr;

#define X(name) \
  void* matrix_##name##_original() { return matrix_##name##_slot.load(std::memory_order_acquire); }
NOLEAX_MATRIX_SLOTS
#undef X

__attribute__((noinline)) void* matrix_malloc(std::size_t n) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reinterpret_cast<void* (*)(std::size_t)>(matrix_malloc_original())(n);
}
__attribute__((noinline)) void matrix_free(void* p) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  reinterpret_cast<void (*)(void*)>(matrix_free_original())(p);
}
__attribute__((noinline)) void* matrix_calloc(std::size_t a, std::size_t b) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reinterpret_cast<void* (*)(std::size_t, std::size_t)>(matrix_calloc_original())(a, b);
}
__attribute__((noinline)) void* matrix_realloc(void* p, std::size_t n) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reinterpret_cast<void* (*)(void*, std::size_t)>(matrix_realloc_original())(p, n);
}
__attribute__((noinline)) int matrix_posix_memalign(void** m, std::size_t a, std::size_t n) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reinterpret_cast<int (*)(void**, std::size_t, std::size_t)>(
      matrix_posix_memalign_original())(m, a, n);
}
__attribute__((noinline)) void* matrix_aligned_alloc(std::size_t a, std::size_t n) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reinterpret_cast<void* (*)(std::size_t, std::size_t)>(matrix_aligned_alloc_original())(a,
                                                                                                n);
}
__attribute__((noinline)) void* matrix_memalign(std::size_t a, std::size_t n) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reinterpret_cast<void* (*)(std::size_t, std::size_t)>(matrix_memalign_original())(a, n);
}
__attribute__((noinline)) void* matrix_valloc(std::size_t n) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reinterpret_cast<void* (*)(std::size_t)>(matrix_valloc_original())(n);
}
__attribute__((noinline)) void* matrix_reallocarray(void* p, std::size_t a, std::size_t b) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reinterpret_cast<void* (*)(void*, std::size_t, std::size_t)>(
      matrix_reallocarray_original())(p, a, b);
}
__attribute__((noinline)) char* matrix_strdup(const char* s) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reinterpret_cast<char* (*)(const char*)>(matrix_strdup_original())(s);
}
__attribute__((noinline)) int matrix_munmap(void* a, std::size_t n) {
  matrix_replacement_calls.fetch_add(1U, std::memory_order_relaxed);
  return reinterpret_cast<int (*)(void*, std::size_t)>(matrix_munmap_original())(a, n);
}

}  // namespace

TEST_CASE("hook backend patches a libc export under concurrent load",
          "[agent][hook-backend][posix]") {
  const LoadedLibc libc;
  void* const target = libc.symbol("getpid");
  const pid_t expected_pid = ::getpid();

  noleax::agent::HookBackend backend;
  std::atomic<bool> stop_hammering{false};
  std::atomic<std::uint64_t> hammer_calls{0U};
  std::atomic<bool> hammer_saw_wrong_pid{false};

  auto hammer = [&] {
    while (!stop_hammering.load(std::memory_order_acquire)) {
      if (::getpid() != expected_pid) {
        hammer_saw_wrong_pid.store(true, std::memory_order_relaxed);
      }
      hammer_calls.fetch_add(1U, std::memory_order_relaxed);
    }
  };

  std::vector<std::thread> hammer_threads;
  for (std::uint32_t index = 0U; index < 8U; ++index) {
    hammer_threads.emplace_back(hammer);
  }

  // Patch and unpatch live glibc text while eight threads execute the target through the
  // PLT. A crash, a torn patch, or a wrong result anywhere fails the run by itself; the
  // counters below only confirm the hooks actually engaged.
  for (std::uint32_t cycle = 0U; cycle < 50U; ++cycle) {
    const auto installed =
        backend.install_fast(target, reinterpret_cast<void*>(&getpid_replacement));
    REQUIRE(installed.installed());
    getpid_original = reinterpret_cast<GetpidFunction>(installed.original);
    const std::uint64_t calls_before = getpid_replacement_calls.load(std::memory_order_acquire);
    REQUIRE(::getpid() == expected_pid);
    CHECK(getpid_replacement_calls.load(std::memory_order_acquire) > calls_before);
    CHECK(backend.uninstall(target) == noleax::agent::HookUninstallStatus::kUninstalled);
    CHECK(::getpid() == expected_pid);
  }

  stop_hammering.store(true, std::memory_order_release);
  for (std::thread& thread : hammer_threads) {
    thread.join();
  }

  CHECK(hammer_calls.load(std::memory_order_relaxed) > 1000U);
  CHECK_FALSE(hammer_saw_wrong_pid.load(std::memory_order_relaxed));
  const std::uint64_t recorded = getpid_replacement_calls.load(std::memory_order_acquire);
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  CHECK(getpid_replacement_calls.load(std::memory_order_acquire) == recorded);
  CHECK(backend.shutdown());
}

TEST_CASE("hook backend survives repeated install cycles on one target",
          "[agent][hook-backend][posix]") {
  const LoadedLibc libc;
  void* const target = libc.symbol("getpid");
  const pid_t expected_pid = ::getpid();

  noleax::agent::HookBackend backend;
  for (std::uint32_t cycle = 0U; cycle < 200U; ++cycle) {
    const auto installed =
        backend.install_fast(target, reinterpret_cast<void*>(&getpid_replacement));
    REQUIRE(installed.installed());
    getpid_original = reinterpret_cast<GetpidFunction>(installed.original);
    REQUIRE(::getpid() == expected_pid);
    REQUIRE(backend.uninstall(target) == noleax::agent::HookUninstallStatus::kUninstalled);
  }
  CHECK(backend.installed_count() == 0U);
  CHECK_FALSE(backend.has_pending_teardown());
  CHECK(backend.shutdown());
}

TEST_CASE("hook backend rehooks a fixture module across dlclose reload cycles",
          "[agent][hook-backend][posix]") {
  constexpr std::uint64_t left = 0x123456789abcdef0ULL;
  constexpr std::uint64_t right = 0x0fedcba987654321ULL;

  for (std::uint32_t cycle = 0U; cycle < 10U; ++cycle) {
    void* const module = dlopen(NOLEAX_HOOK_FIXTURE_PATH, RTLD_NOW | RTLD_LOCAL);
    REQUIRE(module != nullptr);
    const auto target =
        reinterpret_cast<FixtureFunction>(dlsym(module, "noleax_hook_fixture_transform"));
    REQUIRE(target != nullptr);
    const std::uint64_t baseline = target(left, right);

    noleax::agent::HookBackend backend;
    reload_original = nullptr;
    const auto installed = backend.install_fast(reinterpret_cast<void*>(target),
                                                reinterpret_cast<void*>(&reload_replacement));
    REQUIRE(installed.installed());
    reload_original = reinterpret_cast<FixtureFunction>(installed.original);
    CHECK(target(left, right) == (baseline ^ 0xffULL));
    CHECK(reload_replacement_calls.load(std::memory_order_relaxed) >= cycle + 1U);
    REQUIRE(backend.uninstall(reinterpret_cast<void*>(target)) ==
            noleax::agent::HookUninstallStatus::kUninstalled);
    CHECK(target(left, right) == baseline);
    CHECK(backend.shutdown());
    dlclose(module);
  }
}

TEST_CASE("hook backend forced relocation installs on glibc text", "[agent][hook-backend][posix]") {
  const LoadedLibc libc;
  void* const target = libc.symbol("getpid");
  const pid_t expected_pid = ::getpid();

  noleax::agent::HookBackend backend;
  const auto installed =
      backend.install_fast_forced(target, reinterpret_cast<void*>(&getpid_replacement));
  REQUIRE(installed.installed());
  getpid_original = reinterpret_cast<GetpidFunction>(installed.original);
  CHECK(::getpid() == expected_pid);
  CHECK(getpid_replacement_calls.load(std::memory_order_acquire) > 0U);
  CHECK(backend.uninstall(target) == noleax::agent::HookUninstallStatus::kUninstalled);
  CHECK(::getpid() == expected_pid);
  CHECK(backend.shutdown());
}

TEST_CASE("hook backend covers the glibc hook profile target matrix",
          "[agent][hook-backend][posix]") {
  const LoadedLibc libc;

  struct TargetEntry {
    const char* name;
    void* replacement;
    noleax::agent::OriginalTrampolineSlot* slot;
  };
  const TargetEntry targets[] = {
      {"malloc", reinterpret_cast<void*>(&matrix_malloc), &matrix_malloc_slot},
      {"free", reinterpret_cast<void*>(&matrix_free), &matrix_free_slot},
      {"calloc", reinterpret_cast<void*>(&matrix_calloc), &matrix_calloc_slot},
      {"realloc", reinterpret_cast<void*>(&matrix_realloc), &matrix_realloc_slot},
      {"posix_memalign", reinterpret_cast<void*>(&matrix_posix_memalign),
       &matrix_posix_memalign_slot},
      {"aligned_alloc", reinterpret_cast<void*>(&matrix_aligned_alloc), &matrix_aligned_alloc_slot},
      {"memalign", reinterpret_cast<void*>(&matrix_memalign), &matrix_memalign_slot},
      {"valloc", reinterpret_cast<void*>(&matrix_valloc), &matrix_valloc_slot},
      {"reallocarray", reinterpret_cast<void*>(&matrix_reallocarray), &matrix_reallocarray_slot},
      {"strdup", reinterpret_cast<void*>(&matrix_strdup), &matrix_strdup_slot},
      {"munmap", reinterpret_cast<void*>(&matrix_munmap), &matrix_munmap_slot},
  };

  for (const TargetEntry& entry : targets) {
    void* const target = libc.symbol(entry.name);
    CAPTURE(entry.name);

    noleax::agent::HookBackend backend;
    const auto installed = backend.install_fast(target, entry.replacement, entry.slot);
    REQUIRE(installed.installed());

    // One real call through the patched entry, exercising the replacement and the original
    // trampoline with valid arguments.
    const std::uint64_t calls_before = matrix_replacement_calls.load(std::memory_order_acquire);
    if (std::strcmp(entry.name, "malloc") == 0) {
      void* const p = std::malloc(1000U);
      REQUIRE(p != nullptr);
      std::free(p);
    } else if (std::strcmp(entry.name, "free") == 0) {
      void* const p = std::malloc(64U);
      REQUIRE(p != nullptr);
      opaque_sink = p;
      std::free(p);
    } else if (std::strcmp(entry.name, "calloc") == 0) {
      void* const p = std::calloc(4U, 250U);
      REQUIRE(p != nullptr);
      std::free(p);
    } else if (std::strcmp(entry.name, "realloc") == 0) {
      void* const p = std::realloc(std::malloc(64U), 4096U);
      REQUIRE(p != nullptr);
      std::free(p);
    } else if (std::strcmp(entry.name, "posix_memalign") == 0) {
      void* p = nullptr;
      REQUIRE(::posix_memalign(&p, 64U, 1000U) == 0);
      REQUIRE(p != nullptr);
      std::free(p);
    } else if (std::strcmp(entry.name, "aligned_alloc") == 0) {
      void* const p = ::aligned_alloc(64U, 1024U);
      REQUIRE(p != nullptr);
      std::free(p);
    } else if (std::strcmp(entry.name, "memalign") == 0) {
      void* const p = ::memalign(64U, 1000U);
      REQUIRE(p != nullptr);
      std::free(p);
    } else if (std::strcmp(entry.name, "valloc") == 0) {
      void* const p = ::valloc(1000U);
      REQUIRE(p != nullptr);
      std::free(p);
    } else if (std::strcmp(entry.name, "reallocarray") == 0) {
      void* const p = ::reallocarray(std::malloc(10U), 8U, 512U);
      REQUIRE(p != nullptr);
      std::free(p);
    } else if (std::strcmp(entry.name, "strdup") == 0) {
      char* const p = ::strdup("noleax");
      REQUIRE(p != nullptr);
      REQUIRE(std::strcmp(p, "noleax") == 0);
      std::free(p);
    } else if (std::strcmp(entry.name, "munmap") == 0) {
      void* const p =
          ::mmap(nullptr, 4096U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      REQUIRE(p != MAP_FAILED);
      REQUIRE(::munmap(p, 4096U) == 0);
    }
    CHECK(matrix_replacement_calls.load(std::memory_order_acquire) > calls_before);

    CHECK(backend.uninstall(target) == noleax::agent::HookUninstallStatus::kUninstalled);
    CHECK(backend.shutdown());
  }
}
