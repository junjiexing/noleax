// Hot-path probe for the Linux stack capture (docs/LINUX_PORT_PLAN.md M2, risk R3):
// proves that _Unwind_Backtrace captures (a) never allocate in steady state, and
// (b) do not deadlock against the dynamic loader lock while a hooked malloc is active.

#include <dlfcn.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/linux/stack_capture.hpp"

namespace {

std::atomic<unsigned long> alloc_calls{0U};

extern "C" {
void* __libc_malloc(size_t);
void* __libc_calloc(size_t, size_t);
void* __libc_realloc(void*, size_t);
void __libc_free(void*);
}

}  // namespace

// Interpose allocation for this statically-linked probe so libgcc/libc allocation during
// a capture is observable. Passthrough goes to the __libc_* entry points directly.
extern "C" void* malloc(size_t n) {
  alloc_calls.fetch_add(1U, std::memory_order_relaxed);
  return __libc_malloc(n);
}
extern "C" void* calloc(size_t a, size_t b) {
  alloc_calls.fetch_add(1U, std::memory_order_relaxed);
  return __libc_calloc(a, b);
}
extern "C" void* realloc(void* p, size_t n) {
  alloc_calls.fetch_add(1U, std::memory_order_relaxed);
  return __libc_realloc(p, n);
}
extern "C" void free(void* p) { __libc_free(p); }

namespace {

using noleax::agent::linux::capture_current_stack;
using noleax::agent::linux::CapturedStack;
using noleax::agent::linux::stack_capture_succeeded;

noleax::agent::OriginalTrampolineSlot malloc_original{nullptr};
std::atomic<unsigned long> hooked_captures{0U};
std::atomic<unsigned long> capture_failures{0U};

using MallocFn = void* (*)(size_t);

// The real hot path, emulated: every malloc goes through a replacement that captures a
// stack before delegating to the original.
__attribute__((noinline)) void* malloc_replacement(size_t size) {
  CapturedStack stack;
  capture_current_stack(stack, 32U, 1U);
  if (stack_capture_succeeded(stack)) {
    hooked_captures.fetch_add(1U, std::memory_order_relaxed);
  } else {
    capture_failures.fetch_add(1U, std::memory_order_relaxed);
  }
  return reinterpret_cast<MallocFn>(malloc_original.load(std::memory_order_acquire))(size);
}

std::atomic<bool> stop_flag{false};

void allocation_worker() {
  while (!stop_flag.load(std::memory_order_acquire)) {
    void* const p = std::malloc(256U);
    std::free(p);
  }
}

void loader_worker() {
  while (!stop_flag.load(std::memory_order_acquire)) {
    void* const module = dlopen(NOLEAX_HOOK_FIXTURE_PATH, RTLD_NOW | RTLD_LOCAL);
    if (module != nullptr) {
      dlclose(module);
    }
  }
}

}  // namespace

int main() {
  // Warm up the unwinder, then prove steady-state captures never allocate.
  CapturedStack warm;
  capture_current_stack(warm, 64U);
  const unsigned long before = alloc_calls.load();
  unsigned long depth_sink = 0U;
  for (unsigned i = 0U; i < 10000U; ++i) {
    CapturedStack stack;
    capture_current_stack(stack, 32U);
    depth_sink += stack.frame_count;
  }
  const unsigned long capture_allocs = alloc_calls.load() - before;
  std::printf("steady-state: 10000 captures, allocs=%lu, avg depth=%.1f\n", capture_allocs,
              static_cast<double>(depth_sink) / 10000.0);
  if (capture_allocs != 0U || depth_sink == 0U) {
    std::printf("FAIL: captures allocate or capture nothing\n");
    return 1;
  }

  // Hook malloc, then run allocation workers against a loader-lock churn worker. A
  // deadlock against _dl_find_object/loader lock would hang this process; ctest's
  // TIMEOUT turns a hang into a failure.
  void* const libc = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
  if (libc == nullptr) {
    std::printf("FAIL: cannot open libc.so.6\n");
    return 1;
  }
  void* const target = dlsym(libc, "malloc");
  if (target == nullptr) {
    return 1;
  }

  noleax::agent::HookBackend backend;
  const auto installed =
      backend.install_fast(target, reinterpret_cast<void*>(&malloc_replacement), &malloc_original);
  if (!installed.installed()) {
    std::printf("FAIL: malloc hook install\n");
    return 1;
  }

  std::thread alloc_a{allocation_worker};
  std::thread alloc_b{allocation_worker};
  std::thread churn{loader_worker};
  std::this_thread::sleep_for(std::chrono::seconds{2});
  stop_flag.store(true, std::memory_order_release);
  alloc_a.join();
  alloc_b.join();
  churn.join();

  const auto uninstalled = backend.uninstall(target);
  if (uninstalled != noleax::agent::HookUninstallStatus::kUninstalled) {
    std::printf("FAIL: malloc hook uninstall\n");
    return 1;
  }
  static_cast<void>(backend.shutdown());

  std::printf("hooked path: captures=%lu failures=%lu\n", hooked_captures.load(),
              capture_failures.load());
  if (hooked_captures.load() == 0U) {
    std::printf("FAIL: no hooked captures happened\n");
    return 1;
  }
  std::printf("OK\n");
  return 0;
}
