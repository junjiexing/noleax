// End-to-end probe for the Linux custom symbol hooks (docs/CUSTOM_HOOKS.md,
// docs/LINUX_PORT_PLAN.md M7): builds a tiny fixture shared library with the system
// compiler, declares its my_* allocator entry points as custom hook points, installs
// LinuxCustomSymbolHooks on this process, and proves the adapter contract in-process —
// SysV argument mapping (size/ptr/result_arg/calloc/free_size_arg), export and RVA
// locators, wait_module polling, event field mapping, errno preservation, recursion
// suppression, counter conservation, per-point failure degradation, stop/uninstall
// silence, and multi-threaded churn. Standalone main, exit 0/1.

#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/linux/custom_symbol_hooks.hpp"
#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/agent/linux/stack_capture.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/trace/custom_hook.hpp"
#include "noleax/trace/identifiers.hpp"

namespace {

using noleax::agent::linux::LinuxCustomHookApiCounters;
using noleax::agent::linux::LinuxCustomSymbolHooks;
using noleax::agent::linux::LinuxHeapEvent;
using noleax::agent::linux::LinuxHeapEventOperation;
using noleax::agent::linux::LinuxHeapEventQueue;
using noleax::agent::linux::LinuxHeapEventStatus;
using noleax::agent::linux::stack_capture_succeeded;
using noleax::ipc::CustomHookLocator;
using noleax::ipc::CustomHookSpec;

unsigned check_failures = 0;

void check(bool condition, const char* message) {
  if (!condition) {
    std::printf("FAIL: %s\n", message);
    ++check_failures;
  }
}

std::uint64_t as_u64(const void* pointer) {
  return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(pointer));
}

std::size_t drain_events(LinuxHeapEventQueue& queue, std::vector<LinuxHeapEvent>& out) {
  LinuxHeapEvent event;
  const std::size_t before = out.size();
  while (queue.try_pop(event)) {
    out.push_back(event);
  }
  return out.size() - before;
}

// The fixture allocator: thin wrappers over the libc heap with a 16-byte header word so
// the block shapes differ from plain malloc. my_realloc/my_free_sized keep the size in
// argument 0 and the pointer in argument 1 (one shared slot pair serves every role through
// the per-role argument fields); my_malloc_nested deliberately calls the exported
// my_malloc to exercise recursion suppression. Written to a file and compiled by the
// probe with the system compiler.
const char kFixtureSource[] = R"FIXTURE(
#include <cerrno>
#include <cstdint>
#include <cstdlib>

namespace {
constexpr std::uint64_t kBlockMagic = UINT64_C(0x4e4c5850524f4245);
struct BlockHeader {
  std::uint64_t magic;
  std::uint64_t size;
};

void* raw_alloc(std::size_t size) {
  if (size > SIZE_MAX - sizeof(BlockHeader)) {
    errno = ENOMEM;
    return nullptr;
  }
  auto* base = static_cast<BlockHeader*>(std::malloc(size + sizeof(BlockHeader)));
  if (base == nullptr) {
    return nullptr;
  }
  base->magic = kBlockMagic;
  base->size = size;
  return base + 1;
}

void raw_free(void* ptr) {
  if (ptr == nullptr) {
    return;
  }
  auto* base = static_cast<BlockHeader*>(ptr) - 1;
  if (base->magic != kBlockMagic) {
    std::abort();
  }
  std::free(base);
}
}  // namespace

extern "C" {

__attribute__((noinline)) void* my_malloc(std::size_t size) { return raw_alloc(size); }

void* my_realloc(std::size_t size, void* ptr) {
  if (ptr == nullptr) {
    return raw_alloc(size);
  }
  if (size == 0) {
    raw_free(ptr);
    return nullptr;
  }
  if (size > SIZE_MAX - sizeof(BlockHeader)) {
    errno = ENOMEM;
    return nullptr;
  }
  auto* base = static_cast<BlockHeader*>(ptr) - 1;
  if (base->magic != kBlockMagic) {
    std::abort();
  }
  auto* next = static_cast<BlockHeader*>(std::realloc(base, size + sizeof(BlockHeader)));
  if (next == nullptr) {
    return nullptr;
  }
  next->magic = kBlockMagic;
  next->size = size;
  return next + 1;
}

void my_free_sized(std::size_t size, void* ptr) {
  (void)size;  // declared as free_size_arg; the block header stays authoritative
  raw_free(ptr);
}

void* my_calloc(std::size_t count, std::size_t size) {
  if (count != 0U && size > SIZE_MAX / count) {
    errno = ENOMEM;
    return nullptr;
  }
  const std::size_t total = count * size;
  if (total > SIZE_MAX - sizeof(BlockHeader)) {
    errno = ENOMEM;
    return nullptr;
  }
  auto* base = static_cast<BlockHeader*>(std::calloc(1U, total + sizeof(BlockHeader)));
  if (base == nullptr) {
    return nullptr;
  }
  base->magic = kBlockMagic;
  base->size = total;
  return base + 1;
}

void my_free_plain(void* ptr) { raw_free(ptr); }

int my_alloc_out(void** out, std::size_t size) {
  void* result = raw_alloc(size);
  *out = result;
  return result == nullptr ? ENOMEM : 0;
}

void my_free_out(void* ptr) { raw_free(ptr); }

void* my_rva_alloc(std::size_t size) { return raw_alloc(size); }

void my_rva_free(void* ptr) { raw_free(ptr); }

__attribute__((noinline)) void* my_malloc_nested(std::size_t size) {
  void* result = my_malloc(size);
  if (result == nullptr) {
    errno = ENOMEM;
  }
  return result;
}

void my_free_nested(void* ptr) { raw_free(ptr); }

// Wide-signature pair: the size rides in argument 6 and the pointer in argument 7, both
// passed in the caller's stack frame under the System V AMD64 ABI.
void* my_malloc_wide(void* a0, void* a1, void* a2, void* a3, void* a4, void* a5,
                     std::size_t size, void* a7) {
  (void)a0;
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;
  (void)a7;
  return raw_alloc(size);
}

void my_free_wide(void* a0, void* a1, void* a2, void* a3, void* a4, void* a5,
                  std::size_t size, void* ptr) {
  (void)a0;
  (void)a1;
  (void)a2;
  (void)a3;
  (void)a4;
  (void)a5;
  (void)size;
  raw_free(ptr);
}

}  // extern "C"
)FIXTURE";

using MyMalloc = void* (*)(std::size_t);
using MyRealloc = void* (*)(std::size_t, void*);
using MyFreeSized = void (*)(std::size_t, void*);
using MyCalloc = void* (*)(std::size_t, std::size_t);
using MyFreePlain = void (*)(void*);
using MyAllocOut = int (*)(void**, std::size_t);
using MyFreeOut = void (*)(void*);
using MyRvaAlloc = void* (*)(std::size_t);
using MyRvaFree = void (*)(void*);
using MyMallocNested = void* (*)(std::size_t);
using MyFreeNested = void (*)(void*);
using MyMallocWide = void* (*)(void*, void*, void*, void*, void*, void*, std::size_t, void*);
using MyFreeWide = void (*)(void*, void*, void*, void*, void*, void*, std::size_t, void*);

[[nodiscard]] void* export_address(void* module, const char* name) {
  void* const address = ::dlsym(module, name);
  if (address == nullptr) {
    std::printf("FAIL: dlsym %s\n", name);
    ++check_failures;
  }
  return address;
}

// Lowest mapping start of the given absolute path in /proc/self/maps; 0 when absent.
[[nodiscard]] std::uint64_t module_base_from_maps(const std::string& path) {
  std::FILE* const maps = std::fopen("/proc/self/maps", "re");
  if (maps == nullptr) {
    return 0U;
  }
  std::uint64_t base = 0U;
  std::array<char, 4096U> line{};
  while (std::fgets(line.data(), static_cast<int>(line.size()), maps) != nullptr) {
    if (std::strstr(line.data(), path.c_str()) == nullptr) {
      continue;
    }
    const std::uint64_t start = static_cast<std::uint64_t>(std::strtoull(line.data(), nullptr, 16));
    if (base == 0U || start < base) {
      base = start;
    }
  }
  std::fclose(maps);
  return base;
}

struct ExpectedEvent {
  std::uint32_t api_id;
  LinuxHeapEventOperation operation;
  std::uint64_t requested_size;
  std::uint64_t count;
  std::uint64_t address;
  std::uint64_t result_address;
  LinuxHeapEventStatus status;
  std::uint32_t operation_result;
};

void verify_event(const LinuxHeapEvent& event, const ExpectedEvent& expected,
                  std::uint64_t expected_sequence, std::uint64_t main_thread_id,
                  std::uint16_t stack_depth) {
  if (event.api_id != expected.api_id || event.operation != expected.operation ||
      event.requested_size != expected.requested_size || event.count != expected.count ||
      event.address != expected.address || event.result_address != expected.result_address ||
      event.status != expected.status || event.operation_result != expected.operation_result) {
    std::printf(
        "FAIL: event seq=%llu api=%u op=%u size=%llu count=%llu addr=%llu result=%llu "
        "status=%u op_result=%u\n",
        static_cast<unsigned long long>(event.queue_sequence), static_cast<unsigned>(event.api_id),
        static_cast<unsigned>(event.operation),
        static_cast<unsigned long long>(event.requested_size),
        static_cast<unsigned long long>(event.count),
        static_cast<unsigned long long>(event.address),
        static_cast<unsigned long long>(event.result_address), static_cast<unsigned>(event.status),
        static_cast<unsigned>(event.operation_result));
    ++check_failures;
    return;
  }
  check(event.queue_sequence == expected_sequence, "queue sequence is not contiguous");
  check(event.thread_id == main_thread_id, "event thread id matches the caller thread");
  check(event.monotonic_ticks != 0U, "event carries monotonic ticks");
  check(event.requested_address == 0U && event.alignment == 0U && event.protection == 0U &&
            event.map_flags == 0U && event.section_handle == 0U && event.section_offset == 0U,
        "custom event heap/VM fields stay zero");
  check(event.stack.requested_depth == stack_depth, "event stack requested depth");
  check(stack_capture_succeeded(event.stack), "event stack captured");
  check(event.stack.frame_count <= stack_depth, "event stack depth within the requested limit");
}

struct FixtureApi {
  MyMalloc my_malloc{nullptr};
  MyRealloc my_realloc{nullptr};
  MyFreeSized my_free_sized{nullptr};
  MyCalloc my_calloc{nullptr};
  MyFreePlain my_free_plain{nullptr};
};

struct ChurnResult {
  std::uint64_t operations{0U};
};

void churn_worker(std::uint64_t seed, std::uint64_t iterations, const FixtureApi* api,
                  ChurnResult* result) {
  std::uint64_t state = seed;
  void* pointer = nullptr;
  std::size_t pointer_size = 0U;
  for (std::uint64_t i = 0U; i < iterations; ++i) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    const std::size_t size = 512U + static_cast<std::size_t>((state >> 33U) % 4096U);
    switch (state % 4U) {
      case 0U:
        api->my_free_sized(pointer_size, pointer);
        pointer = api->my_malloc(size);
        pointer_size = size;
        break;
      case 1U: {
        void* const next = api->my_realloc(size, pointer);
        if (next != nullptr) {
          pointer = next;
          pointer_size = size;
        }
        break;
      }
      case 2U:
        // Every fixture block carries the same header, so any free variant releases it.
        api->my_free_sized(pointer_size, pointer);
        pointer = api->my_calloc(2U, size / 2U);
        pointer_size = size;
        break;
      default:
        api->my_free_sized(pointer_size, pointer);
        pointer = nullptr;
        pointer_size = 0U;
        break;
    }
    if (pointer != nullptr) {
      static_cast<unsigned char*>(pointer)[0] = static_cast<unsigned char>(i);
      ++result->operations;
    }
  }
  api->my_free_sized(pointer_size, pointer);
}

[[nodiscard]] CustomHookSpec make_point(const char* module, const char* label) {
  CustomHookSpec spec;
  spec.module = module;
  spec.label = label;
  spec.wait_module_ms = 5'000U;
  return spec;
}

}  // namespace

int main() {
  std::printf("linux_custom_hooks_probe\n");

  // ---- fixture build ----
  char directory[] = "/tmp/nlxchookXXXXXX";
  if (::mkdtemp(directory) == nullptr) {
    std::printf("FAIL: mkdtemp\n");
    return 1;
  }
  const std::string source_path = std::string{directory} + "/fixture.cpp";
  const std::string module_path = std::string{directory} + "/libnlxprobealloc.so";
  const std::string module_name = "libnlxprobealloc.so";
  {
    std::FILE* const source = std::fopen(source_path.c_str(), "we");
    if (source == nullptr) {
      std::printf("FAIL: fixture source open\n");
      return 1;
    }
    const std::size_t written =
        std::fwrite(kFixtureSource, 1U, sizeof(kFixtureSource) - 1U, source);
    std::fclose(source);
    if (written != sizeof(kFixtureSource) - 1U) {
      std::printf("FAIL: fixture source write\n");
      return 1;
    }
  }
  const std::string compile_command =
      "g++ -shared -fPIC -O1 -fno-inline -o " + module_path + " " + source_path;
  if (std::system(compile_command.c_str()) != 0) {
    std::printf("FAIL: fixture compile\n");
    return 1;
  }

  // ---- RVA pre-pass: file-relative offsets of the rva-located role pair ----
  std::uint64_t rva_alloc = 0U;
  std::uint64_t rva_free = 0U;
  {
    void* const preopen = ::dlopen(module_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    check(preopen != nullptr, "pre-pass dlopen");
    if (preopen == nullptr) {
      return 1;
    }
    void* const rva_alloc_address = ::dlsym(preopen, "my_rva_alloc");
    void* const rva_free_address = ::dlsym(preopen, "my_rva_free");
    const std::uint64_t pre_base = module_base_from_maps(module_path);
    check(pre_base != 0U, "pre-pass module visible in maps");
    if (rva_alloc_address == nullptr || rva_free_address == nullptr || pre_base == 0U) {
      std::printf("FAIL: rva pre-pass symbols\n");
      return 1;
    }
    rva_alloc = as_u64(rva_alloc_address) - pre_base;
    rva_free = as_u64(rva_free_address) - pre_base;
    check(::dlclose(preopen) == 0, "pre-pass dlclose");
    check(module_base_from_maps(module_path) == 0U, "fixture unloaded after the pre-pass");
  }

  // ---- declaration: five good points plus one with a bad alloc export ----
  std::vector<CustomHookSpec> specs;
  CustomHookSpec point0 = make_point(module_name.c_str(), "my_malloc");
  point0.alloc.locator = CustomHookLocator::kExport;
  point0.alloc.export_name = "my_malloc";
  point0.realloc.locator = CustomHookLocator::kExport;
  point0.realloc.export_name = "my_realloc";
  point0.free.locator = CustomHookLocator::kExport;
  point0.free.export_name = "my_free_sized";
  point0.alloc_size_arg = 0U;
  point0.realloc_size_arg = 0U;
  point0.realloc_ptr_arg = 1U;
  point0.free_ptr_arg = 1U;
  point0.free_size_arg = 0U;
  specs.push_back(point0);

  CustomHookSpec point1 = make_point(module_name.c_str(), "my_calloc");
  point1.alloc.locator = CustomHookLocator::kExport;
  point1.alloc.export_name = "my_calloc";
  point1.free.locator = CustomHookLocator::kExport;
  point1.free.export_name = "my_free_plain";
  point1.calloc = true;
  point1.alloc_count_arg = 0U;
  point1.alloc_size_arg = 1U;
  specs.push_back(point1);

  CustomHookSpec point2 = make_point(module_name.c_str(), "my_alloc_out");
  point2.alloc.locator = CustomHookLocator::kExport;
  point2.alloc.export_name = "my_alloc_out";
  point2.free.locator = CustomHookLocator::kExport;
  point2.free.export_name = "my_free_out";
  point2.result_arg = 0U;
  point2.alloc_size_arg = 1U;
  specs.push_back(point2);

  CustomHookSpec point3 = make_point(module_name.c_str(), "my_rva_alloc");
  point3.alloc.locator = CustomHookLocator::kRva;
  point3.alloc.rva = rva_alloc;
  point3.free.locator = CustomHookLocator::kRva;
  point3.free.rva = rva_free;
  specs.push_back(point3);

  CustomHookSpec point4 = make_point(module_name.c_str(), "my_malloc_nested");
  point4.alloc.locator = CustomHookLocator::kExport;
  point4.alloc.export_name = "my_malloc_nested";
  point4.free.locator = CustomHookLocator::kExport;
  point4.free.export_name = "my_free_nested";
  specs.push_back(point4);

  CustomHookSpec point5 = make_point(module_name.c_str(), "broken");
  point5.alloc.locator = CustomHookLocator::kExport;
  point5.alloc.export_name = "my_missing_export";
  point5.free.locator = CustomHookLocator::kExport;
  point5.free.export_name = "my_free_plain";
  specs.push_back(point5);

  // A module that never loads: its 300 ms wait expires and the whole point fails while
  // the good points around it still install.
  CustomHookSpec point6 = make_point("libnlx_missing_never.so", "never_loaded");
  point6.wait_module_ms = 300U;
  point6.alloc.locator = CustomHookLocator::kExport;
  point6.alloc.export_name = "never_alloc";
  point6.free.locator = CustomHookLocator::kExport;
  point6.free.export_name = "never_free";
  specs.push_back(point6);

  // Stack-passed argument slots: size in argument 6, pointer in argument 7.
  CustomHookSpec point7 = make_point(module_name.c_str(), "my_malloc_wide");
  point7.alloc.locator = CustomHookLocator::kExport;
  point7.alloc.export_name = "my_malloc_wide";
  point7.free.locator = CustomHookLocator::kExport;
  point7.free.export_name = "my_free_wide";
  point7.alloc_size_arg = 6U;
  point7.free_ptr_arg = 7U;
  point7.free_size_arg = 6U;
  specs.push_back(point7);

  constexpr std::size_t kQueueCapacity = 1024U;
  constexpr std::uint16_t kStackDepth = 32U;
  constexpr std::uint64_t kMinCaptureSize = 256U;
  constexpr std::size_t kPointCount = 8U;

  // The module is absent when install starts; a sleeper loads it after 150 ms so the
  // install pass exercises the wait_module polling path for every point.
  std::atomic<void*> module_handle{nullptr};
  std::thread loader([&module_handle, &module_path] {
    std::this_thread::sleep_for(std::chrono::milliseconds{150});
    module_handle.store(::dlopen(module_path.c_str(), RTLD_NOW | RTLD_LOCAL),
                        std::memory_order_release);
  });

  noleax::agent::HookBackend backend;
  LinuxHeapEventQueue queue{kQueueCapacity};
  LinuxCustomSymbolHooks hooks{backend, queue, std::move(specs), kStackDepth, kMinCaptureSize};

  const auto install_begin = std::chrono::steady_clock::now();
  const bool installed = hooks.install();
  const auto install_elapsed = std::chrono::steady_clock::now() - install_begin;
  loader.join();
  check(installed, "install pass ran");
  check(module_handle.load(std::memory_order_acquire) != nullptr, "sleeper dlopen");
  void* const module = module_handle.load(std::memory_order_relaxed);
  if (module == nullptr) {
    return 1;
  }
  check(install_elapsed >= std::chrono::milliseconds{100},
        "install waited for the module to appear");
  check(hooks.is_installed(), "profile is installed (good points are live)");
  check(hooks.is_recording(), "profile is recording after install");
  check(hooks.point_count() == kPointCount, "point count");
  bool api_ids_match = true;
  for (std::size_t index = 0U; index < kPointCount; ++index) {
    api_ids_match =
        api_ids_match && hooks.point_api_id(index) == noleax::trace::kCustomHookApiIdBase +
                                                          static_cast<noleax::trace::ApiId>(index);
  }
  check(api_ids_match, "point api ids are kCustomHookApiIdBase + index");

  // ---- per-point failure degradation: the bad export and the never-loaded module are
  // recorded, the remaining points installed ----
  check(hooks.failures().size() == 2U, "exactly two points failed to install");
  if (hooks.failures().size() == 2U) {
    const noleax::trace::CustomHookFailure& export_failure = hooks.failures()[0];
    check(export_failure.module == module_name, "failure names the fixture module");
    check(export_failure.role == noleax::trace::CustomHookFailureRole::kAlloc,
          "failure role is alloc");
    check(export_failure.reason == noleax::trace::CustomHookFailureReason::kExportNotFound,
          "failure reason is export-not-found");
    check(export_failure.detail.find("my_missing_export") != std::string::npos,
          "failure detail names the missing export");
    const noleax::trace::CustomHookFailure& module_failure = hooks.failures()[1];
    check(module_failure.module == "libnlx_missing_never.so",
          "failure names the never-loaded module");
    check(module_failure.role == noleax::trace::CustomHookFailureRole::kPoint,
          "module failure covers the whole point");
    check(module_failure.reason == noleax::trace::CustomHookFailureReason::kModuleNotLoaded,
          "failure reason is module-not-loaded");
  }
  check(hooks.definitions().size() == kPointCount, "definition count");
  if (hooks.definitions().size() == kPointCount) {
    check(hooks.definitions()[0].label == "my_malloc" &&
              hooks.definitions()[3].label == "my_rva_alloc" &&
              hooks.definitions()[4].module_name == module_name,
          "definitions carry module and label");
  }

  // dlsym casts stay object pointers until the call site, matching the agent's idiom.
  const auto my_malloc = reinterpret_cast<MyMalloc>(export_address(module, "my_malloc"));
  const auto my_realloc = reinterpret_cast<MyRealloc>(export_address(module, "my_realloc"));
  const auto my_free_sized = reinterpret_cast<MyFreeSized>(export_address(module, "my_free_sized"));
  const auto my_calloc = reinterpret_cast<MyCalloc>(export_address(module, "my_calloc"));
  const auto my_free_plain = reinterpret_cast<MyFreePlain>(export_address(module, "my_free_plain"));
  const auto my_alloc_out = reinterpret_cast<MyAllocOut>(export_address(module, "my_alloc_out"));
  const auto my_free_out = reinterpret_cast<MyFreeOut>(export_address(module, "my_free_out"));
  const auto my_rva_alloc = reinterpret_cast<MyRvaAlloc>(export_address(module, "my_rva_alloc"));
  const auto my_rva_free = reinterpret_cast<MyRvaFree>(export_address(module, "my_rva_free"));
  const auto my_malloc_nested =
      reinterpret_cast<MyMallocNested>(export_address(module, "my_malloc_nested"));
  const auto my_free_nested =
      reinterpret_cast<MyFreeNested>(export_address(module, "my_free_nested"));
  const auto my_malloc_wide =
      reinterpret_cast<MyMallocWide>(export_address(module, "my_malloc_wide"));
  const auto my_free_wide = reinterpret_cast<MyFreeWide>(export_address(module, "my_free_wide"));
  if (my_malloc == nullptr || my_realloc == nullptr || my_free_sized == nullptr ||
      my_calloc == nullptr || my_free_plain == nullptr || my_alloc_out == nullptr ||
      my_free_out == nullptr || my_rva_alloc == nullptr || my_rva_free == nullptr ||
      my_malloc_nested == nullptr || my_free_nested == nullptr || my_malloc_wide == nullptr ||
      my_free_wide == nullptr) {
    return 1;  // the missing dlsym already counted a failure; the dtor uninstalls safely
  }

  const std::uint64_t main_tid = static_cast<std::uint64_t>(::syscall(SYS_gettid));

  std::vector<LinuxHeapEvent> events_a;
  std::vector<LinuxHeapEvent> events_b;
  std::vector<LinuxHeapEvent> events_c;
  events_a.reserve(64U);
  events_b.reserve(4096U);
  events_c.reserve(16U);

  // ---- scripted sequence (phase A) ----
  // The dlsym'd call targets are opaque to the compiler, so no call can be folded or
  // rerouted around the hooked entry points. Nothing else in this process calls the
  // fixture functions, so the drained events must match the script exactly.
  errno = EDOM;
  void* const a1 = my_malloc(0x120U);
  const int errno_after_a1 = errno;
  std::memset(a1, 0x11, 0x120U);
  void* const a2 = my_malloc(24U);  // below the capture floor: filtered, no event
  std::memset(a2, 0x22, 24U);
  errno = 0;
  void* const a_fail = my_malloc(SIZE_MAX);
  const int errno_after_fail = errno;
  void* const r1 = my_realloc(0x300U, nullptr);
  std::memset(r1, 0x33, 0x300U);
  void* const r2 = my_realloc(0x600U, r1);
  std::memset(r2, 0x44, 0x600U);
  void* const r3 = my_realloc(0U, r2);  // frees r2, returns nullptr: a success
  my_free_sized(0x120U, a1);
  my_free_sized(24U, a2);
  void* const c1 = my_calloc(3U, 0x80U);
  bool calloc_zeroed = c1 != nullptr;
  if (c1 != nullptr) {
    const auto* const bytes = static_cast<const unsigned char*>(c1);
    for (std::size_t i = 0U; i < 3U * 0x80U; ++i) {
      calloc_zeroed = calloc_zeroed && bytes[i] == 0U;
    }
  }
  errno = 0;
  void* const c_overflow = my_calloc(0x7fffffffffffffffULL, 8U);
  const int errno_after_overflow = errno;
  my_free_plain(c1);
  void* out1 = nullptr;
  errno = EDOM;
  const int out1_result = my_alloc_out(&out1, 0x400U);
  const int errno_after_out1 = errno;
  std::memset(out1, 0x55, 0x400U);
  void* out2 = nullptr;
  errno = 0;
  const int out2_result = my_alloc_out(&out2, SIZE_MAX);
  const int errno_after_out2 = errno;
  my_free_out(out1);
  void* const v1 = my_rva_alloc(0x500U);
  std::memset(v1, 0x66, 0x500U);
  my_rva_free(v1);
  void* const n1 = my_malloc_nested(0x200U);
  std::memset(n1, 0x77, 0x200U);
  my_free_nested(n1);
  // Stack-slot argument mapping: size in slot 6, pointer in slot 7; the tag values in the
  // register slots are opaque padding the fixture never dereferences.
  const auto tag = [](std::uintptr_t value) { return reinterpret_cast<void*>(value); };
  void* const w1 =
      my_malloc_wide(tag(11U), tag(12U), tag(13U), tag(14U), tag(15U), tag(16U), 0x600U, tag(18U));
  std::memset(w1, 0x88, 0x600U);
  my_free_wide(tag(21U), tag(22U), tag(23U), tag(24U), tag(25U), tag(26U), 0x600U, w1);

  check(a1 != nullptr && a2 != nullptr, "scripted my_malloc calls succeed");
  check(errno_after_a1 == EDOM, "errno preserved across a successful custom alloc");
  check(a_fail == nullptr && errno_after_fail == ENOMEM, "failing my_malloc sets ENOMEM");
  check(r1 != nullptr && r2 != nullptr && r3 == nullptr, "my_realloc grow and free semantics");
  check(c1 != nullptr && calloc_zeroed, "my_calloc result is zeroed");
  check(c_overflow == nullptr && errno_after_overflow == ENOMEM, "my_calloc overflow fails");
  check(out1_result == 0 && out1 != nullptr, "my_alloc_out succeeds");
  check(errno_after_out1 == EDOM, "errno preserved across the out-param alloc");
  check(out2_result == ENOMEM && out2 == nullptr, "my_alloc_out failure reports through the code");
  check(errno_after_out2 == ENOMEM, "errno after the failing out-param alloc");
  check(v1 != nullptr, "rva-located alloc succeeds");
  check(n1 != nullptr, "nested alloc succeeds");
  check(w1 != nullptr, "stack-slot alloc succeeds");

  const std::size_t drained_a = drain_events(queue, events_a);

  if (drained_a == 19U) {
    const std::array<ExpectedEvent, 19U> expected{{
        {0x1000U, LinuxHeapEventOperation::kAllocate, 0x120U, 0U, 0U, as_u64(a1),
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1000U, LinuxHeapEventOperation::kAllocate, SIZE_MAX, 0U, 0U, 0U,
         LinuxHeapEventStatus::kFailure, static_cast<std::uint32_t>(ENOMEM)},
        {0x1000U, LinuxHeapEventOperation::kReallocate, 0x300U, 0U, 0U, as_u64(r1),
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1000U, LinuxHeapEventOperation::kReallocate, 0x600U, 0U, as_u64(r1), as_u64(r2),
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1000U, LinuxHeapEventOperation::kReallocate, 0U, 0U, as_u64(r2), 0U,
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1000U, LinuxHeapEventOperation::kFree, 0U, 0U, as_u64(a1), 0U,
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1000U, LinuxHeapEventOperation::kFree, 0U, 0U, as_u64(a2), 0U,
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1001U, LinuxHeapEventOperation::kAllocate, 0x180U, 3U, 0U, as_u64(c1),
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1001U, LinuxHeapEventOperation::kAllocate, 0U, 0x7fffffffffffffffULL, 0U, 0U,
         LinuxHeapEventStatus::kFailure, static_cast<std::uint32_t>(ENOMEM)},
        {0x1001U, LinuxHeapEventOperation::kFree, 0U, 0U, as_u64(c1), 0U,
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1002U, LinuxHeapEventOperation::kAllocate, 0x400U, 0U, 0U, as_u64(out1),
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1002U, LinuxHeapEventOperation::kAllocate, SIZE_MAX, 0U, 0U, 0U,
         LinuxHeapEventStatus::kFailure, static_cast<std::uint32_t>(ENOMEM)},
        {0x1002U, LinuxHeapEventOperation::kFree, 0U, 0U, as_u64(out1), 0U,
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1003U, LinuxHeapEventOperation::kAllocate, 0x500U, 0U, 0U, as_u64(v1),
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1003U, LinuxHeapEventOperation::kFree, 0U, 0U, as_u64(v1), 0U,
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1004U, LinuxHeapEventOperation::kAllocate, 0x200U, 0U, 0U, as_u64(n1),
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1004U, LinuxHeapEventOperation::kFree, 0U, 0U, as_u64(n1), 0U,
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1007U, LinuxHeapEventOperation::kAllocate, 0x600U, 0U, 0U, as_u64(w1),
         LinuxHeapEventStatus::kSuccess, 0U},
        {0x1007U, LinuxHeapEventOperation::kFree, 0U, 0U, as_u64(w1), 0U,
         LinuxHeapEventStatus::kSuccess, 0U},
    }};
    std::uint64_t previous_ticks = 0U;
    for (std::size_t index = 0U; index < events_a.size(); ++index) {
      verify_event(events_a[index], expected[index], static_cast<std::uint64_t>(index) + 1U,
                   main_tid, kStackDepth);
      check(events_a[index].monotonic_ticks >= previous_ticks,
            "monotonic ticks are non-decreasing");
      previous_ticks = events_a[index].monotonic_ticks;
    }
  } else {
    check(false, "phase A event count");
  }

  // Exact scripted-phase counters. The inner my_malloc of my_malloc_nested re-enters the
  // point-0 replacement with the guard held: recursive, unrecorded.
  struct ExpectedCounters {
    std::size_t point;
    std::uint64_t replacement;
    std::uint64_t recordable;
    std::uint64_t recursive;
    std::uint64_t successful;
    std::uint64_t failed;
    std::uint64_t filtered;
  };
  constexpr std::array<ExpectedCounters, kPointCount> expected_counters{{
      {0U, 9U, 8U, 1U, 7U, 1U, 1U},
      {1U, 3U, 3U, 0U, 2U, 1U, 0U},
      {2U, 3U, 3U, 0U, 2U, 1U, 0U},
      {3U, 2U, 2U, 0U, 2U, 0U, 0U},
      {4U, 2U, 2U, 0U, 2U, 0U, 0U},
      {5U, 0U, 0U, 0U, 0U, 0U, 0U},
      {6U, 0U, 0U, 0U, 0U, 0U, 0U},
      {7U, 2U, 2U, 0U, 2U, 0U, 0U},
  }};
  for (const ExpectedCounters& entry : expected_counters) {
    const LinuxCustomHookApiCounters counters = hooks.counters(entry.point);
    check(counters.replacement_calls == entry.replacement, "scripted replacement call count");
    check(counters.recordable_calls == entry.recordable, "scripted recordable call count");
    check(counters.recursive_calls == entry.recursive, "scripted recursive call count");
    check(counters.internal_calls == 0U, "no internal calls during the scripted phase");
    check(counters.successful_calls == entry.successful, "scripted successful call count");
    check(counters.failed_calls == entry.failed, "scripted failed call count");
    check(counters.filtered_calls == entry.filtered, "scripted filtered call count");
    check(counters.dropped_events == 0U, "no drops during the scripted phase");
  }

  // ---- multi-threaded churn (phase B) ----
  constexpr std::uint64_t kChurnIterations = 600U;
  const FixtureApi fixture_api{my_malloc, my_realloc, my_free_sized, my_calloc, my_free_plain};
  std::array<ChurnResult, 4> churn_results{};
  {
    std::array<std::thread, 4> workers;
    for (std::size_t index = 0U; index < workers.size(); ++index) {
      workers[index] = std::thread{churn_worker, 0x9e3779b97f4a7c15ULL * (index + 1U),
                                   kChurnIterations, &fixture_api, &churn_results[index]};
    }
    for (std::thread& worker : workers) {
      worker.join();
    }
  }
  const std::size_t drained_b = drain_events(queue, events_b);
  check(drained_b != 0U, "churn produced events");

  std::array<LinuxCustomHookApiCounters, kPointCount> pre_stop{};
  for (std::size_t index = 0U; index < kPointCount; ++index) {
    pre_stop[index] = hooks.counters(index);
  }

  check(hooks.stop_recording(), "stop_recording");
  check(!hooks.is_recording(), "profile is not recording after stop_recording");
  check(hooks.recording_in_flight_count() == 0U, "no recording calls in flight after stop");

  // kOriginal routing: the fixture still works, nothing is counted or queued.
  {
    void* const quiet = my_malloc(512U);
    std::memset(quiet, 0xee, 512U);
    my_free_sized(512U, quiet);
  }
  const std::size_t drained_c = drain_events(queue, events_c);

  std::array<LinuxCustomHookApiCounters, kPointCount> post_stop{};
  for (std::size_t index = 0U; index < kPointCount; ++index) {
    post_stop[index] = hooks.counters(index);
  }

  check(hooks.uninstall(), "uninstall");
  check(!hooks.is_installed(), "profile is uninstalled");
  check(!hooks.has_pending_teardown(), "no pending teardown after uninstall");

  // Post-uninstall: the original fixture entry points are fully restored.
  {
    void* const after = my_malloc(256U);
    check(after != nullptr, "post-uninstall my_malloc succeeds");
    std::memset(after, 0x5a, 256U);
    void* const grown = my_realloc(1024U, after);
    check(grown != nullptr, "post-uninstall my_realloc succeeds");
    my_free_sized(1024U, grown);
  }
  const std::size_t drained_d = drain_events(queue, events_c);

  check(drained_c == 0U, "no events after stop_recording");
  check(drained_d == 0U, "no events after uninstall");

  // ---- verification ----

  // stop_recording must freeze every counter: the kOriginal route neither counts nor queues.
  for (std::size_t index = 0U; index < kPointCount; ++index) {
    check(post_stop[index] == pre_stop[index], "counters are frozen after stop_recording");
  }

  // Conservation invariants over the whole capture, per point:
  //   replacement_calls == recordable + recursive + internal
  //   recordable_calls  == successful + failed
  //   recordable_calls  == events + filtered + dropped   (custom events are 1:1)
  std::array<std::uint64_t, kPointCount> drained_per_point{};
  const std::array<const std::vector<LinuxHeapEvent>*, 3> phases{{&events_a, &events_b, &events_c}};
  for (const std::vector<LinuxHeapEvent>* phase : phases) {
    for (const LinuxHeapEvent& event : *phase) {
      if (event.api_id >= noleax::trace::kCustomHookApiIdBase) {
        const std::size_t point =
            static_cast<std::size_t>(event.api_id - noleax::trace::kCustomHookApiIdBase);
        if (point < kPointCount) {
          ++drained_per_point[point];
        }
      }
    }
  }
  std::uint64_t total_dropped = 0U;
  for (std::size_t index = 0U; index < kPointCount; ++index) {
    const LinuxCustomHookApiCounters& counters = post_stop[index];
    check(counters.replacement_calls ==
              counters.recordable_calls + counters.recursive_calls + counters.internal_calls,
          "conservation: replacement calls classify exactly");
    check(counters.recordable_calls == counters.successful_calls + counters.failed_calls,
          "conservation: recordable == successful + failed");
    check(counters.recordable_calls ==
              drained_per_point[index] + counters.filtered_calls + counters.dropped_events,
          "conservation: recordable == events + filtered + dropped");
    total_dropped += counters.dropped_events;
  }
  check(total_dropped != 0U, "churn exercised the queue-full drop path");
  check(total_dropped == hooks.dropped_event_count(), "aggregate dropped count");
  std::uint64_t recordable_total = 0U;
  for (const LinuxCustomHookApiCounters& counters : post_stop) {
    recordable_total += counters.recordable_calls;
  }
  check(recordable_total == hooks.recordable_call_count(), "aggregate recordable count");
  check(hooks.filtered_call_count() == 1U, "aggregate filtered count");

  std::uint64_t churn_operations = 0U;
  for (const ChurnResult& result : churn_results) {
    churn_operations += result.operations;
  }
  check(churn_operations != 0U, "churn workers completed operations");

  // Allocation-id namespacing: the writer derives (api_id << 40) | counter per point in
  // drain order (the Windows scheme). Simulate it over every successful allocation event
  // and prove the derived ids are unique across points and disjoint from the built-in
  // counter space (built-ins count from 1, far below 0x1000 << 40).
  {
    std::array<std::uint64_t, kPointCount> next_per_point{};
    std::set<std::uint64_t> derived_ids;
    bool ids_ok = true;
    for (const std::vector<LinuxHeapEvent>* phase : phases) {
      for (const LinuxHeapEvent& event : *phase) {
        const bool creates_id = event.status == LinuxHeapEventStatus::kSuccess &&
                                (event.operation == LinuxHeapEventOperation::kAllocate ||
                                 (event.operation == LinuxHeapEventOperation::kReallocate &&
                                  event.result_address != 0U));
        if (!creates_id) {
          continue;
        }
        const std::size_t point =
            static_cast<std::size_t>(event.api_id - noleax::trace::kCustomHookApiIdBase);
        if (point >= kPointCount) {
          ids_ok = false;
          continue;
        }
        const std::uint64_t counter = ++next_per_point[point];
        const std::uint64_t derived = (static_cast<std::uint64_t>(event.api_id) << 40U) | counter;
        ids_ok = ids_ok && derived >= (std::uint64_t{noleax::trace::kCustomHookApiIdBase} << 40U);
        ids_ok = ids_ok && derived_ids.insert(derived).second;
      }
    }
    check(ids_ok, "namespaced allocation ids are unique and disjoint from built-ins");
  }

  static_cast<void>(backend.shutdown());
  check(::dlclose(module) == 0, "dlclose after uninstall");
  std::remove(source_path.c_str());
  std::remove(module_path.c_str());
  static_cast<void>(::rmdir(directory));

  std::printf(
      "linux custom hooks probe: events A=%zu B=%zu, churn ops=%llu, dropped=%llu, "
      "failures=%u\n",
      drained_a, drained_b, static_cast<unsigned long long>(churn_operations),
      static_cast<unsigned long long>(total_dropped), check_failures);
  if (check_failures != 0U) {
    std::printf("FAIL\n");
    return 1;
  }
  std::printf("OK\n");
  return 0;
}
