#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>

#include "noleax/agent/hook_backend.hpp"

// Deterministic PC-guard test: a worker thread spins inside the bytes that a
// fast hook is about to overwrite. The guard must keep install_fast blocked
// (bounded resume/sleep/re-suspend retries) until the worker leaves the
// prologue range, then succeed.
//
// Page layout: [64 bytes of code][8-byte flag].
// Code (x64):
//   0F B6 05 <disp32>  movzx eax, byte [rip+disp32]   ; loads the flag
//   85 C0              test eax, eax
//   74 F5              je  back to offset 0
//   C3                 ret
//   ...                NOP padding up to offset 64

namespace {

using StubFunction = void (*)();

constexpr std::size_t kPageSize = 4096U;
constexpr std::size_t kFlagOffset = 64U;
constexpr std::uint32_t kWorkerSpinMs = 50U;
// Well inside the guard's bounded retry budget (100 attempts, ~1ms each) even
// under test-host load, while still forcing many guard rounds: the worker
// cannot leave the patch range before the flag is published.
constexpr std::uint32_t kReleaseDelayMs = 30U;
constexpr std::uint32_t kFlushRetries = 16U;

std::atomic<bool> g_replaced{false};
std::atomic<std::chrono::steady_clock::time_point> g_release_time{};

void replacement_function() { g_replaced.store(true, std::memory_order_release); }

[[nodiscard]] std::uint8_t* build_spin_page() {
  auto* const page = static_cast<std::uint8_t*>(
      VirtualAlloc(nullptr, kPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
  if (page == nullptr) {
    return nullptr;
  }

  std::memset(page, 0x90, kFlagOffset);  // NOP sled
  std::memset(page + kFlagOffset, 0, kPageSize - kFlagOffset);

  const std::int32_t disp32 = static_cast<std::int32_t>(kFlagOffset - 7U);
  page[0] = 0x0FU;
  page[1] = 0xB6U;
  page[2] = 0x05U;
  std::memcpy(page + 3, &disp32, sizeof(disp32));
  page[7] = 0x85U;  // test eax, eax
  page[8] = 0xC0U;
  page[9] = 0x74U;   // je rel8
  page[10] = 0xF5U;  // -11: back to offset 0
  page[11] = 0xC3U;  // ret

  return page;
}

[[nodiscard]] bool uninstall_fully(noleax::agent::HookBackend& backend, void* target) noexcept {
  auto status = backend.uninstall(target, 0U);
  for (std::uint32_t retry = 0U;
       retry < kFlushRetries && status == noleax::agent::HookUninstallStatus::kTeardownPending;
       ++retry) {
    if (backend.flush(100'000U)) {
      status = noleax::agent::HookUninstallStatus::kUninstalled;
    }
  }
  return status == noleax::agent::HookUninstallStatus::kUninstalled;
}

}  // namespace

int main() {
  std::uint8_t* const page = build_spin_page();
  if (page == nullptr) {
    return 2;
  }
  auto* const flag = reinterpret_cast<volatile std::uint8_t*>(page + kFlagOffset);
  const auto stub = reinterpret_cast<StubFunction>(page);

  noleax::agent::HookBackend backend;

  // Worker parks its instruction pointer inside the to-be-patched bytes.
  std::thread worker([stub]() { stub(); });

  // Release the spin only well after the install attempt has started.
  std::thread releaser([flag]() {
    Sleep(kReleaseDelayMs);
    *flag = 1U;
    g_release_time.store(std::chrono::steady_clock::now(), std::memory_order_release);
  });

  Sleep(kWorkerSpinMs);

  noleax::agent::OriginalTrampolineSlot slot{};
  // The spin body holds a short backward branch plus a RIP-relative load, so
  // the checked relocation refuses it; forced relocation is the sanctioned
  // path for such prologues.
  const auto result =
      backend.install_fast_forced(page, reinterpret_cast<void*>(&replacement_function), &slot);
  const auto install_end = std::chrono::steady_clock::now();

  if (!result.installed()) {
    const auto name = noleax::agent::hook_install_status_name(result.status);
    std::fprintf(stderr, "install_fast failed: %.*s\n", static_cast<int>(name.size()), name.data());
    return 3;
  }
  if (result.original == nullptr || slot.load(std::memory_order_acquire) == nullptr) {
    return 4;
  }

  // The guard must have held the patch write until the worker left the range,
  // i.e. until the releaser published the flag.
  const auto release_time = g_release_time.load(std::memory_order_acquire);
  if (install_end < release_time) {
    std::fprintf(stderr, "install returned before the worker left the patch range\n");
    return 5;
  }

  worker.join();
  releaser.join();

  // Calls into the patched stub now land in the replacement.
  stub();
  if (!g_replaced.load(std::memory_order_acquire)) {
    return 6;
  }

  // The original trampoline still runs the relocated spin body (flag already
  // set, so it falls straight through to ret).
  const auto original = reinterpret_cast<StubFunction>(slot.load(std::memory_order_acquire));
  original();

  if (!uninstall_fully(backend, page)) {
    return 7;
  }
  if (!backend.shutdown()) {
    return 8;
  }

  VirtualFree(page, 0, MEM_RELEASE);

  std::printf("status=ok blocked=1\n");
  return 0;
}
