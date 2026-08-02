#include "noleax/agent/patch_rendezvous.hpp"

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: tlhelp32.h requires the Windows base types.
#include <windows.h>
#include <tlhelp32.h>
// clang-format on

#include <atomic>
#include <cstddef>
#include <cstring>
#include <thread>

namespace noleax::agent {
namespace {

constexpr std::size_t kMaximumSuspendedThreads = 4096U;
constexpr std::size_t kEnumerationFailed = kMaximumSuspendedThreads + 1U;
constexpr char kHookSectionName[8] = ".nlxhk";

struct SuspendedThread {
  DWORD id;
  HANDLE handle;
};

// Fixed storage: no heap allocation is allowed while peer threads are suspended. The busy flag
// keeps a concurrent teardown attempt fail-closed instead of corrupting the shared storage.
std::atomic<bool> rendezvous_busy{false};
SuspendedThread rendezvous_threads[kMaximumSuspendedThreads];

[[nodiscard]] bool region_contains(const HookCodeRegion& region, std::uintptr_t address) noexcept {
  return address >= reinterpret_cast<std::uintptr_t>(region.begin) &&
         address < reinterpret_cast<std::uintptr_t>(region.end);
}

void resume_suspended_threads(std::size_t count) noexcept {
  for (std::size_t index = 0U; index < count; ++index) {
    // Each thread was suspended exactly once by this rendezvous, so one resume restores the
    // caller-visible suspend count; suspensions owned by others are preserved.
    static_cast<void>(ResumeThread(rendezvous_threads[index].handle));
    static_cast<void>(CloseHandle(rendezvous_threads[index].handle));
  }
}

// Suspends every peer thread, re-enumerating until a full pass finds no new thread so that
// threads created during the enumeration are covered as well. Returns the suspended count or
// kEnumerationFailed when any thread could not be opened or suspended; on failure every thread
// suspended so far has already been resumed.
[[nodiscard]] std::size_t suspend_peer_threads(DWORD current_process_id,
                                               DWORD current_thread_id) noexcept {
  std::size_t count = 0U;
  for (;;) {
    std::size_t newly_suspended = 0U;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0U);
    if (snapshot == INVALID_HANDLE_VALUE) {
      resume_suspended_threads(count);
      return kEnumerationFailed;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    bool failed = false;
    for (BOOL scanning = Thread32First(snapshot, &entry); scanning != FALSE && !failed;
         scanning = Thread32Next(snapshot, &entry)) {
      if (entry.th32OwnerProcessID != current_process_id ||
          entry.th32ThreadID == current_thread_id) {
        continue;
      }
      bool known = false;
      for (std::size_t index = 0U; index < count; ++index) {
        if (rendezvous_threads[index].id == entry.th32ThreadID) {
          known = true;
          break;
        }
      }
      if (known) {
        continue;
      }
      if (count == kMaximumSuspendedThreads) {
        failed = true;
        break;
      }
      const HANDLE thread =
          OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, entry.th32ThreadID);
      if (thread == nullptr) {
        failed = true;
        break;
      }
      if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
        static_cast<void>(CloseHandle(thread));
        failed = true;
        break;
      }
      rendezvous_threads[count] = SuspendedThread{entry.th32ThreadID, thread};
      ++count;
      ++newly_suspended;
    }
    static_cast<void>(CloseHandle(snapshot));
    if (failed) {
      resume_suspended_threads(count);
      return kEnumerationFailed;
    }
    if (newly_suspended == 0U) {
      return count;
    }
  }
}

// Returns true when any suspended thread still executes inside the region or when a context
// cannot be read (fail-closed).
[[nodiscard]] bool any_thread_inside_region(std::size_t count,
                                            const HookCodeRegion& region) noexcept {
  for (std::size_t index = 0U; index < count; ++index) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(rendezvous_threads[index].handle, &context) == FALSE) {
      return true;
    }
#if defined(_M_X64)
    const auto instruction_pointer = static_cast<std::uintptr_t>(context.Rip);
#elif defined(_M_IX86)
    const auto instruction_pointer = static_cast<std::uintptr_t>(context.Eip);
#else
    return true;
#endif
    if (region_contains(region, instruction_pointer)) {
      return true;
    }
  }
  return false;
}

}  // namespace

HookCodeRegion hook_code_region(const void* address_in_module) noexcept {
  HookCodeRegion region;
  if (address_in_module == nullptr) {
    return region;
  }
  HMODULE module = nullptr;
  const DWORD flags =
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
  if (GetModuleHandleExW(flags, static_cast<LPCWSTR>(address_in_module), &module) == FALSE ||
      module == nullptr) {
    return region;
  }
  const auto* const base = static_cast<const std::byte*>(static_cast<void*>(module));
  const auto* const dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    return region;
  }
  const auto* const nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos_header->e_lfanew);
  if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
    return region;
  }
  const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt_headers);
  for (std::uint16_t index = 0U; index < nt_headers->FileHeader.NumberOfSections;
       ++index, ++section) {
    if (std::memcmp(section->Name, kHookSectionName, sizeof(kHookSectionName)) == 0) {
      region.begin = base + section->VirtualAddress;
      region.end = static_cast<const std::byte*>(region.begin) + section->Misc.VirtualSize;
      return region;
    }
  }
  return region;
}

bool verify_replacement_evacuated(HookCodeRegion region, std::uint32_t max_attempts) noexcept {
  const auto invalid_region =
      region.begin == nullptr || reinterpret_cast<std::uintptr_t>(region.begin) >=
                                     reinterpret_cast<std::uintptr_t>(region.end);
  if (invalid_region) {
    return false;
  }
  if (rendezvous_busy.exchange(true, std::memory_order_acquire)) {
    return false;
  }
  const DWORD current_process_id = GetCurrentProcessId();
  const DWORD current_thread_id = GetCurrentThreadId();
  bool evacuated = false;
  for (std::uint32_t attempt = 0U;; ++attempt) {
    const std::size_t count = suspend_peer_threads(current_process_id, current_thread_id);
    if (count != kEnumerationFailed) {
      evacuated = !any_thread_inside_region(count, region);
      resume_suspended_threads(count);
    }
    if (evacuated || attempt == max_attempts) {
      break;
    }
    std::this_thread::yield();
  }
  rendezvous_busy.store(false, std::memory_order_release);
  return evacuated;
}

}  // namespace noleax::agent

#else

namespace noleax::agent {

HookCodeRegion hook_code_region(const void* /*address_in_module*/) noexcept { return {}; }

bool verify_replacement_evacuated(HookCodeRegion /*region*/,
                                  std::uint32_t /*max_attempts*/) noexcept {
  return false;
}

}  // namespace noleax::agent

#endif
