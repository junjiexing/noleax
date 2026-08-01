#include "noleax/controller/windows/thread_suspension.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: tlhelp32.h requires Windows base types.
#include <windows.h>
#include <tlhelp32.h>
// clang-format on

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace noleax::controller::windows {
namespace {

struct SuspendedThread {
  HANDLE handle{nullptr};
  std::uint32_t thread_id{0U};
};

[[noreturn]] void fail(const char* operation, DWORD error) {
  throw ThreadSuspensionError{
      std::string{operation} + " failed with Windows error " + std::to_string(error), error};
}

[[nodiscard]] std::vector<std::uint32_t> enumerate_threads(std::uint32_t process_id) {
  HANDLE snapshot = INVALID_HANDLE_VALUE;
  // Toolhelp snapshots race thread/process churn; ERROR_BAD_LENGTH is transient per MSDN.
  for (std::uint32_t attempt = 0U; attempt < 8U; ++attempt) {
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0U);
    if (snapshot != INVALID_HANDLE_VALUE) {
      break;
    }
    const DWORD error = GetLastError();
    if (error != ERROR_BAD_LENGTH || attempt + 1U == 8U) {
      fail("CreateToolhelp32Snapshot(threads)", error);
    }
  }
  std::vector<std::uint32_t> result;
  THREADENTRY32 entry{};
  entry.dwSize = sizeof(entry);
  if (Thread32First(snapshot, &entry) == FALSE) {
    const DWORD error = GetLastError();
    static_cast<void>(CloseHandle(snapshot));
    if (error == ERROR_NO_MORE_FILES) {
      return result;
    }
    fail("Thread32First", error);
  }
  do {
    if (entry.th32OwnerProcessID == process_id) {
      result.push_back(entry.th32ThreadID);
    }
    entry.dwSize = sizeof(entry);
  } while (Thread32Next(snapshot, &entry) != FALSE);
  const DWORD last_error = GetLastError();
  static_cast<void>(CloseHandle(snapshot));
  if (last_error != ERROR_NO_MORE_FILES) {
    fail("Thread32Next", last_error);
  }
  return result;
}

}  // namespace

class ThreadSuspension::Impl final {
 public:
  Impl(std::uint32_t process_id, std::uint32_t excluded_thread_id)
      : process_id_{process_id}, excluded_thread_id_{excluded_thread_id} {
    if (process_id_ == 0U || excluded_thread_id_ == 0U) {
      throw ThreadSuspensionError{"thread suspension parameters are invalid",
                                  ERROR_INVALID_PARAMETER};
    }
    try {
      suspend_until_stable();
    } catch (...) {
      // The destructor does not run when a constructor throws: resume every thread that
      // was already suspended instead of leaving them frozen for the process lifetime.
      resume_and_close_all();
      throw;
    }
  }

  ~Impl() { resume_and_close_all(); }

  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  [[nodiscard]] std::size_t count() const noexcept { return suspended_.size(); }

 private:
  void resume_and_close_all() noexcept {
    for (auto iterator = suspended_.rbegin(); iterator != suspended_.rend(); ++iterator) {
      static_cast<void>(ResumeThread(iterator->handle));
      static_cast<void>(CloseHandle(iterator->handle));
    }
  }
  void suspend_until_stable() {
    constexpr std::uint32_t kMaximumSnapshots = 16U;
    for (std::uint32_t pass = 0U; pass < kMaximumSnapshots; ++pass) {
      bool added = false;
      for (const std::uint32_t thread_id : enumerate_threads(process_id_)) {
        if (thread_id == excluded_thread_id_ || suspended_ids_.contains(thread_id)) {
          continue;
        }
        const HANDLE thread =
            OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, thread_id);
        if (thread == nullptr) {
          const DWORD error = GetLastError();
          if (error == ERROR_INVALID_PARAMETER) {
            continue;
          }
          fail("OpenThread", error);
        }
        if (SuspendThread(thread) == std::numeric_limits<DWORD>::max()) {
          const DWORD error = GetLastError();
          static_cast<void>(CloseHandle(thread));
          if (error == ERROR_INVALID_PARAMETER) {
            continue;
          }
          fail("SuspendThread", error);
        }
        suspended_.push_back({thread, thread_id});
        suspended_ids_.insert(thread_id);
        added = true;
      }
      if (!added) {
        return;
      }
    }
    throw ThreadSuspensionError{"target thread set did not stabilize", ERROR_BUSY};
  }

  std::uint32_t process_id_{0U};
  std::uint32_t excluded_thread_id_{0U};
  std::vector<SuspendedThread> suspended_;
  std::unordered_set<std::uint32_t> suspended_ids_;
};

ThreadSuspensionError::ThreadSuspensionError(const std::string& message, std::uint32_t system_error)
    : std::runtime_error{message}, system_error_{system_error} {}

std::uint32_t ThreadSuspensionError::system_error() const noexcept { return system_error_; }

ThreadSuspension::ThreadSuspension(std::uint32_t process_id, std::uint32_t excluded_thread_id)
    : impl_{std::make_unique<Impl>(process_id, excluded_thread_id)} {}

ThreadSuspension::~ThreadSuspension() = default;

std::size_t ThreadSuspension::suspended_count() const noexcept { return impl_->count(); }

}  // namespace noleax::controller::windows
