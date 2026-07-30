#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/windows/module_tracker.hpp"

namespace {

class GuardRuntime final {
 public:
  GuardRuntime() {
    if (!noleax::agent::acquire_hook_guard_runtime()) {
      throw std::runtime_error{"cannot acquire hook guard runtime"};
    }
  }
  ~GuardRuntime() { noleax::agent::release_hook_guard_runtime(); }

  GuardRuntime(const GuardRuntime&) = delete;
  GuardRuntime& operator=(const GuardRuntime&) = delete;
};

[[nodiscard]] std::uint64_t monotonic_origin() {
  LARGE_INTEGER value{};
  if (QueryPerformanceCounter(&value) == FALSE || value.QuadPart < 0) {
    throw std::runtime_error{"QueryPerformanceCounter is unavailable"};
  }
  return static_cast<std::uint64_t>(value.QuadPart);
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc != 2) {
      std::cerr << "usage: module_tracker_test FIXTURE\n";
      return 2;
    }
    const std::wstring fixture =
        std::filesystem::absolute(std::filesystem::path{argv[1]}).wstring();
    GuardRuntime guard_runtime;
    noleax::agent::windows::WindowsModuleTracker tracker{monotonic_origin(), 2U};
    if (!tracker.is_registered() || tracker.initial_modules().empty()) {
      throw std::runtime_error{"module tracker did not capture its initial snapshot"};
    }

    for (std::uint32_t iteration = 0U; iteration < 3U; ++iteration) {
      HMODULE module = LoadLibraryW(fixture.c_str());
      if (module == nullptr || FreeLibrary(module) == FALSE) {
        throw std::runtime_error{"fixture load/unload failed"};
      }
    }

    const std::uint64_t drops = tracker.take_dropped_event_count();
    std::vector<noleax::agent::windows::RawModuleEvent> events;
    noleax::agent::windows::RawModuleEvent event;
    while (tracker.try_dequeue(event)) {
      events.push_back(event);
    }
    if (events.size() != 2U || drops != 4U ||
        events[0].type != noleax::agent::windows::RawModuleEventType::kLoad ||
        events[1].type != noleax::agent::windows::RawModuleEventType::kUnload ||
        events[0].path_length == 0U || events[0].image_size == 0U) {
      throw std::runtime_error{"module notification queue did not preserve bounded FIFO loss"};
    }

    std::cout << "status=ok initial=" << tracker.initial_modules().size()
              << " queued=2 dropped=4 load=1 unload=1\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "status=error message=" << error.what() << '\n';
    return 1;
  }
}
