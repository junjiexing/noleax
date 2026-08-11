#include <dlfcn.h>
#include <unistd.h>

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>

#include "noleax/agent/linux/module_tracker.hpp"

namespace {

using noleax::agent::linux::LinuxModuleTracker;
using noleax::agent::linux::RawModuleEvent;
using noleax::agent::linux::RawModuleEventFlag;
using noleax::agent::linux::RawModuleEventType;

[[nodiscard]] bool has_suffix(std::string_view value, std::string_view suffix) {
  return value.size() >= suffix.size() && value.substr(value.size() - suffix.size()) == suffix;
}

}  // namespace

TEST_CASE("linux module tracker snapshots the initial module set",
          "[agent][module-tracker][linux]") {
  std::array<char, 4096U> executable{};
  const ssize_t executable_length =
      ::readlink("/proc/self/exe", executable.data(), executable.size() - 1U);
  REQUIRE(executable_length > 0);
  const std::string expected_main_path{executable.data(),
                                       static_cast<std::size_t>(executable_length)};

  const LinuxModuleTracker tracker{1'000'000U};
  const auto initial = tracker.initial_modules();

  REQUIRE(initial.size() >= 3U);
  bool saw_main_executable = false;
  bool saw_libc = false;
  std::uint64_t previous_base = 0U;
  for (const RawModuleEvent& event : initial) {
    CHECK(event.type == RawModuleEventType::kLoad);
    CHECK((event.flags & static_cast<std::uint32_t>(RawModuleEventFlag::kInitialSnapshot)) != 0U);
    CHECK(event.monotonic_ticks == 1'000'000U);
    CHECK(event.image_size != 0U);
    CHECK(event.path_length != 0U);
    CHECK(event.base_address >= previous_base);
    previous_base = event.base_address;
    const std::string_view path{event.path.data(), event.path_length};
    // The main executable records its real path (readlink of /proc/self/exe) so the
    // offline analyzer opens the right image.
    saw_main_executable = saw_main_executable || path == expected_main_path;
    saw_libc = saw_libc || has_suffix(path, "libc.so.6");
  }
  CHECK(saw_main_executable);
  CHECK(saw_libc);
  CHECK(tracker.live_module_count() == initial.size());
}

TEST_CASE("linux module tracker observes dlopen and dlclose via polling",
          "[agent][module-tracker][linux]") {
  LinuxModuleTracker tracker{1'000'000U};
  RawModuleEvent event;

  tracker.poll();
  CHECK_FALSE(tracker.try_dequeue(event));

  void* const module = dlopen(NOLEAX_HOOK_FIXTURE_PATH, RTLD_NOW | RTLD_LOCAL);
  REQUIRE(module != nullptr);
  tracker.poll();

  bool saw_load = false;
  while (tracker.try_dequeue(event)) {
    if (event.type == RawModuleEventType::kLoad &&
        has_suffix({event.path.data(), event.path_length}, "noleax-hook-backend-fixture.so")) {
      saw_load = true;
      CHECK(event.flags == 0U);
      CHECK(event.image_size != 0U);
    }
  }
  CHECK(saw_load);

  dlclose(module);
  tracker.poll();
  bool saw_unload = false;
  while (tracker.try_dequeue(event)) {
    if (event.type == RawModuleEventType::kUnload &&
        has_suffix({event.path.data(), event.path_length}, "noleax-hook-backend-fixture.so")) {
      saw_unload = true;
    }
  }
  CHECK(saw_unload);

  tracker.poll();
  CHECK_FALSE(tracker.try_dequeue(event));
}

TEST_CASE("linux module tracker drops overflow events and accounts them",
          "[agent][module-tracker][linux]") {
  // Two byte-identical copies at different paths are two distinct modules to the loader,
  // which makes the overflow deterministic: one poll produces two load events for a
  // one-slot queue.
  const std::filesystem::path source = NOLEAX_HOOK_FIXTURE_PATH;
  const std::filesystem::path temp_dir = std::filesystem::temp_directory_path();
  const auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const std::filesystem::path first_copy = temp_dir / ("noleax-mt-a-" + stamp + ".so");
  const std::filesystem::path second_copy = temp_dir / ("noleax-mt-b-" + stamp + ".so");
  std::filesystem::copy_file(source, first_copy);
  std::filesystem::copy_file(source, second_copy);

  LinuxModuleTracker tracker{1'000'000U, 1U};
  void* const first = dlopen(first_copy.c_str(), RTLD_NOW | RTLD_LOCAL);
  void* const second = dlopen(second_copy.c_str(), RTLD_NOW | RTLD_LOCAL);
  REQUIRE(first != nullptr);
  REQUIRE(second != nullptr);

  tracker.poll();
  RawModuleEvent event;
  std::uint32_t dequeued = 0U;
  while (tracker.try_dequeue(event)) {
    ++dequeued;
  }
  CHECK(dequeued == 1U);
  CHECK(tracker.take_dropped_event_count() == 1U);
  CHECK(tracker.take_dropped_event_count() == 0U);

  dlclose(second);
  dlclose(first);
  std::filesystem::remove(first_copy);
  std::filesystem::remove(second_copy);
  CHECK(tracker.queue_capacity() == 1U);
}
