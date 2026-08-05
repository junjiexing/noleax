#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/windows/rtl_heap_event.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/trace/custom_hook.hpp"
#include "noleax/trace/identifiers.hpp"

namespace noleax::agent::windows {

class CustomHookError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct CustomHookApiStatistics {
  noleax::trace::ApiId api_id{0U};
  std::uint64_t recordable_calls{0U};
  std::uint64_t successful_calls{0U};
  std::uint64_t failed_calls{0U};
  std::uint64_t filtered_calls{0U};
  std::uint64_t dropped_events{0U};
};

// Custom symbol hooks declared through [[custom_hooks]]: up to kMaximumHookPoints hook points,
// each binding an arbitrary module's alloc/realloc/free roles to the three generic replacements.
// Behavior (lifecycle routing, guard recursion suppression, min-size filtering, stack capture,
// lock-free queue publication) mirrors the built-in Rtl* adapters.
class CustomSymbolHooks final {
 public:
  static constexpr std::size_t kMaximumHookPoints = noleax::ipc::kMaximumCustomHooks;

  CustomSymbolHooks(HookBackend& backend, RtlHeapEventQueue& event_queue,
                    std::vector<noleax::ipc::CustomHookSpec> hooks,
                    std::uint16_t maximum_stack_depth, std::uint64_t minimum_capture_size);
  ~CustomSymbolHooks();

  CustomSymbolHooks(const CustomSymbolHooks&) = delete;
  CustomSymbolHooks& operator=(const CustomSymbolHooks&) = delete;
  CustomSymbolHooks(CustomSymbolHooks&&) = delete;
  CustomSymbolHooks& operator=(CustomSymbolHooks&&) = delete;

  // Resolves every module (honoring wait_module) and role target, then installs all hooks.
  // Throws CustomHookError with the precise reason and rolls back partial progress.
  void install();
  [[nodiscard]] bool uninstall(
      std::uint32_t flush_attempts = HookBackend::kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool flush(
      std::uint32_t max_attempts = HookBackend::kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool stop_recording(
      std::uint32_t max_attempts = HookBackend::kDefaultFlushAttempts) noexcept;

  [[nodiscard]] bool is_installed() const noexcept;
  [[nodiscard]] bool is_recording() const noexcept;
  [[nodiscard]] std::uint64_t recording_in_flight_count() const noexcept;
  [[nodiscard]] bool has_pending_teardown() const noexcept;
  [[nodiscard]] bool replacement_module_is_referenced() const noexcept;
  [[nodiscard]] RtlHeapEventQueue& event_queue() noexcept;
  [[nodiscard]] const RtlHeapEventQueue& event_queue() const noexcept;
  [[nodiscard]] const std::vector<noleax::trace::CustomHookDefinition>& definitions()
      const noexcept;
  [[nodiscard]] std::vector<CustomHookApiStatistics> api_statistics() const noexcept;
  // Takes (zeroes) the pending dropped-event counters and returns them per API ID; the sum of
  // the returned counts is the aggregate dropped count since the previous take.
  [[nodiscard]] std::vector<std::pair<noleax::trace::ApiId, std::uint64_t>>
  take_dropped_event_counts() noexcept;
  [[nodiscard]] std::uint64_t dropped_event_count() const noexcept;
  [[nodiscard]] std::uint64_t recordable_call_count() const noexcept;
  [[nodiscard]] std::uint64_t filtered_call_count() const noexcept;

 private:
  class Implementation;
  std::unique_ptr<Implementation> implementation_;
};

}  // namespace noleax::agent::windows
