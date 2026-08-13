#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/linux/heap_event.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/trace/custom_hook.hpp"
#include "noleax/trace/identifiers.hpp"

namespace noleax::agent::linux {

// Per-point hot-path counters for the custom symbol hooks, the same field set the built-in
// Linux profiles report (GlibcHeapHookApiCounters). Once the profile is quiescent, every
// point satisfies:
//   replacement_calls == recordable_calls + recursive_calls + internal_calls
//   recordable_calls  == successful_calls + failed_calls
//   recordable_calls  == queued events + filtered_calls + dropped_events
// Wire-record attribution is 1:1 for custom events: one recordable call produces at most
// one queued event (no paired records like the mremap move), so the writer can reconcile
// per-API statistics directly against these counters.
struct LinuxCustomHookApiCounters {
  std::uint64_t replacement_calls{0U};
  std::uint64_t recordable_calls{0U};
  std::uint64_t recursive_calls{0U};
  std::uint64_t internal_calls{0U};
  std::uint64_t successful_calls{0U};
  std::uint64_t failed_calls{0U};
  std::uint64_t filtered_calls{0U};
  std::uint64_t dropped_events{0U};

  bool operator==(const LinuxCustomHookApiCounters&) const = default;
};

// The Linux custom symbol hooks (docs/CUSTOM_HOOKS.md, docs/LINUX_PORT_PLAN.md M7): up to
// kMaximumHookPoints user-declared hook points, each binding a third-party allocator's
// alloc/realloc/free roles in one module to the three generic System V AMD64 replacements.
// Point i owns api_id noleax::trace::kCustomHookApiIdBase + i; every event the points emit
// is stamped with that api_id, which places the writer's allocation ids in the namespaced
// (api_id << 40) | counter space that never collides with the built-in id counter.
//
// Raw event contract on the shared LinuxHeapEventQueue (validated by LinuxTraceWriter,
// which applies the built-in per-operation invariants to custom events):
//   kAllocate:   requested_size = declared size (calloc kind: count*size, 0 on overflow),
//                count = calloc count else 0, result_address = result on success,
//                operation_result = the original's errno (ENOMEM when it left errno zero)
//                on failure, 0 on success
//   kReallocate: address = input pointer, requested_size = new size, result_address = new
//                pointer on success; a null result with a zero size is the glibc
//                realloc(p, 0) success, not a failure
//   kFree:       address = freed pointer, every size/count field 0, always kSuccess.
//                A declared free_size_arg is read by the replacement but its value does
//                not ride the wire (the trace FreeEvent has no size field; see
//                docs/CUSTOM_HOOKS.md §10.4).
//
// Routing, guard recursion suppression, quiescence, and teardown discipline mirror the
// built-in GlibcHeapHooks adapter; install resolution (export names through the on-disk
// ELF .dynsym, RVAs against /proc/self/maps executable ranges, wait_module polling)
// follows the Windows CustomSymbolHooks failure model: a point that fails is recorded in
// failures() and the remaining points still install.
class LinuxCustomSymbolHooks final {
 public:
  static constexpr std::size_t kMaximumHookPoints = noleax::ipc::kMaximumCustomHooks;
  static constexpr std::uint16_t kDefaultMaximumStackDepth = kMaximumCapturedStackDepth;

  // The shared queue is owned by the caller (the linux-native profile's single queue) and
  // is never reset here; the owner coordinates that before installing the profiles that
  // produce into it. Throws std::invalid_argument for an out-of-contract spec vector or
  // stack depth and HookBackendError when the guard runtime or the replacement slot pool
  // is unavailable.
  LinuxCustomSymbolHooks(HookBackend& backend, LinuxHeapEventQueue& shared_queue,
                         std::vector<noleax::ipc::CustomHookSpec> specs,
                         std::uint16_t maximum_stack_depth, std::uint64_t minimum_capture_size);
  ~LinuxCustomSymbolHooks();

  LinuxCustomSymbolHooks(const LinuxCustomSymbolHooks&) = delete;
  LinuxCustomSymbolHooks& operator=(const LinuxCustomSymbolHooks&) = delete;
  LinuxCustomSymbolHooks(LinuxCustomSymbolHooks&&) = delete;
  LinuxCustomSymbolHooks& operator=(LinuxCustomSymbolHooks&&) = delete;

  // One-shot, per-point best effort: resolves and installs every point in declaration
  // order; a point that fails is rolled back, recorded in failures(), and does not affect
  // the other points. Returns false only when an install pass already ran.
  bool install();
  [[nodiscard]] bool stop_recording(
      QuiescenceDeadline deadline = quiescence_deadline_after()) noexcept;
  [[nodiscard]] bool uninstall(QuiescenceDeadline deadline = quiescence_deadline_after()) noexcept;
  [[nodiscard]] bool flush(QuiescenceDeadline deadline = quiescence_deadline_after()) noexcept;

  // Per-point best effort makes installation partial by design: is_installed() reports
  // whether at least one point currently has live hooks.
  [[nodiscard]] bool is_installed() const noexcept;
  [[nodiscard]] bool is_recording() const noexcept;
  [[nodiscard]] bool has_pending_teardown() const noexcept;
  [[nodiscard]] std::uint64_t recording_in_flight_count() const noexcept;
  [[nodiscard]] std::size_t point_count() const noexcept;
  [[nodiscard]] noleax::trace::ApiId point_api_id(std::size_t point_index) const noexcept;
  [[nodiscard]] LinuxCustomHookApiCounters counters(std::size_t point_index) const noexcept;
  [[nodiscard]] const std::vector<noleax::trace::CustomHookDefinition>& definitions()
      const noexcept;
  [[nodiscard]] const std::vector<noleax::trace::CustomHookFailure>& failures() const noexcept;
  [[nodiscard]] std::uint64_t dropped_event_count() const noexcept;
  [[nodiscard]] std::uint64_t recordable_call_count() const noexcept;
  [[nodiscard]] std::uint64_t filtered_call_count() const noexcept;

 private:
  class Implementation;
  std::unique_ptr<Implementation> implementation_;
};

}  // namespace noleax::agent::linux
