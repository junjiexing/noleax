#pragma once

#include <cstdint>

namespace noleax::agent {

enum class HookEntryKind : std::uint8_t {
  kOutermost,
  kRecursive,
  kInternalThread,
};

[[nodiscard]] bool acquire_hook_guard_runtime() noexcept;
void release_hook_guard_runtime() noexcept;
[[nodiscard]] bool hook_guard_runtime_is_ready() noexcept;

// The unscoped pair exists for Windows allocator replacements that must use SEH __finally.
// Every successful enter must be paired with exactly one leave on the same thread.
[[nodiscard]] HookEntryKind enter_hook_invocation_unscoped() noexcept;
void leave_hook_invocation_unscoped() noexcept;

class HookInvocationGuard final {
 public:
  HookInvocationGuard() noexcept;
  ~HookInvocationGuard() noexcept;

  HookInvocationGuard(const HookInvocationGuard&) = delete;
  HookInvocationGuard& operator=(const HookInvocationGuard&) = delete;
  HookInvocationGuard(HookInvocationGuard&&) = delete;
  HookInvocationGuard& operator=(HookInvocationGuard&&) = delete;

  [[nodiscard]] HookEntryKind kind() const noexcept;
  [[nodiscard]] bool should_record() const noexcept;

 private:
  HookEntryKind kind_{HookEntryKind::kRecursive};
};

class InternalThreadScope final {
 public:
  InternalThreadScope() noexcept;
  ~InternalThreadScope() noexcept;

  InternalThreadScope(const InternalThreadScope&) = delete;
  InternalThreadScope& operator=(const InternalThreadScope&) = delete;
  InternalThreadScope(InternalThreadScope&&) = delete;
  InternalThreadScope& operator=(InternalThreadScope&&) = delete;
};

[[nodiscard]] std::uint32_t current_hook_depth() noexcept;
[[nodiscard]] bool current_thread_is_internal() noexcept;

}  // namespace noleax::agent
