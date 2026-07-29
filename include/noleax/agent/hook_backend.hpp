#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace noleax::agent {

using OriginalTrampolineSlot = std::atomic<void*>;

enum class HookInstallStatus : std::uint8_t {
  kInstalled,
  kInvalidArgument,
  kAlreadyInstalled,
  kAlreadyReplaced,
  kWrongSignature,
  kPolicyViolation,
  kWrongType,
  kMissingOriginal,
  kTeardownPending,
  kBackendStopped,
};

[[nodiscard]] std::string_view hook_install_status_name(HookInstallStatus status) noexcept;

struct FastHookResult {
  HookInstallStatus status{HookInstallStatus::kBackendStopped};
  void* original{nullptr};

  [[nodiscard]] bool installed() const noexcept { return status == HookInstallStatus::kInstalled; }
};

enum class HookUninstallStatus : std::uint8_t {
  kUninstalled,
  kNotInstalled,
  kTeardownPending,
  kBackendStopped,
};

[[nodiscard]] std::string_view hook_uninstall_status_name(HookUninstallStatus status) noexcept;

class HookBackendError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class HookBackend {
 public:
  static constexpr std::uint32_t kDefaultFlushAttempts = 1024U;

  HookBackend();
  ~HookBackend();

  HookBackend(const HookBackend&) = delete;
  HookBackend& operator=(const HookBackend&) = delete;
  HookBackend(HookBackend&&) = delete;
  HookBackend& operator=(HookBackend&&) = delete;

  [[nodiscard]] FastHookResult install_fast(void* target, void* replacement,
                                            OriginalTrampolineSlot* original_slot = nullptr);
  [[nodiscard]] HookUninstallStatus uninstall(
      void* target, std::uint32_t flush_attempts = kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool flush(std::uint32_t max_attempts = kDefaultFlushAttempts) noexcept;
  [[nodiscard]] bool shutdown(std::uint32_t flush_attempts = kDefaultFlushAttempts) noexcept;

  [[nodiscard]] bool is_active() const noexcept;
  [[nodiscard]] bool has_pending_teardown() const noexcept;
  [[nodiscard]] std::size_t installed_count() const noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace noleax::agent
