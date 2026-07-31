#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

#include "noleax/agent/windows/bootstrap.hpp"
#include "noleax/controller/windows/remote_injector.hpp"

namespace noleax::controller::windows {

// Entrypoint-code injection (P7B), valid for suspended launch only.
//
// The constructor locates the main image entrypoint in the suspended target,
// saves the original entry bytes and redirects the entrypoint to a bootstrap
// stub written into the target. When the controller resumes the process, the
// stub loads the agent with LdrLoadDll, invokes noleax_agent_bootstrap, waits
// for capture readiness, writes the original entry bytes back, flushes the
// instruction cache, restores the full register state and jumps to the
// original entrypoint. The patched bytes therefore never survive the boot
// sequence, and any failure still restores them before the target continues.
//
// finish() must be called after a successful agent handshake: it waits for
// the stub's restored flag, verifies the entry bytes read back identical to
// the saved originals and re-applies the original page protection.
// describe_failure() explains a stub-reported failure (loader NTSTATUS,
// bootstrap result code or ready timeout) when the handshake never completes.
class EntrypointInjection final {
 public:
  EntrypointInjection(void* process_handle, std::uint32_t process_id,
                      std::wstring_view image_file_name, const std::filesystem::path& agent_path,
                      const noleax::agent::windows::BootstrapParameters& bootstrap);
  ~EntrypointInjection();

  EntrypointInjection(const EntrypointInjection&) = delete;
  EntrypointInjection& operator=(const EntrypointInjection&) = delete;

  [[nodiscard]] std::uintptr_t finish(std::chrono::milliseconds timeout);
  [[nodiscard]] std::string describe_failure() const;
  void abort() noexcept;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

// Returns 4 when the entrypoint begins with endbr64 (the jump patch must keep
// the instruction intact for CET/IBT), 0 otherwise. Exposed for unit tests.
[[nodiscard]] std::uint32_t entrypoint_patch_offset(std::uint32_t first_entry_bytes) noexcept;

}  // namespace noleax::controller::windows
