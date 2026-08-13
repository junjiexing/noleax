#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "noleax/ipc/protocol.hpp"

namespace noleax::controller::linux {

// Stable classification of capture-session failures (docs/CLI.md §12): each kind maps to
// a stable message prefix and a documented exit-code path, so a dead agent no longer
// surfaces as a bare "recv failed: Broken pipe".
enum class ControllerFailureKind : std::uint8_t {
  kNone = 0U,
  // Session socket EOF/reset at an unexpected point while the target keeps running.
  kAgentCrash = 1U,
  // The agent reported a trace writer failure (StartCapture error code 6, or the
  // drained/finalized status in AgentState::kFailed).
  kWriterError = 2U,
  // StartCapture error response / capture-ready failure (hook installation).
  kHookInstall = 3U,
  // The target process exited while the controller talked to the agent.
  kTargetExit = 4U,
  // Frame decode or state-machine validation failure.
  kProtocol = 5U,
};

[[nodiscard]] const char* controller_failure_kind_name(ControllerFailureKind kind) noexcept;

class ControllerError final : public std::runtime_error {
 public:
  explicit ControllerError(const std::string& message, std::uint32_t system_error = 0U);
  ControllerError(const std::string& message, ControllerFailureKind failure_kind,
                  std::uint32_t system_error = 0U);
  [[nodiscard]] std::uint32_t system_error() const noexcept;
  [[nodiscard]] ControllerFailureKind failure_kind() const noexcept;

 private:
  std::uint32_t system_error_{0U};
  ControllerFailureKind failure_kind_{ControllerFailureKind::kNone};
};

struct LaunchOptions {
  std::filesystem::path executable;
  std::vector<std::string> arguments;
  std::filesystem::path working_directory;
};

struct CaptureOptions {
  std::filesystem::path agent_path;
  noleax::ipc::StartCaptureRequest start;
  std::chrono::milliseconds timeout{10'000};
};

// Drives an LD_PRELOAD capture session (docs/LINUX_PORT_PLAN.md §5.1): the target is
// spawned with the agent preloaded and the bootstrap environment; the agent connects back
// over the session socket and the IPC state machine runs from there. There is no separate
// pipe-less direct-write transport on Linux — the default run and --live share this one
// session channel; when the channel closes early (Ctrl+C detach), the agent keeps
// capturing until the target exits and finalizes itself.
class CaptureSession final {
 public:
  ~CaptureSession();

  CaptureSession(const CaptureSession&) = delete;
  CaptureSession& operator=(const CaptureSession&) = delete;
  CaptureSession(CaptureSession&& other) noexcept;
  CaptureSession& operator=(CaptureSession&& other) noexcept;

  [[nodiscard]] static CaptureSession launch(const LaunchOptions& launch,
                                             const CaptureOptions& capture);
  // Attaches to a running process via ptrace injection (docs/LINUX_PTRACE_INJECTION.md).
  [[nodiscard]] static CaptureSession attach(std::uint32_t process_id,
                                             const CaptureOptions& capture);

  [[nodiscard]] noleax::ipc::CaptureStatus query_status();
  // StopCapture + FinalizeHooks handshake; idempotent after the first success.
  [[nodiscard]] noleax::ipc::CaptureStatus stop();
  [[nodiscard]] bool wait_for_target(std::chrono::milliseconds timeout);
  [[nodiscard]] std::uint32_t target_exit_code() const;
  [[nodiscard]] std::uint32_t process_id() const noexcept;
  [[nodiscard]] std::uint32_t agent_thread_id() const noexcept;
  [[nodiscard]] bool stopped() const noexcept;
  [[nodiscard]] bool target_exited() const noexcept;

 private:
  class Impl;
  explicit CaptureSession(std::unique_ptr<Impl> implementation) noexcept;

  std::unique_ptr<Impl> implementation_;
};

}  // namespace noleax::controller::linux
