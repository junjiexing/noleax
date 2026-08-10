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

class ControllerError final : public std::runtime_error {
 public:
  explicit ControllerError(const std::string& message, std::uint32_t system_error = 0U);
  [[nodiscard]] std::uint32_t system_error() const noexcept;

 private:
  std::uint32_t system_error_{0U};
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
