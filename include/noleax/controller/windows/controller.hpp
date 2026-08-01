#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "noleax/controller/windows/process.hpp"
#include "noleax/ipc/protocol.hpp"

namespace noleax::controller::windows {

enum class InjectionMethod : std::uint8_t {
  kRemoteThread,
  kThreadHijack,
  kEntrypointCode,
  kStaticPePatch,
};

struct CaptureOptions {
  std::filesystem::path agent_path;
  noleax::ipc::StartCaptureRequest start;
  std::chrono::milliseconds timeout{10'000};
  InjectionMethod method{InjectionMethod::kRemoteThread};
};

struct LaunchOptions {
  std::filesystem::path executable;
  std::vector<std::string> arguments;
  std::filesystem::path working_directory;
};

class ControllerError final : public std::runtime_error {
 public:
  ControllerError(const std::string& message, std::uint32_t system_error = 0U);
  [[nodiscard]] std::uint32_t system_error() const noexcept;

 private:
  std::uint32_t system_error_{0U};
};

class CaptureSession final {
 public:
  ~CaptureSession();

  CaptureSession(const CaptureSession&) = delete;
  CaptureSession& operator=(const CaptureSession&) = delete;
  CaptureSession(CaptureSession&& other) noexcept;
  CaptureSession& operator=(CaptureSession&& other) noexcept;

  [[nodiscard]] static CaptureSession launch(const LaunchOptions& launch,
                                             const CaptureOptions& capture);
  [[nodiscard]] static CaptureSession attach(std::uint32_t process_id,
                                             const CaptureOptions& capture);

  [[nodiscard]] noleax::ipc::CaptureStatus query_status();
  [[nodiscard]] noleax::ipc::CaptureStatus stop();
  [[nodiscard]] bool wait_for_target(std::chrono::milliseconds timeout) const;
  [[nodiscard]] std::uint32_t target_exit_code() const;
  [[nodiscard]] std::uint32_t process_id() const noexcept;
  [[nodiscard]] std::uint32_t agent_thread_id() const noexcept;
  [[nodiscard]] bool launched_target() const noexcept;
  [[nodiscard]] bool stopped() const noexcept;

 private:
  class Impl;
  explicit CaptureSession(std::unique_ptr<Impl> implementation) noexcept;

  std::unique_ptr<Impl> implementation_;
};

// A minimal owned process handle for agent-capture sessions (no pipe channel).
class AgentProcessHandle final {
 public:
  AgentProcessHandle() noexcept = default;
  explicit AgentProcessHandle(void* handle) noexcept : handle_{handle} {}
  ~AgentProcessHandle();

  AgentProcessHandle(const AgentProcessHandle&) = delete;
  AgentProcessHandle& operator=(const AgentProcessHandle&) = delete;
  AgentProcessHandle(AgentProcessHandle&& other) noexcept;
  AgentProcessHandle& operator=(AgentProcessHandle&& other) noexcept;

  [[nodiscard]] void* get() const noexcept { return handle_; }
  [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr; }

 private:
  void* handle_{nullptr};
};

// Injects the agent with a bootstrap configuration file (agent_config) instead of a pipe
// handshake, and waits for the agent's named ready event where the injection method does
// not already gate the main thread on capture readiness.
[[nodiscard]] SuspendedProcess launch_agent_capture(const LaunchOptions& launch,
                                                    const CaptureOptions& capture,
                                                    const std::filesystem::path& agent_config);
[[nodiscard]] AgentProcessHandle attach_agent_capture(std::uint32_t process_id,
                                                      const CaptureOptions& capture,
                                                      const std::filesystem::path& agent_config);

}  // namespace noleax::controller::windows
