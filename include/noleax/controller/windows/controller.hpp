#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "noleax/ipc/protocol.hpp"

namespace noleax::controller::windows {

struct CaptureOptions {
  std::filesystem::path agent_path;
  noleax::ipc::StartCaptureRequest start;
  std::chrono::milliseconds timeout{10'000};
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

}  // namespace noleax::controller::windows
