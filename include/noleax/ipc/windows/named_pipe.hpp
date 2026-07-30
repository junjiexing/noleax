#pragma once

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "noleax/ipc/protocol.hpp"

namespace noleax::ipc::windows {

class PipeError final : public std::runtime_error {
 public:
  PipeError(const std::string& message, std::uint32_t system_error, bool timed_out = false);

  [[nodiscard]] std::uint32_t system_error() const noexcept;
  [[nodiscard]] bool timed_out() const noexcept;

 private:
  std::uint32_t system_error_{0U};
  bool timed_out_{false};
};

class PipeChannel final {
 public:
  PipeChannel() noexcept = default;
  ~PipeChannel();

  PipeChannel(const PipeChannel&) = delete;
  PipeChannel& operator=(const PipeChannel&) = delete;
  PipeChannel(PipeChannel&& other) noexcept;
  PipeChannel& operator=(PipeChannel&& other) noexcept;

  [[nodiscard]] static PipeChannel connect(const std::wstring& name,
                                           std::chrono::milliseconds timeout);

  void send(const Message& message, std::chrono::milliseconds timeout);
  [[nodiscard]] Message receive(std::chrono::milliseconds timeout);
  [[nodiscard]] std::uint32_t peer_process_id() const;
  [[nodiscard]] bool valid() const noexcept;

 private:
  friend class NamedPipeServer;
  explicit PipeChannel(void* handle) noexcept;

  void* handle_{nullptr};
};

class NamedPipeServer final {
 public:
  explicit NamedPipeServer(const std::wstring& name);
  ~NamedPipeServer();

  NamedPipeServer(const NamedPipeServer&) = delete;
  NamedPipeServer& operator=(const NamedPipeServer&) = delete;
  NamedPipeServer(NamedPipeServer&& other) noexcept;
  NamedPipeServer& operator=(NamedPipeServer&& other) noexcept;

  [[nodiscard]] PipeChannel accept(std::chrono::milliseconds timeout);
  [[nodiscard]] bool valid() const noexcept;

 private:
  void* handle_{nullptr};
};

[[nodiscard]] std::wstring make_pipe_name(std::span<const std::byte, 16U> session_token);

}  // namespace noleax::ipc::windows
