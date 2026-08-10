#pragma once

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "noleax/ipc/protocol.hpp"

namespace noleax::ipc::linux {

class SocketError final : public std::runtime_error {
 public:
  SocketError(const std::string& message, std::uint32_t system_error, bool timed_out = false);

  [[nodiscard]] std::uint32_t system_error() const noexcept;
  [[nodiscard]] bool timed_out() const noexcept;

 private:
  std::uint32_t system_error_{0U};
  bool timed_out_{false};
};

class SocketChannel final {
 public:
  SocketChannel() noexcept = default;
  ~SocketChannel();

  SocketChannel(const SocketChannel&) = delete;
  SocketChannel& operator=(const SocketChannel&) = delete;
  SocketChannel(SocketChannel&& other) noexcept;
  SocketChannel& operator=(SocketChannel&& other) noexcept;

  [[nodiscard]] static SocketChannel connect(const std::string& name,
                                             std::chrono::milliseconds timeout);

  void send(const Message& message, std::chrono::milliseconds timeout);
  [[nodiscard]] Message receive(std::chrono::milliseconds timeout);
  [[nodiscard]] std::uint32_t client_process_id() const;
  [[nodiscard]] std::uint32_t server_process_id() const;
  [[nodiscard]] bool valid() const noexcept;

 private:
  friend class UnixSocketServer;
  explicit SocketChannel(int fd) noexcept;

  int fd_{-1};
};

class UnixSocketServer final {
 public:
  explicit UnixSocketServer(const std::string& name);
  ~UnixSocketServer();

  UnixSocketServer(const UnixSocketServer&) = delete;
  UnixSocketServer& operator=(const UnixSocketServer&) = delete;
  UnixSocketServer(UnixSocketServer&& other) noexcept;
  UnixSocketServer& operator=(UnixSocketServer&& other) noexcept;

  [[nodiscard]] SocketChannel accept(std::chrono::milliseconds timeout);
  [[nodiscard]] bool valid() const noexcept;

 private:
  int fd_{-1};
};

// Abstract-namespace socket name derived from the session token: no filesystem artifact,
// no cleanup, and collision-free across sessions, mirroring the Windows pipe naming.
[[nodiscard]] std::string make_socket_name(std::span<const std::byte, 16U> session_token);

}  // namespace noleax::ipc::linux
