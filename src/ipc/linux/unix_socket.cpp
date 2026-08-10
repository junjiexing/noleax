#include "noleax/ipc/linux/unix_socket.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace noleax::ipc::linux {
namespace {

using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;

void close_fd(int& fd) noexcept {
  if (fd >= 0) {
    static_cast<void>(::close(fd));
  }
  fd = -1;
}

[[nodiscard]] Deadline make_deadline(std::chrono::milliseconds timeout) {
  if (timeout <= std::chrono::milliseconds::zero()) {
    throw SocketError{"socket timeout must be greater than zero", EINVAL};
  }
  return Clock::now() + timeout;
}

[[nodiscard]] int remaining_milliseconds(Deadline deadline) noexcept {
  const auto now = Clock::now();
  if (now >= deadline) {
    return 0;
  }
  const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - now + std::chrono::milliseconds{1});
  return static_cast<int>(remaining.count());
}

[[noreturn]] void fail(const char* operation, int error) {
  throw SocketError{std::string{operation} + " failed: " + std::strerror(error),
                    static_cast<std::uint32_t>(error)};
}

[[noreturn]] void timeout(const char* operation) {
  throw SocketError{std::string{operation} + " timed out", ETIMEDOUT, true};
}

// poll(2) always reports EINTR regardless of SA_RESTART, so every wait retries interrupted
// waits while the deadline permits; the capture teardown signal-park makes this a real path.
void wait_ready(int fd, short events, Deadline deadline, const char* operation) {
  for (;;) {
    pollfd spec{};
    spec.fd = fd;
    spec.events = events;
    const int result = ::poll(&spec, 1U, remaining_milliseconds(deadline));
    if (result > 0) {
      return;
    }
    if (result == 0) {
      timeout(operation);
    }
    if (errno != EINTR) {
      fail("poll", errno);
    }
    if (remaining_milliseconds(deadline) == 0) {
      timeout(operation);
    }
  }
}

void write_exact(int fd, std::span<const std::byte> bytes, Deadline deadline) {
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    wait_ready(fd, POLLOUT, deadline, "socket write wait");
    const ssize_t transferred =
        ::send(fd, bytes.data() + offset, bytes.size() - offset, MSG_NOSIGNAL);
    if (transferred < 0) {
      if (errno == EINTR) {
        continue;
      }
      fail("send", errno);
    }
    if (transferred == 0) {
      fail("send", EPIPE);
    }
    offset += static_cast<std::size_t>(transferred);
  }
}

void read_exact(int fd, std::span<std::byte> bytes, Deadline deadline) {
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    wait_ready(fd, POLLIN, deadline, "socket read wait");
    const ssize_t transferred = ::recv(fd, bytes.data() + offset, bytes.size() - offset, 0);
    if (transferred < 0) {
      if (errno == EINTR) {
        continue;
      }
      fail("recv", errno);
    }
    if (transferred == 0) {
      fail("recv", EPIPE);
    }
    offset += static_cast<std::size_t>(transferred);
  }
}

[[nodiscard]] sockaddr_un socket_address(const std::string& name, socklen_t& length) {
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  if (name.empty() || name.size() > sizeof(address.sun_path)) {
    throw SocketError{"unix socket name is empty or too long", ENAMETOOLONG};
  }
  std::memcpy(address.sun_path, name.data(), name.size());
  length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + name.size());
  return address;
}

[[nodiscard]] std::uint32_t peer_process_id(int fd) {
  ucred credentials{};
  socklen_t length = sizeof(credentials);
  if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0) {
    fail("getsockopt(SO_PEERCRED)", errno);
  }
  if (credentials.pid <= 0) {
    fail("getsockopt(SO_PEERCRED)", ESRCH);
  }
  return static_cast<std::uint32_t>(credentials.pid);
}

}  // namespace

SocketError::SocketError(const std::string& message, std::uint32_t system_error, bool timed_out)
    : std::runtime_error{message}, system_error_{system_error}, timed_out_{timed_out} {}

std::uint32_t SocketError::system_error() const noexcept { return system_error_; }

bool SocketError::timed_out() const noexcept { return timed_out_; }

SocketChannel::SocketChannel(int fd) noexcept : fd_{fd} {}

SocketChannel::~SocketChannel() { close_fd(fd_); }

SocketChannel::SocketChannel(SocketChannel&& other) noexcept : fd_{std::exchange(other.fd_, -1)} {}

SocketChannel& SocketChannel::operator=(SocketChannel&& other) noexcept {
  if (this != &other) {
    close_fd(fd_);
    fd_ = std::exchange(other.fd_, -1);
  }
  return *this;
}

SocketChannel SocketChannel::connect(const std::string& name,
                                     std::chrono::milliseconds timeout_value) {
  if (name.empty()) {
    throw SocketError{"unix socket name must not be empty", EINVAL};
  }
  const Deadline deadline = make_deadline(timeout_value);
  for (;;) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
      fail("socket", errno);
    }
    socklen_t length = 0;
    const sockaddr_un address = socket_address(name, length);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address), length) == 0) {
      return SocketChannel{fd};
    }
    const int error = errno;
    close_fd(fd);
    if (error != ECONNREFUSED && error != ENOENT) {
      fail("connect", error);
    }
    const int remaining = remaining_milliseconds(deadline);
    if (remaining == 0) {
      timeout("unix socket connect");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  }
}

void SocketChannel::send(const Message& message, std::chrono::milliseconds timeout_value) {
  if (!valid()) {
    throw SocketError{"cannot send through a closed socket", EBADF};
  }
  const auto frame = encode_frame(message);
  write_exact(fd_, frame, make_deadline(timeout_value));
}

Message SocketChannel::receive(std::chrono::milliseconds timeout_value) {
  if (!valid()) {
    throw SocketError{"cannot receive through a closed socket", EBADF};
  }
  const Deadline deadline = make_deadline(timeout_value);
  std::array<std::byte, kFrameHeaderSize> header_bytes{};
  read_exact(fd_, header_bytes, deadline);
  const FrameHeader header = decode_frame_header(header_bytes);
  Message message;
  message.type = header.message_type;
  message.request_id = header.request_id;
  message.payload.resize(header.payload_size);
  read_exact(fd_, message.payload, deadline);
  return message;
}

std::uint32_t SocketChannel::client_process_id() const {
  if (!valid()) {
    throw SocketError{"cannot inspect a closed socket", EBADF};
  }
  return peer_process_id(fd_);
}

std::uint32_t SocketChannel::server_process_id() const {
  if (!valid()) {
    throw SocketError{"cannot inspect a closed socket", EBADF};
  }
  return peer_process_id(fd_);
}

bool SocketChannel::valid() const noexcept { return fd_ >= 0; }

UnixSocketServer::UnixSocketServer(const std::string& name) {
  if (name.empty()) {
    throw SocketError{"unix socket name must not be empty", EINVAL};
  }
  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    fail("socket", errno);
  }
  socklen_t length = 0;
  const sockaddr_un address = socket_address(name, length);
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&address), length) != 0) {
    const int error = errno;
    close_fd(fd);
    fail("bind", error);
  }
  if (::listen(fd, 1) != 0) {
    const int error = errno;
    close_fd(fd);
    fail("listen", error);
  }
  fd_ = fd;
}

UnixSocketServer::~UnixSocketServer() { close_fd(fd_); }

UnixSocketServer::UnixSocketServer(UnixSocketServer&& other) noexcept
    : fd_{std::exchange(other.fd_, -1)} {}

UnixSocketServer& UnixSocketServer::operator=(UnixSocketServer&& other) noexcept {
  if (this != &other) {
    close_fd(fd_);
    fd_ = std::exchange(other.fd_, -1);
  }
  return *this;
}

SocketChannel UnixSocketServer::accept(std::chrono::milliseconds timeout_value) {
  if (!valid()) {
    throw SocketError{"cannot accept through a closed socket server", EBADF};
  }
  const Deadline deadline = make_deadline(timeout_value);
  for (;;) {
    wait_ready(fd_, POLLIN, deadline, "unix socket accept");
    const int fd = ::accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (fd >= 0) {
      return SocketChannel{fd};
    }
    if (errno != EINTR) {
      fail("accept4", errno);
    }
  }
}

bool UnixSocketServer::valid() const noexcept { return fd_ >= 0; }

std::string make_socket_name(std::span<const std::byte, 16U> session_token) {
  constexpr char digits[] = "0123456789abcdef";
  std::string name{"\0noleax-", 8U};
  name.reserve(name.size() + session_token.size() * 2U);
  for (const std::byte value : session_token) {
    const unsigned int byte = std::to_integer<unsigned int>(value);
    name.push_back(digits[(byte >> 4U) & 0x0fU]);
    name.push_back(digits[byte & 0x0fU]);
  }
  return name;
}

}  // namespace noleax::ipc::linux
