#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "noleax/ipc/linux/unix_socket.hpp"

namespace {

using namespace std::chrono_literals;

[[nodiscard]] std::string unique_socket_name() {
  static std::atomic<std::uint64_t> sequence{0U};
  std::array<std::byte, 16U> token{};
  const std::uint64_t value =
      (static_cast<std::uint64_t>(::getpid()) << 32U) ^
      static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) ^
      sequence.fetch_add(1U, std::memory_order_relaxed);
  for (std::size_t index = 0U; index < sizeof(value); ++index) {
    token[index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
  }
  return noleax::ipc::linux::make_socket_name(token);
}

}  // namespace

TEST_CASE("unix socket IPC enforces connection timeouts", "[ipc][linux][timeout]") {
  noleax::ipc::linux::UnixSocketServer server{unique_socket_name()};
  try {
    static_cast<void>(server.accept(20ms));
    FAIL("accept unexpectedly completed");
  } catch (const noleax::ipc::linux::SocketError& error) {
    CHECK(error.timed_out());
  }
}

TEST_CASE("unix socket IPC exchanges framed messages and reports peer PID", "[ipc][linux]") {
  const std::string name = unique_socket_name();
  noleax::ipc::linux::UnixSocketServer server{name};
  std::exception_ptr client_error;
  std::atomic<bool> server_pid_matches{false};
  std::thread client{[&] {
    try {
      auto channel = noleax::ipc::linux::SocketChannel::connect(name, 2s);
      server_pid_matches.store(
          channel.server_process_id() == static_cast<std::uint32_t>(::getpid()),
          std::memory_order_relaxed);
      channel.send({noleax::ipc::MessageType::kAgentHello, 1U, {std::byte{0x5a}}}, 2s);
      const auto response = channel.receive(2s);
      if (response.type != noleax::ipc::MessageType::kCaptureStatus || response.request_id != 1U) {
        throw std::runtime_error{"client received an unexpected IPC response"};
      }
    } catch (...) {
      client_error = std::current_exception();
    }
  }};

  auto channel = server.accept(2s);
  CHECK(channel.client_process_id() == static_cast<std::uint32_t>(::getpid()));
  const auto request = channel.receive(2s);
  CHECK(request.type == noleax::ipc::MessageType::kAgentHello);
  CHECK(request.request_id == 1U);
  CHECK(request.payload == std::vector<std::byte>{std::byte{0x5a}});
  channel.send({noleax::ipc::MessageType::kCaptureStatus, request.request_id, {}}, 2s);
  client.join();
  if (client_error != nullptr) {
    std::rethrow_exception(client_error);
  }
  CHECK(server_pid_matches.load(std::memory_order_relaxed));
}

TEST_CASE("unix socket IPC times out on a partial malicious frame", "[ipc][linux][timeout]") {
  const std::string name = unique_socket_name();
  noleax::ipc::linux::UnixSocketServer server{name};
  std::exception_ptr client_error;
  std::thread client{[&] {
    try {
      sockaddr_un address{};
      address.sun_family = AF_UNIX;
      std::memcpy(address.sun_path, name.data(), name.size());
      const auto length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + name.size());
      const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
      if (fd < 0 || ::connect(fd, reinterpret_cast<const sockaddr*>(&address), length) != 0) {
        throw std::runtime_error{"malicious client could not connect the unix socket"};
      }
      const std::array<std::byte, 4U> partial{std::byte{'N'}, std::byte{'L'}, std::byte{'X'},
                                              std::byte{'P'}};
      const ssize_t written = ::send(fd, partial.data(), partial.size(), 0);
      if (written != static_cast<ssize_t>(partial.size())) {
        ::close(fd);
        throw std::runtime_error{"malicious client could not write its partial frame"};
      }
      std::this_thread::sleep_for(100ms);
      ::close(fd);
    } catch (...) {
      client_error = std::current_exception();
    }
  }};

  auto channel = server.accept(2s);
  try {
    static_cast<void>(channel.receive(20ms));
    FAIL("partial frame unexpectedly completed");
  } catch (const noleax::ipc::linux::SocketError& error) {
    CHECK(error.timed_out());
  }
  client.join();
  if (client_error != nullptr) {
    std::rethrow_exception(client_error);
  }
}

TEST_CASE("unix socket names are abstract and token-derived", "[ipc][linux]") {
  std::array<std::byte, 16U> token{};
  token[0] = std::byte{0xab};
  token[15] = std::byte{0xcd};
  const std::string name = noleax::ipc::linux::make_socket_name(token);
  CHECK(name.size() == 8U + 32U);
  CHECK(name[0] == '\0');
  CHECK(name.compare(1U, 7U, "noleax-") == 0);
  CHECK(name.compare(name.size() - 4U, 4U, "00cd") == 0);

  token[1] = std::byte{0x01};
  CHECK(noleax::ipc::linux::make_socket_name(token) != name);
}
