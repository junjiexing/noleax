#include "noleax/ipc/windows/named_pipe.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstddef>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;

[[nodiscard]] std::wstring unique_pipe_name() {
  static std::atomic<std::uint64_t> sequence{0U};
  std::array<std::byte, 16U> token{};
  const std::uint64_t value = (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32U) ^
                              GetTickCount64() ^ sequence.fetch_add(1U, std::memory_order_relaxed);
  for (std::size_t index = 0U; index < sizeof(value); ++index) {
    token[index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
  }
  return noleax::ipc::windows::make_pipe_name(token);
}

}  // namespace

TEST_CASE("named pipe IPC enforces connection timeouts", "[ipc][windows][timeout]") {
  noleax::ipc::windows::NamedPipeServer server{unique_pipe_name()};
  try {
    static_cast<void>(server.accept(20ms));
    FAIL("accept unexpectedly completed");
  } catch (const noleax::ipc::windows::PipeError& error) {
    CHECK(error.timed_out());
  }
}

TEST_CASE("named pipe IPC exchanges framed messages and reports peer PID", "[ipc][windows]") {
  const std::wstring name = unique_pipe_name();
  noleax::ipc::windows::NamedPipeServer server{name};
  std::exception_ptr client_error;
  std::atomic<bool> server_pid_matches{false};
  std::thread client{[&] {
    try {
      auto channel = noleax::ipc::windows::PipeChannel::connect(name, 2s);
      server_pid_matches.store(channel.server_process_id() == GetCurrentProcessId(),
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
  CHECK(channel.client_process_id() == GetCurrentProcessId());
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

TEST_CASE("named pipe IPC times out on a partial malicious frame", "[ipc][windows][timeout]") {
  const std::wstring name = unique_pipe_name();
  noleax::ipc::windows::NamedPipeServer server{name};
  std::exception_ptr client_error;
  std::thread client{[&] {
    try {
      const HANDLE handle = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr,
                                        OPEN_EXISTING, 0U, nullptr);
      if (handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error{"malicious client could not open the named pipe"};
      }
      const std::array<std::byte, 4U> partial{std::byte{'N'}, std::byte{'L'}, std::byte{'X'},
                                              std::byte{'P'}};
      DWORD written = 0U;
      if (WriteFile(handle, partial.data(), static_cast<DWORD>(partial.size()), &written,
                    nullptr) == FALSE ||
          written != partial.size()) {
        static_cast<void>(CloseHandle(handle));
        throw std::runtime_error{"malicious client could not write its partial frame"};
      }
      Sleep(100U);
      static_cast<void>(CloseHandle(handle));
    } catch (...) {
      client_error = std::current_exception();
    }
  }};

  auto channel = server.accept(2s);
  try {
    static_cast<void>(channel.receive(20ms));
    FAIL("partial frame unexpectedly completed");
  } catch (const noleax::ipc::windows::PipeError& error) {
    CHECK(error.timed_out());
  }
  client.join();
  if (client_error != nullptr) {
    std::rethrow_exception(client_error);
  }
}
