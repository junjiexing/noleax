#include "noleax/ipc/windows/named_pipe.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace noleax::ipc::windows {
namespace {

using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;

[[nodiscard]] HANDLE as_handle(void* value) noexcept { return static_cast<HANDLE>(value); }

[[nodiscard]] void* as_storage(HANDLE value) noexcept { return static_cast<void*>(value); }

[[nodiscard]] bool valid_handle(void* value) noexcept {
  return value != nullptr && as_handle(value) != INVALID_HANDLE_VALUE;
}

void close_handle(void*& value) noexcept {
  if (valid_handle(value)) {
    static_cast<void>(CloseHandle(as_handle(value)));
  }
  value = nullptr;
}

[[nodiscard]] Deadline make_deadline(std::chrono::milliseconds timeout) {
  if (timeout <= std::chrono::milliseconds::zero()) {
    throw PipeError{"pipe timeout must be greater than zero", ERROR_INVALID_PARAMETER};
  }
  return Clock::now() + timeout;
}

[[nodiscard]] DWORD remaining_milliseconds(Deadline deadline) noexcept {
  const auto now = Clock::now();
  if (now >= deadline) {
    return 0U;
  }
  const auto remaining = deadline - now;
  const auto rounded = std::chrono::duration_cast<std::chrono::milliseconds>(
      remaining + std::chrono::milliseconds{1});
  return rounded.count() >= static_cast<long long>(INFINITE - 1U)
             ? INFINITE - 1U
             : static_cast<DWORD>(rounded.count());
}

[[noreturn]] void fail(const char* operation, DWORD error) {
  throw PipeError{std::string{operation} + " failed with Windows error " + std::to_string(error),
                  error};
}

[[noreturn]] void timeout(const char* operation) {
  throw PipeError{std::string{operation} + " timed out", WAIT_TIMEOUT, true};
}

class Event final {
 public:
  Event() : handle_{CreateEventW(nullptr, TRUE, FALSE, nullptr)} {
    if (handle_ == nullptr) {
      fail("CreateEventW", GetLastError());
    }
  }
  ~Event() { static_cast<void>(CloseHandle(handle_)); }

  Event(const Event&) = delete;
  Event& operator=(const Event&) = delete;

  [[nodiscard]] HANDLE get() const noexcept { return handle_; }

 private:
  HANDLE handle_{nullptr};
};

void wait_overlapped(HANDLE handle, OVERLAPPED& overlapped, Deadline deadline,
                     const char* operation, DWORD& transferred) {
  const DWORD wait_result =
      WaitForSingleObject(overlapped.hEvent, remaining_milliseconds(deadline));
  if (wait_result == WAIT_TIMEOUT) {
    static_cast<void>(CancelIoEx(handle, &overlapped));
    static_cast<void>(WaitForSingleObject(overlapped.hEvent, INFINITE));
    timeout(operation);
  }
  if (wait_result != WAIT_OBJECT_0) {
    const DWORD error = GetLastError();
    static_cast<void>(CancelIoEx(handle, &overlapped));
    static_cast<void>(WaitForSingleObject(overlapped.hEvent, INFINITE));
    fail("WaitForSingleObject", error);
  }
  if (GetOverlappedResult(handle, &overlapped, &transferred, FALSE) == FALSE) {
    fail(operation, GetLastError());
  }
}

void transfer_exact(HANDLE handle, std::span<std::byte> bytes, bool write, Deadline deadline) {
  std::size_t offset = 0U;
  while (offset < bytes.size()) {
    const std::size_t remaining = bytes.size() - offset;
    const DWORD request = static_cast<DWORD>(
        (std::min)(remaining, static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
    Event event;
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD transferred = 0U;
    const BOOL completed =
        write ? WriteFile(handle, bytes.data() + offset, request, &transferred, &overlapped)
              : ReadFile(handle, bytes.data() + offset, request, &transferred, &overlapped);
    if (completed == FALSE) {
      const DWORD error = GetLastError();
      if (error != ERROR_IO_PENDING) {
        fail(write ? "WriteFile" : "ReadFile", error);
      }
      wait_overlapped(handle, overlapped, deadline, write ? "WriteFile" : "ReadFile", transferred);
    }
    if (transferred == 0U) {
      fail(write ? "WriteFile" : "ReadFile", ERROR_BROKEN_PIPE);
    }
    offset += transferred;
  }
}

void write_exact(HANDLE handle, std::span<const std::byte> bytes, Deadline deadline) {
  transfer_exact(handle, std::span{const_cast<std::byte*>(bytes.data()), bytes.size()}, true,
                 deadline);
}

void read_exact(HANDLE handle, std::span<std::byte> bytes, Deadline deadline) {
  transfer_exact(handle, bytes, false, deadline);
}

[[nodiscard]] HANDLE connect_handle(const std::wstring& name, Deadline deadline) {
  for (;;) {
    HANDLE handle = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0U, nullptr,
                                OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
      DWORD mode = PIPE_READMODE_BYTE;
      if (SetNamedPipeHandleState(handle, &mode, nullptr, nullptr) == FALSE) {
        const DWORD error = GetLastError();
        static_cast<void>(CloseHandle(handle));
        fail("SetNamedPipeHandleState", error);
      }
      return handle;
    }
    const DWORD error = GetLastError();
    if (error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND) {
      fail("CreateFileW(named pipe)", error);
    }
    const DWORD remaining = remaining_milliseconds(deadline);
    if (remaining == 0U) {
      timeout("named pipe connect");
    }
    if (error == ERROR_PIPE_BUSY) {
      if (WaitNamedPipeW(name.c_str(), (std::min)(remaining, DWORD{25U})) == FALSE) {
        const DWORD wait_error = GetLastError();
        if (wait_error != ERROR_SEM_TIMEOUT && wait_error != ERROR_FILE_NOT_FOUND) {
          fail("WaitNamedPipeW", wait_error);
        }
      }
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
  }
}

}  // namespace

PipeError::PipeError(const std::string& message, std::uint32_t system_error, bool timed_out)
    : std::runtime_error{message}, system_error_{system_error}, timed_out_{timed_out} {}

std::uint32_t PipeError::system_error() const noexcept { return system_error_; }

bool PipeError::timed_out() const noexcept { return timed_out_; }

PipeChannel::PipeChannel(void* handle) noexcept : handle_{handle} {}

PipeChannel::~PipeChannel() { close_handle(handle_); }

PipeChannel::PipeChannel(PipeChannel&& other) noexcept
    : handle_{std::exchange(other.handle_, nullptr)} {}

PipeChannel& PipeChannel::operator=(PipeChannel&& other) noexcept {
  if (this != &other) {
    close_handle(handle_);
    handle_ = std::exchange(other.handle_, nullptr);
  }
  return *this;
}

PipeChannel PipeChannel::connect(const std::wstring& name,
                                 std::chrono::milliseconds timeout_value) {
  if (name.empty()) {
    throw PipeError{"named pipe name must not be empty", ERROR_INVALID_NAME};
  }
  return PipeChannel{as_storage(connect_handle(name, make_deadline(timeout_value)))};
}

void PipeChannel::send(const Message& message, std::chrono::milliseconds timeout_value) {
  if (!valid()) {
    throw PipeError{"cannot send through a closed pipe", ERROR_INVALID_HANDLE};
  }
  const auto frame = encode_frame(message);
  write_exact(as_handle(handle_), frame, make_deadline(timeout_value));
}

Message PipeChannel::receive(std::chrono::milliseconds timeout_value) {
  if (!valid()) {
    throw PipeError{"cannot receive through a closed pipe", ERROR_INVALID_HANDLE};
  }
  const Deadline deadline = make_deadline(timeout_value);
  std::array<std::byte, kFrameHeaderSize> header_bytes{};
  read_exact(as_handle(handle_), header_bytes, deadline);
  const FrameHeader header = decode_frame_header(header_bytes);
  Message message;
  message.type = header.message_type;
  message.request_id = header.request_id;
  message.payload.resize(header.payload_size);
  read_exact(as_handle(handle_), message.payload, deadline);
  return message;
}

std::uint32_t PipeChannel::client_process_id() const {
  if (!valid()) {
    throw PipeError{"cannot inspect a closed pipe", ERROR_INVALID_HANDLE};
  }
  ULONG process_id = 0U;
  if (GetNamedPipeClientProcessId(as_handle(handle_), &process_id) == FALSE) {
    fail("GetNamedPipeClientProcessId", GetLastError());
  }
  return static_cast<std::uint32_t>(process_id);
}

std::uint32_t PipeChannel::server_process_id() const {
  if (!valid()) {
    throw PipeError{"cannot inspect a closed pipe", ERROR_INVALID_HANDLE};
  }
  ULONG process_id = 0U;
  if (GetNamedPipeServerProcessId(as_handle(handle_), &process_id) == FALSE) {
    fail("GetNamedPipeServerProcessId", GetLastError());
  }
  return static_cast<std::uint32_t>(process_id);
}

bool PipeChannel::valid() const noexcept { return valid_handle(handle_); }

NamedPipeServer::NamedPipeServer(const std::wstring& name) {
  if (name.empty()) {
    throw PipeError{"named pipe name must not be empty", ERROR_INVALID_NAME};
  }
  constexpr DWORD open_mode =
      PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
  constexpr DWORD pipe_mode =
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
  const HANDLE handle = CreateNamedPipeW(name.c_str(), open_mode, pipe_mode, 1U,
                                         kMaximumPayloadSize + kFrameHeaderSize,
                                         kMaximumPayloadSize + kFrameHeaderSize, 0U, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    fail("CreateNamedPipeW", GetLastError());
  }
  handle_ = as_storage(handle);
}

NamedPipeServer::~NamedPipeServer() { close_handle(handle_); }

NamedPipeServer::NamedPipeServer(NamedPipeServer&& other) noexcept
    : handle_{std::exchange(other.handle_, nullptr)} {}

NamedPipeServer& NamedPipeServer::operator=(NamedPipeServer&& other) noexcept {
  if (this != &other) {
    close_handle(handle_);
    handle_ = std::exchange(other.handle_, nullptr);
  }
  return *this;
}

PipeChannel NamedPipeServer::accept(std::chrono::milliseconds timeout_value) {
  if (!valid()) {
    throw PipeError{"cannot accept through a closed pipe server", ERROR_INVALID_HANDLE};
  }
  Event event;
  OVERLAPPED overlapped{};
  overlapped.hEvent = event.get();
  const BOOL connected = ConnectNamedPipe(as_handle(handle_), &overlapped);
  if (connected == FALSE) {
    const DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) {
      static_cast<void>(SetEvent(event.get()));
    } else if (error == ERROR_IO_PENDING) {
      DWORD transferred = 0U;
      wait_overlapped(as_handle(handle_), overlapped, make_deadline(timeout_value),
                      "ConnectNamedPipe", transferred);
    } else {
      fail("ConnectNamedPipe", error);
    }
  }
  return PipeChannel{std::exchange(handle_, nullptr)};
}

bool NamedPipeServer::valid() const noexcept { return valid_handle(handle_); }

std::wstring make_pipe_name(std::span<const std::byte, 16U> session_token) {
  constexpr wchar_t digits[] = L"0123456789abcdef";
  std::wstring name{L"\\\\.\\pipe\\noleax-"};
  name.reserve(name.size() + session_token.size() * 2U);
  for (const std::byte value : session_token) {
    const unsigned int byte = std::to_integer<unsigned int>(value);
    name.push_back(digits[(byte >> 4U) & 0x0fU]);
    name.push_back(digits[byte & 0x0fU]);
  }
  return name;
}

}  // namespace noleax::ipc::windows
