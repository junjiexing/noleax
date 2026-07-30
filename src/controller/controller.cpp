#include "noleax/controller/windows/controller.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: bcrypt.h requires Windows base types.
#include <windows.h>
#include <bcrypt.h>
// clang-format on

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "noleax/agent/windows/bootstrap.hpp"
#include "noleax/controller/windows/entrypoint_injector.hpp"
#include "noleax/controller/windows/pe_patch.hpp"
#include "noleax/controller/windows/process.hpp"
#include "noleax/controller/windows/remote_injector.hpp"
#include "noleax/controller/windows/thread_hijack_injector.hpp"
#include "noleax/controller/windows/thread_suspension.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/ipc/windows/named_pipe.hpp"
#include "noleax/version.hpp"

#include "windows/injection_common.hpp"

namespace noleax::controller::windows {
namespace {

[[nodiscard]] HANDLE as_handle(void* value) noexcept { return static_cast<HANDLE>(value); }

class OwnedHandle final {
 public:
  explicit OwnedHandle(HANDLE value = nullptr) noexcept : value_{value} {}
  ~OwnedHandle() {
    if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
      static_cast<void>(CloseHandle(value_));
    }
  }
  OwnedHandle(const OwnedHandle&) = delete;
  OwnedHandle& operator=(const OwnedHandle&) = delete;
  OwnedHandle(OwnedHandle&& other) noexcept : value_{std::exchange(other.value_, nullptr)} {}
  OwnedHandle& operator=(OwnedHandle&& other) noexcept {
    if (this != &other) {
      if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
        static_cast<void>(CloseHandle(value_));
      }
      value_ = std::exchange(other.value_, nullptr);
    }
    return *this;
  }
  [[nodiscard]] HANDLE get() const noexcept { return value_; }
  [[nodiscard]] bool valid() const noexcept {
    return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
  }
  [[nodiscard]] HANDLE release() noexcept { return std::exchange(value_, nullptr); }

 private:
  HANDLE value_{nullptr};
};

[[nodiscard]] std::array<std::byte, 16U> random_token() {
  std::array<std::byte, 16U> token{};
  const NTSTATUS status =
      BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(token.data()),
                      static_cast<ULONG>(token.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status < 0) {
    throw ControllerError{"BCryptGenRandom failed", static_cast<std::uint32_t>(status)};
  }
  return token;
}

[[nodiscard]] noleax::agent::windows::BootstrapParameters make_bootstrap(
    const std::wstring& pipe_name, const std::array<std::byte, 16U>& token,
    std::chrono::milliseconds timeout) {
  if (pipe_name.size() >= noleax::agent::windows::kBootstrapPipeNameCapacity ||
      timeout <= std::chrono::milliseconds::zero() ||
      timeout.count() > std::numeric_limits<std::uint32_t>::max()) {
    throw ControllerError{"bootstrap parameters exceed their ABI limits", ERROR_INVALID_PARAMETER};
  }
  noleax::agent::windows::BootstrapParameters bootstrap;
  std::ranges::copy(pipe_name, bootstrap.pipe_name.begin());
  bootstrap.pipe_name[pipe_name.size()] = L'\0';
  bootstrap.session_token = token;
  bootstrap.connect_timeout_ms = static_cast<std::uint32_t>(timeout.count());
  bootstrap.controller_process_id = GetCurrentProcessId();
  return bootstrap;
}

[[nodiscard]] noleax::ipc::CaptureStatus decode_expected_status(
    const noleax::ipc::Message& response, noleax::ipc::MessageType expected,
    std::uint64_t request_id) {
  if (response.request_id != request_id) {
    throw ControllerError{"agent response request id does not match"};
  }
  if (response.type == noleax::ipc::MessageType::kError) {
    const auto error = noleax::ipc::decode_error_response(response.payload);
    throw ControllerError{"agent error: " + error.message, error.system_error};
  }
  if (response.type != expected) {
    throw ControllerError{"agent response has an unexpected message type"};
  }
  return noleax::ipc::decode_capture_status(response.payload);
}

}  // namespace

class CaptureSession::Impl final {
 public:
  Impl(std::uint32_t process_id, HANDLE process_handle, bool owns_process,
       noleax::ipc::windows::PipeChannel channel, noleax::ipc::AgentHello hello,
       std::chrono::milliseconds timeout, std::optional<SuspendedProcess> launched_process)
      : process_id_{process_id},
        owned_process_{owns_process ? OwnedHandle{process_handle} : OwnedHandle{}},
        borrowed_process_{process_handle},
        channel_{std::move(channel)},
        hello_{hello},
        timeout_{timeout},
        launched_process_{std::move(launched_process)} {}

  ~Impl() {
    if (!stopped_) {
      try {
        static_cast<void>(stop());
      } catch (...) {
      }
    }
  }

  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  [[nodiscard]] noleax::ipc::CaptureStatus query_status() {
    require_active();
    return transact(noleax::ipc::MessageType::kQueryStatus,
                    noleax::ipc::MessageType::kCaptureStatus);
  }

  [[nodiscard]] noleax::ipc::CaptureStatus stop() {
    if (stopped_) {
      return final_status_;
    }
    require_active();
    const noleax::ipc::CaptureStatus drained =
        transact(noleax::ipc::MessageType::kStopCapture, noleax::ipc::MessageType::kCaptureDrained);
    if (drained.state != noleax::ipc::AgentState::kDrained) {
      throw ControllerError{"agent did not enter the drained state"};
    }
    ThreadSuspension suspension{process_id_, hello_.worker_thread_id};
    final_status_ = transact(noleax::ipc::MessageType::kFinalizeHooks,
                             noleax::ipc::MessageType::kCaptureFinalized);
    if (final_status_.state != noleax::ipc::AgentState::kFinalized) {
      throw ControllerError{"agent did not enter the finalized state"};
    }
    stopped_ = true;
    return final_status_;
  }

  [[nodiscard]] bool wait_for_target(std::chrono::milliseconds timeout) const {
    if (timeout < std::chrono::milliseconds::zero()) {
      throw ControllerError{"target wait timeout must not be negative", ERROR_INVALID_PARAMETER};
    }
    const DWORD value = timeout.count() >= static_cast<long long>(INFINITE - 1U)
                            ? INFINITE - 1U
                            : static_cast<DWORD>(timeout.count());
    const DWORD result = WaitForSingleObject(process_handle(), value);
    if (result == WAIT_OBJECT_0) {
      return true;
    }
    if (result == WAIT_TIMEOUT) {
      return false;
    }
    const DWORD error = GetLastError();
    throw ControllerError{
        "WaitForSingleObject(target) failed with Windows error " + std::to_string(error), error};
  }

  [[nodiscard]] std::uint32_t target_exit_code() const {
    DWORD code = 0U;
    if (GetExitCodeProcess(process_handle(), &code) == FALSE) {
      const DWORD error = GetLastError();
      throw ControllerError{"GetExitCodeProcess failed with Windows error " + std::to_string(error),
                            error};
    }
    return code;
  }

  [[nodiscard]] std::uint32_t process_id() const noexcept { return process_id_; }
  [[nodiscard]] std::uint32_t agent_thread_id() const noexcept { return hello_.worker_thread_id; }
  [[nodiscard]] bool launched_target() const noexcept { return launched_process_.has_value(); }
  [[nodiscard]] bool stopped() const noexcept { return stopped_; }

 private:
  [[nodiscard]] HANDLE process_handle() const noexcept {
    return launched_process_.has_value()
               ? as_handle(launched_process_->process_handle())
               : (owned_process_.valid() ? owned_process_.get() : borrowed_process_);
  }

  void require_active() const {
    if (stopped_ || !channel_.valid() || process_handle() == nullptr) {
      throw ControllerError{"capture session is not active"};
    }
  }

  [[nodiscard]] noleax::ipc::CaptureStatus transact(noleax::ipc::MessageType request_type,
                                                    noleax::ipc::MessageType response_type) {
    const std::uint64_t request_id = next_request_id_++;
    channel_.send({request_type, request_id, {}}, timeout_);
    return decode_expected_status(channel_.receive(timeout_), response_type, request_id);
  }

  std::uint32_t process_id_{0U};
  OwnedHandle owned_process_;
  HANDLE borrowed_process_{nullptr};
  noleax::ipc::windows::PipeChannel channel_;
  noleax::ipc::AgentHello hello_;
  std::chrono::milliseconds timeout_;
  std::optional<SuspendedProcess> launched_process_;
  std::uint64_t next_request_id_{3U};
  noleax::ipc::CaptureStatus final_status_;
  bool stopped_{false};
};

ControllerError::ControllerError(const std::string& message, std::uint32_t system_error)
    : std::runtime_error{message}, system_error_{system_error} {}

std::uint32_t ControllerError::system_error() const noexcept { return system_error_; }

namespace {

struct ConnectedAgent {
  noleax::ipc::windows::PipeChannel channel;
  noleax::ipc::AgentHello hello;
};

[[nodiscard]] ConnectedAgent connect_agent(noleax::ipc::windows::NamedPipeServer& server,
                                           std::uint32_t process_id,
                                           const std::array<std::byte, 16U>& token,
                                           const CaptureOptions& capture) {
  auto channel = server.accept(capture.timeout);
  if (channel.client_process_id() != process_id) {
    throw ControllerError{"named pipe client PID does not match the target process"};
  }
  const noleax::ipc::Message hello_message = channel.receive(capture.timeout);
  if (hello_message.type != noleax::ipc::MessageType::kAgentHello ||
      hello_message.request_id != 1U) {
    throw ControllerError{"agent did not begin with a valid AgentHello"};
  }
  const noleax::ipc::AgentHello hello = noleax::ipc::decode_agent_hello(hello_message.payload);
  if (hello.agent_abi_version != noleax::kAgentAbiVersion || hello.process_id != process_id ||
      hello.session_token != token || hello.pointer_width != sizeof(void*) ||
      hello.architecture != noleax::ipc::Architecture::kX64) {
    throw ControllerError{"agent hello is incompatible with this controller or session"};
  }

  noleax::ipc::StartCaptureRequest start = capture.start;
  channel.send(
      {noleax::ipc::MessageType::kStartCapture, 2U, noleax::ipc::encode_start_capture(start)},
      capture.timeout);
  const auto ready = decode_expected_status(channel.receive(capture.timeout),
                                            noleax::ipc::MessageType::kCaptureReady, 2U);
  if (ready.state != noleax::ipc::AgentState::kCapturing) {
    throw ControllerError{"agent did not enter the capturing state"};
  }
  return {std::move(channel), hello};
}

void validate_capture_options(const CaptureOptions& capture) {
  if (!capture.agent_path.is_absolute() || capture.timeout <= std::chrono::milliseconds::zero() ||
      capture.start.trace_path_utf8.empty()) {
    throw ControllerError{"capture options are incomplete", ERROR_INVALID_PARAMETER};
  }
}

}  // namespace

CaptureSession::CaptureSession(std::unique_ptr<Impl> implementation) noexcept
    : implementation_{std::move(implementation)} {}

CaptureSession::~CaptureSession() = default;

CaptureSession::CaptureSession(CaptureSession&& other) noexcept = default;

CaptureSession& CaptureSession::operator=(CaptureSession&& other) noexcept = default;

CaptureSession CaptureSession::launch(const LaunchOptions& launch, const CaptureOptions& capture) {
  validate_capture_options(capture);
  const auto token = random_token();
  const std::wstring pipe_name = noleax::ipc::windows::make_pipe_name(token);
  noleax::ipc::windows::NamedPipeServer server{pipe_name};
  SuspendedProcess process =
      SuspendedProcess::create(launch.executable, launch.arguments, launch.working_directory);
  try {
    const auto bootstrap = make_bootstrap(pipe_name, token, capture.timeout);
    CaptureOptions launch_capture = capture;
    launch_capture.start.capture_kind = noleax::ipc::CaptureKind::kLaunch;
    ConnectedAgent connected{{}, {}};
    if (capture.method == InjectionMethod::kThreadHijack) {
      // The stub parked the main thread until the capture is ready; finish()
      // restores its original RtlUserThreadStart context and resumes it.
      ThreadHijack hijack{process.process_handle(),
                          process.process_id(),
                          capture.agent_path,
                          bootstrap,
                          {process.main_thread_handle(), true}};
      hijack.start();
      try {
        connected = connect_agent(server, process.process_id(), token, launch_capture);
      } catch (...) {
        hijack.abort();
        throw;
      }
      static_cast<void>(hijack.finish(capture.timeout));
      process.note_main_thread_resumed();
    } else if (capture.method == InjectionMethod::kEntrypointCode) {
      // The stub restores the original entry bytes itself after the capture
      // is ready; finish() proves the restore and re-applies page protection.
      EntrypointInjection injection{process.process_handle(),
                                    process.process_id(),
                                    launch.executable.filename().native(),
                                    capture.agent_path,
                                    bootstrap};
      process.resume_main_thread();
      process.note_main_thread_resumed();
      try {
        connected = connect_agent(server, process.process_id(), token, launch_capture);
      } catch (const std::exception& handshake_error) {
        const std::string detail = injection.describe_failure();
        injection.abort();
        throw ControllerError{std::string{"agent handshake failed after entrypoint bootstrap: "} +
                              handshake_error.what() + " (" + detail + ")"};
      }
      static_cast<void>(injection.finish(capture.timeout));
    } else if (capture.method == InjectionMethod::kStaticPePatch) {
      // The image already carries the bootstrap section; pass the session
      // parameters through it and let the embedded stub do the rest.
      const auto patch_info = read_static_patch_info(launch.executable);
      if (!patch_info.has_value()) {
        throw ControllerError{"the target is not a noleax-patched executable; create one with "
                              "'noleax patch' first",
                              ERROR_BAD_EXE_FORMAT};
      }
      const auto image = injection::find_remote_image_by_memory(
          static_cast<HANDLE>(process.process_handle()),
          launch.executable.filename().native());
      if (!image.has_value()) {
        throw ControllerError{"cannot locate the main image inside the target process",
                              ERROR_MOD_NOT_FOUND};
      }
      const auto params_address = injection::checked_remote_address(
          image->base, patch_info->params_rva);
      SIZE_T written = 0U;
      if (WriteProcessMemory(static_cast<HANDLE>(process.process_handle()),
                             std::bit_cast<LPVOID>(params_address), &bootstrap, sizeof(bootstrap),
                             &written) == FALSE ||
          written != sizeof(bootstrap)) {
        const DWORD error = GetLastError();
        throw ControllerError{"cannot pass bootstrap parameters to the patched target "
                              "(Windows error " +
                                  std::to_string(error) + ")",
                              error};
      }
      process.resume_main_thread();
      process.note_main_thread_resumed();
      connected = connect_agent(server, process.process_id(), token, launch_capture);
    } else if (capture.method == InjectionMethod::kRemoteThread) {
      static_cast<void>(inject_remote_thread(process.process_handle(), process.process_id(),
                                             capture.agent_path, bootstrap, capture.timeout));
      connected = connect_agent(server, process.process_id(), token, launch_capture);
      process.resume_main_thread();
    } else {
      throw ControllerError{"the selected injection method is not implemented for launch",
                            ERROR_NOT_SUPPORTED};
    }
    const std::uint32_t process_id = process.process_id();
    const HANDLE process_handle = as_handle(process.process_handle());
    return CaptureSession{std::make_unique<Impl>(
        process_id, process_handle, false, std::move(connected.channel), connected.hello,
        capture.timeout, std::optional<SuspendedProcess>{std::move(process)})};
  } catch (...) {
    process.terminate(0xc0000142U);
    throw;
  }
}

CaptureSession CaptureSession::attach(std::uint32_t process_id, const CaptureOptions& capture) {
  validate_capture_options(capture);
  if (process_id == 0U || process_id == GetCurrentProcessId()) {
    throw ControllerError{"attach PID is invalid", ERROR_INVALID_PARAMETER};
  }
  constexpr DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
                           PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE;
  OwnedHandle process{OpenProcess(access, FALSE, process_id)};
  if (!process.valid()) {
    const DWORD error = GetLastError();
    throw ControllerError{"OpenProcess failed with Windows error " + std::to_string(error), error};
  }
  const auto token = random_token();
  const std::wstring pipe_name = noleax::ipc::windows::make_pipe_name(token);
  noleax::ipc::windows::NamedPipeServer server{pipe_name};
  const auto bootstrap = make_bootstrap(pipe_name, token, capture.timeout);
  CaptureOptions attach_capture = capture;
  attach_capture.start.capture_kind = noleax::ipc::CaptureKind::kAttach;
  ConnectedAgent connected{{}, {}};
  if (capture.method == InjectionMethod::kThreadHijack) {
    // Attach does not make the stub wait for capture readiness: finish()
    // restores the thread as soon as the bootstrap returned, which surfaces
    // stub failures (loader error, deadlocked thread) before the pipe wait
    // and keeps the hijacked window as short as possible.
    ThreadHijack hijack{process.get(), process_id, capture.agent_path, bootstrap,
                        {nullptr, false}};
    hijack.start();
    static_cast<void>(hijack.finish(capture.timeout));
    connected = connect_agent(server, process_id, token, attach_capture);
  } else if (capture.method == InjectionMethod::kRemoteThread) {
    static_cast<void>(inject_remote_thread(process.get(), process_id, capture.agent_path,
                                           bootstrap, capture.timeout));
    connected = connect_agent(server, process_id, token, attach_capture);
  } else {
    throw ControllerError{"the selected injection method is not supported for attach",
                          ERROR_NOT_SUPPORTED};
  }
  const HANDLE transferred = process.release();
  return CaptureSession{std::make_unique<Impl>(process_id, transferred, true,
                                               std::move(connected.channel), connected.hello,
                                               capture.timeout, std::nullopt)};
}

noleax::ipc::CaptureStatus CaptureSession::query_status() {
  return implementation_->query_status();
}

noleax::ipc::CaptureStatus CaptureSession::stop() { return implementation_->stop(); }

bool CaptureSession::wait_for_target(std::chrono::milliseconds timeout) const {
  return implementation_->wait_for_target(timeout);
}

std::uint32_t CaptureSession::target_exit_code() const {
  return implementation_->target_exit_code();
}

std::uint32_t CaptureSession::process_id() const noexcept { return implementation_->process_id(); }

std::uint32_t CaptureSession::agent_thread_id() const noexcept {
  return implementation_->agent_thread_id();
}

bool CaptureSession::launched_target() const noexcept { return implementation_->launched_target(); }

bool CaptureSession::stopped() const noexcept { return implementation_->stopped(); }

}  // namespace noleax::controller::windows
