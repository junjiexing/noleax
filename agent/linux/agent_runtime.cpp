// Linux agent runtime skeleton (docs/LINUX_PORT_PLAN.md M2).
//
// Entry is the LD_PRELOAD constructor: the dynamic loader runs it before the target's
// entry point, which is the Linux equivalent of the Windows "inject before entrypoint"
// guarantee. Two modes share the env-channel contract in bootstrap.hpp:
//   - controller session: connect back over the abstract unix socket, run the IPC state
//     machine (mirrors agent/windows/agent_runtime.cpp's agent_worker);
//   - standalone: NOLEAX_AGENT_CONFIG points at the capture TOML (hook profiles land in
//     M3; until then capture start reports a clean unsupported error).

#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <utility>

#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/linux/bootstrap.hpp"
#include "noleax/ipc/linux/unix_socket.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/version.hpp"

namespace {

using noleax::ipc::MessageType;
using noleax::ipc::linux::SocketChannel;
using namespace std::chrono_literals;

std::atomic<bool> bootstrap_started{false};

class HookGuardRuntimeLease final {
 public:
  HookGuardRuntimeLease() { ready_ = noleax::agent::acquire_hook_guard_runtime(); }
  ~HookGuardRuntimeLease() {
    if (ready_) {
      noleax::agent::release_hook_guard_runtime();
    }
  }
  HookGuardRuntimeLease(const HookGuardRuntimeLease&) = delete;
  HookGuardRuntimeLease& operator=(const HookGuardRuntimeLease&) = delete;
  [[nodiscard]] bool ready() const noexcept { return ready_; }

 private:
  bool ready_{false};
};

// ---------------------------------------------------------------------------
// env channel
// ---------------------------------------------------------------------------

struct BootstrapEnvironment {
  std::string socket_name;        // empty unless controller session mode
  std::string session_token_hex;  // 32 lowercase hex chars
  std::uint32_t controller_pid{0U};
  std::uint32_t connect_timeout_ms{noleax::agent::linux::kDefaultConnectTimeoutMs};
  std::string standalone_config_path;  // empty unless standalone mode
};

// Reads and then scrubs every NOLEAX_* variable so the target's children never
// re-bootstrap. Runs inside the loader constructor: getenv/unsetenv only.
[[nodiscard]] BootstrapEnvironment take_bootstrap_environment() noexcept {
  BootstrapEnvironment environment;
  if (const char* value = std::getenv(noleax::agent::linux::kBootstrapSocketEnv)) {
    environment.socket_name = value;
  }
  if (const char* value = std::getenv(noleax::agent::linux::kSessionTokenEnv)) {
    environment.session_token_hex = value;
  }
  if (const char* value = std::getenv(noleax::agent::linux::kControllerPidEnv)) {
    environment.controller_pid = static_cast<std::uint32_t>(std::strtoul(value, nullptr, 10));
  }
  if (const char* value = std::getenv(noleax::agent::linux::kConnectTimeoutEnv)) {
    const unsigned long timeout = std::strtoul(value, nullptr, 10);
    if (timeout > 0UL && timeout <= 3'600'000UL) {
      environment.connect_timeout_ms = static_cast<std::uint32_t>(timeout);
    }
  }
  if (const char* value = std::getenv(noleax::agent::linux::kAgentConfigEnv)) {
    environment.standalone_config_path = value;
  }

  unsetenv(noleax::agent::linux::kBootstrapSocketEnv);
  unsetenv(noleax::agent::linux::kSessionTokenEnv);
  unsetenv(noleax::agent::linux::kControllerPidEnv);
  unsetenv(noleax::agent::linux::kConnectTimeoutEnv);
  unsetenv(noleax::agent::linux::kAgentConfigEnv);
  return environment;
}

[[nodiscard]] bool decode_session_token(const std::string& hex,
                                        std::array<std::byte, 16U>& token) noexcept {
  if (hex.size() != 32U) {
    return false;
  }
  auto nibble = [](char digit) -> int {
    if (digit >= '0' && digit <= '9') {
      return digit - '0';
    }
    if (digit >= 'a' && digit <= 'f') {
      return digit - 'a' + 10;
    }
    return -1;
  };
  for (std::size_t index = 0U; index < token.size(); ++index) {
    const int high = nibble(hex[index * 2U]);
    const int low = nibble(hex[index * 2U + 1U]);
    if (high < 0 || low < 0) {
      return false;
    }
    token[index] = static_cast<std::byte>((high << 4U) | low);
  }
  return true;
}

// ---------------------------------------------------------------------------
// capture state machine (skeleton: hook installation lands in M3)
// ---------------------------------------------------------------------------

class LinuxCaptureRuntime {
 public:
  LinuxCaptureRuntime() = default;

  // M3 replaces this with the profile installer + writer start; the rest of the session
  // protocol already runs for real.
  [[nodiscard]] bool start(const noleax::ipc::StartCaptureRequest& request) {
    static_cast<void>(request);
    state_ = noleax::ipc::AgentState::kStarting;
    start_error_ = noleax::ipc::ErrorResponse{
        5U, 0U, "hook profiles are not implemented on Linux yet (port milestone M3)"};
    state_ = noleax::ipc::AgentState::kFailed;
    return false;
  }

  [[nodiscard]] const noleax::ipc::ErrorResponse& start_error() const noexcept {
    return start_error_;
  }

  [[nodiscard]] noleax::ipc::CaptureStatus status() const noexcept {
    noleax::ipc::CaptureStatus status;
    status.state = state_;
    return status;
  }

  void drain() noexcept { state_ = noleax::ipc::AgentState::kDrained; }

  void finalize() noexcept { state_ = noleax::ipc::AgentState::kFinalized; }

 private:
  noleax::ipc::AgentState state_{noleax::ipc::AgentState::kIdle};
  noleax::ipc::ErrorResponse start_error_{};
};

// ---------------------------------------------------------------------------
// controller session worker
// ---------------------------------------------------------------------------

void send_error(SocketChannel& channel, MessageType operation, std::uint64_t request_id,
                noleax::ipc::ErrorResponse error) {
  error.message =
      "operation " + std::to_string(static_cast<unsigned>(operation)) + ": " + error.message;
  noleax::ipc::Message message;
  message.type = MessageType::kError;
  message.request_id = request_id;
  message.payload = noleax::ipc::encode_error_response(error);
  channel.send(message, 5s);
}

void session_worker(BootstrapEnvironment environment) noexcept {
  try {
    std::array<std::byte, 16U> token{};
    if (!decode_session_token(environment.session_token_hex, token)) {
      return;
    }
    // The abstract namespace name carries a leading NUL that the env channel cannot.
    std::string socket_name{"\0", 1U};
    socket_name += environment.socket_name;

    SocketChannel channel = SocketChannel::connect(
        socket_name, std::chrono::milliseconds{environment.connect_timeout_ms});
    if (channel.server_process_id() != environment.controller_pid) {
      return;
    }

    noleax::ipc::AgentHello hello;
    hello.agent_abi_version = noleax::kAgentAbiVersion;
    hello.process_id = static_cast<std::uint32_t>(::getpid());
    hello.worker_thread_id = static_cast<std::uint32_t>(::syscall(SYS_gettid));
    hello.pointer_width = static_cast<std::uint8_t>(sizeof(void*));
    hello.architecture = noleax::ipc::Architecture::kX64;
    hello.session_token = token;
    noleax::ipc::Message hello_message;
    hello_message.type = MessageType::kAgentHello;
    hello_message.request_id = 1U;
    hello_message.payload = noleax::ipc::encode_agent_hello(hello);
    channel.send(hello_message, 5s);

    const noleax::ipc::Message start =
        channel.receive(std::chrono::milliseconds{environment.connect_timeout_ms});
    if (start.type != MessageType::kStartCapture) {
      return;
    }

    const HookGuardRuntimeLease guard_lease;
    if (!guard_lease.ready()) {
      noleax::ipc::ErrorResponse error{1U, 0U, "hook guard runtime is unavailable"};
      send_error(channel, MessageType::kStartCapture, start.request_id, error);
      return;
    }
    // The session worker is an agent-internal thread; hooks must never record it.
    const noleax::agent::InternalThreadScope internal_scope;

    LinuxCaptureRuntime runtime;
    const noleax::ipc::StartCaptureRequest request =
        noleax::ipc::decode_start_capture(start.payload);
    if (!runtime.start(request)) {
      send_error(channel, MessageType::kStartCapture, start.request_id, runtime.start_error());
      return;
    }

    noleax::ipc::Message ready;
    ready.type = MessageType::kCaptureReady;
    ready.request_id = start.request_id;
    ready.payload = noleax::ipc::encode_capture_status(runtime.status());
    channel.send(ready, 5s);

    for (;;) {
      const noleax::ipc::Message message = channel.receive(24h);
      noleax::ipc::Message response;
      response.request_id = message.request_id;
      switch (message.type) {
        case MessageType::kQueryStatus:
          response.type = MessageType::kCaptureStatus;
          response.payload = noleax::ipc::encode_capture_status(runtime.status());
          channel.send(response, 5s);
          break;
        case MessageType::kStopCapture:
          runtime.drain();
          response.type = MessageType::kCaptureDrained;
          response.payload = noleax::ipc::encode_capture_status(runtime.status());
          channel.send(response, 5s);
          break;
        case MessageType::kFinalizeHooks:
          runtime.finalize();
          response.type = MessageType::kCaptureFinalized;
          response.payload = noleax::ipc::encode_capture_status(runtime.status());
          channel.send(response, 5s);
          return;
        default:
          return;
      }
    }
  } catch (...) {
    // A broken channel or any other failure must never take the target process down;
    // the controller observes the closed channel on its side.
    return;
  }
}

void standalone_worker(std::string config_path) noexcept {
  // Standalone capture start shares the M3 hook-installation seam; say so instead of
  // failing silently in a controller-less run.
  std::fprintf(stderr,
               "noleax-agent: standalone capture from '%s' is not implemented on "
               "Linux yet (port milestone M3)\n",
               config_path.c_str());
}

// ---------------------------------------------------------------------------
// constructor entry
// ---------------------------------------------------------------------------

__attribute__((constructor)) void noleax_agent_linux_init() {
  BootstrapEnvironment environment = take_bootstrap_environment();
  const bool has_session = !environment.socket_name.empty();
  const bool has_standalone = !environment.standalone_config_path.empty();
  if (has_session == has_standalone) {
    return;  // both unset (plain preload) or both set (ambiguous): stay inert
  }
  if (bootstrap_started.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  try {
    if (has_session) {
      std::thread{session_worker, std::move(environment)}.detach();
    } else {
      std::thread{standalone_worker, std::move(environment.standalone_config_path)}.detach();
    }
  } catch (...) {
    // A failed bootstrap must never take the target down with it.
  }
}

}  // namespace
