#include "noleax/controller/linux/controller.hpp"

#include <fcntl.h>
#include <signal.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "noleax/agent/linux/bootstrap.hpp"
#include "noleax/controller/linux/ptrace_injector.hpp"
#include "noleax/ipc/linux/unix_socket.hpp"
#include "noleax/version.hpp"

extern char** environ;

namespace noleax::controller::linux {
namespace {

using Clock = std::chrono::steady_clock;
using noleax::ipc::MessageType;
using namespace std::chrono_literals;

[[nodiscard]] std::array<std::byte, 16U> make_session_token() {
  std::array<std::byte, 16U> token{};
  std::size_t filled = 0U;
  unsigned int flags = GRND_NONBLOCK;
  while (filled < token.size()) {
    const ssize_t count = ::getrandom(token.data() + filled, token.size() - filled, flags);
    if (count < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN && flags == GRND_NONBLOCK) {
        // Preserve token unpredictability during early boot: once the non-blocking probe says
        // the pool is not initialized, wait for the kernel CSPRNG instead of using a weak local
        // fallback.
        flags = 0U;
        continue;
      }
      throw ControllerError{"getrandom failed", static_cast<std::uint32_t>(errno)};
    }
    if (count == 0) {
      throw ControllerError{"getrandom returned no session-token bytes", EIO};
    }
    filled += static_cast<std::size_t>(count);
  }
  return token;
}

[[nodiscard]] std::string hex_encode(std::span<const std::byte> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(bytes.size() * 2U);
  for (const std::byte value : bytes) {
    const auto byte = static_cast<unsigned>(value);
    hex.push_back(digits[(byte >> 4U) & 0x0fU]);
    hex.push_back(digits[byte & 0x0fU]);
  }
  return hex;
}

struct ChildEnvironment {
  std::vector<std::string> storage;
  std::vector<char*> pointers;
};

// Builds the child's environment: current environ minus the variables we override, plus
// the LD_PRELOAD/bootstrap set. All allocation happens here, before fork.
[[nodiscard]] ChildEnvironment make_child_environment(const std::filesystem::path& agent_path,
                                                      std::string_view socket_env_name,
                                                      std::string_view token_hex,
                                                      std::uint32_t controller_pid,
                                                      std::uint32_t timeout_ms) {
  ChildEnvironment environment;
  environment.storage.emplace_back("LD_PRELOAD=" + agent_path.string());
  environment.storage.emplace_back(std::string{noleax::agent::linux::kBootstrapSocketEnv} + "=" +
                                   std::string{socket_env_name});
  environment.storage.emplace_back(std::string{noleax::agent::linux::kSessionTokenEnv} + "=" +
                                   std::string{token_hex});
  environment.storage.emplace_back(std::string{noleax::agent::linux::kControllerPidEnv} + "=" +
                                   std::to_string(controller_pid));
  environment.storage.emplace_back(std::string{noleax::agent::linux::kConnectTimeoutEnv} + "=" +
                                   std::to_string(timeout_ms));

  for (char** current = environ; *current != nullptr; ++current) {
    const std::string_view entry{*current};
    const auto separator = entry.find('=');
    const std::string_view key = entry.substr(0U, separator);
    if (key == "LD_PRELOAD" || key == noleax::agent::linux::kBootstrapSocketEnv ||
        key == noleax::agent::linux::kSessionTokenEnv ||
        key == noleax::agent::linux::kControllerPidEnv ||
        key == noleax::agent::linux::kConnectTimeoutEnv ||
        key == noleax::agent::linux::kAgentConfigEnv) {
      continue;
    }
    environment.pointers.push_back(const_cast<char*>(entry.data()));
  }
  for (std::string& entry : environment.storage) {
    environment.pointers.push_back(entry.data());
  }
  environment.pointers.push_back(nullptr);
  return environment;
}

[[noreturn]] void child_exec(const LaunchOptions& launch, const ChildEnvironment& environment,
                             int error_fd) {
  if (!launch.working_directory.empty()) {
    if (::chdir(launch.working_directory.c_str()) != 0) {
      const int error = errno;
      const ssize_t ignored = ::write(error_fd, &error, sizeof(error));
      static_cast<void>(ignored);
      ::_exit(127);
    }
  }
  std::vector<char*> argv;
  argv.reserve(launch.arguments.size() + 2U);
  argv.push_back(const_cast<char*>(launch.executable.c_str()));
  for (const std::string& argument : launch.arguments) {
    argv.push_back(const_cast<char*>(argument.c_str()));
  }
  argv.push_back(nullptr);
  ::execve(launch.executable.c_str(), argv.data(),
           const_cast<char* const*>(environment.pointers.data()));
  const int error = errno;
  const ssize_t ignored = ::write(error_fd, &error, sizeof(error));
  static_cast<void>(ignored);
  ::_exit(127);
}

// Owns a freshly forked launch until the controller handshake succeeds. A throwing constructor
// does not run CaptureSession::Impl's destructor, so this local guard must terminate and reap the
// child on every error path after fork.
class LaunchChildGuard final {
 public:
  explicit LaunchChildGuard(pid_t process_id) noexcept : process_id_{process_id} {}

  ~LaunchChildGuard() {
    if (process_id_ <= 0) {
      return;
    }
    int status = 0;
    for (;;) {
      const pid_t result = ::waitpid(process_id_, &status, WNOHANG);
      if (result == process_id_ || (result < 0 && errno == ECHILD)) {
        return;
      }
      if (result < 0 && errno == EINTR) {
        continue;
      }
      break;
    }
    static_cast<void>(::kill(process_id_, SIGKILL));
    while (::waitpid(process_id_, &status, 0) < 0 && errno == EINTR) {
    }
  }

  LaunchChildGuard(const LaunchChildGuard&) = delete;
  LaunchChildGuard& operator=(const LaunchChildGuard&) = delete;

  void release() noexcept { process_id_ = -1; }

 private:
  pid_t process_id_{-1};
};

}  // namespace

ControllerError::ControllerError(const std::string& message, std::uint32_t system_error)
    : std::runtime_error{message}, system_error_{system_error} {}

ControllerError::ControllerError(const std::string& message, ControllerFailureKind failure_kind,
                                 std::uint32_t system_error)
    : std::runtime_error{message}, system_error_{system_error}, failure_kind_{failure_kind} {}

std::uint32_t ControllerError::system_error() const noexcept { return system_error_; }

ControllerFailureKind ControllerError::failure_kind() const noexcept { return failure_kind_; }

const char* controller_failure_kind_name(ControllerFailureKind kind) noexcept {
  switch (kind) {
    case ControllerFailureKind::kNone:
      return "none";
    case ControllerFailureKind::kAgentCrash:
      return "agent-crash";
    case ControllerFailureKind::kWriterError:
      return "writer-error";
    case ControllerFailureKind::kHookInstall:
      return "hook-install";
    case ControllerFailureKind::kTargetExit:
      return "target-exit";
    case ControllerFailureKind::kProtocol:
      return "protocol";
  }
  return "unknown";
}

class CaptureSession::Impl {
 public:
  Impl(LaunchOptions launch, const CaptureOptions& capture) {
    if (capture.agent_path.empty()) {
      throw ControllerError{"agent path must not be empty", EINVAL};
    }
    token_ = make_session_token();
    const std::string socket_name = noleax::ipc::linux::make_socket_name(token_);
    server_.emplace(socket_name);

    int error_pipe[2] = {-1, -1};
    if (::pipe2(error_pipe, O_CLOEXEC) != 0) {
      throw ControllerError{"pipe2 failed", static_cast<std::uint32_t>(errno)};
    }

    ChildEnvironment environment =
        make_child_environment(capture.agent_path, std::string_view{socket_name}.substr(1U),
                               hex_encode(token_), static_cast<std::uint32_t>(::getpid()),
                               static_cast<std::uint32_t>(capture.timeout.count()));
    const pid_t child = ::fork();
    if (child < 0) {
      ::close(error_pipe[0]);
      ::close(error_pipe[1]);
      throw ControllerError{"fork failed", static_cast<std::uint32_t>(errno)};
    }
    if (child == 0) {
      ::close(error_pipe[0]);
      child_exec(launch, environment, error_pipe[1]);
    }
    ::close(error_pipe[1]);
    LaunchChildGuard child_guard{child};
    process_id_ = static_cast<std::uint32_t>(child);

    std::optional<int> exec_error;
    for (;;) {
      int value = 0;
      const ssize_t count = ::read(error_pipe[0], &value, sizeof(value));
      if (count == static_cast<ssize_t>(sizeof(value))) {
        exec_error = value;
        break;
      }
      if (count == 0) {
        break;  // write end closed on exec: the target is running
      }
      if (count < 0 && errno != EINTR) {
        ::close(error_pipe[0]);
        throw ControllerError{"failed to read the child exec status",
                              static_cast<std::uint32_t>(errno)};
      }
    }
    ::close(error_pipe[0]);
    if (exec_error.has_value()) {
      throw ControllerError{
          "cannot execute '" + launch.executable.string() + "': " + std::strerror(*exec_error),
          static_cast<std::uint32_t>(*exec_error)};
    }

    run_handshake(capture);
    child_guard.release();
  }

  // Attach path: inject the agent into a running process and let its attach bootstrap
  // call back over the session socket. H1-B: the bootstrap runs synchronously inside the
  // injector's stop window, so inject() blocks until the handshake and hook installation
  // have completed — it runs on a worker while this thread drives the session handshake
  // concurrently. Both error channels are captured; the handshake error (it carries the
  // agent's own start-failure detail) is reported first when both fail.
  Impl(std::uint32_t process_id, const CaptureOptions& capture) {
    if (capture.agent_path.empty()) {
      throw ControllerError{"agent path must not be empty", EINVAL};
    }
    token_ = make_session_token();
    server_.emplace(noleax::ipc::linux::make_socket_name(token_));
    process_id_ = process_id;

    noleax::agent::linux::AttachBootstrapParameters parameters;
    parameters.controller_process_id = static_cast<std::uint32_t>(::getpid());
    parameters.connect_timeout_ms = static_cast<std::uint32_t>(capture.timeout.count());
    const std::string socket_name = noleax::ipc::linux::make_socket_name(token_);
    const std::string_view socket_env = std::string_view{socket_name}.substr(1U);
    if (socket_env.size() >= noleax::agent::linux::kAttachSocketNameCapacity) {
      throw ControllerError{"session socket name is too long", ENAMETOOLONG};
    }
    std::memcpy(parameters.socket_name, socket_env.data(), socket_env.size());
    parameters.session_token = token_;

    std::vector<std::byte> parameter_bytes(sizeof(parameters));
    std::memcpy(parameter_bytes.data(), &parameters, sizeof(parameters));
    std::exception_ptr injection_error;
    std::thread injection_worker{[this, process_id, &capture, &parameter_bytes, &injection_error] {
      try {
        PtraceInjector::inject(process_id, capture.agent_path, parameter_bytes, capture.timeout,
                               capture.start.custom_hooks);
      } catch (...) {
        injection_error = std::current_exception();
      }
    }};
    std::exception_ptr handshake_error;
    try {
      run_handshake(capture);
    } catch (...) {
      handshake_error = std::current_exception();
    }
    injection_worker.join();
    if (handshake_error != nullptr) {
      std::rethrow_exception(handshake_error);
    }
    if (injection_error != nullptr) {
      std::rethrow_exception(injection_error);
    }
  }

  // Classified handshake: a broken session socket means the target died (kTargetExit) or
  // the agent never came up (kAgentCrash); a decode failure is a protocol error.
  void run_handshake(const CaptureOptions& capture) {
    try {
      complete_handshake(capture);
    } catch (const noleax::ipc::linux::SocketError& error) {
      if (note_target_exit()) {
        throw ControllerError{
            "target exited before the agent handshake completed: " + std::string{error.what()},
            ControllerFailureKind::kTargetExit, error.system_error()};
      }
      throw ControllerError{std::string{"agent session failed: "} + error.what(),
                            ControllerFailureKind::kAgentCrash, error.system_error()};
    } catch (const noleax::ipc::ProtocolError& error) {
      throw ControllerError{std::string{"agent protocol violation: "} + error.what(),
                            ControllerFailureKind::kProtocol};
    }
  }

  // Re-checks target liveness after a session failure: a dead target broke the socket by
  // exiting; a live one means the agent died (or never came up) inside it.
  [[nodiscard]] bool note_target_exit() {
    if (target_exited_) {
      return true;
    }
    int status = 0;
    const pid_t result = ::waitpid(static_cast<pid_t>(process_id_), &status, WNOHANG);
    if (result == static_cast<pid_t>(process_id_)) {
      target_exited_ = true;
      if (WIFEXITED(status)) {
        target_exit_code_ = static_cast<std::uint32_t>(WEXITSTATUS(status));
      } else if (WIFSIGNALED(status)) {
        target_exit_code_ = 128U + static_cast<std::uint32_t>(WTERMSIG(status));
      }
      return true;
    }
    if (result < 0 && errno == ECHILD) {
      // Attached targets are not our children: watch the process directory instead.
      const std::string proc_dir = "/proc/" + std::to_string(process_id_);
      if (::access(proc_dir.c_str(), F_OK) != 0) {
        target_exited_ = true;
        return true;
      }
    }
    return false;
  }

  // A session socket that broke mid-capture: the target exiting and the agent crashing
  // look identical on the wire, so liveness decides the classification.
  [[nodiscard]] ControllerError session_broken_error(const char* context,
                                                     const noleax::ipc::linux::SocketError& error) {
    if (note_target_exit()) {
      return ControllerError{std::string{"target exited "} + context + ": " + error.what(),
                             ControllerFailureKind::kTargetExit, error.system_error()};
    }
    return ControllerError{std::string{"agent crashed "} + context + ": " + error.what(),
                           ControllerFailureKind::kAgentCrash, error.system_error()};
  }

  void complete_handshake(const CaptureOptions& capture) {
    channel_.emplace(server_->accept(capture.timeout));
    server_.reset();  // single-shot session: no further accepts

    noleax::ipc::Message hello = channel_->receive(capture.timeout);
    if (hello.type != MessageType::kAgentHello) {
      throw ControllerError{"agent did not start the session with a hello",
                            ControllerFailureKind::kProtocol};
    }
    const auto hello_payload = noleax::ipc::decode_agent_hello(hello.payload);
    if (hello_payload.session_token != token_ ||
        hello_payload.agent_abi_version != noleax::kAgentAbiVersion ||
        hello_payload.pointer_width != sizeof(void*) ||
        hello_payload.architecture != noleax::ipc::Architecture::kX64) {
      throw ControllerError{"agent hello failed validation", ControllerFailureKind::kProtocol};
    }
    agent_thread_id_ = hello_payload.worker_thread_id;
    if (channel_->client_process_id() != process_id_) {
      throw ControllerError{"agent connection did not come from the target process",
                            ControllerFailureKind::kProtocol};
    }

    noleax::ipc::Message start;
    start.type = MessageType::kStartCapture;
    start.request_id = hello.request_id;
    start.payload = noleax::ipc::encode_start_capture(capture.start);
    channel_->send(start, capture.timeout);
    noleax::ipc::Message ready = channel_->receive(capture.timeout);
    if (ready.type == MessageType::kError) {
      const auto error = noleax::ipc::decode_error_response(ready.payload);
      if (error.error_code == noleax::ipc::kAgentStartErrorTraceWriter) {
        throw ControllerError{"trace writer failed to start: " + error.message,
                              ControllerFailureKind::kWriterError, error.system_error};
      }
      throw ControllerError{"agent failed to start the capture: " + error.message,
                            ControllerFailureKind::kHookInstall, error.error_code};
    }
    if (ready.type != MessageType::kCaptureReady) {
      throw ControllerError{"agent did not signal capture ready", ControllerFailureKind::kProtocol};
    }
  }

  ~Impl() {
    if (process_id_ != 0U) {
      int status = 0;
      static_cast<void>(::waitpid(static_cast<pid_t>(process_id_), &status, WNOHANG));
    }
  }

  [[nodiscard]] noleax::ipc::CaptureStatus query_status() {
    noleax::ipc::Message request;
    request.type = MessageType::kQueryStatus;
    request.request_id = ++next_request_id_;
    noleax::ipc::Message response;
    try {
      channel_->send(request, 5s);
      response = channel_->receive(5s);
    } catch (const noleax::ipc::linux::SocketError& error) {
      throw session_broken_error("while the controller queried the capture status", error);
    }
    if (response.type != MessageType::kCaptureStatus) {
      throw ControllerError{"agent did not answer the status query",
                            ControllerFailureKind::kProtocol};
    }
    try {
      return noleax::ipc::decode_capture_status(response.payload);
    } catch (const noleax::ipc::ProtocolError& error) {
      throw ControllerError{std::string{"agent protocol violation: "} + error.what(),
                            ControllerFailureKind::kProtocol};
    }
  }

  [[nodiscard]] noleax::ipc::CaptureStatus stop() {
    if (stopped_) {
      return last_status_;
    }
    noleax::ipc::Message request;
    request.request_id = ++next_request_id_;

    try {
      request.type = MessageType::kStopCapture;
      channel_->send(request, 30s);
      const noleax::ipc::Message drained = channel_->receive(30s);
      if (drained.type != MessageType::kCaptureDrained) {
        throw ControllerError{"agent did not drain the capture", ControllerFailureKind::kProtocol};
      }
      last_status_ = noleax::ipc::decode_capture_status(drained.payload);

      request.request_id = ++next_request_id_;
      request.type = MessageType::kFinalizeHooks;
      channel_->send(request, 30s);
      const noleax::ipc::Message finalized = channel_->receive(30s);
      if (finalized.type != MessageType::kCaptureFinalized) {
        throw ControllerError{"agent did not finalize the capture",
                              ControllerFailureKind::kProtocol};
      }
      last_status_ = noleax::ipc::decode_capture_status(finalized.payload);
    } catch (const noleax::ipc::linux::SocketError& error) {
      throw session_broken_error("while the capture was stopping", error);
    } catch (const noleax::ipc::ProtocolError& error) {
      throw ControllerError{std::string{"agent protocol violation: "} + error.what(),
                            ControllerFailureKind::kProtocol};
    }
    stopped_ = true;
    if (last_status_.state == noleax::ipc::AgentState::kFailed) {
      if ((last_status_.flags & noleax::ipc::kCaptureStatusFlagDrainIncomplete) != 0U) {
        // The drain deadline fired with replacement calls still in flight; their late
        // events cannot reconcile, so the agent finished with the writer error tail.
        throw ControllerError{
            "capture stop did not reach replacement quiescence within the drain budget; "
            "calls still in flight were cut off and the partial trace preserves the "
            "capture up to the stop",
            ControllerFailureKind::kWriterError};
      }
      // The agent already preserved the capture into the trace tail; the controller only
      // learns that the writer failed, not why (the target's stderr has the detail).
      throw ControllerError{
          "trace writer failed in the agent; the partial trace preserves "
          "the capture up to the failure",
          ControllerFailureKind::kWriterError};
    }
    return last_status_;
  }

  [[nodiscard]] bool wait_for_target(std::chrono::milliseconds timeout) {
    const auto deadline = Clock::now() + timeout;
    for (;;) {
      int status = 0;
      const pid_t result = ::waitpid(static_cast<pid_t>(process_id_), &status, WNOHANG);
      if (result == static_cast<pid_t>(process_id_)) {
        target_exited_ = true;
        if (WIFEXITED(status)) {
          target_exit_code_ = static_cast<std::uint32_t>(WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
          target_exit_code_ = 128U + static_cast<std::uint32_t>(WTERMSIG(status));
        }
        return true;
      }
      if (result < 0) {
        if (errno == EINTR) {
          continue;
        }
        if (errno == ECHILD) {
          // Attached targets are not our children: watch the process directory instead.
          const std::string proc_dir = "/proc/" + std::to_string(process_id_);
          if (::access(proc_dir.c_str(), F_OK) != 0) {
            target_exited_ = true;
            return true;
          }
        } else {
          throw ControllerError{"waitpid failed", static_cast<std::uint32_t>(errno)};
        }
      }
      if (Clock::now() >= deadline) {
        return false;
      }
      std::this_thread::sleep_for(1ms);
    }
  }

  [[nodiscard]] std::uint32_t target_exit_code() const {
    if (!target_exited_) {
      throw ControllerError{"target has not exited"};
    }
    return target_exit_code_;
  }

  [[nodiscard]] std::uint32_t process_id() const noexcept { return process_id_; }
  [[nodiscard]] std::uint32_t agent_thread_id() const noexcept { return agent_thread_id_; }
  [[nodiscard]] bool stopped() const noexcept { return stopped_; }
  [[nodiscard]] bool target_exited() const noexcept { return target_exited_; }

 private:
  std::array<std::byte, 16U> token_{};
  std::optional<noleax::ipc::linux::UnixSocketServer> server_;
  std::optional<noleax::ipc::linux::SocketChannel> channel_;
  std::uint32_t process_id_{0U};
  std::uint32_t agent_thread_id_{0U};
  std::uint64_t next_request_id_{1U};
  bool stopped_{false};
  bool target_exited_{false};
  std::uint32_t target_exit_code_{0U};
  noleax::ipc::CaptureStatus last_status_{};
};

CaptureSession::CaptureSession(std::unique_ptr<Impl> implementation) noexcept
    : implementation_{std::move(implementation)} {}

CaptureSession::~CaptureSession() = default;

CaptureSession::CaptureSession(CaptureSession&& other) noexcept = default;

CaptureSession& CaptureSession::operator=(CaptureSession&& other) noexcept = default;

CaptureSession CaptureSession::launch(const LaunchOptions& launch, const CaptureOptions& capture) {
  return CaptureSession{std::make_unique<Impl>(launch, capture)};
}

CaptureSession CaptureSession::attach(std::uint32_t process_id, const CaptureOptions& capture) {
  return CaptureSession{std::make_unique<Impl>(process_id, capture)};
}

noleax::ipc::CaptureStatus CaptureSession::query_status() {
  return implementation_->query_status();
}

noleax::ipc::CaptureStatus CaptureSession::stop() { return implementation_->stop(); }

bool CaptureSession::wait_for_target(std::chrono::milliseconds timeout) {
  return implementation_->wait_for_target(timeout);
}

std::uint32_t CaptureSession::target_exit_code() const {
  return implementation_->target_exit_code();
}

std::uint32_t CaptureSession::process_id() const noexcept { return implementation_->process_id(); }

std::uint32_t CaptureSession::agent_thread_id() const noexcept {
  return implementation_->agent_thread_id();
}

bool CaptureSession::stopped() const noexcept { return implementation_->stopped(); }

bool CaptureSession::target_exited() const noexcept { return implementation_->target_exited(); }

}  // namespace noleax::controller::linux
