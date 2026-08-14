// End-to-end bootstrap test for the Linux agent runtime (M2): the harness plays the
// controller — listens on the session socket, LD_PRELOAD-launches a target, and drives
// the handshake. Capture start is expected to fail with the M3 placeholder error; the
// point under test is the constructor bootstrap, env channel, and protocol exchange.

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include "noleax/ipc/linux/unix_socket.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/version.hpp"

namespace {

using namespace std::chrono_literals;
using noleax::ipc::MessageType;
using noleax::ipc::linux::SocketChannel;
using noleax::ipc::linux::UnixSocketServer;

[[nodiscard]] std::array<std::byte, 16U> make_token(std::uint64_t seed) {
  std::array<std::byte, 16U> token{};
  for (std::size_t index = 0U; index < token.size(); ++index) {
    token[index] = static_cast<std::byte>((seed >> ((index % 8U) * 8U)) + index);
  }
  return token;
}

[[nodiscard]] std::string hex_token(const std::array<std::byte, 16U>& token) {
  constexpr char digits[] = "0123456789abcdef";
  std::string hex;
  for (const std::byte value : token) {
    const auto byte = static_cast<unsigned>(value);
    hex.push_back(digits[(byte >> 4U) & 0x0fU]);
    hex.push_back(digits[byte & 0x0fU]);
  }
  return hex;
}

struct LaunchedTarget {
  pid_t pid{-1};
};

// LD_PRELOAD-launches /bin/sleep with the agent bootstrap environment; returns the child
// pid. The environment scrubbing in the agent constructor is verified separately by the
// child's own view (children of the target must not re-bootstrap).
[[nodiscard]] pid_t launch_target(const std::string& socket_name_without_nul,
                                  const std::string& token_hex, std::uint32_t controller_pid,
                                  const char* sleep_seconds) {
  const pid_t pid = ::fork();
  if (pid != 0) {
    return pid;
  }
  // Child: LD_PRELOAD the agent and exec a short-lived but long-enough target.
  ::setenv("LD_PRELOAD", NOLEAX_AGENT_PATH, 1);
  ::setenv("NOLEAX_BOOTSTRAP_SOCKET", socket_name_without_nul.c_str(), 1);
  ::setenv("NOLEAX_SESSION_TOKEN", token_hex.c_str(), 1);
  ::setenv("NOLEAX_CONTROLLER_PID", std::to_string(controller_pid).c_str(), 1);
  ::setenv("NOLEAX_CONNECT_TIMEOUT_MS", "5000", 1);
  ::execl("/bin/sleep", "sleep", sleep_seconds, static_cast<char*>(nullptr));
  ::_exit(127);
}

[[nodiscard]] noleax::ipc::Message start_capture_message(std::uint64_t request_id) {
  noleax::ipc::StartCaptureRequest request;
  request.capture_kind = noleax::ipc::CaptureKind::kLaunch;
  request.hook_profile = noleax::ipc::HookProfile::kWindowsNative;
  request.trace_path_utf8 = "/tmp/noleax-m2-skeleton.nlx";
  noleax::ipc::Message message;
  message.type = MessageType::kStartCapture;
  message.request_id = request_id;
  message.payload = noleax::ipc::encode_start_capture(request);
  return message;
}

[[nodiscard]] noleax::ipc::Message roundtrip(SocketChannel& channel, MessageType type,
                                             std::uint64_t request_id) {
  noleax::ipc::Message request;
  request.type = type;
  request.request_id = request_id;
  channel.send(request, 10s);
  return channel.receive(10s);
}

// Drives a full launch-shaped session against /bin/sleep and returns the states the agent
// reported at each step. capture_kind selects the finalize shape: launch unpatches to
// kFinalized, attach retains the patches and lands on kDormant (H1-A).
struct SessionStates {
  noleax::ipc::CaptureStatus ready;
  noleax::ipc::CaptureStatus capturing;
  noleax::ipc::CaptureStatus drained;
  noleax::ipc::CaptureStatus finalized;
};

[[nodiscard]] SessionStates drive_session(noleax::ipc::CaptureKind kind, std::uint64_t seed,
                                          const std::filesystem::path& trace) {
  const auto token = make_token(seed);
  const std::string socket_name = noleax::ipc::linux::make_socket_name(token);
  UnixSocketServer server{socket_name};

  const std::uint32_t controller_pid = static_cast<std::uint32_t>(::getpid());
  const pid_t child = launch_target(socket_name.substr(1U), hex_token(token), controller_pid, "30");
  REQUIRE(child > 0);

  SocketChannel channel = server.accept(10s);
  const noleax::ipc::Message hello = channel.receive(10s);
  REQUIRE(hello.type == MessageType::kAgentHello);

  noleax::ipc::StartCaptureRequest request;
  request.capture_kind = kind;
  request.hook_profile = noleax::ipc::HookProfile::kLinuxGlibcHeap;
  request.trace_path_utf8 = trace.string();
  noleax::ipc::Message start;
  start.type = MessageType::kStartCapture;
  start.request_id = hello.request_id;
  start.payload = noleax::ipc::encode_start_capture(request);
  channel.send(start, 10s);

  SessionStates states;
  const noleax::ipc::Message ready = channel.receive(10s);
  REQUIRE(ready.type == MessageType::kCaptureReady);
  states.ready = noleax::ipc::decode_capture_status(ready.payload);

  const noleax::ipc::Message capturing = roundtrip(channel, MessageType::kQueryStatus, 2U);
  REQUIRE(capturing.type == MessageType::kCaptureStatus);
  states.capturing = noleax::ipc::decode_capture_status(capturing.payload);

  const noleax::ipc::Message drained = roundtrip(channel, MessageType::kStopCapture, 3U);
  REQUIRE(drained.type == MessageType::kCaptureDrained);
  states.drained = noleax::ipc::decode_capture_status(drained.payload);

  const noleax::ipc::Message queried = roundtrip(channel, MessageType::kQueryStatus, 4U);
  REQUIRE(queried.type == MessageType::kCaptureStatus);
  CHECK(noleax::ipc::decode_capture_status(queried.payload).state == states.drained.state);

  const noleax::ipc::Message finalized = roundtrip(channel, MessageType::kFinalizeHooks, 5U);
  REQUIRE(finalized.type == MessageType::kCaptureFinalized);
  states.finalized = noleax::ipc::decode_capture_status(finalized.payload);

  // The session loop returns after the finalize response; the target itself keeps
  // running until killed (hooks reverted for launch, dormant for attach).
  ::kill(child, SIGTERM);
  int status = 0;
  CHECK(::waitpid(child, &status, 0) == child);
  return states;
}

}  // namespace

TEST_CASE("linux agent bootstraps over the env channel and runs the session protocol",
          "[agent][runtime][linux]") {
  const auto token = make_token(0x4e4c5820203031ULL);
  const std::string socket_name = noleax::ipc::linux::make_socket_name(token);
  // The env channel cannot carry the leading NUL of the abstract namespace name.
  const std::string socket_env = socket_name.substr(1U);
  UnixSocketServer server{socket_name};

  const std::uint32_t controller_pid = static_cast<std::uint32_t>(::getpid());
  const pid_t child = launch_target(socket_env, hex_token(token), controller_pid, "3");
  REQUIRE(child > 0);

  SocketChannel channel = server.accept(10s);
  const noleax::ipc::Message hello = channel.receive(10s);
  REQUIRE(hello.type == MessageType::kAgentHello);
  const auto hello_payload = noleax::ipc::decode_agent_hello(hello.payload);
  CHECK(hello_payload.agent_abi_version == noleax::kAgentAbiVersion);
  CHECK(hello_payload.process_id == static_cast<std::uint32_t>(child));
  CHECK(hello_payload.pointer_width == 8U);
  CHECK(hello_payload.architecture == noleax::ipc::Architecture::kX64);
  CHECK(hello_payload.session_token == token);
  CHECK(channel.client_process_id() == static_cast<std::uint32_t>(child));

  channel.send(start_capture_message(hello.request_id), 5s);
  const noleax::ipc::Message started = channel.receive(10s);
  REQUIRE(started.type == MessageType::kError);
  const auto error = noleax::ipc::decode_error_response(started.payload);
  CHECK(error.error_code == 5U);
  CHECK(error.message.find("unsupported hook profile") != std::string::npos);

  int status = 0;
  CHECK(::waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status));
}

TEST_CASE("linux agent refuses a controller with the wrong pid", "[agent][runtime][linux]") {
  const auto token = make_token(0x4e4c5820203302ULL);
  const std::string socket_name = noleax::ipc::linux::make_socket_name(token);
  UnixSocketServer server{socket_name};

  // Claim a controller pid that is not this process: the agent must drop the channel.
  const pid_t child = launch_target(socket_name.substr(1U), hex_token(token), 1U, "2");
  REQUIRE(child > 0);

  SocketChannel channel = server.accept(10s);
  bool refused = false;
  try {
    static_cast<void>(channel.receive(2s));
  } catch (const noleax::ipc::linux::SocketError&) {
    refused = true;
  }
  CHECK(refused);

  int status = 0;
  static_cast<void>(::waitpid(child, &status, 0));
}

TEST_CASE("linux agent reports the explicit capture state machine over IPC",
          "[agent][runtime][linux][lifecycle]") {
  const auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const std::filesystem::path trace =
      std::filesystem::temp_directory_path() / ("noleax-lifecycle-" + stamp + ".nlx");

  const SessionStates states =
      drive_session(noleax::ipc::CaptureKind::kLaunch, 0x4e4c5820203403ULL, trace);
  CHECK(states.ready.state == noleax::ipc::AgentState::kCapturing);
  CHECK(states.capturing.state == noleax::ipc::AgentState::kCapturing);
  CHECK(states.drained.state == noleax::ipc::AgentState::kDrained);
  // Launch captures go through the physical unpatch: kDrained -> kUnpatching -> kFinalized
  // (the transient kUnpatching is never observable over the sequential session channel).
  CHECK(states.finalized.state == noleax::ipc::AgentState::kFinalized);
  CHECK(states.finalized.flags == 0U);

  std::error_code error;
  std::filesystem::remove(trace, error);
}

TEST_CASE("linux attach-kind capture finalizes dormant and keeps its patches",
          "[agent][runtime][linux][lifecycle]") {
  const auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const std::filesystem::path trace =
      std::filesystem::temp_directory_path() / ("noleax-dormant-" + stamp + ".nlx");

  // The retain decision is driven by StartCaptureRequest::capture_kind alone, so a
  // preload-launched target told kAttach exercises it without the ptrace injector (the
  // injector-level attach path asserts the same state in linux_ptrace_injector_test).
  const SessionStates states =
      drive_session(noleax::ipc::CaptureKind::kAttach, 0x4e4c5820203504ULL, trace);
  CHECK(states.ready.state == noleax::ipc::AgentState::kCapturing);
  CHECK(states.drained.state == noleax::ipc::AgentState::kDrained);
  CHECK(states.finalized.state == noleax::ipc::AgentState::kDormant);
  CHECK(states.finalized.flags == 0U);

  std::error_code error;
  std::filesystem::remove(trace, error);
}

TEST_CASE("linux agent rejects unload_on_stop at capture start",
          "[agent][runtime][linux][lifecycle]") {
  const auto token = make_token(0x4e4c5820203605ULL);
  const std::string socket_name = noleax::ipc::linux::make_socket_name(token);
  UnixSocketServer server{socket_name};

  const std::uint32_t controller_pid = static_cast<std::uint32_t>(::getpid());
  const pid_t child = launch_target(socket_name.substr(1U), hex_token(token), controller_pid, "5");
  REQUIRE(child > 0);

  SocketChannel channel = server.accept(10s);
  const noleax::ipc::Message hello = channel.receive(10s);
  REQUIRE(hello.type == MessageType::kAgentHello);

  noleax::ipc::StartCaptureRequest request;
  request.capture_kind = noleax::ipc::CaptureKind::kAttach;
  request.hook_profile = noleax::ipc::HookProfile::kLinuxGlibcHeap;
  request.trace_path_utf8 = "/tmp/noleax-unload-on-stop.nlx";
  request.unload_on_stop = true;
  noleax::ipc::Message start;
  start.type = MessageType::kStartCapture;
  start.request_id = hello.request_id;
  start.payload = noleax::ipc::encode_start_capture(request);
  channel.send(start, 10s);

  const noleax::ipc::Message rejected = channel.receive(10s);
  REQUIRE(rejected.type == MessageType::kError);
  const auto error = noleax::ipc::decode_error_response(rejected.payload);
  CHECK(error.error_code == noleax::ipc::kAgentStartErrorUnsupportedOption);
  CHECK(error.message.find("unload_on_stop is not supported") != std::string::npos);

  int status = 0;
  CHECK(::waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status));
}
