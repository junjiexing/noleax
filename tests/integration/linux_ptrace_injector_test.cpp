// End-to-end attach test for the ptrace injector (M6, stop-window bootstrap in H1-B): the
// harness forks a long-running allocation fixture (a direct child, so the attach stays
// ptrace-able under Yama ptrace_scope=1), injects the built agent into it with
// PtraceInjector, then plays the controller over the session socket — hello handshake,
// StartCapture with the linux-glibc-heap profile and attach capture kind, status query,
// drain, finalize. It then asserts the trace analyzes with the attach capture scope
// (started_at_process_start=false, preexisting_allocations_unknown=true) and that the
// fixture kept running correctly through the injection (its own exit code 42 and batch
// report intact). The fixture carries a churn thread and a peer that SIG_BLOCKs hoox's
// peer-park signal, so the synchronous in-window install is the only reason attach
// succeeds at all (the field crash regression).

#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "noleax/agent/linux/bootstrap.hpp"
#include "noleax/analyzer/event_stream.hpp"
#include "noleax/controller/linux/controller.hpp"
#include "noleax/controller/linux/ptrace_injector.hpp"
#include "noleax/ipc/linux/unix_socket.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/version.hpp"

namespace {

using namespace std::chrono_literals;
using noleax::ipc::MessageType;
using noleax::ipc::linux::SocketChannel;
using noleax::ipc::linux::UnixSocketServer;

constexpr std::uint32_t kFixtureExitCode = 42U;

[[nodiscard]] std::array<std::byte, 16U> make_token(std::uint64_t seed) {
  std::array<std::byte, 16U> token{};
  for (std::size_t index = 0U; index < token.size(); ++index) {
    token[index] = static_cast<std::byte>((seed >> ((index % 8U) * 8U)) + index);
  }
  return token;
}

// The injection target: a malloc/free burst per poll quantum until the controller releases
// it through the pipe (or a ~30s watchdog saves the suite from a hung test), then a batch
// report down the second pipe and exit 42. Runs in the forked child without an exec, so it
// keeps producing glibc-heap traffic for the capture while staying a direct child.
//
// Two extra threads make the stop-window attach honest: a detached churn thread keeps
// malloc/free traffic racing the seizure, and a peer that SIG_BLOCKs SIGRTMIN+6 (hoox's
// default Linux peer-park signal) reproduces the field crash — an in-process park can
// never complete while that thread exists, so attach only succeeds because the
// synchronous bootstrap disables the park outright (external thread suspension).
[[noreturn]] void fixture_child(int release_fd, int report_fd) {
  std::atomic<bool> blocked_peer_ready{false};
  std::thread churn{[] {
    for (;;) {
      void* const block = std::malloc(192U);
      if (block == nullptr) {
        ::_exit(47);
      }
      std::memset(block, 0x77, 16U);
      std::free(block);
    }
  }};
  churn.detach();
  std::thread blocked_peer{[&blocked_peer_ready] {
    sigset_t blocked{};
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGRTMIN + 6);  // hoox's default Linux peer-park signal
    if (pthread_sigmask(SIG_BLOCK, &blocked, nullptr) != 0) {
      ::_exit(46);
    }
    blocked_peer_ready.store(true, std::memory_order_release);
    for (;;) {
      static_cast<void>(::poll(nullptr, 0U, 1000));
    }
  }};
  blocked_peer.detach();
  while (!blocked_peer_ready.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }

  std::uint64_t batches = 0U;
  std::vector<void*> retained;
  for (;;) {
    for (std::size_t index = 0U; index < 8U; ++index) {
      void* const block = std::malloc(64U + index * 32U);
      if (block == nullptr) {
        ::_exit(44);
      }
      std::memset(block, 0x5a, 16U);
      std::free(block);
    }
    if (batches % 64U == 0U) {
      retained.push_back(std::malloc(4096U));  // never freed: keeps leaks mode non-empty
    }
    ++batches;
    pollfd release{release_fd, POLLIN, 0};
    const int poll_result = ::poll(&release, 1U, 5);
    if (poll_result > 0) {
      break;  // released (or the controller vanished: POLLHUP)
    }
    // EINTR is routine here: the agent's hook-quiescence rendezvous signals every thread
    // while it installs or reverts the malloc hooks. Keep looping like any real target.
    if (poll_result < 0 && errno != EINTR) {
      ::_exit(45);
    }
    if (batches >= 6000U) {
      break;  // watchdog: never hang the suite
    }
  }
  char report[96]{};
  const int length = std::snprintf(report, sizeof(report), "noleax-ptrace-fixture batches=%llu\n",
                                   static_cast<unsigned long long>(batches));
  const ssize_t written = ::write(report_fd, report, static_cast<std::size_t>(length));
  static_cast<void>(written);
  ::_exit(static_cast<int>(kFixtureExitCode));
}

// Kills and reaps the fixture child if the test fails before the orderly release path.
struct ChildGuard {
  pid_t pid{-1};
  ~ChildGuard() {
    if (pid > 0) {
      ::kill(pid, SIGKILL);
      ::waitpid(pid, nullptr, 0);
    }
  }
};

[[nodiscard]] noleax::ipc::Message roundtrip(SocketChannel& channel, MessageType type,
                                             std::uint64_t request_id) {
  noleax::ipc::Message request;
  request.type = type;
  request.request_id = request_id;
  channel.send(request, 10s);
  return channel.receive(10s);
}

[[nodiscard]] int shell_exit_code(const std::string& command) {
  const int status = std::system(command.c_str());
  if (status == -1 || !WIFEXITED(status)) {
    return -1;
  }
  return WEXITSTATUS(status);
}

[[nodiscard]] std::string read_text_file(const std::filesystem::path& path) {
  std::ifstream input{path, std::ios::binary};
  return std::string{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

}  // namespace

TEST_CASE("linux ptrace injector attaches the agent to a running process",
          "[controller][linux][ptrace][attach]") {
  const auto token = make_token(0x4e4c5820203631ULL);
  const std::string socket_name = noleax::ipc::linux::make_socket_name(token);
  UnixSocketServer server{socket_name};

  int release_pipe[2] = {-1, -1};
  int report_pipe[2] = {-1, -1};
  REQUIRE(::pipe(release_pipe) == 0);
  REQUIRE(::pipe(report_pipe) == 0);

  const pid_t child = ::fork();
  if (child == 0) {
    // The child must never touch Catch2 assertion state: straight into the fixture.
    ::close(release_pipe[1]);
    ::close(report_pipe[0]);
    fixture_child(release_pipe[0], report_pipe[1]);
  }
  REQUIRE(child > 0);
  ::close(release_pipe[0]);
  ::close(report_pipe[1]);
  ChildGuard guard{child};

  // Let the fixture settle into its poll loop: a thread parked in a libc syscall wrapper
  // is the preferred injection point.
  std::this_thread::sleep_for(200ms);

  // The attach bootstrap ABI as opaque bytes, exactly what the injector receives.
  noleax::agent::linux::AttachBootstrapParameters parameters{};
  parameters.controller_process_id = static_cast<std::uint32_t>(::getpid());
  parameters.connect_timeout_ms = 8'000U;
  const std::string socket_env = socket_name.substr(1U);  // abstract name without the NUL
  REQUIRE(socket_env.size() < noleax::agent::linux::kAttachSocketNameCapacity);
  std::memcpy(parameters.socket_name, socket_env.c_str(), socket_env.size());
  parameters.session_token = token;
  std::vector<std::byte> parameter_bytes(sizeof(parameters));
  std::memcpy(parameter_bytes.data(), &parameters, sizeof(parameters));

  // H1-B: inject() now blocks until the synchronous in-window bootstrap has completed
  // the handshake and installed every hook, so it runs on a worker while this thread
  // drives the session channel — the same concurrency the controller uses internally.
  std::exception_ptr injection_error;
  std::jthread injection_worker{[&] {
    try {
      noleax::controller::linux::PtraceInjector::inject(static_cast<std::uint32_t>(child),
                                                        NOLEAX_AGENT_PATH, parameter_bytes,
                                                        std::chrono::seconds{10});
    } catch (...) {
      injection_error = std::current_exception();
    }
  }};

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

  const auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const std::filesystem::path trace =
      std::filesystem::temp_directory_path() / ("noleax-attach-" + stamp + ".nlx");
  const std::filesystem::path analyze_out =
      std::filesystem::temp_directory_path() / ("noleax-attach-" + stamp + ".txt");

  noleax::ipc::StartCaptureRequest start_request;
  start_request.capture_kind = noleax::ipc::CaptureKind::kAttach;
  start_request.hook_profile = noleax::ipc::HookProfile::kLinuxGlibcHeap;
  start_request.trace_path_utf8 = trace.string();
  noleax::ipc::Message start;
  start.type = MessageType::kStartCapture;
  start.request_id = hello.request_id;
  start.payload = noleax::ipc::encode_start_capture(start_request);
  channel.send(start, 10s);
  const noleax::ipc::Message ready = channel.receive(10s);
  if (ready.type == MessageType::kError) {
    INFO(noleax::ipc::decode_error_response(ready.payload).message);
  }
  REQUIRE(ready.type == MessageType::kCaptureReady);
  // The injector returns only after the agent's install-complete signal: by the time the
  // ready arrives, the injection worker must be done, without an error.
  injection_worker.join();
  if (injection_error != nullptr) {
    try {
      std::rethrow_exception(injection_error);
    } catch (const std::exception& error) {
      INFO(error.what());
    }
  }
  REQUIRE(injection_error == nullptr);

  // Let the capture accumulate fixture traffic, then prove events are flowing.
  std::this_thread::sleep_for(300ms);
  const noleax::ipc::Message status = roundtrip(channel, MessageType::kQueryStatus, 2U);
  REQUIRE(status.type == MessageType::kCaptureStatus);
  const auto capturing = noleax::ipc::decode_capture_status(status.payload);
  CHECK(capturing.state == noleax::ipc::AgentState::kCapturing);
  CHECK(capturing.observed_calls > 0U);
  // H2 live telemetry: the default 16 MiB buffer floors to 16384 slots (648-byte events);
  // the writer flushes on its flush interval, so bytes and the flush stamp are live.
  CHECK(capturing.queue_capacity == 16'384U);
  CHECK(capturing.queued_events <= capturing.queue_capacity);
  CHECK(capturing.queue_high_water_events >= capturing.queued_events);
  CHECK(capturing.queue_high_water_events <= capturing.queue_capacity);
  CHECK(capturing.consumed_events > 0U);
  CHECK(capturing.bytes_written > 0U);
  CHECK(capturing.last_flush_monotonic_ns > 0U);

  const noleax::ipc::Message drained = roundtrip(channel, MessageType::kStopCapture, 3U);
  REQUIRE(drained.type == MessageType::kCaptureDrained);
  CHECK(noleax::ipc::decode_capture_status(drained.payload).state ==
        noleax::ipc::AgentState::kDrained);
  const noleax::ipc::Message finalized = roundtrip(channel, MessageType::kFinalizeHooks, 4U);
  REQUIRE(finalized.type == MessageType::kCaptureFinalized);
  // H1-A: attach captures never live-unpatch — the patches stay installed but dormant
  // (drain already routed replacements to the originals), so the agent reports kDormant
  // instead of kFinalized and the fixture keeps running with them in place.
  const auto final_status = noleax::ipc::decode_capture_status(finalized.payload);
  CHECK(final_status.state == noleax::ipc::AgentState::kDormant);
  // H4: only the informational buffer-adjusted flag (default buffer floors to 16384
  // slots); no degradation flag.
  CHECK(final_status.flags == noleax::ipc::kCaptureStatusFlagBufferAdjusted);

  // Orderly fixture exit: release it and check its own exit code and report survived the
  // injection (the only thread was hijacked, restored, and detached mid-run).
  const ssize_t released = ::write(release_pipe[1], "x", 1U);
  REQUIRE(released == 1);
  ::close(release_pipe[1]);
  release_pipe[1] = -1;

  int exit_status = 0;
  bool reaped = false;
  for (int attempt = 0; attempt < 500 && !reaped; ++attempt) {
    reaped = ::waitpid(child, &exit_status, WNOHANG) == child;
    if (!reaped) {
      std::this_thread::sleep_for(10ms);
    }
  }
  REQUIRE(reaped);
  guard.pid = -1;
  CHECK(WIFEXITED(exit_status));
  CHECK(WEXITSTATUS(exit_status) == static_cast<int>(kFixtureExitCode));

  std::string report;
  char chunk[128]{};
  for (;;) {
    const ssize_t count = ::read(report_pipe[0], chunk, sizeof(chunk));
    if (count <= 0) {
      break;
    }
    report.append(chunk, static_cast<std::size_t>(count));
  }
  ::close(report_pipe[0]);
  report_pipe[0] = -1;
  INFO(report);
  CHECK(report.find("batches=") != std::string::npos);

  // The attach trace exists, analyzes, and carries the attach capture scope.
  REQUIRE(std::filesystem::exists(trace));
  REQUIRE(std::filesystem::file_size(trace) > 0U);
  std::ifstream input{trace, std::ios::binary};
  REQUIRE(input.good());
  const auto analyzed = noleax::analyzer::analyze_event_stream(input);
  CHECK_FALSE(analyzed.capture_scope.started_at_process_start);
  CHECK(analyzed.capture_scope.preexisting_allocations_unknown);
  CHECK(analyzed.event_count > 0U);
  REQUIRE(analyzed.end_of_trace.has_value());
  CHECK(analyzed.end_of_trace->normal_stop);

  // The CLI agrees: analyze exits 0 (complete) or 2 (incomplete due to the attach blind
  // spot); both are acceptable for an attach trace.
  const int analyze_code =
      shell_exit_code("\"" NOLEAX_CLI_PATH "\" analyze --mode events \"" + trace.string() +
                      "\" > \"" + analyze_out.string() + "\" 2>&1");
  INFO(read_text_file(analyze_out));
  CHECK((analyze_code == 0 || analyze_code == 2));

  std::filesystem::remove(trace);
  std::filesystem::remove(analyze_out);
  if (release_pipe[1] >= 0) {
    ::close(release_pipe[1]);
  }
  if (report_pipe[0] >= 0) {
    ::close(report_pipe[0]);
  }
}

// H2 failure classification: the controller must say WHY a capture failed. An uncreatable
// trace path surfaces as a StartCapture error with the trace-writer code, and a SIGKILLed
// target mid-capture classifies as target-exit (not a bare broken pipe).
TEST_CASE("linux controller classifies writer start failures and target exit",
          "[controller][linux][classification]") {
  const auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const std::filesystem::path trace =
      std::filesystem::temp_directory_path() / ("noleax-classify-" + stamp + ".nlx");

  // Case 1: the agent cannot create the trace file -> kWriterError at the handshake.
  {
    int release_pipe[2] = {-1, -1};
    int report_pipe[2] = {-1, -1};
    REQUIRE(::pipe(release_pipe) == 0);
    REQUIRE(::pipe(report_pipe) == 0);
    const pid_t child = ::fork();
    if (child == 0) {
      ::close(release_pipe[1]);
      ::close(report_pipe[0]);
      fixture_child(release_pipe[0], report_pipe[1]);
    }
    REQUIRE(child > 0);
    ::close(release_pipe[0]);
    ::close(report_pipe[1]);
    ChildGuard guard{child};
    std::this_thread::sleep_for(200ms);

    noleax::controller::linux::CaptureOptions capture;
    capture.agent_path = NOLEAX_AGENT_PATH;
    capture.timeout = 10s;
    capture.start.capture_kind = noleax::ipc::CaptureKind::kAttach;
    capture.start.hook_profile = noleax::ipc::HookProfile::kLinuxGlibcHeap;
    capture.start.trace_path_utf8 = "/noleax-h2-no-such-dir/trace.nlx";
    try {
      auto session = noleax::controller::linux::CaptureSession::attach(
          static_cast<std::uint32_t>(child), capture);
      FAIL("expected a classified ControllerError");
    } catch (const noleax::controller::linux::ControllerError& error) {
      CHECK(error.failure_kind() == noleax::controller::linux::ControllerFailureKind::kWriterError);
      CHECK(std::string{error.what()}.find("trace writer failed to start") != std::string::npos);
      CHECK(error.system_error() == static_cast<std::uint32_t>(ENOENT));
    }
    const ssize_t released = ::write(release_pipe[1], "x", 1U);
    REQUIRE(released == 1);
    ::close(release_pipe[1]);
    int exit_status = 0;
    ::waitpid(child, &exit_status, 0);
    guard.pid = -1;
    // The report pipe stays open until the fixture's final write has landed.
    ::close(report_pipe[0]);
    CHECK(WIFEXITED(exit_status));  // the target survived the failed capture start
  }

  // Case 2: SIGKILL the target mid-capture -> the next session operation reports
  // kTargetExit (liveness decides), not a raw socket error.
  {
    int release_pipe[2] = {-1, -1};
    int report_pipe[2] = {-1, -1};
    REQUIRE(::pipe(release_pipe) == 0);
    REQUIRE(::pipe(report_pipe) == 0);
    const pid_t child = ::fork();
    if (child == 0) {
      ::close(release_pipe[1]);
      ::close(report_pipe[0]);
      fixture_child(release_pipe[0], report_pipe[1]);
    }
    REQUIRE(child > 0);
    ::close(release_pipe[0]);
    ::close(report_pipe[1]);
    ChildGuard guard{child};
    std::this_thread::sleep_for(200ms);

    noleax::controller::linux::CaptureOptions capture;
    capture.agent_path = NOLEAX_AGENT_PATH;
    capture.timeout = 10s;
    capture.start.capture_kind = noleax::ipc::CaptureKind::kAttach;
    capture.start.hook_profile = noleax::ipc::HookProfile::kLinuxGlibcHeap;
    capture.start.trace_path_utf8 = trace.string();
    auto session = noleax::controller::linux::CaptureSession::attach(
        static_cast<std::uint32_t>(child), capture);
    REQUIRE(session.query_status().state == noleax::ipc::AgentState::kCapturing);

    REQUIRE(::kill(child, SIGKILL) == 0);
    // The kill lands asynchronously: an early poll can still see the target alive and
    // classify the dead socket as an agent crash. Keep polling until the target-exit
    // classification shows up; only its absence within the deadline is a failure.
    std::optional<noleax::controller::linux::ControllerFailureKind> last_kind;
    std::string last_message;
    bool classified = false;
    for (int attempt = 0; attempt != 50 && !classified; ++attempt) {
      try {
        static_cast<void>(session.query_status());
        std::this_thread::sleep_for(20ms);  // the socket may die a beat after the kill
      } catch (const noleax::controller::linux::ControllerError& error) {
        last_kind = error.failure_kind();
        last_message = error.what();
        classified = last_kind == noleax::controller::linux::ControllerFailureKind::kTargetExit;
        if (!classified) {
          std::this_thread::sleep_for(20ms);
        }
      }
    }
    CHECK(classified);
    CHECK(last_kind == noleax::controller::linux::ControllerFailureKind::kTargetExit);
    CHECK(last_message.find("target exited") != std::string::npos);
    CHECK(session.target_exited());
    // SIGKILL leaves the trace as a .partial the analyzer can still open.
    const std::filesystem::path partial = trace.string() + ".partial";
    std::error_code error;
    if (std::filesystem::is_regular_file(partial, error)) {
      std::ifstream input{partial, std::ios::binary};
      REQUIRE(input.good());
      static_cast<void>(noleax::analyzer::analyze_event_stream(input));
      std::filesystem::remove(partial, error);
    }
    ::close(release_pipe[1]);
    ::close(report_pipe[0]);
    int exit_status = 0;
    ::waitpid(child, &exit_status, 0);  // already reaped by the session: ECHILD is fine
    guard.pid = -1;
  }
}

namespace {

// Forks the churning fixture child (with its park-signal-blocking peer) and closes the
// harness ends of the pipes. When bootstrap_delay_ms is nonzero the child environment
// carries the H1-B test seam that slows the agent's attach bootstrap inside the window.
[[nodiscard]] pid_t spawn_fixture(int (&release_pipe)[2], int (&report_pipe)[2],
                                  unsigned long bootstrap_delay_ms = 0UL) {
  if (bootstrap_delay_ms != 0UL) {
    ::setenv("NOLEAX_ATTACH_BOOTSTRAP_DELAY_MS", std::to_string(bootstrap_delay_ms).c_str(), 1);
  }
  const pid_t child = ::fork();
  if (child == 0) {
    ::close(release_pipe[1]);
    ::close(report_pipe[0]);
    fixture_child(release_pipe[0], report_pipe[1]);
  }
  if (bootstrap_delay_ms != 0UL) {
    // Parent only (the child never returns from fixture_child): keep the harness env clean.
    ::unsetenv("NOLEAX_ATTACH_BOOTSTRAP_DELAY_MS");
  }
  return child;
}

// Every tid of a process, for the wedged-test cleanup (the abandoned seizure's threads
// must be detached one by one before the kill can be reaped).
[[nodiscard]] std::vector<pid_t> list_task_threads(pid_t pid) {
  std::vector<pid_t> tids;
  const std::string task_dir = "/proc/" + std::to_string(pid) + "/task";
  DIR* const dir = ::opendir(task_dir.c_str());
  if (dir == nullptr) {
    return tids;
  }
  while (const dirent* const entry = ::readdir(dir)) {
    const long tid = std::strtol(entry->d_name, nullptr, 10);
    if (tid > 0) {
      tids.push_back(static_cast<pid_t>(tid));
    }
  }
  ::closedir(dir);
  return tids;
}

// Releases the fixture, reaps it, and checks it kept running correctly through whatever
// the test put it through (its own exit code and batch report intact).
void check_fixture_exit(pid_t child, int release_fd, int report_fd) {
  const ssize_t released = ::write(release_fd, "x", 1U);
  REQUIRE(released == 1);
  ::close(release_fd);

  int exit_status = 0;
  bool reaped = false;
  for (int attempt = 0; attempt < 500 && !reaped; ++attempt) {
    reaped = ::waitpid(child, &exit_status, WNOHANG) == child;
    if (!reaped) {
      std::this_thread::sleep_for(10ms);
    }
  }
  REQUIRE(reaped);
  CHECK(WIFEXITED(exit_status));
  CHECK(WEXITSTATUS(exit_status) == static_cast<int>(kFixtureExitCode));

  std::string report;
  char chunk[128]{};
  for (;;) {
    const ssize_t count = ::read(report_fd, chunk, sizeof(chunk));
    if (count <= 0) {
      break;
    }
    report.append(chunk, static_cast<std::size_t>(count));
  }
  ::close(report_fd);
  INFO(report);
  CHECK(report.find("batches=") != std::string::npos);
}

}  // namespace

// H1-B stress: repeated attach/drain cycles against the churning multi-threaded fixture
// (including the park-signal-blocking peer). The in-window install must never crash and
// the handshake must complete cleanly on every round. Field target: 100 rounds.
TEST_CASE("linux ptrace attach loop stays clean across repeated seizures",
          "[controller][linux][ptrace][attach][stress]") {
#ifdef NDEBUG
  constexpr int kRounds = 100;
#else
  constexpr int kRounds = 25;  // debug installs are slower; keep the suite time bounded
#endif
  for (int round = 0; round < kRounds; ++round) {
    int release_pipe[2] = {-1, -1};
    int report_pipe[2] = {-1, -1};
    REQUIRE(::pipe(release_pipe) == 0);
    REQUIRE(::pipe(report_pipe) == 0);
    const pid_t child = spawn_fixture(release_pipe, report_pipe);
    REQUIRE(child > 0);
    ::close(release_pipe[0]);
    ::close(report_pipe[1]);
    ChildGuard guard{child};
    std::this_thread::sleep_for(50ms);  // let the churn and blocked threads arm

    noleax::controller::linux::CaptureOptions capture;
    capture.agent_path = NOLEAX_AGENT_PATH;
    capture.timeout = 10s;
    capture.start.capture_kind = noleax::ipc::CaptureKind::kAttach;
    capture.start.hook_profile = noleax::ipc::HookProfile::kLinuxGlibcHeap;
    const std::filesystem::path trace = std::filesystem::temp_directory_path() /
                                        ("noleax-attach-loop-" + std::to_string(round) + ".nlx");
    capture.start.trace_path_utf8 = trace.string();

    std::optional<noleax::controller::linux::CaptureSession> session;
    try {
      session.emplace(noleax::controller::linux::CaptureSession::attach(
          static_cast<std::uint32_t>(child), capture));
    } catch (const std::exception& error) {
      INFO(std::string{"attach round "} + std::to_string(round) + ": " + error.what());
      FAIL("attach round failed");
    }
    CHECK(session->query_status().state == noleax::ipc::AgentState::kCapturing);
    const auto stopped = session->stop();
    CHECK(stopped.state == noleax::ipc::AgentState::kDormant);  // attach never live-unpatches
    session.reset();

    check_fixture_exit(child, release_pipe[1], report_pipe[0]);
    guard.pid = -1;
    std::error_code error;
    std::filesystem::remove(trace, error);
  }
}

// H1-B fault reporting: a capture the agent rejects at start must surface the phase and
// the root cause, and the target's threads/registers must come through the failed
// injection untouched (the fixture keeps running correctly).
TEST_CASE("linux attach surfaces the failing phase and root cause",
          "[controller][linux][ptrace][attach][failure]") {
  const auto stamp = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const std::filesystem::path trace =
      std::filesystem::temp_directory_path() / ("noleax-attach-fault-" + stamp + ".nlx");

  int release_pipe[2] = {-1, -1};
  int report_pipe[2] = {-1, -1};
  REQUIRE(::pipe(release_pipe) == 0);
  REQUIRE(::pipe(report_pipe) == 0);
  const pid_t child = spawn_fixture(release_pipe, report_pipe);
  REQUIRE(child > 0);
  ::close(release_pipe[0]);
  ::close(report_pipe[1]);
  ChildGuard guard{child};
  std::this_thread::sleep_for(200ms);

  noleax::controller::linux::CaptureOptions capture;
  capture.agent_path = NOLEAX_AGENT_PATH;
  capture.timeout = 10s;
  capture.start.capture_kind = noleax::ipc::CaptureKind::kAttach;
  capture.start.hook_profile = noleax::ipc::HookProfile::kLinuxGlibcHeap;
  capture.start.trace_path_utf8 = trace.string();
  capture.start.unload_on_stop = true;  // the Linux agent rejects this at capture start
  try {
    auto session = noleax::controller::linux::CaptureSession::attach(
        static_cast<std::uint32_t>(child), capture);
    FAIL("expected a classified ControllerError");
  } catch (const noleax::controller::linux::ControllerError& error) {
    CHECK(error.failure_kind() == noleax::controller::linux::ControllerFailureKind::kHookInstall);
    CHECK(std::string{error.what()}.find("unload_on_stop is not supported") != std::string::npos);
  }

  check_fixture_exit(child, release_pipe[1], report_pipe[0]);
  guard.pid = -1;
  std::error_code error;
  std::filesystem::remove(trace, error);
  std::filesystem::remove(trace.string() + ".partial", error);
}

// H1-B failure window: a bootstrap that outlives the injection timeout but finishes
// within the grace budget is an ORDINARY outcome (here: a start failure, because no
// session server exists) — the injector restores and detaches every thread and the
// target keeps running correctly.
TEST_CASE("linux injector grace covers a slow bootstrap with registers intact",
          "[controller][linux][ptrace][attach][grace]") {
  int release_pipe[2] = {-1, -1};
  int report_pipe[2] = {-1, -1};
  REQUIRE(::pipe(release_pipe) == 0);
  REQUIRE(::pipe(report_pipe) == 0);
  const pid_t child = spawn_fixture(release_pipe, report_pipe, 2'500UL);
  REQUIRE(child > 0);
  ::close(release_pipe[0]);
  ::close(report_pipe[1]);
  ChildGuard guard{child};
  std::this_thread::sleep_for(200ms);

  noleax::agent::linux::AttachBootstrapParameters parameters{};
  parameters.controller_process_id = static_cast<std::uint32_t>(::getpid());
  parameters.connect_timeout_ms = 500U;
  std::vector<std::byte> parameter_bytes(sizeof(parameters));
  std::memcpy(parameter_bytes.data(), &parameters, sizeof(parameters));

  // The 2 s budget expires while the bootstrap sleeps; the 2 s grace lets it reach the
  // trap, where it reports the failed session (no server is listening) as a plain
  // bootstrap return code instead of a wedged stub.
  try {
    noleax::controller::linux::PtraceInjector::inject(static_cast<std::uint32_t>(child),
                                                      NOLEAX_AGENT_PATH, parameter_bytes,
                                                      std::chrono::seconds{2});
    FAIL("expected the bootstrap failure to surface");
  } catch (const noleax::controller::linux::ControllerError& error) {
    INFO(error.what());
    CHECK(std::string{error.what()}.find("noleax_agent_attach_bootstrap returned") !=
          std::string::npos);
    CHECK(std::string{error.what()}.find("wedged") == std::string::npos);
  }

  check_fixture_exit(child, release_pipe[1], report_pipe[0]);
  guard.pid = -1;
}

// H1-B failure window: a bootstrap that outlives the timeout plus the grace budget is
// wedged. The injector must NOT restore the thread's saved registers (teleporting it out
// of mid-agent code): it leaves the process stopped under the seizure and fails loudly.
TEST_CASE("linux injector leaves a wedged bootstrap stopped instead of corrupting the target",
          "[controller][linux][ptrace][attach][grace]") {
  int release_pipe[2] = {-1, -1};
  int report_pipe[2] = {-1, -1};
  REQUIRE(::pipe(release_pipe) == 0);
  REQUIRE(::pipe(report_pipe) == 0);
  const pid_t child = spawn_fixture(release_pipe, report_pipe, 30'000UL);
  REQUIRE(child > 0);
  ::close(release_pipe[0]);
  ::close(report_pipe[1]);
  ChildGuard guard{child};
  std::this_thread::sleep_for(200ms);

  noleax::agent::linux::AttachBootstrapParameters parameters{};
  parameters.controller_process_id = static_cast<std::uint32_t>(::getpid());
  parameters.connect_timeout_ms = 1'000U;
  std::vector<std::byte> parameter_bytes(sizeof(parameters));
  std::memcpy(parameter_bytes.data(), &parameters, sizeof(parameters));

  // 1 s budget + 1 s grace expire while the bootstrap sleeps for 30 s: wedged.
  try {
    noleax::controller::linux::PtraceInjector::inject(static_cast<std::uint32_t>(child),
                                                      NOLEAX_AGENT_PATH, parameter_bytes,
                                                      std::chrono::seconds{1});
    FAIL("expected the wedged-stub error");
  } catch (const noleax::controller::linux::ControllerError& error) {
    INFO(error.what());
    CHECK(std::string{error.what()}.find("wedged") != std::string::npos);
    CHECK(std::string{error.what()}.find("must be restarted") != std::string::npos);
  }

  // The target was left seized and stopped: still there, not progressing. Kill it (the
  // documented operator action for a wedged target) and reap.
  CHECK(::kill(child, 0) == 0);
  ::close(release_pipe[1]);
  ::close(report_pipe[0]);
  // The abandoned seizure keeps every thread traced: each non-leader thread must be
  // reaped by tid under __WALL before the group leader becomes reappable. The thread set
  // is enumerated BEFORE the kill: a dead process no longer lists its traced zombies.
  const std::vector<pid_t> tids = list_task_threads(child);
  REQUIRE(::kill(child, SIGKILL) == 0);
  for (const pid_t tid : tids) {
    if (tid != child) {
      int thread_status = 0;
      static_cast<void>(::waitpid(tid, &thread_status, __WALL));
    }
  }
  int exit_status = 0;
  CHECK(::waitpid(child, &exit_status, __WALL) == child);
  CHECK(WIFSIGNALED(exit_status));
  CHECK(WTERMSIG(exit_status) == SIGKILL);
  guard.pid = -1;
}
