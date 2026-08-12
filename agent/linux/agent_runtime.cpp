// Linux agent runtime (docs/LINUX_PORT_PLAN.md M2 skeleton, M3 integration).
//
// Entry is the LD_PRELOAD constructor: the dynamic loader runs it before the target's
// entry point, which is the Linux equivalent of the Windows "inject before entrypoint"
// guarantee. The constructor does the whole bootstrap synchronously — connect, hello,
// StartCapture, hook installation, writer start — because (a) the "before entrypoint"
// promise requires hooks installed before the constructor returns, and (b) the loader
// lock is held during constructors and is only recursive on the SAME thread, so all
// dlsym/dl_iterate_phdr work must happen on the constructor thread, never on a helper
// thread that would deadlock against it. Post-start work (session loop, duration timer)
// runs on detached workers after the constructor returns.
//
// Modes (env contract in bootstrap.hpp):
//   - controller session: handshake over the abstract unix socket;
//   - standalone: NOLEAX_AGENT_CONFIG points at the capture TOML.
// The capture self-finalizes on target exit via hooked exit/_exit (see §4 of
// docs/LINUX_LAUNCH_INJECTION.md); a broken session channel mid-capture never stops the
// capture (controller detach semantics).

#include <dlfcn.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/hook_guard.hpp"
#include "noleax/agent/linux/bootstrap.hpp"
#include "noleax/agent/linux/custom_symbol_hooks.hpp"
#include "noleax/agent/linux/glibc_heap_hooks.hpp"
#include "noleax/agent/linux/module_tracker.hpp"
#include "noleax/agent/linux/trace_writer.hpp"
#include "noleax/agent/linux/virtual_memory_hooks.hpp"
#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"
#include "noleax/config/hook_profile_ipc.hpp"
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

[[nodiscard]] std::uint64_t monotonic_now_ns() noexcept {
  timespec value{};
  clock_gettime(CLOCK_MONOTONIC, &value);
  return static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
         static_cast<std::uint64_t>(value.tv_nsec);
}

[[nodiscard]] std::int64_t utc_now_ns() noexcept {
  timespec value{};
  clock_gettime(CLOCK_REALTIME, &value);
  return static_cast<std::int64_t>(value.tv_sec) * 1'000'000'000LL +
         static_cast<std::int64_t>(value.tv_nsec);
}

[[nodiscard]] noleax::trace::CompressionCodec wire_compression(
    noleax::ipc::CompressionCodec codec) {
  switch (codec) {
    case noleax::ipc::CompressionCodec::kNone:
      return noleax::trace::CompressionCodec::kNone;
    case noleax::ipc::CompressionCodec::kLz4:
      return noleax::trace::CompressionCodec::kLz4;
    case noleax::ipc::CompressionCodec::kZstd:
      return noleax::trace::CompressionCodec::kZstd;
  }
  return noleax::trace::CompressionCodec::kLz4;
}

// ---------------------------------------------------------------------------
// capture runtime
// ---------------------------------------------------------------------------

class LinuxCaptureRuntime {
 public:
  LinuxCaptureRuntime() = default;

  LinuxCaptureRuntime(const LinuxCaptureRuntime&) = delete;
  LinuxCaptureRuntime& operator=(const LinuxCaptureRuntime&) = delete;

  // Runs on the constructor thread (loader-lock discipline, see the file header).
  [[nodiscard]] bool start(const noleax::ipc::StartCaptureRequest& request,
                           const std::array<std::byte, 16U>& session_id) {
    const bool want_heap = request.hook_profile == noleax::ipc::HookProfile::kLinuxGlibcHeap ||
                           request.hook_profile == noleax::ipc::HookProfile::kLinuxNative;
    const bool want_vm = request.hook_profile == noleax::ipc::HookProfile::kLinuxVirtualMemory ||
                         request.hook_profile == noleax::ipc::HookProfile::kLinuxNative;
    if (!want_heap && !want_vm) {
      start_error_ =
          noleax::ipc::ErrorResponse{5U, 0U, "unsupported hook profile for the Linux agent"};
      return false;
    }
    state_ = noleax::ipc::AgentState::kStarting;

    const std::uint64_t origin = monotonic_now_ns();
    tracker_ = std::make_unique<noleax::agent::linux::LinuxModuleTracker>(origin);
    backend_ = std::make_unique<noleax::agent::HookBackend>();

    constexpr std::uint64_t kMaximumCapacity = 1U << 24U;
    const std::uint64_t requested = (std::max)(
        std::uint64_t{2U}, request.buffer_size / sizeof(noleax::agent::linux::LinuxHeapEvent));
    const auto capacity =
        static_cast<std::size_t>(std::bit_floor((std::min)(requested, kMaximumCapacity)));
    if (want_heap) {
      heap_hooks_ = std::make_unique<noleax::agent::linux::GlibcHeapHooks>(
          *backend_, capacity, request.maximum_stack_depth, request.minimum_capture_size);
    }
    if (want_vm) {
      // linux-native merges both families into the heap-owned queue (the owner coordinates
      // queue lifecycle, mirroring the Windows profile orchestration).
      if (heap_hooks_ != nullptr) {
        vm_hooks_ = std::make_unique<noleax::agent::linux::VirtualMemoryHooks>(
            *backend_, heap_hooks_->event_queue(), request.maximum_stack_depth,
            request.minimum_capture_size);
      } else {
        vm_hooks_ = std::make_unique<noleax::agent::linux::VirtualMemoryHooks>(
            *backend_, capacity, request.maximum_stack_depth, request.minimum_capture_size);
      }
    }
    noleax::agent::linux::LinuxHeapEventQueue& event_queue =
        heap_hooks_ != nullptr ? heap_hooks_->event_queue() : vm_hooks_->event_queue();

    noleax::agent::linux::LinuxTraceWriterOptions writer_options;
    writer_options.compression = wire_compression(request.compression);
    writer_options.trace.max_file_size = request.maximum_trace_size;
    writer_options.trace.zstd_level = request.compression_level;
    writer_options.flush_interval =
        std::chrono::nanoseconds{static_cast<std::int64_t>(request.flush_interval_ns)};
    writer_options.memory_counters_interval =
        std::chrono::nanoseconds{static_cast<std::int64_t>(request.memory_counters_interval_ns)};
    writer_options.memory_map_interval =
        std::chrono::nanoseconds{static_cast<std::int64_t>(request.memory_map_interval_ns)};
    writer_options.capture_scope =
        noleax::trace::CaptureScope{request.capture_kind == noleax::ipc::CaptureKind::kLaunch,
                                    request.capture_kind != noleax::ipc::CaptureKind::kLaunch};
    writer_options.session_id = session_id;
    writer_options.monotonic_origin = origin;
    writer_options.utc_origin_ns = utc_now_ns();
    writer_options.counter_source = [this] { return counter_snapshot(); };
    writer_options.custom_hooks = request.custom_hooks;
    writer_ = std::make_unique<noleax::agent::linux::LinuxTraceWriter>(
        event_queue, *tracker_, request.trace_path_utf8, writer_options);

    if (heap_hooks_ != nullptr && !heap_hooks_->install()) {
      start_error_ =
          noleax::ipc::ErrorResponse{3U, 0U, "failed to install the linux-glibc-heap hooks"};
      state_ = noleax::ipc::AgentState::kFailed;
      return false;
    }
    if (vm_hooks_ != nullptr && !vm_hooks_->install()) {
      if (heap_hooks_ != nullptr) {
        static_cast<void>(heap_hooks_->uninstall());
      }
      start_error_ =
          noleax::ipc::ErrorResponse{3U, 0U, "failed to install the linux-virtual-memory hooks"};
      state_ = noleax::ipc::AgentState::kFailed;
      return false;
    }
    if (!request.custom_hooks.empty()) {
      // Per-point best effort: failures degrade into the trace (CustomHookFailure records
      // + completeness bit 10), never fail the capture.
      custom_hooks_ = std::make_unique<noleax::agent::linux::LinuxCustomSymbolHooks>(
          *backend_, event_queue, request.custom_hooks, request.maximum_stack_depth,
          request.minimum_capture_size);
      static_cast<void>(custom_hooks_->install());
      writer_->note_custom_hook_failures(custom_hooks_->failures());
    }
    install_exit_hooks();

    writer_->begin_capture();
    state_ = noleax::ipc::AgentState::kCapturing;
    return true;
  }

  [[nodiscard]] const noleax::ipc::ErrorResponse& start_error() const noexcept {
    return start_error_;
  }

  [[nodiscard]] noleax::ipc::CaptureStatus status() const noexcept {
    noleax::ipc::CaptureStatus status;
    status.state = state_;
    if (writer_ != nullptr && state_ != noleax::ipc::AgentState::kCapturing) {
      const auto result = writer_result_;
      status.observed_calls = result.statistics.observed_calls;
      status.written_events = result.statistics.observed_calls -
                              result.statistics.filtered_before_queue -
                              result.statistics.dropped_events;
      status.filtered_calls = result.statistics.filtered_before_queue;
      status.dropped_events = result.statistics.dropped_events;
      status.bytes_written = result.bytes_written;
    } else {
      for (const auto& entry : noleax::agent::linux::kLinuxHookRegistry) {
        if (entry.group == noleax::agent::linux::LinuxHookApiGroup::kGlibcHeap &&
            heap_hooks_ != nullptr) {
          const auto counters = heap_hooks_->counters(entry.logical_api);
          status.observed_calls += counters.recordable_calls;
          status.filtered_calls += counters.filtered_calls;
          status.dropped_events += counters.dropped_events;
        } else if (entry.group == noleax::agent::linux::LinuxHookApiGroup::kVirtualMemory &&
                   vm_hooks_ != nullptr) {
          const auto counters = vm_hooks_->counters(entry.logical_api);
          status.observed_calls += counters.recordable_calls;
          status.filtered_calls += counters.filtered_calls;
          status.dropped_events += counters.dropped_events;
        }
      }
      if (custom_hooks_ != nullptr) {
        for (std::size_t index = 0U; index < custom_hooks_->point_count(); ++index) {
          const auto counters = custom_hooks_->counters(index);
          status.observed_calls += counters.recordable_calls;
          status.filtered_calls += counters.filtered_calls;
          status.dropped_events += counters.dropped_events;
        }
      }
      status.written_events = status.observed_calls - status.filtered_calls - status.dropped_events;
    }
    return status;
  }

  // Logical stop: replacements route to original, the writer drains and closes the trace.
  void drain() {
    if (state_ != noleax::ipc::AgentState::kCapturing) {
      return;
    }
    if (heap_hooks_ != nullptr) {
      static_cast<void>(heap_hooks_->stop_recording());
    }
    if (vm_hooks_ != nullptr) {
      static_cast<void>(vm_hooks_->stop_recording());
    }
    if (custom_hooks_ != nullptr) {
      static_cast<void>(custom_hooks_->stop_recording());
    }
    writer_result_ = writer_->finish();
    state_ = noleax::ipc::AgentState::kDrained;
  }

  // Physical teardown: revert every patch and shut the backend down.
  void finalize() {
    if (state_ == noleax::ipc::AgentState::kCapturing) {
      drain();
    }
    if (state_ != noleax::ipc::AgentState::kDrained) {
      return;
    }
    if (custom_hooks_ != nullptr) {
      static_cast<void>(custom_hooks_->uninstall());
    }
    if (vm_hooks_ != nullptr) {
      static_cast<void>(vm_hooks_->uninstall());
    }
    if (heap_hooks_ != nullptr) {
      static_cast<void>(heap_hooks_->uninstall());
    }
    static_cast<void>(backend_->shutdown());
    state_ = noleax::ipc::AgentState::kFinalized;
  }

  [[nodiscard]] noleax::ipc::AgentState state() const noexcept { return state_; }

  static LinuxCaptureRuntime* active() noexcept {
    return active_runtime.load(std::memory_order_acquire);
  }

  // Publishes the process-wide runtime for the exit-hook path. Called once per process
  // (bootstrap is single-shot).
  static void activate(LinuxCaptureRuntime* runtime) noexcept {
    active_runtime.store(runtime, std::memory_order_release);
  }

  // Target-exit finalize: first caller wins; every later exit-path call chains through.
  // Graceful drain only — never uninstall hooks or shut the backend down here: this
  // runs inside replacement_exit/replacement_exit_group, and the call to the original
  // exit trampoline happens after this returns, so tearing the backend down would free
  // that trampoline out from under the caller. The process is exiting anyway, so
  // leaving the patches installed is harmless (mirrors the Windows exit-hook path,
  // which also finalizes gracefully without physical teardown).
  void finalize_on_exit() noexcept {
    bool expected = false;
    if (!exit_finalize_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
      return;
    }
    // The exiting thread becomes an internal worker for the finalize: its own
    // allocations during the writer join must not be recorded.
    const noleax::agent::InternalThreadScope internal_scope;
    try {
      drain();
    } catch (...) {
    }
  }

  [[nodiscard]] bool capture_started() const noexcept {
    return state_ != noleax::ipc::AgentState::kIdle && state_ != noleax::ipc::AgentState::kFailed;
  }

 private:
  [[nodiscard]] std::vector<noleax::agent::linux::LinuxTraceWriterApiCounterSnapshot>
  counter_snapshot() const {
    std::vector<noleax::agent::linux::LinuxTraceWriterApiCounterSnapshot> snapshots;
    for (const auto& entry : noleax::agent::linux::kLinuxHookRegistry) {
      if (entry.group == noleax::agent::linux::LinuxHookApiGroup::kGlibcHeap &&
          heap_hooks_ != nullptr) {
        const auto counters = heap_hooks_->counters(entry.logical_api);
        snapshots.push_back(noleax::agent::linux::LinuxTraceWriterApiCounterSnapshot{
            entry.api_id, counters.recordable_calls, counters.successful_calls,
            counters.failed_calls, counters.filtered_calls, counters.dropped_events});
      } else if (entry.group == noleax::agent::linux::LinuxHookApiGroup::kVirtualMemory &&
                 vm_hooks_ != nullptr) {
        const auto counters = vm_hooks_->counters(entry.logical_api);
        // Wire-space statistics: a moved mremap emits a record pair, so the recordable/
        // successful counts gain one per paired record (see virtual_memory_hooks.hpp).
        snapshots.push_back(noleax::agent::linux::LinuxTraceWriterApiCounterSnapshot{
            entry.api_id, counters.recordable_calls + counters.paired_records,
            counters.successful_calls + counters.paired_records, counters.failed_calls,
            counters.filtered_calls, counters.dropped_events});
      }
    }
    if (custom_hooks_ != nullptr) {
      for (std::size_t index = 0U; index < custom_hooks_->point_count(); ++index) {
        const auto counters = custom_hooks_->counters(index);
        snapshots.push_back(noleax::agent::linux::LinuxTraceWriterApiCounterSnapshot{
            custom_hooks_->point_api_id(index), counters.recordable_calls,
            counters.successful_calls, counters.failed_calls, counters.filtered_calls,
            counters.dropped_events});
      }
    }
    return snapshots;
  }

  void install_exit_hooks();

  static std::atomic<LinuxCaptureRuntime*> active_runtime;
  static std::atomic<bool> exit_finalize_started;

  std::unique_ptr<noleax::agent::HookBackend> backend_;
  std::unique_ptr<noleax::agent::linux::GlibcHeapHooks> heap_hooks_;
  std::unique_ptr<noleax::agent::linux::VirtualMemoryHooks> vm_hooks_;
  std::unique_ptr<noleax::agent::linux::LinuxCustomSymbolHooks> custom_hooks_;
  std::unique_ptr<noleax::agent::linux::LinuxModuleTracker> tracker_;
  std::unique_ptr<noleax::agent::linux::LinuxTraceWriter> writer_;
  noleax::agent::linux::LinuxTraceWriterResult writer_result_{};
  noleax::ipc::AgentState state_{noleax::ipc::AgentState::kIdle};
  noleax::ipc::ErrorResponse start_error_{};
};

std::atomic<LinuxCaptureRuntime*> LinuxCaptureRuntime::active_runtime{nullptr};
std::atomic<bool> LinuxCaptureRuntime::exit_finalize_started{false};

// ---------------------------------------------------------------------------
// exit hooks: self-finalize when the target exits (exit, _exit/_Exit)
// ---------------------------------------------------------------------------

noleax::agent::OriginalTrampolineSlot exit_original{nullptr};
noleax::agent::OriginalTrampolineSlot exit_group_original{nullptr};

using ExitFunction = void (*)(int) noexcept;
using ExitGroupFunction = void (*)(int) noexcept;

__attribute__((noinline)) void replacement_exit(int status) {
  if (LinuxCaptureRuntime* const runtime = LinuxCaptureRuntime::active()) {
    runtime->finalize_on_exit();
  }
  reinterpret_cast<ExitFunction>(exit_original.load(std::memory_order_acquire))(status);
  __builtin_unreachable();
}

__attribute__((noinline)) void replacement_exit_group(int status) {
  if (LinuxCaptureRuntime* const runtime = LinuxCaptureRuntime::active()) {
    runtime->finalize_on_exit();
  }
  reinterpret_cast<ExitGroupFunction>(exit_group_original.load(std::memory_order_acquire))(status);
  __builtin_unreachable();
}

void LinuxCaptureRuntime::install_exit_hooks() {
  void* const libc = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
  if (libc == nullptr) {
    return;
  }
  if (void* const target = dlsym(libc, "exit")) {
    static_cast<void>(
        backend_->install_fast(target, reinterpret_cast<void*>(&replacement_exit), &exit_original));
  }
  // glibc routes exit() through _exit; hooking _exit also covers _Exit and direct calls.
  if (void* const target = dlsym(libc, "_exit")) {
    static_cast<void>(backend_->install_fast(
        target, reinterpret_cast<void*>(&replacement_exit_group), &exit_group_original));
  }
}

// ---------------------------------------------------------------------------
// controller session
// ---------------------------------------------------------------------------

void send_error(SocketChannel& channel, std::uint64_t request_id,
                noleax::ipc::ErrorResponse error) {
  noleax::ipc::Message message;
  message.type = MessageType::kError;
  message.request_id = request_id;
  message.payload = noleax::ipc::encode_error_response(error);
  channel.send(message, 5s);
}

void serve_session(SocketChannel channel, LinuxCaptureRuntime& runtime,
                   std::uint64_t start_request_id) {
  noleax::ipc::Message ready;
  ready.type = MessageType::kCaptureReady;
  ready.request_id = start_request_id;
  ready.payload = noleax::ipc::encode_capture_status(runtime.status());
  channel.send(ready, 5s);

  for (;;) {
    noleax::ipc::Message message;
    try {
      message = channel.receive(24h);
    } catch (...) {
      // Controller detached or died: keep capturing; the exit hook finalizes.
      return;
    }
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
}

// Runs on the constructor thread (launch) or a dedicated worker (attach). Returns false
// when the session never started.
bool session_bootstrap(std::string_view socket_name_without_nul,
                       const std::array<std::byte, 16U>& token, std::uint32_t controller_pid,
                       std::uint32_t connect_timeout_ms) {
  std::string socket_name{"\0", 1U};
  socket_name += socket_name_without_nul;

  SocketChannel channel =
      SocketChannel::connect(socket_name, std::chrono::milliseconds{connect_timeout_ms});
  if (channel.server_process_id() != controller_pid) {
    return false;
  }

  // The runtime lives on the heap for process lifetime: the session loop and the exit
  // hook both reference it after the constructor frame returns. One per process by
  // construction (bootstrap_started).
  LinuxCaptureRuntime* const runtime = new LinuxCaptureRuntime{};
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

  const noleax::ipc::Message start = channel.receive(std::chrono::milliseconds{connect_timeout_ms});
  if (start.type != MessageType::kStartCapture) {
    delete runtime;
    return false;
  }

  const HookGuardRuntimeLease guard_lease;
  if (!guard_lease.ready()) {
    send_error(channel, start.request_id,
               noleax::ipc::ErrorResponse{1U, 0U, "hook guard runtime is unavailable"});
    delete runtime;
    return false;
  }

  const noleax::ipc::StartCaptureRequest request = noleax::ipc::decode_start_capture(start.payload);
  if (!runtime->start(request, token)) {
    send_error(channel, start.request_id, runtime->start_error());
    delete runtime;
    return false;
  }

  LinuxCaptureRuntime::activate(runtime);
  std::thread{[channel = std::move(channel), runtime, request_id = start.request_id]() mutable {
    serve_session(std::move(channel), *runtime, request_id);
  }}.detach();
  return true;
}

// ---------------------------------------------------------------------------
// standalone
// ---------------------------------------------------------------------------

// One role of a standalone custom hook: the TOML locators map straight to the wire model
// (export names resolve against the target's .dynsym, ELF symbols against the module's
// on-disk image, RVAs are used as given). PDB symbols are Windows-only and there is no
// controller to bake them to RVAs here, so they reject the configuration outright.
[[nodiscard]] noleax::ipc::CustomHookRoleSpec standalone_custom_hook_role(
    const noleax::config::CustomHookRole& role, const std::string& module, const char* role_name) {
  if (role.pdb_symbol.has_value()) {
    throw std::runtime_error{"custom hook " + std::string{role_name} + " of module '" + module +
                             "' uses the PDB symbol '" + *role.pdb_symbol +
                             "', which is only supported on Windows; use an export name, a _sym "
                             "symbol, or an RVA instead"};
  }
  noleax::ipc::CustomHookRoleSpec spec;
  if (role.export_name.has_value()) {
    spec.locator = noleax::ipc::CustomHookLocator::kExport;
    spec.export_name = *role.export_name;
  } else if (role.symbol.has_value()) {
    spec.locator = noleax::ipc::CustomHookLocator::kElfSymbol;
    spec.export_name = *role.symbol;
  } else if (role.rva.has_value()) {
    spec.locator = noleax::ipc::CustomHookLocator::kRva;
    spec.rva = *role.rva;
  }
  return spec;
}

[[nodiscard]] std::vector<noleax::ipc::CustomHookSpec> standalone_custom_hooks(
    const std::vector<noleax::config::CustomHook>& hooks) {
  std::vector<noleax::ipc::CustomHookSpec> specs;
  specs.reserve(hooks.size());
  for (const auto& hook : hooks) {
    noleax::ipc::CustomHookSpec spec;
    spec.module = hook.module;
    spec.alloc = standalone_custom_hook_role(hook.alloc, hook.module, "alloc");
    spec.realloc = standalone_custom_hook_role(hook.realloc, hook.module, "realloc");
    spec.free = standalone_custom_hook_role(hook.free, hook.module, "free");
    const noleax::config::CustomHookRoleArguments arguments =
        noleax::config::resolve_custom_hook_arguments(hook);
    spec.alloc_size_arg = arguments.alloc_size_arg;
    spec.alloc_count_arg = arguments.alloc_count_arg;
    spec.realloc_ptr_arg = arguments.realloc_ptr_arg;
    spec.realloc_size_arg = arguments.realloc_size_arg;
    spec.free_ptr_arg = arguments.free_ptr_arg;
    spec.result_arg = hook.result_arg;
    spec.free_size_arg = hook.free_size_arg;
    spec.calloc = hook.kind == noleax::config::CustomHookKind::kCalloc;
    spec.forced = hook.forced;
    // Round up so a sub-millisecond wait still polls once (the wait itself is 100 ms-granular).
    spec.wait_module_ms =
        static_cast<std::uint64_t>((hook.wait_module.count() + 999'999) / 1'000'000);
    spec.label = noleax::config::custom_hook_label(hook);
    if (hook.image_identity.has_value()) {
      spec.image_identity = noleax::ipc::CustomHookImageIdentity{hook.image_identity->timestamp,
                                                                 hook.image_identity->checksum,
                                                                 hook.image_identity->image_size};
    }
    specs.push_back(std::move(spec));
  }
  return specs;
}

[[nodiscard]] noleax::ipc::StartCaptureRequest standalone_capture_request(
    const noleax::config::Configuration& configuration, noleax::ipc::HookProfile hook_profile) {
  noleax::ipc::StartCaptureRequest request;
  request.capture_kind = noleax::ipc::CaptureKind::kLaunch;
  request.hook_profile = hook_profile;
  request.maximum_stack_depth = configuration.capture.max_stack_depth.value;
  request.minimum_capture_size = configuration.capture.min_size.value;
  request.buffer_size = configuration.trace.buffer_size.value;
  request.maximum_trace_size = configuration.trace.max_file_size.value;
  request.flush_interval_ns =
      static_cast<std::uint64_t>(configuration.trace.flush_interval.value.count());
  request.memory_counters_interval_ns =
      static_cast<std::uint64_t>(configuration.capture.memory_counters_interval.value.count());
  request.memory_map_interval_ns =
      static_cast<std::uint64_t>(configuration.capture.memory_map_interval.value.count());
  switch (configuration.trace.compression.value) {
    case noleax::config::Compression::kNone:
      request.compression = noleax::ipc::CompressionCodec::kNone;
      break;
    case noleax::config::Compression::kLz4:
      request.compression = noleax::ipc::CompressionCodec::kLz4;
      break;
    case noleax::config::Compression::kZstd:
      request.compression = noleax::ipc::CompressionCodec::kZstd;
      break;
  }
  request.compression_level = configuration.trace.compression_level.value;
  if (configuration.trace.path.value.has_value()) {
    const auto utf8 = configuration.trace.path.value->generic_u8string();
    request.trace_path_utf8 = std::string{utf8.begin(), utf8.end()};
  } else {
    std::array<char, 4096U> executable{};
    const ssize_t length = ::readlink("/proc/self/exe", executable.data(), executable.size() - 1U);
    const std::filesystem::path stem =
        length > 0 ? std::filesystem::path{std::string{executable.data(),
                                                       static_cast<std::size_t>(length)}}
                         .stem()
                   : std::filesystem::path{"noleax"};
    const auto utf8 =
        (std::filesystem::current_path() / (stem.string() + ".nlx")).generic_u8string();
    request.trace_path_utf8 = std::string{utf8.begin(), utf8.end()};
  }
  request.custom_hooks = standalone_custom_hooks(configuration.custom_hooks.value);
  return request;
}

// Standalone mode honors a fixed subset of the configuration (see
// docs/LINUX_LAUNCH_INJECTION.md): [capture] hook_profile/max_stack_depth/min_size/
// duration/memory_counters_interval/memory_map_interval, [trace] path/buffer_size/
// max_file_size/flush_interval/compression/compression_level, and [[custom_hooks]].
// Anything else with a non-default value would be silently ignored, so it is rejected up
// front. Field names only — never values — so diagnostics cannot leak configured paths or
// sizes.
[[nodiscard]] std::vector<std::string> unsupported_standalone_fields(
    const noleax::config::Configuration& configuration) {
  const noleax::config::Configuration defaults = noleax::config::make_default_configuration();
  std::vector<std::string> unsupported;
  const auto reject_if = [&unsupported](bool condition, const char* name) {
    if (condition) {
      unsupported.emplace_back(name);
    }
  };
  const auto different = [&defaults](const auto& setting, const auto& fallback) {
    return setting.value != fallback;
  };

  reject_if(configuration.operation.value.has_value(), "operation");
  reject_if(configuration.target.path.value.has_value(), "target.path");
  reject_if(!configuration.target.args.value.empty(), "target.args");
  reject_if(configuration.target.working_directory.value.has_value(), "target.working_directory");
  // target.pid keeps its dedicated "standalone attach" message in standalone_bootstrap.
  reject_if(different(configuration.injection.method, defaults.injection.method.value),
            "injection.method");
  reject_if(configuration.injection.agent_path.value.has_value(), "injection.agent_path");
  reject_if(different(configuration.injection.timeout, defaults.injection.timeout.value),
            "injection.timeout");
  reject_if(
      different(configuration.injection.unload_on_stop, defaults.injection.unload_on_stop.value),
      "injection.unload_on_stop");
  reject_if(different(configuration.capture.live, defaults.capture.live.value), "capture.live");
  reject_if(different(configuration.trace.max_files, defaults.trace.max_files.value),
            "trace.max_files (trace rotation is not implemented)");
  reject_if(different(configuration.trace.on_full, defaults.trace.on_full.value),
            "trace.on_full (trace rotation is not implemented)");
  reject_if(different(configuration.symbols.mode, defaults.symbols.mode.value), "symbols.mode");
  reject_if(!configuration.symbols.paths.value.empty(), "symbols.paths");
  reject_if(!configuration.symbols.servers.value.empty(), "symbols.servers");
  reject_if(!configuration.analysis.inputs.value.empty(), "analysis.inputs");
  reject_if(different(configuration.analysis.mode, defaults.analysis.mode.value), "analysis.mode");
  reject_if(different(configuration.analysis.format, defaults.analysis.format.value),
            "analysis.format");
  reject_if(configuration.analysis.output.value.has_value(), "analysis.output");
  reject_if(configuration.analysis.from.value.has_value(), "analysis.from");
  reject_if(configuration.analysis.to.value.has_value(), "analysis.to");
  reject_if(configuration.analysis.end.value.has_value(), "analysis.end");
  reject_if(configuration.analysis.group_by.value.has_value(), "analysis.group_by");
  reject_if(different(configuration.analysis.sort, defaults.analysis.sort.value), "analysis.sort");
  reject_if(different(configuration.analysis.trim_agent_frames,
                      defaults.analysis.trim_agent_frames.value),
            "analysis.trim_agent_frames");
  reject_if(configuration.filters.min_size.value.has_value(), "filters.min_size");
  reject_if(configuration.filters.max_size.value.has_value(), "filters.max_size");
  reject_if(!configuration.filters.events.value.empty(), "filters.events");
  reject_if(!configuration.filters.threads.value.empty(), "filters.threads");
  reject_if(!configuration.filters.apis.value.empty(), "filters.apis");
  reject_if(!configuration.filters.modules.value.empty(), "filters.modules");
  reject_if(!configuration.filters.stack_modules.value.empty(), "filters.stack_modules");
  reject_if(!configuration.filters.allocation_ids.value.empty(), "filters.allocation_ids");
  reject_if(!configuration.filters.statuses.value.empty(), "filters.statuses");
  reject_if(configuration.symbol_listing.input.value.has_value(), "symbol_listing.input");
  reject_if(different(configuration.symbol_listing.format, defaults.symbol_listing.format.value),
            "symbol_listing.format");
  reject_if(configuration.symbol_listing.output.value.has_value(), "symbol_listing.output");
  reject_if(!configuration.symbol_listing.name.value.empty(), "symbol_listing.name");
  reject_if(
      different(configuration.symbol_listing.match_case, defaults.symbol_listing.match_case.value),
      "symbol_listing.match_case");
  reject_if(!configuration.symbol_listing.kind.value.empty(), "symbol_listing.kind");
  reject_if(!configuration.symbol_listing.fields.value.empty(), "symbol_listing.fields");
  reject_if(configuration.patch.input.value.has_value(), "patch.input");
  reject_if(configuration.patch.output.value.has_value(), "patch.output");
  reject_if(different(configuration.patch.method, defaults.patch.method.value), "patch.method");
  reject_if(different(configuration.patch.agent_name, defaults.patch.agent_name.value),
            "patch.agent_name");
  reject_if(different(configuration.patch.allow_break_signature,
                      defaults.patch.allow_break_signature.value),
            "patch.allow_break_signature");
  reject_if(different(configuration.patch.verify, defaults.patch.verify.value), "patch.verify");
  reject_if(different(configuration.patch.standalone, defaults.patch.standalone.value),
            "patch.standalone");
  reject_if(different(configuration.diagnostics.log_level, defaults.diagnostics.log_level.value),
            "diagnostics.log_level");
  reject_if(different(configuration.diagnostics.color, defaults.diagnostics.color.value),
            "diagnostics.color");
  return unsupported;
}

// Runs on the constructor thread.
bool standalone_bootstrap(const std::string& config_path) {
  noleax::config::Configuration configuration = noleax::config::make_default_configuration();
  try {
    noleax::config::apply_overrides(configuration, noleax::config::load_toml_config(config_path),
                                    noleax::config::ValueSource::kConfig);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "noleax-agent: standalone configuration '%s' failed to load: %s\n",
                 config_path.c_str(), error.what());
    return false;
  }
  if (configuration.target.pid.value.has_value()) {
    std::fprintf(stderr, "noleax-agent: standalone attach is not supported on Linux\n");
    return false;
  }
  const std::vector<std::string> unsupported = unsupported_standalone_fields(configuration);
  if (!unsupported.empty()) {
    for (const std::string& field : unsupported) {
      std::fprintf(stderr,
                   "noleax-agent: standalone configuration '%s' rejected: field '%s' is not "
                   "supported in standalone mode\n",
                   config_path.c_str(), field.c_str());
    }
    return false;
  }
  const auto standalone_profile =
      noleax::config::linux_ipc_hook_profile(configuration.capture.hook_profile.value);
  if (!standalone_profile.has_value()) {
    std::fprintf(stderr, "noleax-agent: standalone requires a linux-* hook profile\n");
    return false;
  }

  const HookGuardRuntimeLease guard_lease;
  if (!guard_lease.ready()) {
    std::fprintf(stderr, "noleax-agent: hook guard runtime is unavailable\n");
    return false;
  }

  auto* const runtime = new LinuxCaptureRuntime;
  noleax::ipc::StartCaptureRequest request;
  try {
    request = standalone_capture_request(configuration, *standalone_profile);
  } catch (const std::exception& error) {
    // A bad declaration (a Windows-only PDB locator, a mixed argument mapping, ...) rejects
    // the configuration; the target itself must never be taken down by it.
    std::fprintf(stderr, "noleax-agent: standalone configuration '%s' rejected: %s\n",
                 config_path.c_str(), error.what());
    delete runtime;
    return false;
  }
  std::array<std::byte, 16U> session_id{};
  const ssize_t random_bytes = ::getrandom(session_id.data(), session_id.size(), 0U);
  static_cast<void>(random_bytes);
  if (!runtime->start(request, session_id)) {
    std::fprintf(stderr, "noleax-agent: standalone capture failed to start: %s\n",
                 runtime->start_error().message.c_str());
    delete runtime;
    return false;
  }
  LinuxCaptureRuntime::activate(runtime);

  if (configuration.capture.duration.value.has_value()) {
    const auto duration = *configuration.capture.duration.value;
    std::thread{[runtime, duration] {
      std::this_thread::sleep_for(duration);
      runtime->finalize();
    }}.detach();
  }
  return true;
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
      std::array<std::byte, 16U> token{};
      if (decode_session_token(environment.session_token_hex, token)) {
        static_cast<void>(session_bootstrap(environment.socket_name, token,
                                            environment.controller_pid,
                                            environment.connect_timeout_ms));
      }
    } else {
      static_cast<void>(standalone_bootstrap(environment.standalone_config_path));
    }
  } catch (...) {
    // A failed bootstrap must never take the target down with it; the controller
    // observes the missing/failed session on its side.
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// attach bootstrap export (called by the controller's ptrace injector)
// ---------------------------------------------------------------------------

extern "C" __attribute__((visibility("default"))) std::uint32_t noleax_agent_attach_bootstrap(
    const noleax::agent::linux::AttachBootstrapParameters* parameters) noexcept {
  if (parameters == nullptr ||
      parameters->structure_size != sizeof(noleax::agent::linux::AttachBootstrapParameters) ||
      parameters->version != noleax::agent::linux::kAttachBootstrapVersion) {
    return 1U;
  }
  if (bootstrap_started.exchange(true, std::memory_order_acq_rel)) {
    return 2U;  // already bootstrapped (e.g. agent was preloaded too)
  }
  try {
    const std::string_view socket_name{
        parameters->socket_name,
        strnlen(parameters->socket_name, noleax::agent::linux::kAttachSocketNameCapacity)};
    std::thread([socket_name = std::string{socket_name}, token = parameters->session_token,
                 pid = parameters->controller_process_id,
                 timeout = parameters->connect_timeout_ms]() mutable {
      // The worker runs outside any guarded caller: a dead controller socket or any
      // other failure must never terminate the attached target.
      try {
        static_cast<void>(session_bootstrap(socket_name, token, pid, timeout));
      } catch (...) {
      }
    }).detach();
    return 0U;
  } catch (...) {
    return 3U;
  }
}
