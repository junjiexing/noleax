#include "noleax/agent/windows/bootstrap.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off: bcrypt.h requires Windows base types.
#include <windows.h>
#include <bcrypt.h>
// clang-format on

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "noleax/agent/hook_backend.hpp"
#include "noleax/agent/replacement_lifecycle.hpp"
#include "noleax/agent/windows/rtl_allocate_heap_trace_writer.hpp"
#include "noleax/agent/windows/windows_memory_hooks.hpp"
#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"
#include "noleax/ipc/protocol.hpp"
#include "noleax/ipc/windows/named_pipe.hpp"
#include "noleax/trace/wire_format.hpp"
#include "noleax/version.hpp"

namespace {

using noleax::agent::windows::BootstrapParameters;
using noleax::agent::windows::RtlAllocateHeapTraceWriter;
using noleax::agent::windows::RtlAllocateHeapTraceWriterOptions;
using noleax::agent::windows::RtlAllocateHeapTraceWriterResult;
using noleax::agent::windows::WindowsHookProfile;
using noleax::agent::windows::WindowsMemoryHookOptions;
using noleax::agent::windows::WindowsMemoryHooks;

std::atomic<bool> bootstrap_started{false};
std::atomic<bool> capture_ready{false};
std::atomic<void*> standalone_runtime{nullptr};

class HookGuardRuntimeLease final {
 public:
  HookGuardRuntimeLease() {
    if (!noleax::agent::acquire_hook_guard_runtime()) {
      throw std::runtime_error{"hook guard runtime is unavailable"};
    }
  }
  ~HookGuardRuntimeLease() { noleax::agent::release_hook_guard_runtime(); }

  HookGuardRuntimeLease(const HookGuardRuntimeLease&) = delete;
  HookGuardRuntimeLease& operator=(const HookGuardRuntimeLease&) = delete;
};

[[nodiscard]] std::filesystem::path utf8_path(const std::string& value) {
  if (value.empty() || value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw std::invalid_argument{"trace path is empty or too long"};
  }
  const int input_size = static_cast<int>(value.size());
  const int output_size =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_size, nullptr, 0);
  if (output_size <= 0) {
    throw std::invalid_argument{"trace path is not valid UTF-8"};
  }
  std::wstring wide(static_cast<std::size_t>(output_size), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_size, wide.data(),
                          output_size) != output_size) {
    throw std::runtime_error{"trace path conversion failed"};
  }
  return std::filesystem::path{wide};
}

[[nodiscard]] WindowsHookProfile hook_profile(noleax::ipc::HookProfile profile) {
  switch (profile) {
    case noleax::ipc::HookProfile::kWindowsNtHeap:
      return WindowsHookProfile::kNtHeap;
    case noleax::ipc::HookProfile::kWindowsVirtualMemory:
      return WindowsHookProfile::kVirtualMemory;
    case noleax::ipc::HookProfile::kWindowsNative:
      return WindowsHookProfile::kNative;
  }
  throw std::invalid_argument{"unsupported hook profile"};
}

[[nodiscard]] noleax::trace::CompressionCodec compression_codec(
    noleax::ipc::CompressionCodec codec) {
  switch (codec) {
    case noleax::ipc::CompressionCodec::kNone:
      return noleax::trace::CompressionCodec::kNone;
    case noleax::ipc::CompressionCodec::kLz4:
      return noleax::trace::CompressionCodec::kLz4;
    case noleax::ipc::CompressionCodec::kZstd:
      return noleax::trace::CompressionCodec::kZstd;
  }
  throw std::invalid_argument{"unsupported compression codec"};
}

[[nodiscard]] std::size_t queue_capacity(std::uint64_t buffer_size) {
  constexpr std::uint64_t kMaximumCapacity = 1U << 24U;
  const std::uint64_t requested =
      (std::max)(std::uint64_t{2U}, buffer_size / sizeof(noleax::agent::windows::RtlHeapEvent));
  const std::uint64_t capacity = std::bit_floor((std::min)(requested, kMaximumCapacity));
  return static_cast<std::size_t>(capacity);
}

[[nodiscard]] std::int64_t utc_now_nanoseconds() noexcept {
  FILETIME file_time{};
  GetSystemTimePreciseAsFileTime(&file_time);
  ULARGE_INTEGER ticks{};
  ticks.LowPart = file_time.dwLowDateTime;
  ticks.HighPart = file_time.dwHighDateTime;
  constexpr std::uint64_t kWindowsToUnixTicks = 116'444'736'000'000'000ULL;
  if (ticks.QuadPart < kWindowsToUnixTicks) {
    return 0;
  }
  const std::uint64_t unix_ticks = ticks.QuadPart - kWindowsToUnixTicks;
  if (unix_ticks > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) / 100U) {
    return 0;
  }
  return static_cast<std::int64_t>(unix_ticks * 100U);
}

[[nodiscard]] noleax::trace::FileHeader make_header(
    const std::array<std::byte, 16U>& session_token) {
  LARGE_INTEGER frequency{};
  LARGE_INTEGER origin{};
  if (QueryPerformanceFrequency(&frequency) == FALSE || QueryPerformanceCounter(&origin) == FALSE ||
      frequency.QuadPart <= 0 || origin.QuadPart < 0) {
    throw std::runtime_error{"performance counter is unavailable"};
  }
  noleax::trace::FileHeader header;
  header.pointer_width = sizeof(void*);
  header.platform = noleax::trace::Platform::kWindows;
#if defined(_M_X64)
  header.architecture = noleax::trace::Architecture::kX64;
#elif defined(_M_IX86)
  header.architecture = noleax::trace::Architecture::kX86;
#elif defined(_M_ARM64)
  header.architecture = noleax::trace::Architecture::kArm64;
#else
  header.architecture = noleax::trace::Architecture::kUnknown;
#endif
  header.session_id = session_token;
  header.monotonic_frequency = static_cast<std::uint64_t>(frequency.QuadPart);
  header.monotonic_origin = static_cast<std::uint64_t>(origin.QuadPart);
  header.utc_origin_ns = utc_now_nanoseconds();
  return header;
}

void add_saturating(std::uint64_t& destination, std::uint64_t value) noexcept {
  destination = value > std::numeric_limits<std::uint64_t>::max() - destination
                    ? std::numeric_limits<std::uint64_t>::max()
                    : destination + value;
}

class CaptureRuntime final {
 public:
  explicit CaptureRuntime(std::array<std::byte, 16U> token) : session_token_{token} {}
  ~CaptureRuntime() { release_finalize_gate(); }

  void start(const noleax::ipc::StartCaptureRequest& request) {
    if (state_ != noleax::ipc::AgentState::kIdle) {
      throw std::logic_error{"capture session has already started"};
    }
    state_ = noleax::ipc::AgentState::kStarting;
    const std::filesystem::path path = utf8_path(request.trace_path_utf8);
    output_ = std::make_unique<std::ofstream>(path, std::ios::binary | std::ios::trunc);
    if (!*output_) {
      throw std::runtime_error{"cannot create the trace output file"};
    }
    backend_ = std::make_unique<noleax::agent::HookBackend>();
    WindowsMemoryHookOptions hook_options;
    hook_options.profile = hook_profile(request.hook_profile);
    hook_options.event_queue_capacity = queue_capacity(request.buffer_size);
    hook_options.maximum_stack_depth = request.maximum_stack_depth;
    hook_options.minimum_capture_size = request.minimum_capture_size;
    hooks_ = std::make_unique<WindowsMemoryHooks>(*backend_, hook_options);

    RtlAllocateHeapTraceWriterOptions writer_options;
    writer_options.trace.max_file_size = request.maximum_trace_size;
    writer_options.trace.zstd_level =
        request.compression_level == 0 ? 1 : request.compression_level;
    writer_options.compression = compression_codec(request.compression);
    writer_options.capture_scope = request.capture_kind == noleax::ipc::CaptureKind::kLaunch
                                       ? noleax::trace::CaptureScope{true, false}
                                       : noleax::trace::CaptureScope{false, true};
    const auto flush_ns = std::chrono::nanoseconds{request.flush_interval_ns};
    writer_options.flush_interval = (std::max)(
        std::chrono::milliseconds{1}, std::chrono::duration_cast<std::chrono::milliseconds>(
                                          flush_ns + std::chrono::milliseconds{1}));
    writer_ = std::make_unique<RtlAllocateHeapTraceWriter>(
        *hooks_, *output_, make_header(session_token_), writer_options);
    const auto installed = hooks_->install();
    if (!installed.installed()) {
      throw std::runtime_error{"one or more selected memory hooks could not be installed"};
    }
    writer_->begin_capture();
    state_ = noleax::ipc::AgentState::kCapturing;
    capture_ready.store(true, std::memory_order_release);
  }

  void drain() {
    if (state_ != noleax::ipc::AgentState::kCapturing) {
      throw std::logic_error{"capture session is not recording"};
    }
    if (!noleax::agent::ReplacementQuiescenceGate::close_and_wait(10'000U)) {
      const std::uint64_t active = noleax::agent::ReplacementQuiescenceGate::active_call_count();
      const std::uint64_t transitions =
          noleax::agent::ReplacementQuiescenceGate::transition_count();
      noleax::agent::ReplacementQuiescenceGate::open();
      throw std::runtime_error{"replacement callbacks did not reach the finalize gate: active=" +
                               std::to_string(active) +
                               " transitions=" + std::to_string(transitions)};
    }
    finalize_gate_closed_ = true;
    try {
      if (!hooks_->stop_recording(1'000'000U)) {
        throw std::runtime_error{"recording callbacks did not become quiescent"};
      }
      capture_ready.store(false, std::memory_order_release);
      release_finalize_gate();
      result_ = writer_->finish();
      writer_.reset();
      output_->flush();
      output_->close();
      if (!*output_) {
        throw std::runtime_error{"trace output could not be closed cleanly"};
      }
      if (!noleax::agent::ReplacementQuiescenceGate::close_and_wait(1'000'000U)) {
        noleax::agent::ReplacementQuiescenceGate::open();
        throw std::runtime_error{"logically stopped callbacks did not reach the finalize gate"};
      }
      finalize_gate_closed_ = true;
    } catch (...) {
      release_finalize_gate();
      throw;
    }
    state_ = noleax::ipc::AgentState::kDrained;
  }

  void finalize() {
    if (state_ != noleax::ipc::AgentState::kDrained) {
      throw std::logic_error{"capture session has not been drained"};
    }
    if (!finalize_gate_closed_) {
      throw std::logic_error{"replacement finalize gate is not closed"};
    }
    try {
      if (!hooks_->uninstall(1'000'000U)) {
        throw std::runtime_error{"physical hook teardown did not become quiescent"};
      }
      if (!backend_->shutdown()) {
        throw std::runtime_error{"hook backend shutdown failed"};
      }
      hooks_.reset();
      backend_.reset();
      output_.reset();
    } catch (...) {
      release_finalize_gate();
      throw;
    }
    release_finalize_gate();
    state_ = noleax::ipc::AgentState::kFinalized;
  }

  // Finalizes the capture while the process is still fully alive (standalone ExitProcess
  // hook). Mirrors drain(): the writer worker is running, so finish() can join it after
  // a clean final drain.
  void finalize_graceful() {
    if (state_ != noleax::ipc::AgentState::kCapturing) {
      return;
    }
    if (!noleax::agent::ReplacementQuiescenceGate::close_and_wait(10'000U)) {
      noleax::agent::ReplacementQuiescenceGate::open();
      throw std::runtime_error{"replacement callbacks did not reach the finalize gate"};
    }
    finalize_gate_closed_ = true;
    try {
      if (!hooks_->stop_recording(1'000'000U)) {
        throw std::runtime_error{"recording callbacks did not become quiescent"};
      }
      release_finalize_gate();
      result_ = writer_->finish();
      writer_.reset();
      output_->flush();
      output_->close();
    } catch (...) {
      release_finalize_gate();
      throw;
    }
    state_ = noleax::ipc::AgentState::kFinalized;
  }

  [[nodiscard]] noleax::agent::HookBackend& backend() noexcept { return *backend_; }

  void release_finalize_gate() noexcept {
    if (finalize_gate_closed_) {
      noleax::agent::ReplacementQuiescenceGate::open();
      finalize_gate_closed_ = false;
    }
  }

  // Finalizes the capture during DLL_PROCESS_DETACH: every other thread is already
  // dead, so this runs single-threaded and must stay loader-lock safe (no new
  // threads, no library loads, only inline drain and file IO).
  void finalize_detached() noexcept {
    if (state_ != noleax::ipc::AgentState::kCapturing) {
      return;
    }
    state_ = noleax::ipc::AgentState::kDrained;
    try {
      static_cast<void>(hooks_->stop_recording(1'000'000U));
      result_ = writer_->finish_after_worker_exit();
      writer_.reset();
      output_->flush();
      output_->close();
    } catch (...) {
    }
    state_ = noleax::ipc::AgentState::kFinalized;
  }

  [[nodiscard]] noleax::ipc::CaptureStatus status() const noexcept {
    noleax::ipc::CaptureStatus status;
    status.state = state_;
    if (result_.has_value()) {
      status.observed_calls = result_->statistics.observed_calls;
      status.filtered_calls = result_->statistics.filtered_before_queue;
      status.dropped_events = result_->statistics.dropped_events;
      status.written_events = status.observed_calls - status.filtered_calls - status.dropped_events;
      status.bytes_written = result_->bytes_written;
      return status;
    }
    if (hooks_ == nullptr) {
      return status;
    }
    if (const auto* heap = hooks_->nt_heap_hooks(); heap != nullptr) {
      add_saturating(status.observed_calls, heap->allocate_hook().recordable_call_count());
      add_saturating(status.observed_calls, heap->reallocate_hook().recordable_call_count());
      add_saturating(status.observed_calls, heap->free_hook().recordable_call_count());
      add_saturating(status.observed_calls, heap->create_hook().recordable_call_count());
      add_saturating(status.observed_calls, heap->destroy_hook().recordable_call_count());
      add_saturating(status.filtered_calls, heap->allocate_hook().filtered_call_count());
      add_saturating(status.dropped_events, heap->allocate_hook().dropped_event_count());
      add_saturating(status.dropped_events, heap->reallocate_hook().dropped_event_count());
      add_saturating(status.dropped_events, heap->free_hook().dropped_event_count());
      add_saturating(status.dropped_events, heap->create_hook().dropped_event_count());
      add_saturating(status.dropped_events, heap->destroy_hook().dropped_event_count());
    }
    if (const auto* memory = hooks_->virtual_memory_hooks(); memory != nullptr) {
      for (const auto& statistics : {memory->allocate_statistics(), memory->free_statistics(),
                                     memory->map_statistics(), memory->unmap_statistics()}) {
        add_saturating(status.observed_calls, statistics.recordable_calls);
        add_saturating(status.filtered_calls, statistics.filtered_calls);
        add_saturating(status.dropped_events, statistics.dropped_events);
      }
    }
    if (status.observed_calls >= status.filtered_calls &&
        status.observed_calls - status.filtered_calls >= status.dropped_events) {
      status.written_events = status.observed_calls - status.filtered_calls - status.dropped_events;
    }
    return status;
  }

  [[nodiscard]] noleax::ipc::AgentState state() const noexcept { return state_; }

 private:
  std::array<std::byte, 16U> session_token_{};
  noleax::ipc::AgentState state_{noleax::ipc::AgentState::kIdle};
  std::unique_ptr<std::ofstream> output_;
  std::unique_ptr<noleax::agent::HookBackend> backend_;
  std::unique_ptr<WindowsMemoryHooks> hooks_;
  std::unique_ptr<RtlAllocateHeapTraceWriter> writer_;
  std::optional<RtlAllocateHeapTraceWriterResult> result_;
  bool finalize_gate_closed_{false};
};

[[nodiscard]] noleax::ipc::Architecture current_architecture() noexcept {
#if defined(_M_X64)
  return noleax::ipc::Architecture::kX64;
#elif defined(_M_IX86)
  return noleax::ipc::Architecture::kX86;
#elif defined(_M_ARM64)
  return noleax::ipc::Architecture::kArm64;
#else
  return noleax::ipc::Architecture::kUnknown;
#endif
}

void send_status(noleax::ipc::windows::PipeChannel& channel, noleax::ipc::MessageType type,
                 std::uint64_t request_id, const CaptureRuntime& runtime,
                 std::chrono::milliseconds timeout) {
  channel.send({type, request_id, noleax::ipc::encode_capture_status(runtime.status())}, timeout);
}

DWORD WINAPI agent_worker(void* parameter) noexcept {
  std::unique_ptr<BootstrapParameters> bootstrap{static_cast<BootstrapParameters*>(parameter)};
  const auto timeout = std::chrono::milliseconds{bootstrap->connect_timeout_ms};
  std::unique_ptr<CaptureRuntime> runtime;
  try {
    auto channel = noleax::ipc::windows::PipeChannel::connect(bootstrap->pipe_name.data(), timeout);
    if (channel.server_process_id() != bootstrap->controller_process_id) {
      throw std::runtime_error{"named pipe server PID does not match the controller process"};
    }
    noleax::ipc::AgentHello hello;
    hello.agent_abi_version = noleax::kAgentAbiVersion;
    hello.process_id = GetCurrentProcessId();
    hello.worker_thread_id = GetCurrentThreadId();
    hello.pointer_width = sizeof(void*);
    hello.architecture = current_architecture();
    hello.session_token = bootstrap->session_token;
    channel.send(
        {noleax::ipc::MessageType::kAgentHello, 1U, noleax::ipc::encode_agent_hello(hello)},
        timeout);

    const noleax::ipc::Message start_message = channel.receive(timeout);
    if (start_message.type != noleax::ipc::MessageType::kStartCapture) {
      throw std::runtime_error{"controller did not send StartCapture after AgentHello"};
    }
    const HookGuardRuntimeLease hook_guard_runtime;
    const noleax::agent::ReplacementGateCoordinatorScope finalize_coordinator;
    runtime = std::make_unique<CaptureRuntime>(bootstrap->session_token);
    runtime->start(noleax::ipc::decode_start_capture(start_message.payload));
    send_status(channel, noleax::ipc::MessageType::kCaptureReady, start_message.request_id,
                *runtime, timeout);

    for (;;) {
      const noleax::ipc::Message request = channel.receive(std::chrono::hours{24});
      try {
        if (request.type == noleax::ipc::MessageType::kQueryStatus && request.payload.empty()) {
          send_status(channel, noleax::ipc::MessageType::kCaptureStatus, request.request_id,
                      *runtime, timeout);
          continue;
        }
        if (request.type == noleax::ipc::MessageType::kStopCapture && request.payload.empty()) {
          runtime->drain();
          send_status(channel, noleax::ipc::MessageType::kCaptureDrained, request.request_id,
                      *runtime, timeout);
          continue;
        }
        if (request.type == noleax::ipc::MessageType::kFinalizeHooks && request.payload.empty()) {
          runtime->finalize();
          send_status(channel, noleax::ipc::MessageType::kCaptureFinalized, request.request_id,
                      *runtime, timeout);
          return 0U;
        }
        throw std::runtime_error{"controller sent a message invalid for the agent state"};
      } catch (const std::exception& error) {
        const noleax::ipc::ErrorResponse response{1U, 0U, error.what()};
        channel.send({noleax::ipc::MessageType::kError, request.request_id,
                      noleax::ipc::encode_error_response(response)},
                     timeout);
        throw;
      }
    }
  } catch (const std::exception&) {
    if (runtime != nullptr && runtime->state() == noleax::ipc::AgentState::kCapturing) {
      try {
        runtime->drain();
      } catch (...) {
      }
      // Physical revert is unsafe without controller thread suspension. Preserve the logically
      // stopped hook state for process lifetime if the control channel disappeared.
      runtime->release_finalize_gate();
      static_cast<void>(runtime.release());
    } else if (runtime != nullptr && runtime->state() == noleax::ipc::AgentState::kDrained) {
      runtime->release_finalize_gate();
      static_cast<void>(runtime.release());
    }
    return 1U;
  } catch (...) {
    if (runtime != nullptr && (runtime->state() == noleax::ipc::AgentState::kCapturing ||
                               runtime->state() == noleax::ipc::AgentState::kDrained)) {
      runtime->release_finalize_gate();
      static_cast<void>(runtime.release());
    }
    return 2U;
  }
}

// ---- standalone capture (patched image running without a controller) ----

void standalone_report(const std::string& message) noexcept {
  try {
    const std::string line = "noleax-agent: standalone capture disabled: " + message + "\n";
    DWORD written = 0U;
    static_cast<void>(WriteFile(GetStdHandle(STD_ERROR_HANDLE), line.data(),
                                static_cast<DWORD>(line.size()), &written, nullptr));
    static_cast<void>(written);
    OutputDebugStringA(line.c_str());
  } catch (...) {
  }
}

[[nodiscard]] std::array<std::byte, 16U> random_session_token() {
  std::array<std::byte, 16U> token{};
  if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(token.data()),
                      static_cast<ULONG>(token.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    throw std::runtime_error{"session token generation failed"};
  }
  return token;
}

[[nodiscard]] std::filesystem::path executable_path() {
  std::wstring buffer(MAX_PATH, L'\0');
  const DWORD length =
      GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0U || length >= buffer.size()) {
    throw std::runtime_error{"cannot resolve the executable path"};
  }
  buffer.resize(length);
  return std::filesystem::path{buffer};
}

[[nodiscard]] std::optional<std::filesystem::path> discover_standalone_config() {
  wchar_t environment[MAX_PATH];
  const DWORD env_length = GetEnvironmentVariableW(L"NOLEAX_AGENT_CONFIG", environment, MAX_PATH);
  if (env_length > 0U && env_length < MAX_PATH) {
    return std::filesystem::path{environment, environment + env_length};
  }
  auto sibling = executable_path().parent_path() / "noleax-agent.toml";
  std::error_code error;
  if (std::filesystem::is_regular_file(sibling, error) && !error) {
    return sibling;
  }
  return std::nullopt;
}

[[nodiscard]] noleax::config::Configuration load_standalone_configuration(
    const std::filesystem::path& config_path) {
  auto configuration = noleax::config::make_default_configuration();
  noleax::config::apply_overrides(configuration, noleax::config::load_toml_config(config_path),
                                  noleax::config::ValueSource::kConfig);
  return configuration;
}

[[nodiscard]] noleax::ipc::HookProfile ipc_hook_profile(noleax::config::HookProfile profile) {
  switch (profile) {
    case noleax::config::HookProfile::kWindowsNtHeap:
      return noleax::ipc::HookProfile::kWindowsNtHeap;
    case noleax::config::HookProfile::kWindowsVirtualMemory:
      return noleax::ipc::HookProfile::kWindowsVirtualMemory;
    case noleax::config::HookProfile::kWindowsNative:
      return noleax::ipc::HookProfile::kWindowsNative;
  }
  throw std::invalid_argument{"unsupported hook profile"};
}

[[nodiscard]] noleax::ipc::CompressionCodec ipc_compression(
    noleax::config::Compression compression) {
  switch (compression) {
    case noleax::config::Compression::kNone:
      return noleax::ipc::CompressionCodec::kNone;
    case noleax::config::Compression::kLz4:
      return noleax::ipc::CompressionCodec::kLz4;
    case noleax::config::Compression::kZstd:
      return noleax::ipc::CompressionCodec::kZstd;
  }
  throw std::invalid_argument{"unsupported compression codec"};
}

[[nodiscard]] noleax::ipc::StartCaptureRequest standalone_capture_request(
    const noleax::config::Configuration& configuration, const std::filesystem::path& executable) {
  noleax::ipc::StartCaptureRequest request;
  request.capture_kind = noleax::ipc::CaptureKind::kLaunch;
  request.hook_profile = ipc_hook_profile(configuration.capture.hook_profile.value);
  request.maximum_stack_depth = configuration.capture.max_stack_depth.value;
  request.minimum_capture_size = configuration.capture.min_size.value;
  request.buffer_size = configuration.trace.buffer_size.value;
  request.maximum_trace_size = configuration.trace.max_file_size.value;
  request.flush_interval_ns =
      static_cast<std::uint64_t>(configuration.trace.flush_interval.value.count());
  request.compression = ipc_compression(configuration.trace.compression.value);
  request.compression_level = configuration.trace.compression_level.value;
  const std::filesystem::path trace_path = configuration.trace.path.value.value_or(
      executable.parent_path() / (executable.stem().wstring() + L".nlx"));
  request.trace_path_utf8 = noleax::config::path_to_utf8(trace_path);
  return request;
}

void install_exit_process_hook(noleax::agent::HookBackend& backend) noexcept;

DWORD WINAPI standalone_worker(void*) noexcept {
  try {
    const auto config_path = discover_standalone_config();
    if (!config_path.has_value()) {
      throw std::runtime_error{
          "no configuration found (NOLEAX_AGENT_CONFIG or "
          "noleax-agent.toml beside the executable)"};
    }
    const HookGuardRuntimeLease hook_guard_runtime;
    const noleax::agent::ReplacementGateCoordinatorScope finalize_coordinator;
    auto runtime = std::make_unique<CaptureRuntime>(random_session_token());
    runtime->start(
        standalone_capture_request(load_standalone_configuration(*config_path), executable_path()));
    standalone_runtime.store(runtime.get(), std::memory_order_release);
    install_exit_process_hook(runtime->backend());
    static_cast<void>(runtime.release());
    return 0U;
  } catch (const std::exception& error) {
    capture_ready.store(true, std::memory_order_release);  // unblock the bootstrap stub
    standalone_report(error.what());
    return 1U;
  } catch (...) {
    capture_ready.store(true, std::memory_order_release);
    standalone_report("unknown standalone capture failure");
    return 2U;
  }
}

void standalone_finalize() noexcept {
  auto* runtime =
      static_cast<CaptureRuntime*>(standalone_runtime.exchange(nullptr, std::memory_order_acq_rel));
  if (runtime == nullptr) {
    return;
  }
  runtime->finalize_detached();
}

// The standalone ExitProcess hook finalizes the capture while the writer worker is still
// alive; the detach path remains as the fallback for exits that bypass ExitProcess.
using ExitProcessFunction = void(NTAPI*)(long);

std::atomic<bool> exit_finalize_started{false};
std::atomic<ExitProcessFunction> original_exit_process{nullptr};
std::atomic<bool> exit_hook_install_attempted{false};

void standalone_finalize_graceful() noexcept {
  try {
    auto* runtime =
        static_cast<CaptureRuntime*>(standalone_runtime.load(std::memory_order_acquire));
    if (runtime != nullptr) {
      runtime->finalize_graceful();
    }
  } catch (...) {
  }
}

void NTAPI replacement_exit_process(long exit_code) {
  if (!exit_finalize_started.exchange(true, std::memory_order_acq_rel)) {
    standalone_finalize_graceful();
  }
  const ExitProcessFunction original = original_exit_process.load(std::memory_order_acquire);
  if (original != nullptr) {
    original(exit_code);
  }
  TerminateProcess(GetCurrentProcess(), static_cast<UINT>(exit_code));
}

void install_exit_process_hook(noleax::agent::HookBackend& backend) noexcept {
  if (exit_hook_install_attempted.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  try {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    void* const target = ntdll == nullptr
                             ? nullptr
                             : reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlExitUserProcess"));
    if (target == nullptr) {
      throw std::runtime_error{"RtlExitUserProcess is unavailable"};
    }
    const auto installed =
        backend.install_fast_forced(target, reinterpret_cast<void*>(&replacement_exit_process));
    if (!installed.installed()) {
      throw std::runtime_error{
          "hook install failed: " +
          std::string{noleax::agent::hook_install_status_name(installed.status)}};
    }
    original_exit_process.store(reinterpret_cast<ExitProcessFunction>(installed.original),
                                std::memory_order_release);
  } catch (const std::exception& error) {
    standalone_report(std::string{"exit hook unavailable, detach finalize only: "} + error.what());
  }
}

}  // namespace

extern "C" __declspec(dllexport) DWORD WINAPI noleax_agent_bootstrap(void* parameter) noexcept {
  BootstrapParameters copied{};
  SIZE_T bytes_read = 0U;
  if (parameter == nullptr ||
      ReadProcessMemory(GetCurrentProcess(), parameter, &copied, sizeof(copied), &bytes_read) ==
          FALSE ||
      bytes_read != sizeof(copied) || copied.structure_size != sizeof(copied) ||
      copied.version != noleax::agent::windows::kBootstrapVersion) {
    return static_cast<DWORD>(noleax::agent::windows::BootstrapResult::kInvalidParameters);
  }
  bool expected = false;
  if (!bootstrap_started.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
    return static_cast<DWORD>(noleax::agent::windows::BootstrapResult::kAlreadyStarted);
  }
  if (copied.session_token == noleax::agent::windows::kStandaloneMagic) {
    const HANDLE standalone_thread =
        CreateThread(nullptr, 0U, &standalone_worker, nullptr, 0U, nullptr);
    if (standalone_thread == nullptr) {
      bootstrap_started.store(false, std::memory_order_release);
      return static_cast<DWORD>(noleax::agent::windows::BootstrapResult::kThreadCreationFailed);
    }
    static_cast<void>(CloseHandle(standalone_thread));
    return static_cast<DWORD>(noleax::agent::windows::BootstrapResult::kSuccess);
  }
  if (copied.pipe_name.front() == L'\0' || copied.pipe_name.back() != L'\0' ||
      copied.connect_timeout_ms == 0U || copied.controller_process_id == 0U) {
    bootstrap_started.store(false, std::memory_order_release);
    return static_cast<DWORD>(noleax::agent::windows::BootstrapResult::kInvalidParameters);
  }
  auto* worker_parameters = new (std::nothrow) BootstrapParameters{copied};
  if (worker_parameters == nullptr) {
    bootstrap_started.store(false, std::memory_order_release);
    return static_cast<DWORD>(noleax::agent::windows::BootstrapResult::kAllocationFailed);
  }
  const HANDLE thread = CreateThread(nullptr, 0U, &agent_worker, worker_parameters, 0U, nullptr);
  if (thread == nullptr) {
    delete worker_parameters;
    bootstrap_started.store(false, std::memory_order_release);
    return static_cast<DWORD>(noleax::agent::windows::BootstrapResult::kThreadCreationFailed);
  }
  static_cast<void>(CloseHandle(thread));
  return static_cast<DWORD>(noleax::agent::windows::BootstrapResult::kSuccess);
}

extern "C" __declspec(dllexport) bool noleax_agent_capture_is_ready() noexcept {
  return capture_ready.load(std::memory_order_acquire);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, void*) noexcept {
  if (reason == DLL_PROCESS_DETACH) {
    standalone_finalize();
  }
  return TRUE;
}
