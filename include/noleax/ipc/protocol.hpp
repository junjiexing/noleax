#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace noleax::ipc {

inline constexpr std::array<std::byte, 4U> kProtocolMagic{std::byte{'N'}, std::byte{'L'},
                                                          std::byte{'X'}, std::byte{'P'}};
inline constexpr std::uint16_t kProtocolMajor = 1U;
inline constexpr std::uint16_t kProtocolMinor = 0U;
inline constexpr std::uint16_t kFrameHeaderSize = 32U;
inline constexpr std::uint32_t kMaximumPayloadSize = 64U * 1024U;
inline constexpr std::uint32_t kMaximumStringSize = 32U * 1024U;

enum class MessageType : std::uint16_t {  // NOLINT(performance-enum-size)
  kAgentHello = 1U,
  kStartCapture = 2U,
  kCaptureReady = 3U,
  kQueryStatus = 4U,
  kCaptureStatus = 5U,
  kStopCapture = 6U,
  kCaptureDrained = 7U,
  kFinalizeHooks = 8U,
  kCaptureFinalized = 9U,
  kError = 10U,
};

enum class CaptureKind : std::uint8_t {
  kLaunch = 1U,
  kAttach = 2U,
};

enum class HookProfile : std::uint8_t {
  kWindowsNtHeap = 1U,
  kWindowsVirtualMemory = 2U,
  kWindowsNative = 3U,
};

enum class CompressionCodec : std::uint8_t {
  kNone = 0U,
  kLz4 = 1U,
  kZstd = 2U,
};

enum class AgentState : std::uint8_t {
  kIdle = 0U,
  kStarting = 1U,
  kCapturing = 2U,
  kDrained = 3U,
  kFinalized = 4U,
  kFailed = 5U,
};

enum class Architecture : std::uint16_t {  // NOLINT(performance-enum-size)
  kUnknown = 0U,
  kX86 = 1U,
  kX64 = 2U,
  kArm64 = 3U,
};

struct FrameHeader {
  std::uint16_t protocol_major{kProtocolMajor};
  std::uint16_t protocol_minor{kProtocolMinor};
  MessageType message_type{MessageType::kError};
  std::uint32_t flags{0U};
  std::uint64_t request_id{0U};
  std::uint32_t payload_size{0U};

  bool operator==(const FrameHeader&) const = default;
};

struct Message {
  MessageType type{MessageType::kError};
  std::uint64_t request_id{0U};
  std::vector<std::byte> payload;

  bool operator==(const Message&) const = default;
};

struct AgentHello {
  std::uint32_t agent_abi_version{0U};
  std::uint32_t process_id{0U};
  std::uint32_t worker_thread_id{0U};
  std::uint8_t pointer_width{0U};
  Architecture architecture{Architecture::kUnknown};
  std::array<std::byte, 16U> session_token{};

  bool operator==(const AgentHello&) const = default;
};

struct StartCaptureRequest {
  CaptureKind capture_kind{CaptureKind::kAttach};
  HookProfile hook_profile{HookProfile::kWindowsNative};
  CompressionCodec compression{CompressionCodec::kLz4};
  std::uint16_t maximum_stack_depth{64U};
  std::uint64_t minimum_capture_size{0U};
  std::uint64_t buffer_size{16U * 1024U * 1024U};
  std::uint64_t maximum_trace_size{256U * 1024U * 1024U};
  std::uint64_t flush_interval_ns{250U * 1000U * 1000U};
  std::int32_t compression_level{0};
  std::string trace_path_utf8;
  // Unload the agent module from the target after the capture finalizes (attach).
  bool unload_on_stop{false};

  bool operator==(const StartCaptureRequest&) const = default;
};

struct CaptureStatus {
  AgentState state{AgentState::kIdle};
  std::uint64_t observed_calls{0U};
  std::uint64_t written_events{0U};
  std::uint64_t filtered_calls{0U};
  std::uint64_t dropped_events{0U};
  std::uint64_t bytes_written{0U};

  bool operator==(const CaptureStatus&) const = default;
};

struct ErrorResponse {
  std::uint32_t error_code{0U};
  std::uint32_t system_error{0U};
  std::string message;

  bool operator==(const ErrorResponse&) const = default;
};

class ProtocolError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

[[nodiscard]] bool is_known_message_type(MessageType type) noexcept;
[[nodiscard]] std::vector<std::byte> encode_frame(const Message& message);
[[nodiscard]] FrameHeader decode_frame_header(std::span<const std::byte> bytes);
[[nodiscard]] Message decode_frame(std::span<const std::byte> bytes);

[[nodiscard]] std::vector<std::byte> encode_agent_hello(const AgentHello& hello);
[[nodiscard]] AgentHello decode_agent_hello(std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_start_capture(const StartCaptureRequest& request);
[[nodiscard]] StartCaptureRequest decode_start_capture(std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_capture_status(const CaptureStatus& status);
[[nodiscard]] CaptureStatus decode_capture_status(std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_error_response(const ErrorResponse& error);
[[nodiscard]] ErrorResponse decode_error_response(std::span<const std::byte> payload);

}  // namespace noleax::ipc
