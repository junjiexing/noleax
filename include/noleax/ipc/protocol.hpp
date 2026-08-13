#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
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
// The agent binds every custom hook point to one replacement thunk from a fixed pool.
inline constexpr std::uint32_t kMaximumCustomHooks = 32U;

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
  kLinuxGlibcHeap = 4U,
  kLinuxVirtualMemory = 5U,
  kLinuxNative = 6U,
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
  // ABI 5 in-place extension (ABI 5 predates any release): the explicit lifecycle states
  // of the Linux H1-A state machine. kDraining/kUnpatching are transient (a concurrent
  // QueryStatus can observe them); kDormant is terminal — patches stay installed but
  // route to the originals, the capture is drained and the writer closed.
  kDraining = 6U,
  kDormant = 7U,
  kUnpatching = 8U,
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

enum class CustomHookLocator : std::uint8_t {
  kNone = 0U,
  kExport = 1U,
  kRva = 2U,
  kElfSymbol = 3U,
};

// One function role of a custom hook point: nothing, an export-table symbol the agent resolves
// inside the target, a pre-resolved RVA (PDB symbols are baked to RVAs by the controller), or
// an ELF symtab/dynsym symbol the agent resolves against the module's on-disk image (Linux
// only). kElfSymbol carries the symbol name in export_name, exactly like kExport.
struct CustomHookRoleSpec {
  CustomHookLocator locator{CustomHookLocator::kNone};
  std::string export_name;
  std::uint64_t rva{0U};

  bool operator==(const CustomHookRoleSpec&) const = default;
};

// PE image identity recorded when PDB symbols are baked to RVAs ahead of time; the agent
// verifies it against the loaded module before installing an RVA-located hook.
struct CustomHookImageIdentity {
  std::uint32_t timestamp{0U};
  std::uint32_t checksum{0U};
  std::uint32_t image_size{0U};

  bool operator==(const CustomHookImageIdentity&) const = default;
};

// One custom hook point: a module plus its alloc/realloc/free roles and the per-role argument
// mapping of the generic replacements. The point's api_id is kCustomHookApiIdBase + its index
// in StartCaptureRequest::custom_hooks.
struct CustomHookSpec {
  std::string module;
  CustomHookRoleSpec alloc;
  CustomHookRoleSpec realloc;
  CustomHookRoleSpec free;
  std::uint8_t alloc_size_arg{0U};
  std::optional<std::uint8_t> alloc_count_arg;
  std::uint8_t realloc_ptr_arg{0U};
  std::uint8_t realloc_size_arg{0U};
  std::uint8_t free_ptr_arg{0U};
  std::optional<std::uint8_t> result_arg;
  std::optional<std::uint8_t> free_size_arg;
  bool calloc{false};
  bool forced{false};
  std::uint64_t wait_module_ms{0U};
  std::string label;
  std::optional<CustomHookImageIdentity> image_identity;

  bool operator==(const CustomHookSpec&) const = default;
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
  // Periodic memory snapshot intervals; 0 disables that sampler.
  std::uint64_t memory_counters_interval_ns{1'000U * 1000U * 1000U};
  std::uint64_t memory_map_interval_ns{1'000U * 1000U * 1000U};
  std::int32_t compression_level{0};
  std::string trace_path_utf8;
  // Unload the agent module from the target after the capture finalizes (attach,
  // Windows only; the Linux agent rejects the request — no safe out-of-process unpatch).
  bool unload_on_stop{false};
  std::vector<CustomHookSpec> custom_hooks;
  // H4 (P0-1): reject the capture when the buffer_size → slot conversion adjusted the
  // request (capacity cap or power-of-two floor) instead of just warning about it.
  // In-place ABI 5 extension, appended after custom_hooks.
  bool strict_buffer{false};

  bool operator==(const StartCaptureRequest&) const = default;
};

// CaptureStatus::flags bits (in-place ABI 5 extension, appended after
// last_flush_monotonic_ns): non-fatal stop/finalize degradation the controller must see.
// kDrainIncomplete: the logical stop timed out with replacement calls still in flight;
// events those calls record afterwards never reach the trace. kUnpatchIncomplete: the
// physical teardown could not prove completion within its budget; the patches stay
// installed (dormant) and the agent reports kDormant instead of kFinalized.
// kBufferAdjusted (H4): the requested buffer_size did not survive the slot conversion
// unchanged; the buffer_* fields carry the exact math.
inline constexpr std::uint32_t kCaptureStatusFlagDrainIncomplete = 1U << 0U;
inline constexpr std::uint32_t kCaptureStatusFlagUnpatchIncomplete = 1U << 1U;
inline constexpr std::uint32_t kCaptureStatusFlagBufferAdjusted = 1U << 2U;

struct CaptureStatus {
  AgentState state{AgentState::kIdle};
  std::uint64_t observed_calls{0U};
  std::uint64_t written_events{0U};
  std::uint64_t filtered_calls{0U};
  std::uint64_t dropped_events{0U};
  std::uint64_t bytes_written{0U};
  // Live queue and writer telemetry (in-place ABI 5 extension; ABI 5 predates any
  // release, so the same version number covers both shapes). Zeros before the queue or
  // the writer exist.
  std::uint64_t queued_events{0U};
  std::uint64_t queue_capacity{0U};
  std::uint64_t queue_high_water_events{0U};
  std::uint64_t consumed_events{0U};
  // CLOCK_MONOTONIC nanoseconds of the agent writer's last successful stream flush;
  // 0 = never flushed.
  std::uint64_t last_flush_monotonic_ns{0U};
  // kCaptureStatusFlag* mask; 0 when the stop/finalize completed cleanly.
  std::uint32_t flags{0U};
  // H4 (P0-1) buffer conversion transparency + agent-owned memory (in-place ABI 5
  // extension, appended after flags; zeros when the agent predates H4 or has not sampled
  // yet). buffer_slot_bytes is the ring slot footprint (sequence + event);
  // buffer_reserved_bytes = buffer_effective_slots * buffer_slot_bytes;
  // buffer_resident_bytes is the slot ring's resident bytes at the last memory snapshot.
  // agent_reserved/agent_resident_bytes total every agent-owned category at the last
  // snapshot (0 before the first one).
  std::uint64_t buffer_requested_bytes{0U};
  std::uint64_t buffer_effective_slots{0U};
  std::uint64_t buffer_slot_bytes{0U};
  std::uint64_t buffer_reserved_bytes{0U};
  std::uint64_t buffer_resident_bytes{0U};
  std::uint64_t agent_reserved_bytes{0U};
  std::uint64_t agent_resident_bytes{0U};

  bool operator==(const CaptureStatus&) const = default;
};

struct ErrorResponse {
  std::uint32_t error_code{0U};
  std::uint32_t system_error{0U};
  std::string message;

  bool operator==(const ErrorResponse&) const = default;
};

// Stable agent-side codes for the ErrorResponse answering StartCapture: the agent sends
// them and the controller maps them onto its failure classification (docs/CLI.md §12).
inline constexpr std::uint32_t kAgentStartErrorGeneric = 1U;
inline constexpr std::uint32_t kAgentStartErrorHookInstall = 3U;
inline constexpr std::uint32_t kAgentStartErrorUnsupportedProfile = 5U;
inline constexpr std::uint32_t kAgentStartErrorTraceWriter = 6U;
inline constexpr std::uint32_t kAgentStartErrorUnsupportedOption = 7U;
// H4 (P0-1): the slot conversion adjusted the requested buffer_size and the request
// opted into strict_buffer, so the capture was refused instead of started degraded.
inline constexpr std::uint32_t kAgentStartErrorBufferAdjusted = 8U;
// H4 (P0-1): a dedicated agent allocation (the event queue mapping) failed.
inline constexpr std::uint32_t kAgentStartErrorAgentMemory = 9U;

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
