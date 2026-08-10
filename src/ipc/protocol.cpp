#include "noleax/ipc/protocol.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace noleax::ipc {
namespace {

class PayloadWriter final {
 public:
  template <typename Integer>
  void integer(Integer value) {
    static_assert(std::is_integral_v<Integer>);
    using Unsigned = std::make_unsigned_t<Integer>;
    Unsigned bits = std::bit_cast<Unsigned>(value);
    for (std::size_t index = 0U; index < sizeof(Integer); ++index) {
      bytes_.push_back(static_cast<std::byte>(bits & static_cast<Unsigned>(0xffU)));
      bits = static_cast<Unsigned>(static_cast<std::uintmax_t>(bits) >> 8U);
    }
  }

  void bytes(std::span<const std::byte> value) {
    bytes_.insert(bytes_.end(), value.begin(), value.end());
  }

  void string(std::string_view value) {
    if (value.size() > kMaximumStringSize) {
      throw ProtocolError{"protocol string exceeds the maximum length"};
    }
    if (value.find('\0') != std::string_view::npos) {
      throw ProtocolError{"protocol string contains an embedded NUL"};
    }
    integer(static_cast<std::uint32_t>(value.size()));
    bytes(std::as_bytes(std::span{value.data(), value.size()}));
  }

  [[nodiscard]] std::vector<std::byte> finish() && { return std::move(bytes_); }

 private:
  std::vector<std::byte> bytes_;
};

class PayloadReader final {
 public:
  explicit PayloadReader(std::span<const std::byte> bytes) : bytes_{bytes} {}

  template <typename Integer>
  [[nodiscard]] Integer integer() {
    static_assert(std::is_integral_v<Integer>);
    require(sizeof(Integer));
    using Unsigned = std::make_unsigned_t<Integer>;
    Unsigned value = 0U;
    for (std::size_t index = 0U; index < sizeof(Integer); ++index) {
      const auto byte =
          static_cast<Unsigned>(std::to_integer<unsigned int>(bytes_[offset_ + index]));
      value = static_cast<Unsigned>(value | static_cast<Unsigned>(byte << (index * 8U)));
    }
    offset_ += sizeof(Integer);
    return std::bit_cast<Integer>(value);
  }

  [[nodiscard]] std::span<const std::byte> bytes(std::size_t size) {
    require(size);
    const auto result = bytes_.subspan(offset_, size);
    offset_ += size;
    return result;
  }

  [[nodiscard]] std::string string() {
    const std::uint32_t size = integer<std::uint32_t>();
    if (size > kMaximumStringSize) {
      throw ProtocolError{"protocol string length exceeds the maximum"};
    }
    const auto value = bytes(size);
    const std::string result{reinterpret_cast<const char*>(value.data()), value.size()};
    if (result.find('\0') != std::string::npos) {
      throw ProtocolError{"protocol string contains an embedded NUL"};
    }
    return result;
  }

  void finish() const {
    if (offset_ != bytes_.size()) {
      throw ProtocolError{"protocol payload has trailing bytes"};
    }
  }

 private:
  void require(std::size_t size) const {
    if (size > bytes_.size() - offset_) {
      throw ProtocolError{"protocol payload is truncated"};
    }
  }

  std::span<const std::byte> bytes_;
  std::size_t offset_{0U};
};

template <typename Enum>
[[nodiscard]] Enum read_enum(PayloadReader& reader) {
  using Underlying = std::underlying_type_t<Enum>;
  return static_cast<Enum>(reader.integer<Underlying>());
}

template <typename Enum>
void write_enum(PayloadWriter& writer, Enum value) {
  writer.integer(static_cast<std::underlying_type_t<Enum>>(value));
}

[[nodiscard]] bool valid_capture_kind(CaptureKind value) noexcept {
  return value == CaptureKind::kLaunch || value == CaptureKind::kAttach;
}

[[nodiscard]] bool valid_hook_profile(HookProfile value) noexcept {
  return value == HookProfile::kWindowsNtHeap || value == HookProfile::kWindowsVirtualMemory ||
         value == HookProfile::kWindowsNative || value == HookProfile::kLinuxGlibcHeap;
}

[[nodiscard]] bool valid_compression(CompressionCodec value) noexcept {
  return value == CompressionCodec::kNone || value == CompressionCodec::kLz4 ||
         value == CompressionCodec::kZstd;
}

[[nodiscard]] bool valid_agent_state(AgentState value) noexcept {
  return value >= AgentState::kIdle && value <= AgentState::kFailed;
}

[[nodiscard]] bool valid_architecture(Architecture value) noexcept {
  return value >= Architecture::kUnknown && value <= Architecture::kArm64;
}

[[nodiscard]] bool valid_custom_hook_locator(CustomHookLocator value) noexcept {
  return value == CustomHookLocator::kNone || value == CustomHookLocator::kExport ||
         value == CustomHookLocator::kRva;
}

[[nodiscard]] bool valid_argument_slot(std::uint8_t value) noexcept { return value <= 7U; }

void validate_custom_hook_role(const CustomHookRoleSpec& role, bool required) {
  if (!valid_custom_hook_locator(role.locator)) {
    throw ProtocolError{"custom hook role locator is not supported"};
  }
  switch (role.locator) {
    case CustomHookLocator::kNone:
      if (required || !role.export_name.empty() || role.rva != 0U) {
        throw ProtocolError{"custom hook role is missing or inconsistent"};
      }
      return;
    case CustomHookLocator::kExport:
      if (role.export_name.empty() || role.rva != 0U) {
        throw ProtocolError{"custom hook export role is inconsistent"};
      }
      return;
    case CustomHookLocator::kRva:
      if (role.rva == 0U || !role.export_name.empty()) {
        throw ProtocolError{"custom hook RVA role is inconsistent"};
      }
      return;
  }
  throw ProtocolError{"custom hook role locator is not supported"};
}

void validate_custom_hooks(const std::vector<CustomHookSpec>& hooks) {
  if (hooks.size() > kMaximumCustomHooks) {
    throw ProtocolError{"start capture request declares too many custom hooks"};
  }
  for (const CustomHookSpec& hook : hooks) {
    validate_custom_hook_role(hook.alloc, true);
    validate_custom_hook_role(hook.realloc, false);
    validate_custom_hook_role(hook.free, true);
    if (hook.module.empty() || hook.label.empty()) {
      throw ProtocolError{"custom hook module and label must not be empty"};
    }
    if (!valid_argument_slot(hook.size_arg) || !valid_argument_slot(hook.ptr_arg) ||
        (hook.result_arg.has_value() && !valid_argument_slot(*hook.result_arg)) ||
        (hook.count_arg.has_value() && !valid_argument_slot(*hook.count_arg)) ||
        (hook.free_size_arg.has_value() && !valid_argument_slot(*hook.free_size_arg))) {
      throw ProtocolError{"custom hook argument slot is out of range"};
    }
    if (hook.calloc != hook.count_arg.has_value()) {
      throw ProtocolError{"custom hook calloc mapping requires count_arg and vice versa"};
    }
  }
}

void write_custom_hook_role(PayloadWriter& writer, const CustomHookRoleSpec& role) {
  write_enum(writer, role.locator);
  writer.integer(std::uint8_t{0U});
  writer.integer(std::uint16_t{0U});
  writer.integer(std::uint32_t{0U});
  writer.integer(role.rva);
  writer.string(role.export_name);
}

[[nodiscard]] CustomHookRoleSpec read_custom_hook_role(PayloadReader& reader) {
  CustomHookRoleSpec role;
  role.locator = read_enum<CustomHookLocator>(reader);
  const std::uint8_t reserved8 = reader.integer<std::uint8_t>();
  const std::uint16_t reserved16 = reader.integer<std::uint16_t>();
  const std::uint32_t reserved32 = reader.integer<std::uint32_t>();
  role.rva = reader.integer<std::uint64_t>();
  role.export_name = reader.string();
  if (reserved8 != 0U || reserved16 != 0U || reserved32 != 0U) {
    throw ProtocolError{"custom hook role reserved fields must be zero"};
  }
  return role;
}

void write_custom_hooks(PayloadWriter& writer, const std::vector<CustomHookSpec>& hooks) {
  writer.integer(static_cast<std::uint32_t>(hooks.size()));
  for (const CustomHookSpec& hook : hooks) {
    writer.integer(hook.size_arg);
    writer.integer(hook.ptr_arg);
    writer.integer(static_cast<std::uint8_t>(hook.result_arg.value_or(0xFFU)));
    writer.integer(static_cast<std::uint8_t>(hook.count_arg.value_or(0xFFU)));
    writer.integer(static_cast<std::uint8_t>(hook.free_size_arg.value_or(0xFFU)));
    writer.integer(static_cast<std::uint8_t>(hook.calloc ? 1U : 0U));
    writer.integer(static_cast<std::uint8_t>(hook.forced ? 1U : 0U));
    writer.integer(std::uint8_t{0U});
    writer.integer(hook.wait_module_ms);
    write_custom_hook_role(writer, hook.alloc);
    write_custom_hook_role(writer, hook.realloc);
    write_custom_hook_role(writer, hook.free);
    writer.string(hook.module);
    writer.string(hook.label);
    writer.integer(static_cast<std::uint8_t>(hook.image_identity.has_value() ? 1U : 0U));
    writer.integer(std::uint8_t{0U});
    writer.integer(std::uint16_t{0U});
    writer.integer(hook.image_identity.has_value() ? hook.image_identity->timestamp : 0U);
    writer.integer(hook.image_identity.has_value() ? hook.image_identity->checksum : 0U);
    writer.integer(hook.image_identity.has_value() ? hook.image_identity->image_size : 0U);
  }
}

[[nodiscard]] std::uint8_t read_argument_slot(PayloadReader& reader) {
  const std::uint8_t value = reader.integer<std::uint8_t>();
  if (value != 0xFFU && !valid_argument_slot(value)) {
    throw ProtocolError{"custom hook argument slot is out of range"};
  }
  return value;
}

void read_custom_hooks(PayloadReader& reader, StartCaptureRequest& request) {
  const std::uint32_t count = reader.integer<std::uint32_t>();
  if (count > kMaximumCustomHooks) {
    throw ProtocolError{"start capture request declares too many custom hooks"};
  }
  request.custom_hooks.reserve(count);
  for (std::uint32_t index = 0U; index < count; ++index) {
    CustomHookSpec hook;
    hook.size_arg = read_argument_slot(reader);
    hook.ptr_arg = read_argument_slot(reader);
    const std::uint8_t result_arg = read_argument_slot(reader);
    const std::uint8_t count_arg = read_argument_slot(reader);
    const std::uint8_t free_size_arg = read_argument_slot(reader);
    if (result_arg != 0xFFU) {
      hook.result_arg = result_arg;
    }
    if (count_arg != 0xFFU) {
      hook.count_arg = count_arg;
    }
    if (free_size_arg != 0xFFU) {
      hook.free_size_arg = free_size_arg;
    }
    hook.calloc = reader.integer<std::uint8_t>() != 0U;
    hook.forced = reader.integer<std::uint8_t>() != 0U;
    const std::uint8_t reserved = reader.integer<std::uint8_t>();
    hook.wait_module_ms = reader.integer<std::uint64_t>();
    hook.alloc = read_custom_hook_role(reader);
    hook.realloc = read_custom_hook_role(reader);
    hook.free = read_custom_hook_role(reader);
    hook.module = reader.string();
    hook.label = reader.string();
    const std::uint8_t identity_present = reader.integer<std::uint8_t>();
    const std::uint8_t identity_reserved8 = reader.integer<std::uint8_t>();
    const std::uint16_t identity_reserved16 = reader.integer<std::uint16_t>();
    const std::uint32_t identity_timestamp = reader.integer<std::uint32_t>();
    const std::uint32_t identity_checksum = reader.integer<std::uint32_t>();
    const std::uint32_t identity_image_size = reader.integer<std::uint32_t>();
    if (reserved != 0U || identity_reserved8 != 0U || identity_reserved16 != 0U ||
        identity_present > 1U) {
      throw ProtocolError{"custom hook reserved fields must be zero"};
    }
    if (identity_present != 0U) {
      hook.image_identity =
          CustomHookImageIdentity{identity_timestamp, identity_checksum, identity_image_size};
    } else if (identity_timestamp != 0U || identity_checksum != 0U || identity_image_size != 0U) {
      throw ProtocolError{"absent custom hook image identity must be zero"};
    }
    request.custom_hooks.push_back(std::move(hook));
  }
}

void append_frame_header(PayloadWriter& writer, const Message& message) {
  writer.bytes(kProtocolMagic);
  writer.integer(kProtocolMajor);
  writer.integer(kProtocolMinor);
  writer.integer(kFrameHeaderSize);
  write_enum(writer, message.type);
  writer.integer(std::uint32_t{0U});
  writer.integer(message.request_id);
  writer.integer(static_cast<std::uint32_t>(message.payload.size()));
  writer.integer(std::uint32_t{0U});
}

}  // namespace

bool is_known_message_type(MessageType type) noexcept {
  return type >= MessageType::kAgentHello && type <= MessageType::kError;
}

std::vector<std::byte> encode_frame(const Message& message) {
  if (!is_known_message_type(message.type)) {
    throw ProtocolError{"cannot encode an unknown message type"};
  }
  if (message.request_id == 0U) {
    throw ProtocolError{"protocol request id must be nonzero"};
  }
  if (message.payload.size() > kMaximumPayloadSize) {
    throw ProtocolError{"protocol payload exceeds the maximum length"};
  }
  PayloadWriter writer;
  append_frame_header(writer, message);
  writer.bytes(message.payload);
  return std::move(writer).finish();
}

FrameHeader decode_frame_header(std::span<const std::byte> bytes) {
  if (bytes.size() != kFrameHeaderSize) {
    throw ProtocolError{"protocol frame header has an invalid length"};
  }
  PayloadReader reader{bytes};
  if (!std::ranges::equal(reader.bytes(kProtocolMagic.size()), kProtocolMagic)) {
    throw ProtocolError{"protocol frame magic is invalid"};
  }
  FrameHeader header;
  header.protocol_major = reader.integer<std::uint16_t>();
  header.protocol_minor = reader.integer<std::uint16_t>();
  const std::uint16_t header_size = reader.integer<std::uint16_t>();
  header.message_type = read_enum<MessageType>(reader);
  header.flags = reader.integer<std::uint32_t>();
  header.request_id = reader.integer<std::uint64_t>();
  header.payload_size = reader.integer<std::uint32_t>();
  const std::uint32_t reserved = reader.integer<std::uint32_t>();
  reader.finish();

  if (header.protocol_major != kProtocolMajor || header.protocol_minor > kProtocolMinor) {
    throw ProtocolError{"protocol version is not supported"};
  }
  if (header_size != kFrameHeaderSize) {
    throw ProtocolError{"protocol header size is not supported"};
  }
  if (!is_known_message_type(header.message_type)) {
    throw ProtocolError{"protocol message type is unknown"};
  }
  if (header.flags != 0U || reserved != 0U) {
    throw ProtocolError{"protocol frame contains unsupported flags or reserved bits"};
  }
  if (header.request_id == 0U) {
    throw ProtocolError{"protocol request id must be nonzero"};
  }
  if (header.payload_size > kMaximumPayloadSize) {
    throw ProtocolError{"protocol payload length exceeds the maximum"};
  }
  return header;
}

Message decode_frame(std::span<const std::byte> bytes) {
  if (bytes.size() < kFrameHeaderSize) {
    throw ProtocolError{"protocol frame is truncated"};
  }
  const FrameHeader header = decode_frame_header(bytes.first(kFrameHeaderSize));
  const std::size_t expected_size = kFrameHeaderSize + header.payload_size;
  if (bytes.size() != expected_size) {
    throw ProtocolError{"protocol frame length does not match its header"};
  }
  Message message;
  message.type = header.message_type;
  message.request_id = header.request_id;
  const auto payload = bytes.subspan(kFrameHeaderSize);
  message.payload.assign(payload.begin(), payload.end());
  return message;
}

std::vector<std::byte> encode_agent_hello(const AgentHello& hello) {
  if (hello.agent_abi_version == 0U || hello.process_id == 0U || hello.worker_thread_id == 0U ||
      (hello.pointer_width != 4U && hello.pointer_width != 8U) ||
      !valid_architecture(hello.architecture)) {
    throw ProtocolError{"agent hello contains invalid fields"};
  }
  PayloadWriter writer;
  writer.integer(hello.agent_abi_version);
  writer.integer(hello.process_id);
  writer.integer(hello.worker_thread_id);
  writer.integer(hello.pointer_width);
  writer.integer(std::uint8_t{0U});
  write_enum(writer, hello.architecture);
  writer.bytes(hello.session_token);
  return std::move(writer).finish();
}

AgentHello decode_agent_hello(std::span<const std::byte> payload) {
  PayloadReader reader{payload};
  AgentHello hello;
  hello.agent_abi_version = reader.integer<std::uint32_t>();
  hello.process_id = reader.integer<std::uint32_t>();
  hello.worker_thread_id = reader.integer<std::uint32_t>();
  hello.pointer_width = reader.integer<std::uint8_t>();
  const std::uint8_t reserved = reader.integer<std::uint8_t>();
  hello.architecture = read_enum<Architecture>(reader);
  const auto token = reader.bytes(hello.session_token.size());
  std::ranges::copy(token, hello.session_token.begin());
  reader.finish();
  if (reserved != 0U || hello.agent_abi_version == 0U || hello.process_id == 0U ||
      hello.worker_thread_id == 0U || (hello.pointer_width != 4U && hello.pointer_width != 8U) ||
      !valid_architecture(hello.architecture)) {
    throw ProtocolError{"agent hello contains invalid fields"};
  }
  return hello;
}

std::vector<std::byte> encode_start_capture(const StartCaptureRequest& request) {
  if (!valid_capture_kind(request.capture_kind) || !valid_hook_profile(request.hook_profile) ||
      !valid_compression(request.compression) || request.maximum_stack_depth == 0U ||
      request.buffer_size == 0U || request.maximum_trace_size == 0U ||
      request.flush_interval_ns == 0U || request.trace_path_utf8.empty()) {
    throw ProtocolError{"start capture request contains invalid fields"};
  }
  validate_custom_hooks(request.custom_hooks);
  PayloadWriter writer;
  write_enum(writer, request.capture_kind);
  write_enum(writer, request.hook_profile);
  write_enum(writer, request.compression);
  writer.integer(std::uint8_t{0U});
  writer.integer(request.maximum_stack_depth);
  writer.integer(std::uint16_t{0U});
  writer.integer(request.minimum_capture_size);
  writer.integer(request.buffer_size);
  writer.integer(request.maximum_trace_size);
  writer.integer(request.flush_interval_ns);
  writer.integer(request.memory_counters_interval_ns);
  writer.integer(request.memory_map_interval_ns);
  writer.integer(request.compression_level);
  writer.integer(std::uint32_t{0U});
  writer.string(request.trace_path_utf8);
  writer.integer(static_cast<std::uint8_t>(request.unload_on_stop ? 1U : 0U));
  write_custom_hooks(writer, request.custom_hooks);
  return std::move(writer).finish();
}

StartCaptureRequest decode_start_capture(std::span<const std::byte> payload) {
  PayloadReader reader{payload};
  StartCaptureRequest request;
  request.capture_kind = read_enum<CaptureKind>(reader);
  request.hook_profile = read_enum<HookProfile>(reader);
  request.compression = read_enum<CompressionCodec>(reader);
  const std::uint8_t reserved8 = reader.integer<std::uint8_t>();
  request.maximum_stack_depth = reader.integer<std::uint16_t>();
  const std::uint16_t reserved16 = reader.integer<std::uint16_t>();
  request.minimum_capture_size = reader.integer<std::uint64_t>();
  request.buffer_size = reader.integer<std::uint64_t>();
  request.maximum_trace_size = reader.integer<std::uint64_t>();
  request.flush_interval_ns = reader.integer<std::uint64_t>();
  request.memory_counters_interval_ns = reader.integer<std::uint64_t>();
  request.memory_map_interval_ns = reader.integer<std::uint64_t>();
  request.compression_level = reader.integer<std::int32_t>();
  const std::uint32_t reserved32 = reader.integer<std::uint32_t>();
  request.trace_path_utf8 = reader.string();
  request.unload_on_stop = reader.integer<std::uint8_t>() != 0U;
  read_custom_hooks(reader, request);
  reader.finish();
  if (reserved8 != 0U || reserved16 != 0U || reserved32 != 0U ||
      !valid_capture_kind(request.capture_kind) || !valid_hook_profile(request.hook_profile) ||
      !valid_compression(request.compression) || request.maximum_stack_depth == 0U ||
      request.buffer_size == 0U || request.maximum_trace_size == 0U ||
      request.flush_interval_ns == 0U || request.trace_path_utf8.empty()) {
    throw ProtocolError{"start capture request contains invalid fields"};
  }
  validate_custom_hooks(request.custom_hooks);
  return request;
}

std::vector<std::byte> encode_capture_status(const CaptureStatus& status) {
  if (!valid_agent_state(status.state)) {
    throw ProtocolError{"capture status contains an invalid state"};
  }
  PayloadWriter writer;
  write_enum(writer, status.state);
  writer.integer(std::uint8_t{0U});
  writer.integer(std::uint16_t{0U});
  writer.integer(std::uint32_t{0U});
  writer.integer(status.observed_calls);
  writer.integer(status.written_events);
  writer.integer(status.filtered_calls);
  writer.integer(status.dropped_events);
  writer.integer(status.bytes_written);
  return std::move(writer).finish();
}

CaptureStatus decode_capture_status(std::span<const std::byte> payload) {
  PayloadReader reader{payload};
  CaptureStatus status;
  status.state = read_enum<AgentState>(reader);
  const std::uint8_t reserved8 = reader.integer<std::uint8_t>();
  const std::uint16_t reserved16 = reader.integer<std::uint16_t>();
  const std::uint32_t reserved32 = reader.integer<std::uint32_t>();
  status.observed_calls = reader.integer<std::uint64_t>();
  status.written_events = reader.integer<std::uint64_t>();
  status.filtered_calls = reader.integer<std::uint64_t>();
  status.dropped_events = reader.integer<std::uint64_t>();
  status.bytes_written = reader.integer<std::uint64_t>();
  reader.finish();
  if (!valid_agent_state(status.state) || reserved8 != 0U || reserved16 != 0U || reserved32 != 0U) {
    throw ProtocolError{"capture status contains invalid fields"};
  }
  return status;
}

std::vector<std::byte> encode_error_response(const ErrorResponse& error) {
  if (error.error_code == 0U || error.message.empty()) {
    throw ProtocolError{"error response contains invalid fields"};
  }
  PayloadWriter writer;
  writer.integer(error.error_code);
  writer.integer(error.system_error);
  writer.string(error.message);
  return std::move(writer).finish();
}

ErrorResponse decode_error_response(std::span<const std::byte> payload) {
  PayloadReader reader{payload};
  ErrorResponse error;
  error.error_code = reader.integer<std::uint32_t>();
  error.system_error = reader.integer<std::uint32_t>();
  error.message = reader.string();
  reader.finish();
  if (error.error_code == 0U || error.message.empty()) {
    throw ProtocolError{"error response contains invalid fields"};
  }
  return error;
}

}  // namespace noleax::ipc
