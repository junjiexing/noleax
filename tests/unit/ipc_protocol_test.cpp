#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "noleax/ipc/protocol.hpp"

namespace {

void set_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::byte>(value & 0xffU);
  bytes[offset + 1U] = static_cast<std::byte>((value >> 8U) & 0xffU);
}

void set_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0U; index < 4U; ++index) {
    bytes[offset + index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
  }
}

}  // namespace

TEST_CASE("IPC frame round-trips bounded versioned messages", "[ipc][protocol]") {
  noleax::ipc::Message expected;
  expected.type = noleax::ipc::MessageType::kStartCapture;
  expected.request_id = 42U;
  expected.payload = {std::byte{0x01}, std::byte{0x7f}, std::byte{0xff}};
  const auto encoded = noleax::ipc::encode_frame(expected);
  CHECK(encoded.size() == noleax::ipc::kFrameHeaderSize + expected.payload.size());
  CHECK(noleax::ipc::decode_frame(encoded) == expected);

  const auto header = noleax::ipc::decode_frame_header(
      std::span<const std::byte>{encoded}.first(noleax::ipc::kFrameHeaderSize));
  CHECK(header.protocol_major == noleax::ipc::kProtocolMajor);
  CHECK(header.protocol_minor == noleax::ipc::kProtocolMinor);
  CHECK(header.message_type == expected.type);
  CHECK(header.request_id == expected.request_id);
  CHECK(header.payload_size == expected.payload.size());
}

TEST_CASE("IPC rejects incompatible versions and malicious lengths", "[ipc][protocol][security]") {
  noleax::ipc::Message message{noleax::ipc::MessageType::kQueryStatus, 1U, {}};
  const auto valid = noleax::ipc::encode_frame(message);

  SECTION("major version") {
    auto frame = valid;
    set_u16(frame, 4U, noleax::ipc::kProtocolMajor + 1U);
    CHECK_THROWS_AS(noleax::ipc::decode_frame(frame), noleax::ipc::ProtocolError);
  }
  SECTION("newer minor version") {
    auto frame = valid;
    set_u16(frame, 6U, noleax::ipc::kProtocolMinor + 1U);
    CHECK_THROWS_AS(noleax::ipc::decode_frame(frame), noleax::ipc::ProtocolError);
  }
  SECTION("oversized advertised payload") {
    auto frame = valid;
    set_u32(frame, 24U, noleax::ipc::kMaximumPayloadSize + 1U);
    CHECK_THROWS_AS(noleax::ipc::decode_frame_header(frame), noleax::ipc::ProtocolError);
  }
  SECTION("truncated payload") {
    auto frame = valid;
    set_u32(frame, 24U, 1U);
    CHECK_THROWS_AS(noleax::ipc::decode_frame(frame), noleax::ipc::ProtocolError);
  }
  SECTION("reserved bits") {
    auto frame = valid;
    set_u32(frame, 12U, 1U);
    CHECK_THROWS_AS(noleax::ipc::decode_frame(frame), noleax::ipc::ProtocolError);
  }
}

TEST_CASE("IPC payload codecs preserve capture contracts", "[ipc][protocol]") {
  noleax::ipc::AgentHello hello;
  hello.agent_abi_version = 1U;
  hello.process_id = 100U;
  hello.worker_thread_id = 101U;
  hello.pointer_width = 8U;
  hello.architecture = noleax::ipc::Architecture::kX64;
  hello.session_token[0] = std::byte{0xa5};
  CHECK(noleax::ipc::decode_agent_hello(noleax::ipc::encode_agent_hello(hello)) == hello);

  noleax::ipc::StartCaptureRequest start;
  start.capture_kind = noleax::ipc::CaptureKind::kLaunch;
  start.hook_profile = noleax::ipc::HookProfile::kWindowsNtHeap;
  start.compression = noleax::ipc::CompressionCodec::kZstd;
  start.maximum_stack_depth = 96U;
  start.minimum_capture_size = 4096U;
  start.buffer_size = 8U * 1024U * 1024U;
  start.maximum_trace_size = 64U * 1024U * 1024U;
  start.flush_interval_ns = 10U * 1000U * 1000U;
  start.memory_counters_interval_ns = 500U * 1000U * 1000U;
  start.memory_map_interval_ns = 0U;
  start.compression_level = 1;
  start.trace_path_utf8 = "C:/traces/app.nlx";
  start.unload_on_stop = true;
  CHECK(noleax::ipc::decode_start_capture(noleax::ipc::encode_start_capture(start)) == start);

  const noleax::ipc::CaptureStatus status{
      noleax::ipc::AgentState::kCapturing, 10U, 9U, 1U, 0U, 4096U};
  CHECK(noleax::ipc::decode_capture_status(noleax::ipc::encode_capture_status(status)) == status);

  const noleax::ipc::ErrorResponse error{7U, 5U, "access denied"};
  CHECK(noleax::ipc::decode_error_response(noleax::ipc::encode_error_response(error)) == error);
}

TEST_CASE("IPC start capture round trips custom hook declarations",
          "[ipc][protocol][custom-hook]") {
  noleax::ipc::StartCaptureRequest start;
  start.trace_path_utf8 = "trace.nlx";

  noleax::ipc::CustomHookSpec hook;
  hook.module = "myalloc.dll";
  hook.alloc.locator = noleax::ipc::CustomHookLocator::kExport;
  hook.alloc.export_name = "my_malloc";
  hook.realloc.locator = noleax::ipc::CustomHookLocator::kRva;
  hook.realloc.rva = 0x12340U;
  hook.free.locator = noleax::ipc::CustomHookLocator::kExport;
  hook.free.export_name = "my_free";
  hook.size_arg = 1U;
  hook.ptr_arg = 2U;
  hook.result_arg = std::uint8_t{0U};
  hook.calloc = true;
  hook.count_arg = std::uint8_t{3U};
  hook.free_size_arg = std::uint8_t{4U};
  hook.forced = true;
  hook.wait_module_ms = 10'000U;
  hook.label = "my_malloc";
  hook.image_identity = noleax::ipc::CustomHookImageIdentity{0x65a1b2c3U, 0x1a2bU, 198656U};

  noleax::ipc::CustomHookSpec minimal;
  minimal.module = "other.dll";
  minimal.alloc.locator = noleax::ipc::CustomHookLocator::kRva;
  minimal.alloc.rva = 0x2000U;
  minimal.free.locator = noleax::ipc::CustomHookLocator::kRva;
  minimal.free.rva = 0x2100U;
  minimal.label = "other.dll+0x2000";

  start.custom_hooks = {hook, minimal};
  CHECK(noleax::ipc::decode_start_capture(noleax::ipc::encode_start_capture(start)) == start);
}

TEST_CASE("IPC custom hook codec rejects malformed declarations", "[ipc][protocol][custom-hook]") {
  noleax::ipc::StartCaptureRequest start;
  start.trace_path_utf8 = "trace.nlx";

  noleax::ipc::CustomHookSpec valid;
  valid.module = "myalloc.dll";
  valid.alloc.locator = noleax::ipc::CustomHookLocator::kExport;
  valid.alloc.export_name = "my_malloc";
  valid.free.locator = noleax::ipc::CustomHookLocator::kExport;
  valid.free.export_name = "my_free";
  valid.label = "my_malloc";

  // The free role is required.
  start.custom_hooks = {valid};
  start.custom_hooks.at(0U).free.locator = noleax::ipc::CustomHookLocator::kNone;
  CHECK_THROWS_AS(noleax::ipc::encode_start_capture(start), noleax::ipc::ProtocolError);

  // An export role must not carry an RVA.
  start.custom_hooks = {valid};
  start.custom_hooks.at(0U).alloc.rva = 0x1000U;
  CHECK_THROWS_AS(noleax::ipc::encode_start_capture(start), noleax::ipc::ProtocolError);

  // Argument slots are bounded.
  start.custom_hooks = {valid};
  start.custom_hooks.at(0U).size_arg = 8U;
  CHECK_THROWS_AS(noleax::ipc::encode_start_capture(start), noleax::ipc::ProtocolError);

  // calloc requires count_arg and vice versa.
  start.custom_hooks = {valid};
  start.custom_hooks.at(0U).calloc = true;
  CHECK_THROWS_AS(noleax::ipc::encode_start_capture(start), noleax::ipc::ProtocolError);

  // The point count is bounded.
  start.custom_hooks.assign(noleax::ipc::kMaximumCustomHooks + 1U, valid);
  CHECK_THROWS_AS(noleax::ipc::encode_start_capture(start), noleax::ipc::ProtocolError);

  // Trailing bytes after a valid payload are rejected.
  start.custom_hooks = {valid};
  auto payload = noleax::ipc::encode_start_capture(start);
  payload.push_back(std::byte{0U});
  CHECK_THROWS_AS(noleax::ipc::decode_start_capture(payload), noleax::ipc::ProtocolError);
}

TEST_CASE("IPC payload codecs reject malformed fields and trailing bytes",
          "[ipc][protocol][security]") {
  noleax::ipc::StartCaptureRequest start;
  start.trace_path_utf8 = "trace.nlx";
  auto payload = noleax::ipc::encode_start_capture(start);
  payload.push_back(std::byte{0U});
  CHECK_THROWS_AS(noleax::ipc::decode_start_capture(payload), noleax::ipc::ProtocolError);

  start.trace_path_utf8.clear();
  CHECK_THROWS_AS(noleax::ipc::encode_start_capture(start), noleax::ipc::ProtocolError);
}
