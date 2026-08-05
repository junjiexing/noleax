#include "noleax/trace/wire_format.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace noleax::trace {
namespace {

[[nodiscard]] bool is_supported_platform(Platform platform) noexcept {
  switch (platform) {
    case Platform::kWindows:
    case Platform::kLinux:
    case Platform::kMacos:
      return true;
    case Platform::kUnknown:
      return false;
  }
  return false;
}

[[nodiscard]] bool is_supported_architecture(Architecture architecture) noexcept {
  switch (architecture) {
    case Architecture::kX86:
    case Architecture::kX64:
    case Architecture::kArm64:
      return true;
    case Architecture::kUnknown:
      return false;
  }
  return false;
}

[[nodiscard]] bool is_supported_chunk_type(ChunkType type) noexcept {
  switch (type) {
    case ChunkType::kMetadata:
    case ChunkType::kModule:
    case ChunkType::kStack:
    case ChunkType::kEvent:
    case ChunkType::kStatistics:
    case ChunkType::kEnd:
    case ChunkType::kMemory:
      return true;
  }
  return false;
}

[[nodiscard]] bool is_supported_codec(CompressionCodec codec) noexcept {
  switch (codec) {
    case CompressionCodec::kNone:
    case CompressionCodec::kLz4:
    case CompressionCodec::kZstd:
      return true;
  }
  return false;
}

void append_u8(std::vector<std::byte>& output, std::uint8_t value) {
  output.push_back(static_cast<std::byte>(value));
}

void append_u16(std::vector<std::byte>& output, std::uint16_t value) {
  append_u8(output, static_cast<std::uint8_t>(value & 0xFFU));
  append_u8(output, static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void append_u32(std::vector<std::byte>& output, std::uint32_t value) {
  for (std::uint32_t shift = 0; shift < 32U; shift += 8U) {
    append_u8(output, static_cast<std::uint8_t>((value >> shift) & 0xFFU));
  }
}

void append_u64(std::vector<std::byte>& output, std::uint64_t value) {
  for (std::uint32_t shift = 0; shift < 64U; shift += 8U) {
    append_u8(output, static_cast<std::uint8_t>((value >> shift) & 0xFFU));
  }
}

void validate_file_header(const FileHeader& header) {
  if (header.pointer_width != 4U && header.pointer_width != 8U) {
    throw WireFormatError{"pointer width must be 4 or 8 bytes"};
  }
  if (!is_supported_platform(header.platform)) {
    throw WireFormatError{"trace platform is not supported"};
  }
  if (!is_supported_architecture(header.architecture)) {
    throw WireFormatError{"trace architecture is not supported"};
  }
  if (header.monotonic_frequency == 0U) {
    throw WireFormatError{"monotonic frequency must not be zero"};
  }
}

void validate_chunk_header(const ChunkHeader& header) {
  if (!is_supported_chunk_type(header.descriptor.type)) {
    throw WireFormatError{"chunk type is not supported"};
  }
  if (!is_supported_codec(header.descriptor.codec)) {
    throw WireFormatError{"compression codec is not supported"};
  }
  if (header.descriptor.version == 0U) {
    throw WireFormatError{"chunk version must not be zero"};
  }
  const bool has_begin = header.descriptor.sequence_begin.is_valid();
  const bool has_end = header.descriptor.sequence_end.is_valid();
  if (has_begin != has_end) {
    throw WireFormatError{"chunk sequence range must contain both endpoints or neither"};
  }
  if (has_begin && header.descriptor.sequence_begin > header.descriptor.sequence_end) {
    throw WireFormatError{"chunk sequence range is reversed"};
  }
}

[[nodiscard]] constexpr std::array<std::uint32_t, 256> make_crc32c_table() {
  constexpr std::uint32_t kPolynomial = 0x82F63B78U;
  std::array<std::uint32_t, 256> table{};
  for (std::uint32_t index = 0; index < table.size(); ++index) {
    std::uint32_t value = index;
    for (std::uint32_t bit = 0; bit < 8U; ++bit) {
      value = (value & 1U) != 0U ? (value >> 1U) ^ kPolynomial : value >> 1U;
    }
    table[index] = value;
  }
  return table;
}

inline constexpr auto kCrc32cTable = make_crc32c_table();

}  // namespace

std::vector<std::byte> encode_file_header(const FileHeader& header) {
  validate_file_header(header);
  std::vector<std::byte> output;
  output.reserve(kFileHeaderSize);
  output.insert(output.end(), kTraceMagic.begin(), kTraceMagic.end());
  append_u16(output, kFileHeaderSize);
  append_u16(output, kTraceFormatMajor);
  append_u16(output, kTraceFormatMinor);
  append_u8(output, static_cast<std::uint8_t>(ByteOrder::kLittleEndian));
  append_u8(output, header.pointer_width);
  append_u16(output, static_cast<std::uint16_t>(header.platform));
  append_u16(output, static_cast<std::uint16_t>(header.architecture));
  append_u32(output, header.flags);
  output.insert(output.end(), header.session_id.begin(), header.session_id.end());
  append_u32(output, header.file_index);
  append_u64(output, header.monotonic_frequency);
  append_u64(output, header.monotonic_origin);
  append_u64(output, std::bit_cast<std::uint64_t>(header.utc_origin_ns));
  return output;
}

std::vector<std::byte> encode_chunk_header(const ChunkHeader& header) {
  validate_chunk_header(header);
  std::vector<std::byte> output;
  output.reserve(kChunkHeaderSize);
  append_u16(output, static_cast<std::uint16_t>(header.descriptor.type));
  append_u16(output, header.descriptor.version);
  append_u16(output, kChunkHeaderSize);
  append_u16(output, header.descriptor.flags);
  append_u8(output, static_cast<std::uint8_t>(header.descriptor.codec));
  for (std::uint32_t index = 0; index < 7U; ++index) {
    append_u8(output, 0U);
  }
  append_u64(output, header.descriptor.sequence_begin.value());
  append_u64(output, header.descriptor.sequence_end.value());
  append_u64(output, header.uncompressed_size);
  append_u64(output, header.stored_size);
  append_u32(output, header.crc32c);
  append_u32(output, 0U);
  return output;
}

void append_record(std::vector<std::byte>& chunk_payload, std::uint16_t record_type,
                   std::uint16_t record_version, std::span<const std::byte> payload,
                   std::uint32_t maximum_record_size) {
  if (record_type == 0U) {
    throw WireFormatError{"record type must not be zero"};
  }
  if (record_version == 0U) {
    throw WireFormatError{"record version must not be zero"};
  }
  if (maximum_record_size < kRecordHeaderSize ||
      payload.size() > static_cast<std::size_t>(maximum_record_size - kRecordHeaderSize)) {
    throw WireFormatError{"record exceeds the configured size limit"};
  }
  if (payload.size() > std::numeric_limits<std::uint32_t>::max() - kRecordHeaderSize) {
    throw WireFormatError{"record size does not fit uint32"};
  }
  const auto record_size =
      static_cast<std::uint32_t>(payload.size()) + static_cast<std::uint32_t>(kRecordHeaderSize);
  if (chunk_payload.size() > std::numeric_limits<std::size_t>::max() - record_size) {
    throw WireFormatError{"chunk payload size overflow"};
  }

  chunk_payload.reserve(chunk_payload.size() + record_size);
  append_u16(chunk_payload, record_type);
  append_u16(chunk_payload, record_version);
  append_u32(chunk_payload, record_size);
  chunk_payload.insert(chunk_payload.end(), payload.begin(), payload.end());
}

std::uint32_t crc32c(std::span<const std::byte> bytes) noexcept {
  std::uint32_t crc = 0xFFFFFFFFU;
  for (const auto byte : bytes) {
    const auto table_index = static_cast<std::uint8_t>(
        (crc ^ static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(byte))) & 0xFFU);
    crc = kCrc32cTable[table_index] ^ (crc >> 8U);
  }
  return ~crc;
}

}  // namespace noleax::trace
