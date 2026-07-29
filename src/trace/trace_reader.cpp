#include "noleax/trace/trace_reader.hpp"

#include <lz4.h>
#include <zstd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <istream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "noleax/trace/wire_format.hpp"

namespace noleax::trace {
namespace {

[[nodiscard]] std::uint16_t read_u16(std::span<const std::byte> input, std::size_t offset) {
  return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(input[offset])) |
         static_cast<std::uint16_t>(
             static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(input[offset + 1U])) << 8U);
}

[[nodiscard]] std::uint32_t read_u32(std::span<const std::byte> input, std::size_t offset) {
  std::uint32_t value = 0U;
  for (std::size_t index = 0; index < sizeof(value); ++index) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(input[offset + index]))
             << (index * 8U);
  }
  return value;
}

[[nodiscard]] std::uint64_t read_u64(std::span<const std::byte> input, std::size_t offset) {
  std::uint64_t value = 0U;
  for (std::size_t index = 0; index < sizeof(value); ++index) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(input[offset + index]))
             << (index * 8U);
  }
  return value;
}

[[nodiscard]] Platform parse_platform(std::uint16_t value) {
  switch (value) {
    case static_cast<std::uint16_t>(Platform::kWindows):
      return Platform::kWindows;
    case static_cast<std::uint16_t>(Platform::kLinux):
      return Platform::kLinux;
    case static_cast<std::uint16_t>(Platform::kMacos):
      return Platform::kMacos;
    default:
      throw TraceReadError{"trace platform is not supported"};
  }
}

[[nodiscard]] Architecture parse_architecture(std::uint16_t value) {
  switch (value) {
    case static_cast<std::uint16_t>(Architecture::kX86):
      return Architecture::kX86;
    case static_cast<std::uint16_t>(Architecture::kX64):
      return Architecture::kX64;
    case static_cast<std::uint16_t>(Architecture::kArm64):
      return Architecture::kArm64;
    default:
      throw TraceReadError{"trace architecture is not supported"};
  }
}

[[nodiscard]] std::optional<ChunkType> parse_chunk_type(std::uint16_t value) noexcept {
  switch (value) {
    case static_cast<std::uint16_t>(ChunkType::kMetadata):
      return ChunkType::kMetadata;
    case static_cast<std::uint16_t>(ChunkType::kModule):
      return ChunkType::kModule;
    case static_cast<std::uint16_t>(ChunkType::kStack):
      return ChunkType::kStack;
    case static_cast<std::uint16_t>(ChunkType::kEvent):
      return ChunkType::kEvent;
    case static_cast<std::uint16_t>(ChunkType::kStatistics):
      return ChunkType::kStatistics;
    case static_cast<std::uint16_t>(ChunkType::kEnd):
      return ChunkType::kEnd;
    default:
      return std::nullopt;
  }
}

[[nodiscard]] std::optional<CompressionCodec> parse_codec(std::uint8_t value) noexcept {
  switch (value) {
    case static_cast<std::uint8_t>(CompressionCodec::kNone):
      return CompressionCodec::kNone;
    case static_cast<std::uint8_t>(CompressionCodec::kLz4):
      return CompressionCodec::kLz4;
    case static_cast<std::uint8_t>(CompressionCodec::kZstd):
      return CompressionCodec::kZstd;
    default:
      return std::nullopt;
  }
}

void validate_options(const TraceReaderOptions& options) {
  if (options.max_file_header_size < kFileHeaderSize) {
    throw TraceReadError{"maximum file header size is smaller than the V1 header"};
  }
  if (options.max_chunk_header_size < kChunkHeaderSize) {
    throw TraceReadError{"maximum chunk header size is smaller than the V1 header"};
  }
  if (options.max_uncompressed_chunk_size == 0U || options.max_stored_chunk_size == 0U) {
    throw TraceReadError{"chunk size limits must not be zero"};
  }
  if (options.max_compression_ratio == 0U) {
    throw TraceReadError{"maximum compression ratio must not be zero"};
  }
}

void validate_sequence_range(std::uint64_t begin, std::uint64_t end) {
  const bool has_begin = begin != 0U;
  const bool has_end = end != 0U;
  if (has_begin != has_end) {
    throw TraceReadError{"chunk sequence range has only one endpoint"};
  }
  if (has_begin && begin > end) {
    throw TraceReadError{"chunk sequence range is reversed"};
  }
}

void validate_chunk_sizes(std::optional<CompressionCodec> codec, std::uint64_t uncompressed_size,
                          std::uint64_t stored_size, const TraceReaderOptions& options) {
  if (uncompressed_size > options.max_uncompressed_chunk_size) {
    throw TraceReadError{"uncompressed chunk exceeds the configured size limit"};
  }
  if (stored_size > options.max_stored_chunk_size) {
    throw TraceReadError{"stored chunk exceeds the configured size limit"};
  }
  if (!codec.has_value()) {
    return;
  }
  if (*codec == CompressionCodec::kNone) {
    if (uncompressed_size != stored_size) {
      throw TraceReadError{"uncompressed chunk sizes do not match"};
    }
    return;
  }
  if ((uncompressed_size == 0U) != (stored_size == 0U)) {
    throw TraceReadError{"empty compressed chunks must use an empty stored payload"};
  }
  if (stored_size == 0U) {
    return;
  }
  if (stored_size <= std::numeric_limits<std::uint64_t>::max() / options.max_compression_ratio &&
      uncompressed_size > stored_size * options.max_compression_ratio) {
    throw TraceReadError{"compressed chunk exceeds the configured expansion ratio"};
  }
}

[[nodiscard]] std::vector<std::byte> decompress_lz4(std::span<const std::byte> stored,
                                                    std::uint64_t uncompressed_size) {
  if (stored.empty()) {
    return {};
  }
  if (stored.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
      uncompressed_size > static_cast<std::uint64_t>(std::numeric_limits<int>::max())) {
    throw TraceReadError{"LZ4 chunk exceeds its supported size"};
  }
  std::vector<std::byte> output(static_cast<std::size_t>(uncompressed_size));
  const int decoded_size = LZ4_decompress_safe(
      reinterpret_cast<const char*>(stored.data()), reinterpret_cast<char*>(output.data()),
      static_cast<int>(stored.size()), static_cast<int>(output.size()));
  if (decoded_size < 0 || static_cast<std::size_t>(decoded_size) != output.size()) {
    throw TraceReadError{"LZ4 chunk is corrupt or has an unexpected decoded size"};
  }
  return output;
}

[[nodiscard]] std::vector<std::byte> decompress_zstd(std::span<const std::byte> stored,
                                                     std::uint64_t uncompressed_size) {
  if (stored.empty()) {
    return {};
  }
  if (uncompressed_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    throw TraceReadError{"Zstd decoded size does not fit this process"};
  }
  std::vector<std::byte> output(static_cast<std::size_t>(uncompressed_size));
  const std::size_t decoded_size =
      ZSTD_decompress(output.data(), output.size(), stored.data(), stored.size());
  if (ZSTD_isError(decoded_size) != 0U) {
    throw TraceReadError{"Zstd chunk is corrupt: " + std::string{ZSTD_getErrorName(decoded_size)}};
  }
  if (decoded_size != output.size()) {
    throw TraceReadError{"Zstd chunk has an unexpected decoded size"};
  }
  return output;
}

[[nodiscard]] std::vector<std::byte> decompress_payload(CompressionCodec codec,
                                                        std::vector<std::byte> stored,
                                                        std::uint64_t uncompressed_size) {
  switch (codec) {
    case CompressionCodec::kNone:
      return stored;
    case CompressionCodec::kLz4:
      return decompress_lz4(stored, uncompressed_size);
    case CompressionCodec::kZstd:
      return decompress_zstd(stored, uncompressed_size);
  }
  throw TraceReadError{"compression codec is not supported"};
}

}  // namespace

TraceReader::TraceReader(std::istream& input, TraceReaderOptions options)
    : input_{input}, options_{options} {
  validate_options(options_);

  std::array<std::byte, kFileHeaderSize> encoded{};
  if (read_exact(encoded) != ExactReadResult::kComplete) {
    throw TraceReadError{"trace file header is truncated"};
  }
  if (!std::equal(kTraceMagic.begin(), kTraceMagic.end(), encoded.begin())) {
    throw TraceReadError{"trace magic does not match NLXTRACE"};
  }
  const auto byte_order = std::to_integer<std::uint8_t>(encoded[14U]);
  if (byte_order != static_cast<std::uint8_t>(ByteOrder::kLittleEndian)) {
    throw TraceReadError{"trace byte order is not supported"};
  }

  const std::uint16_t header_size = read_u16(encoded, 8U);
  if (header_size < kFileHeaderSize || header_size > options_.max_file_header_size) {
    throw TraceReadError{"trace file header size is invalid"};
  }
  const std::uint16_t format_major = read_u16(encoded, 10U);
  const std::uint16_t format_minor = read_u16(encoded, 12U);
  if (format_major != kTraceFormatMajor) {
    throw TraceReadError{"trace format major version is not supported"};
  }
  if (format_minor > kTraceFormatMinor) {
    partially_understood_ = true;
  }

  file_header_.pointer_width = std::to_integer<std::uint8_t>(encoded[15U]);
  if (file_header_.pointer_width != 4U && file_header_.pointer_width != 8U) {
    throw TraceReadError{"trace pointer width must be 4 or 8 bytes"};
  }
  file_header_.platform = parse_platform(read_u16(encoded, 16U));
  file_header_.architecture = parse_architecture(read_u16(encoded, 18U));
  file_header_.flags = read_u32(encoded, 20U);
  std::copy_n(encoded.begin() + 24U, file_header_.session_id.size(),
              file_header_.session_id.begin());
  file_header_.file_index = read_u32(encoded, 40U);
  file_header_.monotonic_frequency = read_u64(encoded, 44U);
  if (file_header_.monotonic_frequency == 0U) {
    throw TraceReadError{"trace monotonic frequency must not be zero"};
  }
  file_header_.monotonic_origin = read_u64(encoded, 52U);
  file_header_.utc_origin_ns = std::bit_cast<std::int64_t>(read_u64(encoded, 60U));

  const std::uint64_t extension_size = header_size - kFileHeaderSize;
  if (extension_size != 0U) {
    partially_understood_ = true;
    if (skip_exact(extension_size) != ExactReadResult::kComplete) {
      throw TraceReadError{"trace file header extension is truncated"};
    }
  }
}

const FileHeader& TraceReader::file_header() const noexcept { return file_header_; }

ChunkReadResult TraceReader::read_next_chunk() {
  if (terminal_status_.has_value()) {
    return ChunkReadResult{*terminal_status_, std::nullopt};
  }

  for (;;) {
    std::array<std::byte, kChunkHeaderSize> encoded{};
    const ExactReadResult header_result = read_exact(encoded);
    if (header_result == ExactReadResult::kNoBytes) {
      return finish(ChunkReadStatus::kEndOfFile);
    }
    if (header_result == ExactReadResult::kPartial) {
      return finish(ChunkReadStatus::kTruncated);
    }

    const std::uint16_t raw_type = read_u16(encoded, 0U);
    const std::uint16_t version = read_u16(encoded, 2U);
    const std::uint16_t header_size = read_u16(encoded, 4U);
    const std::uint16_t flags = read_u16(encoded, 6U);
    const std::uint8_t raw_codec = std::to_integer<std::uint8_t>(encoded[8U]);
    if (header_size < kChunkHeaderSize || header_size > options_.max_chunk_header_size) {
      throw TraceReadError{"chunk header size is invalid"};
    }
    if (version == 0U) {
      throw TraceReadError{"chunk version must not be zero"};
    }
    if (std::any_of(encoded.begin() + 9U, encoded.begin() + 16U,
                    [](std::byte value) { return value != std::byte{0}; }) ||
        read_u32(encoded, 52U) != 0U) {
      throw TraceReadError{"chunk reserved fields must be zero"};
    }

    const std::uint64_t sequence_begin = read_u64(encoded, 16U);
    const std::uint64_t sequence_end = read_u64(encoded, 24U);
    validate_sequence_range(sequence_begin, sequence_end);
    const std::uint64_t uncompressed_size = read_u64(encoded, 32U);
    const std::uint64_t stored_size = read_u64(encoded, 40U);
    const std::uint32_t expected_crc32c = read_u32(encoded, 48U);
    const auto type = parse_chunk_type(raw_type);
    const auto codec = parse_codec(raw_codec);
    validate_chunk_sizes(codec, uncompressed_size, stored_size, options_);

    const std::uint64_t extension_size = header_size - kChunkHeaderSize;
    if (extension_size != 0U) {
      partially_understood_ = true;
      if (skip_exact(extension_size) != ExactReadResult::kComplete) {
        return finish(ChunkReadStatus::kTruncated);
      }
    }

    if (!type.has_value()) {
      partially_understood_ = true;
      if (skip_exact(stored_size) != ExactReadResult::kComplete) {
        return finish(ChunkReadStatus::kTruncated);
      }
      continue;
    }
    if (!codec.has_value()) {
      throw TraceReadError{"compression codec is not supported"};
    }
    if (version > 1U) {
      partially_understood_ = true;
    }
    if (stored_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
        stored_size > static_cast<std::uint64_t>(std::numeric_limits<std::streamsize>::max())) {
      throw TraceReadError{"stored chunk size does not fit this process"};
    }

    std::vector<std::byte> stored(static_cast<std::size_t>(stored_size));
    if (read_exact(stored) != ExactReadResult::kComplete) {
      return finish(ChunkReadStatus::kTruncated);
    }
    auto payload = decompress_payload(*codec, std::move(stored), uncompressed_size);
    if (crc32c(payload) != expected_crc32c) {
      throw TraceReadError{"chunk CRC32C does not match"};
    }

    ChunkHeader header;
    header.descriptor.type = *type;
    header.descriptor.version = version;
    header.descriptor.flags = flags;
    header.descriptor.codec = *codec;
    header.descriptor.sequence_begin = Sequence{sequence_begin};
    header.descriptor.sequence_end = Sequence{sequence_end};
    header.uncompressed_size = uncompressed_size;
    header.stored_size = stored_size;
    header.crc32c = expected_crc32c;
    return ChunkReadResult{ChunkReadStatus::kChunk, TraceChunk{header, std::move(payload)}};
  }
}

std::uint64_t TraceReader::bytes_read() const noexcept { return bytes_read_; }

bool TraceReader::partially_understood() const noexcept { return partially_understood_; }

TraceReader::ExactReadResult TraceReader::read_exact(std::span<std::byte> destination) {
  if (destination.empty()) {
    return ExactReadResult::kComplete;
  }
  if (destination.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
    throw TraceReadError{"read size exceeds std::streamsize"};
  }

  const auto requested = static_cast<std::streamsize>(destination.size());
  try {
    input_.read(reinterpret_cast<char*>(destination.data()), requested);
  } catch (const std::ios_base::failure&) {
    // An exception mask may throw on failbit/eofbit. The state and gcount below still
    // distinguish a normal boundary, a truncated field, and a real I/O error.
  }
  const std::streamsize count = input_.gcount();
  if (count < 0) {
    throw TraceReadError{"trace input stream returned a negative read count"};
  }
  const auto unsigned_count = static_cast<std::uint64_t>(count);
  if (bytes_read_ > std::numeric_limits<std::uint64_t>::max() - unsigned_count) {
    throw TraceReadError{"trace byte count overflow"};
  }
  bytes_read_ += unsigned_count;

  if (input_.bad()) {
    throw TraceReadError{"trace input stream read failed"};
  }
  if (count == requested) {
    return ExactReadResult::kComplete;
  }
  if (!input_.eof()) {
    throw TraceReadError{"trace input stream stopped before the requested bytes were read"};
  }
  return count == 0 ? ExactReadResult::kNoBytes : ExactReadResult::kPartial;
}

TraceReader::ExactReadResult TraceReader::skip_exact(std::uint64_t size) {
  std::array<std::byte, 4096> scratch{};
  bool consumed_any = false;
  while (size != 0U) {
    const auto part_size = static_cast<std::size_t>(std::min<std::uint64_t>(size, scratch.size()));
    const ExactReadResult result = read_exact(std::span{scratch}.first(part_size));
    if (result != ExactReadResult::kComplete) {
      return consumed_any || result == ExactReadResult::kPartial ? ExactReadResult::kPartial
                                                                 : ExactReadResult::kNoBytes;
    }
    consumed_any = true;
    size -= part_size;
  }
  return ExactReadResult::kComplete;
}

ChunkReadResult TraceReader::finish(ChunkReadStatus status) {
  terminal_status_ = status;
  return ChunkReadResult{status, std::nullopt};
}

RecordCursor::RecordCursor(std::span<const std::byte> chunk_payload,
                           std::uint32_t maximum_record_size)
    : chunk_payload_{chunk_payload}, maximum_record_size_{maximum_record_size} {
  if (maximum_record_size_ < kRecordHeaderSize) {
    throw TraceReadError{"maximum record size is smaller than the record header"};
  }
}

std::optional<RecordView> RecordCursor::next() {
  if (done()) {
    return std::nullopt;
  }
  const std::size_t remaining = chunk_payload_.size() - offset_;
  if (remaining < kRecordHeaderSize) {
    throw TraceReadError{"record header is truncated"};
  }
  const std::uint16_t type = read_u16(chunk_payload_, offset_);
  const std::uint16_t version = read_u16(chunk_payload_, offset_ + 2U);
  const std::uint32_t record_size = read_u32(chunk_payload_, offset_ + 4U);
  if (type == 0U || version == 0U) {
    throw TraceReadError{"record type and version must not be zero"};
  }
  if (record_size < kRecordHeaderSize || record_size > maximum_record_size_ ||
      record_size > remaining) {
    throw TraceReadError{"record size is invalid"};
  }

  const std::size_t payload_offset = offset_ + kRecordHeaderSize;
  const std::size_t payload_size = record_size - kRecordHeaderSize;
  offset_ += record_size;
  return RecordView{type, version, chunk_payload_.subspan(payload_offset, payload_size)};
}

std::size_t RecordCursor::bytes_consumed() const noexcept { return offset_; }

bool RecordCursor::done() const noexcept { return offset_ == chunk_payload_.size(); }

}  // namespace noleax::trace
