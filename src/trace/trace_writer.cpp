#include "noleax/trace/trace_writer.hpp"

#include <lz4.h>
#include <zstd.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <ostream>
#include <span>
#include <string>
#include <vector>

#include "noleax/trace/wire_format.hpp"

namespace noleax::trace {
namespace {

void write_bytes(std::ostream& output, std::span<const std::byte> bytes) {
  if (bytes.empty()) {
    return;
  }
  if (bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
    throw TraceWriteError{"write size exceeds std::streamsize"};
  }
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  if (!output) {
    throw TraceWriteError{"trace output stream write failed"};
  }
}

[[nodiscard]] std::vector<std::byte> copy_payload(std::span<const std::byte> payload) {
  return {payload.begin(), payload.end()};
}

[[nodiscard]] std::vector<std::byte> compress_lz4(std::span<const std::byte> payload) {
  if (payload.empty()) {
    return {};
  }
  if (payload.size() > static_cast<std::size_t>(LZ4_MAX_INPUT_SIZE) ||
      payload.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw TraceWriteError{"LZ4 input exceeds its supported size"};
  }
  const int source_size = static_cast<int>(payload.size());
  const int bound = LZ4_compressBound(source_size);
  if (bound <= 0) {
    throw TraceWriteError{"LZ4 could not compute a compression bound"};
  }

  std::vector<std::byte> stored(static_cast<std::size_t>(bound));
  const int compressed_size =
      LZ4_compress_default(reinterpret_cast<const char*>(payload.data()),
                           reinterpret_cast<char*>(stored.data()), source_size, bound);
  if (compressed_size <= 0) {
    throw TraceWriteError{"LZ4 compression failed"};
  }
  stored.resize(static_cast<std::size_t>(compressed_size));
  return stored;
}

[[nodiscard]] std::vector<std::byte> compress_zstd(std::span<const std::byte> payload,
                                                   std::int32_t configured_level) {
  if (payload.empty()) {
    return {};
  }
  const int level = configured_level == 0 ? 1 : configured_level;
  if (level != 1) {
    throw TraceWriteError{"V1 trace writer supports Zstd level 1"};
  }
  const std::size_t bound = ZSTD_compressBound(payload.size());
  if (ZSTD_isError(bound) != 0U) {
    throw TraceWriteError{"Zstd could not compute a compression bound"};
  }
  std::vector<std::byte> stored(bound);
  const std::size_t compressed_size =
      ZSTD_compress(stored.data(), stored.size(), payload.data(), payload.size(), level);
  if (ZSTD_isError(compressed_size) != 0U) {
    throw TraceWriteError{"Zstd compression failed: " +
                          std::string{ZSTD_getErrorName(compressed_size)}};
  }
  stored.resize(compressed_size);
  return stored;
}

[[nodiscard]] std::vector<std::byte> compress_payload(CompressionCodec codec,
                                                      std::span<const std::byte> payload,
                                                      std::int32_t zstd_level) {
  switch (codec) {
    case CompressionCodec::kNone:
      return copy_payload(payload);
    case CompressionCodec::kLz4:
      return compress_lz4(payload);
    case CompressionCodec::kZstd:
      return compress_zstd(payload, zstd_level);
  }
  throw TraceWriteError{"unsupported compression codec"};
}

[[nodiscard]] bool exceeds_file_limit(std::uint64_t bytes_written, std::uint64_t stored_size,
                                      std::uint64_t max_file_size) noexcept {
  constexpr std::uint64_t kHeaderSize = kChunkHeaderSize;
  if (stored_size > std::numeric_limits<std::uint64_t>::max() - kHeaderSize) {
    return true;
  }
  const std::uint64_t chunk_size = kHeaderSize + stored_size;
  return bytes_written > max_file_size || chunk_size > max_file_size - bytes_written;
}

}  // namespace

TraceWriter::TraceWriter(std::ostream& output, const FileHeader& header, TraceWriterOptions options)
    : output_{output}, options_{options} {
  if (options_.max_file_size < kFileHeaderSize) {
    throw TraceWriteError{"max file size is smaller than the trace header"};
  }
  if (options_.max_uncompressed_chunk_size == 0U || options_.max_stored_chunk_size == 0U) {
    throw TraceWriteError{"chunk size limits must not be zero"};
  }
  if (options_.zstd_level != 0 && options_.zstd_level != 1) {
    throw TraceWriteError{"V1 trace writer supports Zstd level 0 or 1"};
  }
  const auto encoded_header = encode_file_header(header);
  write_bytes(output_, encoded_header);
  bytes_written_ = encoded_header.size();
}

ChunkWriteResult TraceWriter::write_chunk(const ChunkDescriptor& descriptor,
                                          std::span<const std::byte> uncompressed_payload) {
  if (uncompressed_payload.size() > options_.max_uncompressed_chunk_size) {
    throw TraceWriteError{"uncompressed chunk exceeds its configured size limit"};
  }

  const auto stored_payload =
      compress_payload(descriptor.codec, uncompressed_payload, options_.zstd_level);
  if (stored_payload.size() > options_.max_stored_chunk_size) {
    throw TraceWriteError{"stored chunk exceeds its configured size limit"};
  }
  const auto stored_size = static_cast<std::uint64_t>(stored_payload.size());

  ChunkHeader header;
  header.descriptor = descriptor;
  header.uncompressed_size = uncompressed_payload.size();
  header.stored_size = stored_size;
  header.crc32c = crc32c(uncompressed_payload);
  const auto encoded_header = encode_chunk_header(header);

  if (exceeds_file_limit(bytes_written_, stored_size, options_.max_file_size)) {
    return ChunkWriteResult::kFileLimit;
  }

  write_bytes(output_, encoded_header);
  write_bytes(output_, stored_payload);
  bytes_written_ += static_cast<std::uint64_t>(encoded_header.size()) + stored_size;
  return ChunkWriteResult::kWritten;
}

void TraceWriter::flush() {
  output_.flush();
  if (!output_) {
    throw TraceWriteError{"trace output stream flush failed"};
  }
}

std::uint64_t TraceWriter::bytes_written() const noexcept { return bytes_written_; }

std::uint64_t TraceWriter::remaining_bytes() const noexcept {
  return bytes_written_ >= options_.max_file_size ? 0U : options_.max_file_size - bytes_written_;
}

}  // namespace noleax::trace
