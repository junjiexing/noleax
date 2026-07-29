#include "noleax/trace/trace_reader.hpp"

#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <ios>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "noleax/trace/trace_writer.hpp"
#include "noleax/trace/wire_format.hpp"

namespace {

[[nodiscard]] noleax::trace::FileHeader file_header() {
  noleax::trace::FileHeader header;
  header.pointer_width = 8U;
  header.platform = noleax::trace::Platform::kWindows;
  header.architecture = noleax::trace::Architecture::kX64;
  header.flags = 0x10203040U;
  header.session_id[0] = std::byte{0xAA};
  header.file_index = 3U;
  header.monotonic_frequency = 10'000'000U;
  header.monotonic_origin = 1234U;
  header.utc_origin_ns = -5678;
  return header;
}

[[nodiscard]] std::vector<std::byte> bytes(std::string_view value) {
  const auto* begin = reinterpret_cast<const std::byte*>(value.data());
  return {begin, begin + value.size()};
}

[[nodiscard]] std::vector<std::byte> bytes(std::initializer_list<unsigned int> values) {
  std::vector<std::byte> result;
  result.reserve(values.size());
  for (const auto value : values) {
    result.push_back(static_cast<std::byte>(value));
  }
  return result;
}

[[nodiscard]] std::string byte_string(std::span<const std::byte> value) {
  return {reinterpret_cast<const char*>(value.data()), value.size()};
}

void write_u16(std::string& output, std::size_t offset, std::uint16_t value) {
  output.at(offset) = static_cast<char>(value & 0xFFU);
  output.at(offset + 1U) = static_cast<char>((value >> 8U) & 0xFFU);
}

void write_u64(std::string& output, std::size_t offset, std::uint64_t value) {
  for (std::size_t index = 0; index < sizeof(value); ++index) {
    output.at(offset + index) = static_cast<char>((value >> (index * 8U)) & 0xFFU);
  }
}

void write_u32(std::vector<std::byte>& output, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < sizeof(value); ++index) {
    output.at(offset + index) = static_cast<std::byte>((value >> (index * 8U)) & 0xFFU);
  }
}

struct ChunkInput {
  noleax::trace::ChunkDescriptor descriptor;
  std::vector<std::byte> payload;
};

[[nodiscard]] std::string write_trace(std::span<const ChunkInput> chunks) {
  std::ostringstream output{std::ios::binary};
  noleax::trace::TraceWriter writer{output, file_header()};
  for (const auto& chunk : chunks) {
    const auto result = writer.write_chunk(chunk.descriptor, chunk.payload);
    if (result != noleax::trace::ChunkWriteResult::kWritten) {
      throw std::runtime_error{"test trace unexpectedly reached its file limit"};
    }
  }
  return output.str();
}

[[nodiscard]] noleax::trace::ChunkDescriptor descriptor(noleax::trace::CompressionCodec codec,
                                                        std::uint64_t sequence) {
  noleax::trace::ChunkDescriptor result;
  result.type = noleax::trace::ChunkType::kEvent;
  result.codec = codec;
  result.sequence_begin = noleax::trace::Sequence{sequence};
  result.sequence_end = noleax::trace::Sequence{sequence};
  return result;
}

[[nodiscard]] std::vector<std::byte> compressible_payload(std::size_t size) {
  std::vector<std::byte> result(size);
  for (std::size_t index = 0; index < result.size(); ++index) {
    result[index] = static_cast<std::byte>(index % 7U);
  }
  return result;
}

}  // namespace

TEST_CASE("trace reader round trips none LZ4 and Zstd chunks", "[trace][reader]") {
  const std::array chunks{
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kNone, 1U), bytes("plain")},
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kLz4, 2U),
                 compressible_payload(4096U)},
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kZstd, 3U),
                 std::vector<std::byte>(1024U * 1024U, std::byte{0})},
  };
  const std::string encoded = write_trace(chunks);
  std::istringstream input{encoded, std::ios::binary};
  noleax::trace::TraceReader reader{input};

  CHECK(reader.file_header() == file_header());
  CHECK_FALSE(reader.partially_understood());
  for (const auto& expected : chunks) {
    const auto result = reader.read_next_chunk();
    REQUIRE(result.status == noleax::trace::ChunkReadStatus::kChunk);
    REQUIRE(result.chunk.has_value());
    CHECK(result.chunk->header.descriptor == expected.descriptor);
    CHECK(result.chunk->header.uncompressed_size == expected.payload.size());
    CHECK(result.chunk->payload == expected.payload);
  }

  CHECK(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kEndOfFile);
  CHECK(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kEndOfFile);
  CHECK(reader.bytes_read() == encoded.size());
}

TEST_CASE("newer header extensions are skipped and marked partially understood",
          "[trace][reader]") {
  auto encoded_header = noleax::trace::encode_file_header(file_header());
  std::string encoded = byte_string(encoded_header);
  write_u16(encoded, 8U, noleax::trace::kFileHeaderSize + 4U);
  write_u16(encoded, 12U, noleax::trace::kTraceFormatMinor + 1U);
  encoded.append("ext!", 4U);

  std::istringstream input{encoded, std::ios::binary};
  noleax::trace::TraceReader reader{input};
  CHECK(reader.file_header() == file_header());
  CHECK(reader.partially_understood());
  CHECK(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kEndOfFile);
  CHECK(reader.bytes_read() == encoded.size());
}

TEST_CASE("chunk header extensions are skipped before decoding the payload", "[trace][reader]") {
  const std::array chunks{
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kNone, 1U), bytes("payload")},
  };
  std::string encoded = write_trace(chunks);
  const std::size_t extension_offset =
      noleax::trace::kFileHeaderSize + noleax::trace::kChunkHeaderSize;
  encoded.insert(extension_offset, "ext!", 4U);
  write_u16(encoded, noleax::trace::kFileHeaderSize + 4U, noleax::trace::kChunkHeaderSize + 4U);

  std::istringstream input{encoded, std::ios::binary};
  noleax::trace::TraceReader reader{input};
  const auto result = reader.read_next_chunk();
  REQUIRE(result.status == noleax::trace::ChunkReadStatus::kChunk);
  REQUIRE(result.chunk.has_value());
  CHECK(result.chunk->payload == chunks[0].payload);
  CHECK(reader.partially_understood());
}

TEST_CASE("stream exception masks preserve EOF and truncation classification", "[trace][reader]") {
  const std::array chunks{
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kNone, 1U), bytes("payload")},
  };
  const std::string encoded = write_trace(chunks);

  SECTION("clean EOF") {
    std::istringstream input{encoded, std::ios::binary};
    input.exceptions(std::ios::failbit | std::ios::badbit);
    noleax::trace::TraceReader reader{input};
    REQUIRE(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kChunk);
    CHECK(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kEndOfFile);
  }

  SECTION("truncated payload") {
    std::istringstream input{encoded.substr(0U, encoded.size() - 1U), std::ios::binary};
    input.exceptions(std::ios::failbit | std::ios::badbit);
    noleax::trace::TraceReader reader{input};
    CHECK(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kTruncated);
  }
}

TEST_CASE("unknown chunks are skipped without blocking later known chunks", "[trace][reader]") {
  const std::array chunks{
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kNone, 1U), bytes("skip")},
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kNone, 2U), bytes("keep")},
  };
  std::string encoded = write_trace(chunks);
  const std::size_t first_chunk = noleax::trace::kFileHeaderSize;
  write_u16(encoded, first_chunk, 0xFFFFU);
  encoded.at(first_chunk + 8U) = static_cast<char>(0xFFU);

  std::istringstream input{encoded, std::ios::binary};
  noleax::trace::TraceReader reader{input};
  const auto result = reader.read_next_chunk();
  REQUIRE(result.status == noleax::trace::ChunkReadStatus::kChunk);
  REQUIRE(result.chunk.has_value());
  CHECK(result.chunk->header.descriptor.sequence_begin == noleax::trace::Sequence{2U});
  CHECK(result.chunk->payload == chunks[1].payload);
  CHECK(reader.partially_understood());
  CHECK(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kEndOfFile);
}

TEST_CASE("known chunks reject unknown codecs and corrupt payloads", "[trace][reader]") {
  const std::array chunks{
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kNone, 1U), bytes("data")},
  };

  SECTION("unknown codec") {
    std::string encoded = write_trace(chunks);
    encoded.at(noleax::trace::kFileHeaderSize + 8U) = static_cast<char>(0xFFU);
    std::istringstream input{encoded, std::ios::binary};
    noleax::trace::TraceReader reader{input};
    CHECK_THROWS_AS(reader.read_next_chunk(), noleax::trace::TraceReadError);
  }

  SECTION("CRC mismatch") {
    std::string encoded = write_trace(chunks);
    encoded.back() = static_cast<char>(encoded.back() ^ 0x01);
    std::istringstream input{encoded, std::ios::binary};
    noleax::trace::TraceReader reader{input};
    CHECK_THROWS_AS(reader.read_next_chunk(), noleax::trace::TraceReadError);
  }

  SECTION("corrupt compressed data") {
    const std::array compressed{
        ChunkInput{descriptor(noleax::trace::CompressionCodec::kLz4, 1U),
                   compressible_payload(4096U)},
    };
    std::string encoded = write_trace(compressed);
    encoded.resize(encoded.size() - 1U);
    write_u64(encoded, noleax::trace::kFileHeaderSize + 40U,
              encoded.size() - noleax::trace::kFileHeaderSize - noleax::trace::kChunkHeaderSize);
    std::istringstream input{encoded, std::ios::binary};
    noleax::trace::TraceReader reader{input};
    CHECK_THROWS_AS(reader.read_next_chunk(), noleax::trace::TraceReadError);
  }
}

TEST_CASE("reader validates untrusted chunk metadata before allocating", "[trace][reader]") {
  const std::array chunks{
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kNone, 1U), bytes("abc")},
  };
  const std::string valid = write_trace(chunks);
  const std::size_t chunk = noleax::trace::kFileHeaderSize;

  SECTION("stored size limit") {
    std::string encoded = valid;
    write_u64(encoded, chunk + 40U, 18U * 1024U * 1024U);
    std::istringstream input{encoded, std::ios::binary};
    noleax::trace::TraceReader reader{input};
    CHECK_THROWS_AS(reader.read_next_chunk(), noleax::trace::TraceReadError);
  }

  SECTION("uncompressed size limit") {
    std::string encoded = valid;
    write_u64(encoded, chunk + 32U, 17U * 1024U * 1024U);
    std::istringstream input{encoded, std::ios::binary};
    noleax::trace::TraceReader reader{input};
    CHECK_THROWS_AS(reader.read_next_chunk(), noleax::trace::TraceReadError);
  }

  SECTION("none codec size mismatch") {
    std::string encoded = valid;
    write_u64(encoded, chunk + 40U, 2U);
    std::istringstream input{encoded, std::ios::binary};
    noleax::trace::TraceReader reader{input};
    CHECK_THROWS_AS(reader.read_next_chunk(), noleax::trace::TraceReadError);
  }

  SECTION("compression expansion ratio") {
    std::string encoded = valid;
    encoded.at(chunk + 8U) = static_cast<char>(noleax::trace::CompressionCodec::kLz4);
    write_u64(encoded, chunk + 32U, 100U);
    noleax::trace::TraceReaderOptions options;
    options.max_compression_ratio = 2U;
    std::istringstream input{encoded, std::ios::binary};
    noleax::trace::TraceReader reader{input, options};
    CHECK_THROWS_AS(reader.read_next_chunk(), noleax::trace::TraceReadError);
  }

  SECTION("reserved bytes") {
    std::string encoded = valid;
    encoded.at(chunk + 9U) = static_cast<char>(1);
    std::istringstream input{encoded, std::ios::binary};
    noleax::trace::TraceReader reader{input};
    CHECK_THROWS_AS(reader.read_next_chunk(), noleax::trace::TraceReadError);
  }

  SECTION("half sequence range") {
    std::string encoded = valid;
    write_u64(encoded, chunk + 24U, 0U);
    std::istringstream input{encoded, std::ios::binary};
    noleax::trace::TraceReader reader{input};
    CHECK_THROWS_AS(reader.read_next_chunk(), noleax::trace::TraceReadError);
  }
}

TEST_CASE("reader preserves complete chunks before a truncated tail", "[trace][reader]") {
  const std::array chunks{
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kNone, 1U), bytes("one")},
      ChunkInput{descriptor(noleax::trace::CompressionCodec::kNone, 2U), bytes("second")},
  };
  const std::string encoded = write_trace(chunks);
  const std::size_t second_chunk =
      noleax::trace::kFileHeaderSize + noleax::trace::kChunkHeaderSize + chunks[0].payload.size();

  SECTION("clean boundary is EOF") {
    std::istringstream input{encoded.substr(0U, second_chunk), std::ios::binary};
    noleax::trace::TraceReader reader{input};
    REQUIRE(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kChunk);
    CHECK(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kEndOfFile);
  }

  SECTION("every partial second chunk is truncated") {
    for (std::size_t size = second_chunk + 1U; size < encoded.size(); ++size) {
      CAPTURE(size);
      std::istringstream input{encoded.substr(0U, size), std::ios::binary};
      noleax::trace::TraceReader reader{input};
      const auto first = reader.read_next_chunk();
      REQUIRE(first.status == noleax::trace::ChunkReadStatus::kChunk);
      REQUIRE(first.chunk.has_value());
      REQUIRE(first.chunk->payload == chunks[0].payload);
      CHECK(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kTruncated);
      CHECK(reader.read_next_chunk().status == noleax::trace::ChunkReadStatus::kTruncated);
    }
  }
}

TEST_CASE("file header validation rejects truncation and incompatible fields", "[trace][reader]") {
  const auto encoded_header = noleax::trace::encode_file_header(file_header());
  const std::string valid = byte_string(encoded_header);

  for (std::size_t size = 0; size < valid.size(); ++size) {
    CAPTURE(size);
    std::istringstream input{valid.substr(0U, size), std::ios::binary};
    CHECK_THROWS_AS(noleax::trace::TraceReader(input), noleax::trace::TraceReadError);
  }

  SECTION("wrong magic") {
    std::string encoded = valid;
    encoded.front() = static_cast<char>('X');
    std::istringstream input{encoded, std::ios::binary};
    CHECK_THROWS_AS(noleax::trace::TraceReader(input), noleax::trace::TraceReadError);
  }

  SECTION("unsupported major") {
    std::string encoded = valid;
    write_u16(encoded, 10U, noleax::trace::kTraceFormatMajor + 1U);
    std::istringstream input{encoded, std::ios::binary};
    CHECK_THROWS_AS(noleax::trace::TraceReader(input), noleax::trace::TraceReadError);
  }

  SECTION("unsupported byte order") {
    std::string encoded = valid;
    encoded.at(14U) = static_cast<char>(noleax::trace::ByteOrder::kBigEndian);
    std::istringstream input{encoded, std::ios::binary};
    CHECK_THROWS_AS(noleax::trace::TraceReader(input), noleax::trace::TraceReadError);
  }
}

TEST_CASE("record cursor allows callers to skip unknown records", "[trace][reader]") {
  std::vector<std::byte> payload;
  noleax::trace::append_record(payload, 1U, 1U, bytes("first"), 128U);
  noleax::trace::append_record(payload, 0xFFFFU, 7U, bytes("unknown"), 128U);
  noleax::trace::append_record(payload, 2U, 1U, bytes("last"), 128U);

  noleax::trace::RecordCursor cursor{payload, 128U};
  const auto first = cursor.next();
  REQUIRE(first.has_value());
  CHECK(first->type == 1U);

  const auto unknown = cursor.next();
  REQUIRE(unknown.has_value());
  CHECK(unknown->type == 0xFFFFU);

  const auto last = cursor.next();
  REQUIRE(last.has_value());
  CHECK(last->type == 2U);
  const auto expected_last = bytes("last");
  CHECK(std::equal(last->payload.begin(), last->payload.end(), expected_last.begin()));
  CHECK(cursor.done());
  CHECK(cursor.bytes_consumed() == payload.size());
  CHECK_FALSE(cursor.next().has_value());
}

TEST_CASE("record cursor rejects malformed framing", "[trace][reader]") {
  CHECK_THROWS_AS(noleax::trace::RecordCursor({}, 7U), noleax::trace::TraceReadError);

  SECTION("truncated header") {
    const auto payload = bytes({1U});
    noleax::trace::RecordCursor cursor{payload};
    CHECK_THROWS_AS(cursor.next(), noleax::trace::TraceReadError);
  }

  SECTION("record extends past chunk") {
    auto payload = bytes({1U, 0U, 1U, 0U, 8U, 0U, 0U, 0U});
    write_u32(payload, 4U, 9U);
    noleax::trace::RecordCursor cursor{payload};
    CHECK_THROWS_AS(cursor.next(), noleax::trace::TraceReadError);
  }

  SECTION("record exceeds configured limit") {
    std::vector<std::byte> payload;
    noleax::trace::append_record(payload, 1U, 1U, bytes("payload"), 64U);
    noleax::trace::RecordCursor cursor{payload, 8U};
    CHECK_THROWS_AS(cursor.next(), noleax::trace::TraceReadError);
  }
}
