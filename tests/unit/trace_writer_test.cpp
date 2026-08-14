#include "noleax/trace/trace_writer.hpp"

#include <lz4.h>
#include <zstd.h>

#include <algorithm>
#include <array>
#include <bit>
#include <catch2/catch_test_macros.hpp>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using noleax::trace::Architecture;
using noleax::trace::ChunkDescriptor;
using noleax::trace::FileHeader;
using noleax::trace::Platform;

[[nodiscard]] FileHeader minimal_file_header() {
  FileHeader header;
  header.pointer_width = 8U;
  header.platform = Platform::kWindows;
  header.architecture = Architecture::kX64;
  header.monotonic_frequency = 10'000'000U;
  return header;
}

[[nodiscard]] std::vector<std::byte> bytes(std::initializer_list<unsigned int> values) {
  std::vector<std::byte> output;
  output.reserve(values.size());
  for (const auto value : values) {
    output.push_back(static_cast<std::byte>(value));
  }
  return output;
}

[[nodiscard]] std::vector<std::byte> bytes(std::string_view value) {
  const auto* begin = reinterpret_cast<const std::byte*>(value.data());
  return {begin, begin + value.size()};
}

[[nodiscard]] std::vector<std::byte> stream_bytes(const std::ostringstream& stream) {
  return bytes(stream.str());
}

[[nodiscard]] std::uint64_t read_u64(std::span<const std::byte> input, std::size_t offset) {
  REQUIRE(offset <= input.size());
  REQUIRE(input.size() - offset >= sizeof(std::uint64_t));
  std::uint64_t value = 0U;
  for (std::size_t index = 0; index < sizeof(value); ++index) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(input[offset + index]))
             << (index * 8U);
  }
  return value;
}

[[nodiscard]] ChunkDescriptor descriptor(noleax::trace::CompressionCodec codec) {
  ChunkDescriptor result;
  result.type = noleax::trace::ChunkType::kEvent;
  result.codec = codec;
  result.sequence_begin = noleax::trace::Sequence{5U};
  result.sequence_end = noleax::trace::Sequence{6U};
  return result;
}

[[nodiscard]] std::vector<std::byte> compressible_payload() {
  std::vector<std::byte> payload(4096U);
  for (std::size_t index = 0; index < payload.size(); ++index) {
    payload[index] = static_cast<std::byte>(index % 13U);
  }
  return payload;
}

}  // namespace

TEST_CASE("CRC32C matches the standard check value", "[trace][writer]") {
  const auto input = bytes("123456789");
  CHECK(noleax::trace::crc32c(input) == 0xE3069283U);
}

TEST_CASE("file header encoding has stable golden bytes", "[trace][writer]") {
  auto header = minimal_file_header();
  header.flags = 0x11223344U;
  for (std::size_t index = 0; index < header.session_id.size(); ++index) {
    header.session_id[index] = static_cast<std::byte>(index);
  }
  header.file_index = 0x55667788U;
  header.monotonic_frequency = 0x0102030405060708ULL;
  header.monotonic_origin = 0x1112131415161718ULL;
  header.utc_origin_ns = std::bit_cast<std::int64_t>(0xFFEEDDCCBBAA9988ULL);

  // Offset 12 is the format minor (4 = H4 agent-memory records).
  const auto expected = bytes({
      0x4E, 0x4C, 0x58, 0x54, 0x52, 0x41, 0x43, 0x45, 0x44, 0x00, 0x01, 0x00, 0x04, 0x00,
      0x01, 0x08, 0x01, 0x00, 0x02, 0x00, 0x44, 0x33, 0x22, 0x11, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x88, 0x77,
      0x66, 0x55, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x18, 0x17, 0x16, 0x15,
      0x14, 0x13, 0x12, 0x11, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  });

  const auto encoded = noleax::trace::encode_file_header(header);
  CHECK(encoded.size() == noleax::trace::kFileHeaderSize);
  CHECK(encoded == expected);
}

TEST_CASE("record framing has stable golden bytes and enforces limits", "[trace][writer]") {
  auto chunk = bytes({0xFE});
  const auto payload = bytes({0xAA, 0xBB});
  noleax::trace::append_record(chunk, 0x1234U, 0x5678U, payload, 10U);
  CHECK(chunk == bytes({0xFE, 0x34, 0x12, 0x78, 0x56, 0x0A, 0x00, 0x00, 0x00, 0xAA, 0xBB}));

  const auto before_failure = chunk;
  CHECK_THROWS_AS(noleax::trace::append_record(chunk, 1U, 1U, payload, 9U),
                  noleax::trace::WireFormatError);
  CHECK(chunk == before_failure);
  CHECK_THROWS_AS(noleax::trace::append_record(chunk, 0U, 1U, {}, 8U),
                  noleax::trace::WireFormatError);
  CHECK_THROWS_AS(noleax::trace::append_record(chunk, 1U, 0U, {}, 8U),
                  noleax::trace::WireFormatError);
}

TEST_CASE("uncompressed chunk encoding has stable golden bytes", "[trace][writer]") {
  std::ostringstream output{std::ios::binary};
  noleax::trace::TraceWriter writer{output, minimal_file_header()};
  auto chunk_descriptor = descriptor(noleax::trace::CompressionCodec::kNone);
  chunk_descriptor.version = 2U;
  chunk_descriptor.flags = 0x3344U;
  const auto payload = bytes("abc");

  CHECK(writer.write_chunk(chunk_descriptor, payload) == noleax::trace::ChunkWriteResult::kWritten);
  const auto actual = stream_bytes(output);
  const auto expected_chunk = bytes({
      0x04, 0x00, 0x02, 0x00, 0x38, 0x00, 0x44, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0xB7, 0x3F, 0x4B, 0x36, 0x00, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63,
  });

  REQUIRE(actual.size() == noleax::trace::kFileHeaderSize + expected_chunk.size());
  CHECK(std::equal(expected_chunk.begin(), expected_chunk.end(),
                   actual.begin() + noleax::trace::kFileHeaderSize));
  CHECK(writer.bytes_written() == actual.size());
  CHECK(writer.uncompressed_payload_bytes_written() == payload.size());
  CHECK(writer.stored_payload_bytes_written() == payload.size());
}

TEST_CASE("LZ4 and Zstd chunks decompress to their original payload", "[trace][writer]") {
  const auto payload = compressible_payload();

  for (const auto codec :
       {noleax::trace::CompressionCodec::kLz4, noleax::trace::CompressionCodec::kZstd}) {
    CAPTURE(codec);
    std::ostringstream output{std::ios::binary};
    noleax::trace::TraceWriter writer{output, minimal_file_header()};
    REQUIRE(writer.write_chunk(descriptor(codec), payload) ==
            noleax::trace::ChunkWriteResult::kWritten);
    const auto encoded = stream_bytes(output);
    const std::size_t chunk_offset = noleax::trace::kFileHeaderSize;
    const auto uncompressed_size = read_u64(encoded, chunk_offset + 32U);
    const auto stored_size = read_u64(encoded, chunk_offset + 40U);
    REQUIRE(uncompressed_size == payload.size());
    REQUIRE(stored_size < payload.size());
    REQUIRE(encoded.size() == chunk_offset + noleax::trace::kChunkHeaderSize + stored_size);

    const auto* stored = encoded.data() + chunk_offset + noleax::trace::kChunkHeaderSize;
    std::vector<std::byte> restored(payload.size());
    if (codec == noleax::trace::CompressionCodec::kLz4) {
      const int result = LZ4_decompress_safe(
          reinterpret_cast<const char*>(stored), reinterpret_cast<char*>(restored.data()),
          static_cast<int>(stored_size), static_cast<int>(restored.size()));
      REQUIRE(result == static_cast<int>(payload.size()));
    } else {
      const std::size_t result =
          ZSTD_decompress(restored.data(), restored.size(), stored, stored_size);
      REQUIRE(ZSTD_isError(result) == 0U);
      REQUIRE(result == payload.size());
    }
    CHECK(restored == payload);
  }
}

TEST_CASE("file size limit accepts an exact chunk and never writes a partial chunk",
          "[trace][writer]") {
  const auto payload = bytes("abc");
  constexpr std::uint64_t kExactSize =
      noleax::trace::kFileHeaderSize + noleax::trace::kChunkHeaderSize + 3U;

  SECTION("exact fit") {
    std::ostringstream output{std::ios::binary};
    noleax::trace::TraceWriterOptions options;
    options.max_file_size = kExactSize;
    noleax::trace::TraceWriter writer{output, minimal_file_header(), options};
    CHECK(writer.write_chunk(descriptor(noleax::trace::CompressionCodec::kNone), payload) ==
          noleax::trace::ChunkWriteResult::kWritten);
    CHECK(stream_bytes(output).size() == kExactSize);
    CHECK(writer.remaining_bytes() == 0U);
  }

  SECTION("one byte short") {
    std::ostringstream output{std::ios::binary};
    noleax::trace::TraceWriterOptions options;
    options.max_file_size = kExactSize - 1U;
    noleax::trace::TraceWriter writer{output, minimal_file_header(), options};
    CHECK(writer.write_chunk(descriptor(noleax::trace::CompressionCodec::kNone), payload) ==
          noleax::trace::ChunkWriteResult::kFileLimit);
    CHECK(stream_bytes(output).size() == noleax::trace::kFileHeaderSize);
    CHECK(writer.bytes_written() == noleax::trace::kFileHeaderSize);
    CHECK(writer.uncompressed_payload_bytes_written() == 0U);
    CHECK(writer.stored_payload_bytes_written() == 0U);
  }
}

TEST_CASE("file tail reserve is released only for terminal chunks", "[trace][writer]") {
  const auto payload = bytes("abc");
  constexpr std::uint64_t kChunkSize = noleax::trace::kChunkHeaderSize + 3U;
  constexpr std::uint64_t kExactSize = noleax::trace::kFileHeaderSize + kChunkSize;
  std::ostringstream output{std::ios::binary};
  noleax::trace::TraceWriterOptions options;
  options.max_file_size = kExactSize;
  options.reserved_tail_size = kChunkSize;
  noleax::trace::TraceWriter writer{output, minimal_file_header(), options};

  CHECK(writer.write_chunk(descriptor(noleax::trace::CompressionCodec::kNone), payload) ==
        noleax::trace::ChunkWriteResult::kFileLimit);
  CHECK(writer.bytes_written() == noleax::trace::kFileHeaderSize);
  CHECK(writer.remaining_bytes() == 0U);
  writer.release_file_reserve();
  CHECK(writer.remaining_bytes() == kChunkSize);
  CHECK(writer.write_chunk(descriptor(noleax::trace::CompressionCodec::kNone), payload) ==
        noleax::trace::ChunkWriteResult::kWritten);
  CHECK(writer.bytes_written() == kExactSize);
  CHECK(writer.remaining_bytes() == 0U);
}

TEST_CASE("wire format validation rejects invalid headers descriptors and records",
          "[trace][writer]") {
  auto invalid_file_header = minimal_file_header();
  invalid_file_header.pointer_width = 16U;
  std::ostringstream invalid_header_output{std::ios::binary};
  CHECK_THROWS_AS(noleax::trace::TraceWriter(invalid_header_output, invalid_file_header),
                  noleax::trace::WireFormatError);
  CHECK(stream_bytes(invalid_header_output).empty());

  invalid_file_header = minimal_file_header();
  invalid_file_header.platform = static_cast<Platform>(99U);
  CHECK_THROWS_AS(noleax::trace::encode_file_header(invalid_file_header),
                  noleax::trace::WireFormatError);

  std::ostringstream output{std::ios::binary};
  noleax::trace::TraceWriterOptions options;
  options.max_file_size = noleax::trace::kFileHeaderSize;
  noleax::trace::TraceWriter writer{output, minimal_file_header(), options};
  auto invalid_descriptor = descriptor(noleax::trace::CompressionCodec::kNone);
  invalid_descriptor.sequence_end = noleax::trace::Sequence{};
  CHECK_THROWS_AS(writer.write_chunk(invalid_descriptor, {}), noleax::trace::WireFormatError);
  CHECK(stream_bytes(output).size() == noleax::trace::kFileHeaderSize);

  invalid_descriptor.sequence_begin = noleax::trace::Sequence{7U};
  invalid_descriptor.sequence_end = noleax::trace::Sequence{6U};
  CHECK_THROWS_AS(writer.write_chunk(invalid_descriptor, {}), noleax::trace::WireFormatError);

  noleax::trace::ChunkHeader invalid_chunk_header;
  invalid_chunk_header.descriptor.type = static_cast<noleax::trace::ChunkType>(99U);
  CHECK_THROWS_AS(noleax::trace::encode_chunk_header(invalid_chunk_header),
                  noleax::trace::WireFormatError);
  invalid_chunk_header.descriptor.type = noleax::trace::ChunkType::kEvent;
  invalid_chunk_header.descriptor.codec = static_cast<noleax::trace::CompressionCodec>(99U);
  CHECK_THROWS_AS(noleax::trace::encode_chunk_header(invalid_chunk_header),
                  noleax::trace::WireFormatError);

  noleax::trace::TraceWriterOptions invalid_options;
  invalid_options.zstd_level = 2;
  std::ostringstream invalid_options_output{std::ios::binary};
  CHECK_THROWS_AS(
      noleax::trace::TraceWriter(invalid_options_output, minimal_file_header(), invalid_options),
      noleax::trace::TraceWriteError);
  CHECK(stream_bytes(invalid_options_output).empty());

  invalid_options = {};
  invalid_options.max_file_size = noleax::trace::kFileHeaderSize;
  invalid_options.reserved_tail_size = 1U;
  CHECK_THROWS_AS(
      noleax::trace::TraceWriter(invalid_options_output, minimal_file_header(), invalid_options),
      noleax::trace::TraceWriteError);
  CHECK(stream_bytes(invalid_options_output).empty());
}

namespace {

// A streambuf stand-in for a full disk: writes succeed until the byte budget runs out,
// then fail with ENOSPC; sync (flush) fails once armed.
class BudgetFailBuffer final : public std::streambuf {
 public:
  explicit BudgetFailBuffer(std::size_t budget, bool fail_sync = false)
      : budget_{budget}, fail_sync_{fail_sync} {}

 protected:
  std::streamsize xsputn(const char* data, std::streamsize count) override {
    const auto allowed =
        static_cast<std::streamsize>((std::min)(budget_, static_cast<std::size_t>(count)));
    sink_.append(data, static_cast<std::size_t>(allowed));
    budget_ -= static_cast<std::size_t>(allowed);
    if (allowed < count) {
      errno = ENOSPC;
    }
    return allowed;
  }

  int_type overflow(int_type value) override {
    if (budget_ == 0U) {
      errno = ENOSPC;
      return traits_type::eof();
    }
    --budget_;
    sink_.push_back(traits_type::to_char_type(value));
    return value;
  }

  int sync() override {
    if (fail_sync_) {
      errno = EIO;
      return -1;
    }
    return 0;
  }

 private:
  std::size_t budget_;
  bool fail_sync_;
  std::string sink_;
};

}  // namespace

TEST_CASE("trace write errors carry phase errno offset and chunk type", "[trace][writer]") {
  // Header phase: no budget at all, so the constructor's header write fails.
  {
    BudgetFailBuffer buffer{0U};
    std::ostream output{&buffer};
    try {
      noleax::trace::TraceWriter writer{output, minimal_file_header(), {}};
      FAIL("expected a TraceWriteError");
    } catch (const noleax::trace::TraceWriteError& error) {
      CHECK(error.phase() == noleax::trace::TraceWritePhase::kHeader);
      CHECK(error.system_error() == static_cast<std::uint32_t>(ENOSPC));
      CHECK(error.file_offset().has_value());
      CHECK(*error.file_offset() == 0U);
      CHECK(!error.chunk_type().has_value());
    }
  }

  // Write phase: the budget covers the file header only; the first chunk write fails.
  {
    BudgetFailBuffer buffer{noleax::trace::kFileHeaderSize};
    std::ostream output{&buffer};
    noleax::trace::TraceWriter writer{output, minimal_file_header(), {}};
    try {
      static_cast<void>(writer.write_chunk(descriptor(noleax::trace::CompressionCodec::kNone),
                                           compressible_payload()));
      FAIL("expected a TraceWriteError");
    } catch (const noleax::trace::TraceWriteError& error) {
      CHECK(error.phase() == noleax::trace::TraceWritePhase::kWrite);
      CHECK(error.system_error() == static_cast<std::uint32_t>(ENOSPC));
      CHECK(error.file_offset().has_value());
      CHECK(*error.file_offset() == noleax::trace::kFileHeaderSize);
      CHECK(error.chunk_type().has_value());
      CHECK(*error.chunk_type() == noleax::trace::ChunkType::kEvent);
    }
  }

  // Flush phase: writes fit the budget; the stream flush fails.
  {
    BudgetFailBuffer buffer{1024U * 1024U, true};
    std::ostream output{&buffer};
    noleax::trace::TraceWriter writer{output, minimal_file_header(), {}};
    REQUIRE(writer.write_chunk(descriptor(noleax::trace::CompressionCodec::kNone),
                               compressible_payload()) ==
            noleax::trace::ChunkWriteResult::kWritten);
    try {
      writer.flush();
      FAIL("expected a TraceWriteError");
    } catch (const noleax::trace::TraceWriteError& error) {
      CHECK(error.phase() == noleax::trace::TraceWritePhase::kFlush);
      CHECK(error.system_error() == static_cast<std::uint32_t>(EIO));
      CHECK(error.file_offset().has_value());
      CHECK(*error.file_offset() == writer.bytes_written());
    }
  }

  // The message-only constructor stays source compatible and defaults to "no context".
  {
    const noleax::trace::TraceWriteError legacy{"plain failure"};
    CHECK(std::string_view{legacy.what()} == "plain failure");
    CHECK(legacy.phase() == noleax::trace::TraceWritePhase::kNone);
    CHECK(legacy.system_error() == 0U);
    CHECK(!legacy.file_offset().has_value());
    CHECK(!legacy.chunk_type().has_value());
  }

  CHECK(std::string_view{noleax::trace::trace_write_phase_name(
            noleax::trace::TraceWritePhase::kCompression)} == "compression");
}
