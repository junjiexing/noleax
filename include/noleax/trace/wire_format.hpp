#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

#include "noleax/trace/identifiers.hpp"

namespace noleax::trace {

inline constexpr std::array<std::byte, 8> kTraceMagic{
    std::byte{'N'}, std::byte{'L'}, std::byte{'X'}, std::byte{'T'},
    std::byte{'R'}, std::byte{'A'}, std::byte{'C'}, std::byte{'E'},
};
inline constexpr std::uint16_t kTraceFormatMajor = 1;
// minor 4 (H4, P0-1): AgentMemory memory-chunk record + BufferConfiguration metadata record.
inline constexpr std::uint16_t kTraceFormatMinor = 4;
inline constexpr std::uint16_t kFileHeaderSize = 68;
inline constexpr std::uint16_t kChunkHeaderSize = 56;
inline constexpr std::uint32_t kRecordHeaderSize = 8;

enum class ByteOrder : std::uint8_t {
  kLittleEndian = 1,
  kBigEndian = 2,
};

// The underlying type intentionally matches the protocol's uint16 field.
enum class Platform : std::uint16_t {  // NOLINT(performance-enum-size)
  kUnknown = 0,
  kWindows = 1,
  kLinux = 2,
  kMacos = 3,
};

// The underlying type intentionally matches the protocol's uint16 field.
enum class Architecture : std::uint16_t {  // NOLINT(performance-enum-size)
  kUnknown = 0,
  kX86 = 1,
  kX64 = 2,
  kArm64 = 3,
};

// The underlying type intentionally matches the protocol's uint16 field.
enum class ChunkType : std::uint16_t {  // NOLINT(performance-enum-size)
  kMetadata = 1,
  kModule = 2,
  kStack = 3,
  kEvent = 4,
  kStatistics = 5,
  kEnd = 6,
  kMemory = 7,
};

enum class CompressionCodec : std::uint8_t {
  kNone = 0,
  kLz4 = 1,
  kZstd = 2,
};

struct FileHeader {
  std::uint8_t pointer_width{0};
  Platform platform{Platform::kUnknown};
  Architecture architecture{Architecture::kUnknown};
  std::uint32_t flags{0};
  std::array<std::byte, 16> session_id{};
  std::uint32_t file_index{0};
  std::uint64_t monotonic_frequency{0};
  std::uint64_t monotonic_origin{0};
  std::int64_t utc_origin_ns{0};

  bool operator==(const FileHeader&) const = default;
};

struct ChunkDescriptor {
  ChunkType type{ChunkType::kEvent};
  std::uint16_t version{1};
  std::uint16_t flags{0};
  CompressionCodec codec{CompressionCodec::kNone};
  Sequence sequence_begin;
  Sequence sequence_end;

  bool operator==(const ChunkDescriptor&) const = default;
};

struct ChunkHeader {
  ChunkDescriptor descriptor;
  std::uint64_t uncompressed_size{0};
  std::uint64_t stored_size{0};
  std::uint32_t crc32c{0};

  bool operator==(const ChunkHeader&) const = default;
};

class WireFormatError final : public std::invalid_argument {
 public:
  using std::invalid_argument::invalid_argument;
};

[[nodiscard]] std::vector<std::byte> encode_file_header(const FileHeader& header);
[[nodiscard]] std::vector<std::byte> encode_chunk_header(const ChunkHeader& header);
void append_record(std::vector<std::byte>& chunk_payload, std::uint16_t record_type,
                   std::uint16_t record_version, std::span<const std::byte> payload,
                   std::uint32_t maximum_record_size);
[[nodiscard]] std::uint32_t crc32c(std::span<const std::byte> bytes) noexcept;

}  // namespace noleax::trace
