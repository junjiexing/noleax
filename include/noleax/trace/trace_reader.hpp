#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

#include "noleax/trace/wire_format.hpp"

namespace noleax::trace {

inline constexpr std::uint32_t kDefaultMaximumRecordSize = 1024U * 1024U;

struct TraceReaderOptions {
  std::uint64_t max_file_header_size{64U * 1024U};
  std::uint64_t max_chunk_header_size{64U * 1024U};
  std::uint64_t max_uncompressed_chunk_size{16U * 1024U * 1024U};
  std::uint64_t max_stored_chunk_size{17U * 1024U * 1024U};
  std::uint64_t max_compression_ratio{64U * 1024U};
};

struct TraceChunk {
  ChunkHeader header;
  std::vector<std::byte> payload;
};

enum class ChunkReadStatus : std::uint8_t {
  kChunk,
  kEndOfFile,
  kTruncated,
};

struct ChunkReadResult {
  ChunkReadStatus status{ChunkReadStatus::kEndOfFile};
  std::optional<TraceChunk> chunk;
};

class TraceReadError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class TraceReader {
 public:
  explicit TraceReader(std::istream& input, TraceReaderOptions options = {});

  TraceReader(const TraceReader&) = delete;
  TraceReader& operator=(const TraceReader&) = delete;

  [[nodiscard]] const FileHeader& file_header() const noexcept;
  [[nodiscard]] ChunkReadResult read_next_chunk();
  [[nodiscard]] std::uint64_t bytes_read() const noexcept;
  [[nodiscard]] bool partially_understood() const noexcept;

 private:
  enum class ExactReadResult : std::uint8_t {
    kComplete,
    kNoBytes,
    kPartial,
  };

  [[nodiscard]] ExactReadResult read_exact(std::span<std::byte> destination);
  [[nodiscard]] ExactReadResult skip_exact(std::uint64_t size);
  [[nodiscard]] ChunkReadResult finish(ChunkReadStatus status);

  std::istream& input_;
  TraceReaderOptions options_;
  FileHeader file_header_;
  std::uint64_t bytes_read_{0};
  bool partially_understood_{false};
  std::optional<ChunkReadStatus> terminal_status_;
};

struct RecordView {
  std::uint16_t type{0};
  std::uint16_t version{0};
  std::span<const std::byte> payload;
};

class RecordCursor {
 public:
  explicit RecordCursor(std::span<const std::byte> chunk_payload,
                        std::uint32_t maximum_record_size = kDefaultMaximumRecordSize);

  [[nodiscard]] std::optional<RecordView> next();
  [[nodiscard]] std::size_t bytes_consumed() const noexcept;
  [[nodiscard]] bool done() const noexcept;

 private:
  std::span<const std::byte> chunk_payload_;
  std::size_t offset_{0};
  std::uint32_t maximum_record_size_;
};

}  // namespace noleax::trace
