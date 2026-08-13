#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>

#include "noleax/trace/wire_format.hpp"

namespace noleax::trace {

struct TraceWriterOptions {
  std::uint64_t max_file_size{256U * 1024U * 1024U};
  std::uint64_t max_uncompressed_chunk_size{16U * 1024U * 1024U};
  std::uint64_t max_stored_chunk_size{17U * 1024U * 1024U};
  std::uint64_t reserved_tail_size{0U};
  std::int32_t zstd_level{1};
};

enum class ChunkWriteResult : std::uint8_t {
  kWritten,
  kFileLimit,
};

// The writer phase a trace write failure occurred in. kNone marks failures that precede
// any I/O (invalid options, size-limit accounting); the core writer never opens files
// itself, so kOpen is reported by callers that wrap stream creation in a TraceWriteError.
enum class TraceWritePhase : std::uint8_t {
  kNone = 0U,
  kOpen = 1U,
  kWrite = 2U,
  kFlush = 3U,
  kClose = 4U,
  kCompression = 5U,
  kHeader = 6U,
};

[[nodiscard]] const char* trace_write_phase_name(TraceWritePhase phase) noexcept;

// A trace write failure with structured context: the human-readable message stays in
// what(); the fields locate the failure for diagnostics. Every field is optional in
// spirit: system_error is 0 when no errno applies, file_offset/chunk_type are empty when
// the failure has no file position or chunk context.
class TraceWriteError final : public std::runtime_error {
 public:
  // Message-only constructor: kept so existing throw sites and consumers stay source
  // compatible; the context fields default to "not applicable".
  explicit TraceWriteError(const std::string& message) : std::runtime_error{message} {}
  explicit TraceWriteError(const char* message) : std::runtime_error{message} {}
  TraceWriteError(const std::string& message, TraceWritePhase phase, std::uint32_t system_error,
                  std::optional<std::uint64_t> file_offset = std::nullopt,
                  std::optional<ChunkType> chunk_type = std::nullopt)
      : std::runtime_error{message},
        phase_{phase},
        system_error_{system_error},
        file_offset_{file_offset},
        chunk_type_{chunk_type} {}

  [[nodiscard]] TraceWritePhase phase() const noexcept { return phase_; }
  [[nodiscard]] std::uint32_t system_error() const noexcept { return system_error_; }
  [[nodiscard]] std::optional<std::uint64_t> file_offset() const noexcept { return file_offset_; }
  [[nodiscard]] std::optional<ChunkType> chunk_type() const noexcept { return chunk_type_; }

 private:
  TraceWritePhase phase_{TraceWritePhase::kNone};
  std::uint32_t system_error_{0U};
  std::optional<std::uint64_t> file_offset_;
  std::optional<ChunkType> chunk_type_;
};

class TraceWriter {
 public:
  TraceWriter(std::ostream& output, const FileHeader& header, TraceWriterOptions options = {});

  TraceWriter(const TraceWriter&) = delete;
  TraceWriter& operator=(const TraceWriter&) = delete;

  [[nodiscard]] ChunkWriteResult write_chunk(const ChunkDescriptor& descriptor,
                                             std::span<const std::byte> uncompressed_payload);
  void release_file_reserve() noexcept;
  void flush();

  [[nodiscard]] std::uint64_t bytes_written() const noexcept;
  [[nodiscard]] std::uint64_t uncompressed_payload_bytes_written() const noexcept;
  [[nodiscard]] std::uint64_t stored_payload_bytes_written() const noexcept;
  [[nodiscard]] std::uint64_t remaining_bytes() const noexcept;

 private:
  std::ostream& output_;
  TraceWriterOptions options_;
  std::uint64_t bytes_written_{0};
  std::uint64_t uncompressed_payload_bytes_written_{0};
  std::uint64_t stored_payload_bytes_written_{0};
};

}  // namespace noleax::trace
