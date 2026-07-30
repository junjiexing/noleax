#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <span>
#include <stdexcept>

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

class TraceWriteError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
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
