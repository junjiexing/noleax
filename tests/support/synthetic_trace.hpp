#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/trace_reader.hpp"
#include "noleax/trace/trace_writer.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::testing {

struct SyntheticTraceOptions {
  noleax::trace::CompressionCodec codec{noleax::trace::CompressionCodec::kLz4};
  noleax::trace::TraceWriterOptions writer_options;
  std::uint32_t maximum_record_size{noleax::trace::kDefaultMaximumRecordSize};
};

class SyntheticTraceError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class SyntheticTraceBuilder {
 public:
  SyntheticTraceBuilder(noleax::trace::FileHeader file_header,
                        noleax::trace::CaptureScope capture_scope,
                        SyntheticTraceOptions options = {});

  SyntheticTraceBuilder& add_event(const noleax::trace::Event& event);
  SyntheticTraceBuilder& add_loss(const noleax::trace::LossRecord& loss);
  SyntheticTraceBuilder& set_statistics(const noleax::trace::CaptureStatistics& statistics);
  SyntheticTraceBuilder& set_end_of_trace(const noleax::trace::EndOfTrace& end);
  SyntheticTraceBuilder& finish_normally(std::optional<std::int32_t> target_exit_code = 0);

  [[nodiscard]] std::string build() const;

 private:
  using EventRecord = std::variant<noleax::trace::Event, noleax::trace::LossRecord>;

  noleax::trace::FileHeader file_header_;
  noleax::trace::CaptureScope capture_scope_;
  SyntheticTraceOptions options_;
  std::vector<EventRecord> event_records_;
  std::optional<noleax::trace::CaptureStatistics> statistics_;
  std::optional<noleax::trace::EndOfTrace> end_;
};

[[nodiscard]] std::vector<noleax::trace::Event> make_all_memory_event_kinds();

}  // namespace noleax::testing
