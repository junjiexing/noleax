#include "support/synthetic_trace.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/record_codec.hpp"
#include "noleax/trace/trace_writer.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::testing {
namespace {

struct EventBounds {
  std::uint64_t sequence_begin{0};
  std::uint64_t sequence_end{0};
  std::uint64_t maximum_ticks{0};
  std::uint64_t event_count{0};
};

[[nodiscard]] EventBounds validate_and_measure(
    std::span<const std::variant<noleax::trace::Event, noleax::trace::LossRecord>> records,
    std::uint64_t monotonic_origin) {
  EventBounds bounds;
  std::uint64_t previous_sequence = 0U;
  std::uint64_t previous_ticks = 0U;
  bool has_event = false;

  const auto include_sequence_range = [&bounds](std::uint64_t begin, std::uint64_t end) {
    if (bounds.sequence_begin == 0U || begin < bounds.sequence_begin) {
      bounds.sequence_begin = begin;
    }
    bounds.sequence_end = std::max(bounds.sequence_end, end);
  };

  for (const auto& record : records) {
    if (const auto* event = std::get_if<noleax::trace::Event>(&record)) {
      noleax::trace::validate_event(*event);
      if (event->header.monotonic_ticks < monotonic_origin) {
        throw SyntheticTraceError{"synthetic event ticks precede the trace origin"};
      }
      const std::uint64_t sequence = event->header.sequence.value();
      if (has_event && sequence <= previous_sequence) {
        throw SyntheticTraceError{"synthetic event sequences must be strictly increasing"};
      }
      if (has_event && event->header.monotonic_ticks < previous_ticks) {
        throw SyntheticTraceError{"synthetic event ticks must not move backwards"};
      }
      include_sequence_range(sequence, sequence);
      previous_sequence = sequence;
      previous_ticks = event->header.monotonic_ticks;
      bounds.maximum_ticks = std::max(bounds.maximum_ticks, event->header.monotonic_ticks);
      if (bounds.event_count == std::numeric_limits<std::uint64_t>::max()) {
        throw SyntheticTraceError{"synthetic event count overflow"};
      }
      ++bounds.event_count;
      has_event = true;
      continue;
    }

    const auto& loss = std::get<noleax::trace::LossRecord>(record);
    noleax::trace::validate_loss_record(loss);
    if (loss.sequence_range.has_value()) {
      include_sequence_range(loss.sequence_range->begin.value(), loss.sequence_range->end.value());
    }
    if (loss.tick_range.has_value()) {
      if (loss.tick_range->begin < monotonic_origin) {
        throw SyntheticTraceError{"synthetic Loss ticks precede the trace origin"};
      }
      bounds.maximum_ticks = std::max(bounds.maximum_ticks, loss.tick_range->end);
    }
  }
  return bounds;
}

void require_written(noleax::trace::TraceWriter& writer,
                     const noleax::trace::ChunkDescriptor& descriptor,
                     std::span<const std::byte> payload) {
  if (writer.write_chunk(descriptor, payload) != noleax::trace::ChunkWriteResult::kWritten) {
    throw SyntheticTraceError{"synthetic trace reached its configured file size limit"};
  }
}

[[nodiscard]] noleax::trace::EventHeader event_header(std::uint64_t sequence) {
  noleax::trace::EventHeader header;
  header.sequence = noleax::trace::Sequence{sequence};
  header.monotonic_ticks = sequence * 10U;
  header.thread_id = 7U;
  header.api_id = static_cast<noleax::trace::ApiId>(sequence);
  header.status = noleax::trace::EventStatus::kSuccess;
  header.stack_id = noleax::trace::StackId{sequence + 100U};
  return header;
}

}  // namespace

SyntheticTraceBuilder::SyntheticTraceBuilder(noleax::trace::FileHeader file_header,
                                             noleax::trace::CaptureScope capture_scope,
                                             SyntheticTraceOptions options)
    : file_header_{file_header}, capture_scope_{capture_scope}, options_{options} {
  noleax::trace::validate_capture_scope(capture_scope_);
  if (options_.maximum_record_size < noleax::trace::kRecordHeaderSize) {
    throw SyntheticTraceError{"maximum synthetic record size is smaller than its header"};
  }
}

SyntheticTraceBuilder& SyntheticTraceBuilder::add_event(const noleax::trace::Event& event) {
  if (end_.has_value()) {
    throw SyntheticTraceError{"cannot add an event after EndOfTrace"};
  }
  noleax::trace::validate_event(event);
  event_records_.emplace_back(event);
  return *this;
}

SyntheticTraceBuilder& SyntheticTraceBuilder::add_loss(const noleax::trace::LossRecord& loss) {
  if (end_.has_value()) {
    throw SyntheticTraceError{"cannot add Loss after EndOfTrace"};
  }
  noleax::trace::validate_loss_record(loss);
  event_records_.emplace_back(loss);
  return *this;
}

SyntheticTraceBuilder& SyntheticTraceBuilder::set_statistics(
    const noleax::trace::CaptureStatistics& statistics) {
  if (statistics_.has_value()) {
    throw SyntheticTraceError{"synthetic trace already has Statistics"};
  }
  noleax::trace::validate_statistics(statistics);
  statistics_ = statistics;
  return *this;
}

SyntheticTraceBuilder& SyntheticTraceBuilder::set_end_of_trace(
    const noleax::trace::EndOfTrace& end) {
  if (end_.has_value()) {
    throw SyntheticTraceError{"synthetic trace already has EndOfTrace"};
  }
  noleax::trace::validate_end_of_trace(end);
  end_ = end;
  return *this;
}

SyntheticTraceBuilder& SyntheticTraceBuilder::finish_normally(
    std::optional<std::int32_t> target_exit_code) {
  if (end_.has_value()) {
    throw SyntheticTraceError{"synthetic trace already has EndOfTrace"};
  }
  const EventBounds bounds = validate_and_measure(event_records_, file_header_.monotonic_origin);
  noleax::trace::CompletenessTracker tracker{capture_scope_};
  for (const auto& record : event_records_) {
    if (const auto* loss = std::get_if<noleax::trace::LossRecord>(&record)) {
      tracker.observe_loss(*loss);
    }
  }

  noleax::trace::EndOfTrace end;
  end.final_sequence = noleax::trace::Sequence{bounds.sequence_end};
  end.final_monotonic_ticks = std::max(bounds.maximum_ticks, file_header_.monotonic_origin);
  end.normal_stop = true;
  end.target_exit_code = target_exit_code;
  end.aggregate_completeness = tracker.report();
  end.aggregate_completeness.remove(noleax::trace::CompletenessIssue::kMissingEndOfTrace);
  end_ = end;
  return *this;
}

std::string SyntheticTraceBuilder::build() const {
  const EventBounds bounds = validate_and_measure(event_records_, file_header_.monotonic_origin);
  if (statistics_.has_value()) {
    const std::uint64_t recorded_events = statistics_->observed_calls -
                                          statistics_->filtered_before_queue -
                                          statistics_->dropped_events;
    if (recorded_events != bounds.event_count) {
      throw SyntheticTraceError{
          "synthetic Statistics recorded-event count does not match encoded events"};
    }
  }
  if (end_.has_value()) {
    if (end_->final_sequence.value() < bounds.sequence_end ||
        end_->final_monotonic_ticks <
            std::max(bounds.maximum_ticks, file_header_.monotonic_origin)) {
      throw SyntheticTraceError{"synthetic EndOfTrace precedes encoded events or Loss ranges"};
    }
  }

  std::ostringstream output{std::ios::binary};
  noleax::trace::TraceWriter writer{output, file_header_, options_.writer_options};

  std::vector<std::byte> metadata_payload;
  noleax::trace::append_capture_scope_record(metadata_payload, capture_scope_,
                                             options_.maximum_record_size);
  noleax::trace::ChunkDescriptor metadata_descriptor;
  metadata_descriptor.type = noleax::trace::ChunkType::kMetadata;
  metadata_descriptor.codec = options_.codec;
  require_written(writer, metadata_descriptor, metadata_payload);

  if (!event_records_.empty()) {
    std::vector<std::byte> event_payload;
    for (const auto& record : event_records_) {
      if (const auto* event = std::get_if<noleax::trace::Event>(&record)) {
        noleax::trace::append_event_record(event_payload, *event, options_.maximum_record_size);
      } else {
        noleax::trace::append_loss_record(event_payload,
                                          std::get<noleax::trace::LossRecord>(record),
                                          options_.maximum_record_size);
      }
    }
    noleax::trace::ChunkDescriptor event_descriptor;
    event_descriptor.type = noleax::trace::ChunkType::kEvent;
    event_descriptor.codec = options_.codec;
    event_descriptor.sequence_begin = noleax::trace::Sequence{bounds.sequence_begin};
    event_descriptor.sequence_end = noleax::trace::Sequence{bounds.sequence_end};
    require_written(writer, event_descriptor, event_payload);
  }

  if (statistics_.has_value()) {
    std::vector<std::byte> statistics_payload;
    noleax::trace::append_statistics_record(statistics_payload, *statistics_,
                                            options_.maximum_record_size);
    noleax::trace::ChunkDescriptor statistics_descriptor;
    statistics_descriptor.type = noleax::trace::ChunkType::kStatistics;
    statistics_descriptor.codec = options_.codec;
    require_written(writer, statistics_descriptor, statistics_payload);
  }

  if (end_.has_value()) {
    std::vector<std::byte> end_payload;
    noleax::trace::append_end_of_trace_record(end_payload, *end_, options_.maximum_record_size);
    noleax::trace::ChunkDescriptor end_descriptor;
    end_descriptor.type = noleax::trace::ChunkType::kEnd;
    end_descriptor.codec = options_.codec;
    require_written(writer, end_descriptor, end_payload);
  }

  writer.flush();
  return output.str();
}

std::vector<noleax::trace::Event> make_all_memory_event_kinds() {
  using namespace noleax::trace;
  std::vector<Event> events;

  HeapCreateEvent heap_create;
  heap_create.heap_handle = 0x1000U;
  heap_create.heap_id = HeapId{1U};
  heap_create.heap_flags = 2U;
  heap_create.reserve_size = 4096U;
  heap_create.commit_size = 1024U;
  events.emplace_back(Event{event_header(1U), heap_create});

  HeapDestroyEvent heap_destroy;
  heap_destroy.heap_handle = 0x1000U;
  heap_destroy.heap_id = HeapId{1U};
  heap_destroy.raw_result = 1U;
  events.emplace_back(Event{event_header(2U), heap_destroy});

  AllocationEvent allocation;
  allocation.heap_handle = 0x1000U;
  allocation.heap_id = HeapId{1U};
  allocation.requested_size = 64U;
  allocation.result_address = 0x2000U;
  allocation.allocation_id = AllocationId{10U};
  allocation.api_flags = 8U;
  events.emplace_back(Event{event_header(3U), allocation});

  ReallocationEvent reallocation;
  reallocation.heap_handle = 0x1000U;
  reallocation.heap_id = HeapId{1U};
  reallocation.old_address = 0x2000U;
  reallocation.old_allocation_id = AllocationId{10U};
  reallocation.requested_size = 128U;
  reallocation.result_address = 0x3000U;
  reallocation.new_allocation_id = AllocationId{11U};
  reallocation.api_flags = 9U;
  reallocation.effect = ReallocationEffect::kNewGeneration;
  events.emplace_back(Event{event_header(4U), reallocation});

  FreeEvent free_event;
  free_event.heap_handle = 0x1000U;
  free_event.heap_id = HeapId{1U};
  free_event.address = 0x3000U;
  free_event.allocation_id = AllocationId{11U};
  free_event.raw_result = 1U;
  free_event.api_flags = 10U;
  events.emplace_back(Event{event_header(5U), free_event});

  ProcessTarget current_process;
  current_process.scope = ProcessMemoryScope::kCurrentProcess;
  current_process.process_handle = 0xFFFFU;
  current_process.process_id = 42U;

  VmAllocateEvent vm_allocate;
  vm_allocate.target = current_process;
  vm_allocate.result_base = 0x4000U;
  vm_allocate.requested_size = 4096U;
  vm_allocate.result_size = 8192U;
  vm_allocate.allocation_type = 0x3000U;
  vm_allocate.protection = 4U;
  vm_allocate.mapping_id = MappingId{20U};
  events.emplace_back(Event{event_header(6U), vm_allocate});

  VmFreeEvent vm_free;
  vm_free.target = current_process;
  vm_free.base = 0x4000U;
  vm_free.free_type = 0x8000U;
  vm_free.mapping_id = MappingId{20U};
  events.emplace_back(Event{event_header(7U), vm_free});

  MapEvent map;
  map.section_handle = 0x1234U;
  map.target = current_process;
  map.result_base = 0x5000U;
  map.view_size = 16384U;
  map.section_offset = 4096U;
  map.protection = 2U;
  map.mapping_id = MappingId{21U};
  events.emplace_back(Event{event_header(8U), map});

  UnmapEvent unmap;
  unmap.target = current_process;
  unmap.base = 0x5000U;
  unmap.mapping_id = MappingId{21U};
  events.emplace_back(Event{event_header(9U), unmap});

  return events;
}

}  // namespace noleax::testing
