#include "noleax/analyzer/event_stream.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/record_codec.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/trace_reader.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {
namespace {

struct RecordBounds {
  std::uint64_t sequence_begin{0};
  std::uint64_t sequence_end{0};
  std::uint64_t maximum_ticks{0};

  void include_sequence(std::uint64_t begin, std::uint64_t end) noexcept {
    if (sequence_begin == 0U || begin < sequence_begin) {
      sequence_begin = begin;
    }
    sequence_end = std::max(sequence_end, end);
  }

  void include_ticks(std::uint64_t ticks) noexcept {
    maximum_ticks = std::max(maximum_ticks, ticks);
  }
};

void checked_increment(std::uint64_t& value, const char* subject) {
  if (value == std::numeric_limits<std::uint64_t>::max()) {
    throw TraceAnalysisError{std::string{subject} + " count overflow"};
  }
  ++value;
}

[[nodiscard]] bool descriptor_has_sequence(
    const noleax::trace::ChunkDescriptor& descriptor) noexcept {
  return descriptor.sequence_begin.is_valid();
}

void require_empty_sequence_range(const noleax::trace::ChunkDescriptor& descriptor) {
  if (descriptor_has_sequence(descriptor)) {
    throw TraceAnalysisError{"non-event chunk has an event sequence range"};
  }
}

void validate_event_sequence_range(const noleax::trace::ChunkDescriptor& descriptor,
                                   const RecordBounds& bounds, bool skipped_unknown_record) {
  const bool descriptor_has_range = descriptor_has_sequence(descriptor);
  const bool records_have_range = bounds.sequence_begin != 0U;
  if (records_have_range && !descriptor_has_range) {
    throw TraceAnalysisError{"event chunk omits the sequence range of its records"};
  }
  if (!records_have_range && !skipped_unknown_record && descriptor_has_range) {
    throw TraceAnalysisError{"event chunk declares a sequence range without sequenced records"};
  }
  if (!records_have_range) {
    return;
  }

  const std::uint64_t descriptor_begin = descriptor.sequence_begin.value();
  const std::uint64_t descriptor_end = descriptor.sequence_end.value();
  if (skipped_unknown_record) {
    if (descriptor_begin > bounds.sequence_begin || descriptor_end < bounds.sequence_end) {
      throw TraceAnalysisError{"event chunk sequence range does not cover its known records"};
    }
    return;
  }
  if (descriptor_begin != bounds.sequence_begin || descriptor_end != bounds.sequence_end) {
    throw TraceAnalysisError{"event chunk sequence range does not match its records"};
  }
}

class EventStreamDecoder {
 public:
  EventStreamDecoder(std::istream& input, const EventStreamCallbacks& callbacks,
                     EventStreamOptions options)
      : reader_{input, options.reader_options},
        callbacks_{callbacks},
        maximum_record_size_{options.maximum_record_size} {
    result_.file_header = reader_.file_header();
  }

  [[nodiscard]] EventStreamResult run() {
    if (callbacks_.on_file_header) {
      callbacks_.on_file_header(result_.file_header);
    }
    synchronize_reader_understanding();

    while (true) {
      auto read_result = reader_.read_next_chunk();
      synchronize_reader_understanding();
      if (read_result.status == noleax::trace::ChunkReadStatus::kEndOfFile) {
        break;
      }
      if (read_result.status == noleax::trace::ChunkReadStatus::kTruncated) {
        result_.truncated = true;
        mark_trace_truncated();
        break;
      }
      if (!read_result.chunk.has_value()) {
        throw TraceAnalysisError{"trace reader returned a chunk status without a chunk"};
      }
      if (saw_end_chunk_) {
        throw TraceAnalysisError{"trace contains a chunk after EndOfTrace"};
      }
      process_chunk(*read_result.chunk);
    }

    if (!capture_scope_.has_value() || !completeness_.has_value()) {
      throw TraceAnalysisError{"trace does not contain a CaptureScope record"};
    }
    result_.capture_scope = *capture_scope_;
    result_.completeness = completeness_->report();
    result_.bytes_read = reader_.bytes_read();
    result_.partially_understood =
        result_.completeness.understanding_state() == noleax::trace::UnderstandingState::kPartial;
    return result_;
  }

 private:
  void process_chunk(const noleax::trace::TraceChunk& chunk) {
    const auto& descriptor = chunk.header.descriptor;
    if (descriptor.flags != 0U) {
      mark_partially_understood();
    }
    if (descriptor.type == noleax::trace::ChunkType::kEvent) {
      require_capture_scope("event chunk appears before CaptureScope");
      if (result_.statistics.has_value()) {
        throw TraceAnalysisError{"trace contains events after CaptureStatistics"};
      }
    }
    if (descriptor.version != 1U) {
      mark_partially_understood();
      if (descriptor.type == noleax::trace::ChunkType::kEvent) {
        mark_unknown_event_data();
        include_future_event_range(descriptor);
      } else {
        mark_unknown_record_skipped();
      }
      if (descriptor.type == noleax::trace::ChunkType::kEnd) {
        saw_end_chunk_ = true;
      }
      return;
    }

    switch (descriptor.type) {
      case noleax::trace::ChunkType::kMetadata:
        require_empty_sequence_range(descriptor);
        process_metadata(chunk.payload);
        break;
      case noleax::trace::ChunkType::kModule:
        require_empty_sequence_range(descriptor);
        process_modules(chunk.payload);
        break;
      case noleax::trace::ChunkType::kStack:
        require_empty_sequence_range(descriptor);
        process_stacks(chunk.payload);
        break;
      case noleax::trace::ChunkType::kEvent:
        process_events(descriptor, chunk.payload);
        break;
      case noleax::trace::ChunkType::kStatistics:
        require_empty_sequence_range(descriptor);
        process_statistics(chunk.payload);
        break;
      case noleax::trace::ChunkType::kEnd:
        require_empty_sequence_range(descriptor);
        process_end_of_trace(chunk.payload);
        saw_end_chunk_ = true;
        break;
    }
  }

  void process_metadata(std::span<const std::byte> payload) {
    noleax::trace::RecordCursor cursor{payload, maximum_record_size_};
    std::optional<noleax::trace::CaptureScope> decoded_scope;
    std::vector<noleax::trace::CustomHookDefinition> decoded_custom_hooks;
    bool skipped_unknown = false;
    while (const auto record = cursor.next()) {
      auto scope = noleax::trace::decode_capture_scope_record(*record);
      if (scope.has_value()) {
        if (decoded_scope.has_value() || capture_scope_.has_value()) {
          throw TraceAnalysisError{"trace contains more than one CaptureScope record"};
        }
        decoded_scope = *scope;
        continue;
      }
      auto custom_hook = noleax::trace::decode_custom_hook_definition_record(*record);
      if (custom_hook.has_value()) {
        if (custom_hook_api_ids_.contains(custom_hook->api_id)) {
          throw TraceAnalysisError{"trace contains a duplicate CustomHookDefinition api_id"};
        }
        custom_hook_api_ids_.insert(custom_hook->api_id);
        decoded_custom_hooks.push_back(std::move(*custom_hook));
        continue;
      }
      skipped_unknown = true;
    }

    if (decoded_scope.has_value()) {
      capture_scope_ = *decoded_scope;
      completeness_.emplace(*capture_scope_);
      apply_pending_completeness();
      if (callbacks_.on_capture_scope) {
        callbacks_.on_capture_scope(*capture_scope_);
      }
    }
    if (skipped_unknown) {
      mark_unknown_record_skipped();
    }
    for (const auto& definition : decoded_custom_hooks) {
      result_.custom_hooks.push_back(definition);
      if (callbacks_.on_custom_hook_definition) {
        callbacks_.on_custom_hook_definition(definition);
      }
    }
  }

  struct ModuleState {
    noleax::trace::ModuleLoad load;
    bool live{true};
  };

  static void validate_module_range(const noleax::trace::ModuleLoad& load,
                                    const std::map<std::uint64_t, std::uint64_t>& live_modules,
                                    const std::unordered_map<std::uint64_t, ModuleState>& states) {
    const std::uint64_t end = load.base_address + load.image_size;
    const auto next = live_modules.lower_bound(load.base_address);
    if (next != live_modules.end()) {
      const auto state = states.find(next->second);
      if (state == states.end() || state->second.load.base_address < end) {
        throw TraceAnalysisError{"live module address ranges overlap"};
      }
    }
    if (next != live_modules.begin()) {
      const auto previous = std::prev(next);
      const auto state = states.find(previous->second);
      if (state == states.end() ||
          state->second.load.base_address + state->second.load.image_size > load.base_address) {
        throw TraceAnalysisError{"live module address ranges overlap"};
      }
    }
  }

  void process_modules(std::span<const std::byte> payload) {
    require_capture_scope("module record appears before CaptureScope");
    noleax::trace::RecordCursor cursor{payload, maximum_record_size_};
    std::vector<noleax::trace::ModuleRecord> records;
    bool skipped_unknown = false;
    while (const auto record = cursor.next()) {
      auto decoded = noleax::trace::decode_module_record(*record);
      if (!decoded.has_value()) {
        skipped_unknown = true;
        continue;
      }
      records.push_back(std::move(*decoded));
    }

    auto states = module_states_;
    auto live_modules = live_modules_;
    std::uint64_t previous_ticks = previous_module_ticks_;
    for (const auto& record : records) {
      const std::uint64_t ticks =
          std::visit([](const auto& value) { return value.monotonic_ticks; }, record);
      if (ticks < result_.file_header.monotonic_origin) {
        throw TraceAnalysisError{"module record monotonic time precedes the trace origin"};
      }
      if (ticks < previous_ticks) {
        throw TraceAnalysisError{"module record monotonic ticks move backwards"};
      }
      previous_ticks = ticks;

      if (const auto* load = std::get_if<noleax::trace::ModuleLoad>(&record)) {
        if (states.contains(load->module_id.value())) {
          throw TraceAnalysisError{"trace contains a duplicate ModuleLoad ID"};
        }
        validate_module_range(*load, live_modules, states);
        states.emplace(load->module_id.value(), ModuleState{*load, true});
        if (!live_modules.emplace(load->base_address, load->module_id.value()).second) {
          throw TraceAnalysisError{"trace loads two live modules at the same base"};
        }
      } else {
        const auto& unload = std::get<noleax::trace::ModuleUnload>(record);
        const auto state = states.find(unload.module_id.value());
        if (state == states.end() || !state->second.live) {
          throw TraceAnalysisError{"ModuleUnload does not reference a live module generation"};
        }
        if (unload.monotonic_ticks < state->second.load.monotonic_ticks) {
          throw TraceAnalysisError{"ModuleUnload precedes its ModuleLoad"};
        }
        live_modules.erase(state->second.load.base_address);
        state->second.live = false;
      }
    }

    module_states_ = std::move(states);
    live_modules_ = std::move(live_modules);
    previous_module_ticks_ = previous_ticks;
    result_.known_monotonic_end = std::max(result_.known_monotonic_end, previous_ticks);
    if (skipped_unknown) {
      mark_unknown_record_skipped();
    }
    for (const auto& record : records) {
      if (const auto* load = std::get_if<noleax::trace::ModuleLoad>(&record)) {
        checked_increment(result_.module_load_count, "module load");
        if (callbacks_.on_module_load) {
          callbacks_.on_module_load(*load);
        }
      } else {
        const auto& unload = std::get<noleax::trace::ModuleUnload>(record);
        checked_increment(result_.module_unload_count, "module unload");
        if (callbacks_.on_module_unload) {
          callbacks_.on_module_unload(unload);
        }
      }
    }
  }

  void process_stacks(std::span<const std::byte> payload) {
    require_capture_scope("StackDefinition appears before CaptureScope");
    noleax::trace::RecordCursor cursor{payload, maximum_record_size_};
    std::vector<noleax::trace::StackDefinition> definitions;
    std::unordered_set<std::uint64_t> chunk_ids;
    bool skipped_unknown = false;
    while (const auto record = cursor.next()) {
      auto definition = noleax::trace::decode_stack_definition_record(*record);
      if (!definition.has_value()) {
        skipped_unknown = true;
        continue;
      }
      const std::uint64_t stack_id = definition->stack_id.value();
      if (stack_ids_.contains(stack_id) || !chunk_ids.insert(stack_id).second) {
        throw TraceAnalysisError{"trace contains a duplicate StackDefinition ID"};
      }
      for (const auto& frame : definition->frames) {
        if (!frame.module_id) {
          continue;
        }
        const auto module = module_states_.find(frame.module_id.value());
        if (module == module_states_.end()) {
          throw TraceAnalysisError{"StackDefinition references an unknown module generation"};
        }
        if (frame.module_offset >= module->second.load.image_size ||
            module->second.load.base_address + frame.module_offset != frame.absolute_address) {
          throw TraceAnalysisError{"StackDefinition module-relative frame is inconsistent"};
        }
      }
      definitions.push_back(std::move(*definition));
    }
    if (skipped_unknown) {
      mark_unknown_record_skipped();
    }
    for (const auto& definition : definitions) {
      stack_ids_.insert(definition.stack_id.value());
      checked_increment(result_.stack_definition_count, "stack definition");
      if (callbacks_.on_stack_definition) {
        callbacks_.on_stack_definition(definition);
      }
    }
  }

  void process_events(const noleax::trace::ChunkDescriptor& descriptor,
                      std::span<const std::byte> payload) {
    require_capture_scope("event chunk appears before CaptureScope");
    if (result_.statistics.has_value()) {
      throw TraceAnalysisError{"trace contains events after CaptureStatistics"};
    }

    noleax::trace::RecordCursor cursor{payload, maximum_record_size_};
    std::vector<noleax::trace::EventChunkRecord> records;
    RecordBounds bounds;
    bool skipped_unknown = false;
    std::uint64_t previous_sequence = previous_event_sequence_;
    std::uint64_t previous_ticks = previous_event_ticks_;
    bool has_previous_event = saw_event_;

    while (const auto record = cursor.next()) {
      auto decoded = noleax::trace::decode_event_chunk_record(*record);
      if (!decoded.has_value()) {
        skipped_unknown = true;
        continue;
      }
      if (const auto* event = std::get_if<noleax::trace::Event>(&*decoded)) {
        if (event->header.monotonic_ticks < result_.file_header.monotonic_origin) {
          throw TraceAnalysisError{"event monotonic time precedes the trace origin"};
        }
        const std::uint64_t sequence = event->header.sequence.value();
        if (has_previous_event && sequence <= previous_sequence) {
          throw TraceAnalysisError{"event sequences are not strictly increasing"};
        }
        if (has_previous_event && event->header.monotonic_ticks < previous_ticks) {
          throw TraceAnalysisError{"event monotonic ticks move backwards"};
        }
        previous_sequence = sequence;
        previous_ticks = event->header.monotonic_ticks;
        has_previous_event = true;
        bounds.include_sequence(sequence, sequence);
        bounds.include_ticks(event->header.monotonic_ticks);
      } else {
        const auto& loss = std::get<noleax::trace::LossRecord>(*decoded);
        if (loss.sequence_range.has_value()) {
          bounds.include_sequence(loss.sequence_range->begin.value(),
                                  loss.sequence_range->end.value());
        }
        if (loss.tick_range.has_value()) {
          if (loss.tick_range->begin < result_.file_header.monotonic_origin) {
            throw TraceAnalysisError{"Loss tick range precedes the trace origin"};
          }
          bounds.include_ticks(loss.tick_range->end);
        }
      }
      records.push_back(*decoded);
    }

    validate_event_sequence_range(descriptor, bounds, skipped_unknown);
    if (skipped_unknown) {
      mark_unknown_event_data();
    }
    previous_event_sequence_ = previous_sequence;
    previous_event_ticks_ = previous_ticks;
    saw_event_ = has_previous_event;
    include_known_bounds(bounds);

    for (const auto& record : records) {
      if (const auto* event = std::get_if<noleax::trace::Event>(&record)) {
        checked_increment(result_.event_count, "event");
        checked_increment(events_per_api_[event->header.api_id], "per-API event");
        if (callbacks_.on_event) {
          callbacks_.on_event(*event);
        }
      } else {
        const auto& loss = std::get<noleax::trace::LossRecord>(record);
        checked_increment(result_.loss_record_count, "Loss record");
        completeness_->observe_loss(loss);
        if (callbacks_.on_loss) {
          callbacks_.on_loss(loss);
        }
      }
    }
  }

  void process_statistics(std::span<const std::byte> payload) {
    require_capture_scope("CaptureStatistics appears before CaptureScope");
    noleax::trace::RecordCursor cursor{payload, maximum_record_size_};
    std::optional<noleax::trace::CaptureStatistics> decoded_statistics;
    bool skipped_unknown = false;
    while (const auto record = cursor.next()) {
      auto statistics = noleax::trace::decode_statistics_record(*record);
      if (!statistics.has_value()) {
        skipped_unknown = true;
        continue;
      }
      if (decoded_statistics.has_value() || result_.statistics.has_value()) {
        throw TraceAnalysisError{"trace contains more than one CaptureStatistics record"};
      }
      decoded_statistics = std::move(*statistics);
    }
    if (skipped_unknown) {
      mark_unknown_record_skipped();
    }
    if (!decoded_statistics.has_value()) {
      return;
    }

    const std::uint64_t recorded_events = decoded_statistics->observed_calls -
                                          decoded_statistics->filtered_before_queue -
                                          decoded_statistics->dropped_events;
    if (recorded_events < result_.event_count ||
        (!may_have_unknown_events_ && recorded_events != result_.event_count)) {
      throw TraceAnalysisError{"CaptureStatistics does not match decoded event count"};
    }
    std::unordered_map<noleax::trace::ApiId, std::uint64_t> statistics_per_api;
    statistics_per_api.reserve(decoded_statistics->per_api.size());
    for (const auto& api : decoded_statistics->per_api) {
      statistics_per_api.emplace(
          api.api_id, api.observed_calls - api.filtered_before_queue - api.dropped_events);
    }
    for (const auto& [api_id, known_count] : events_per_api_) {
      const auto statistics = statistics_per_api.find(api_id);
      if (statistics == statistics_per_api.end() || statistics->second < known_count ||
          (!may_have_unknown_events_ && statistics->second != known_count)) {
        throw TraceAnalysisError{"CaptureStatistics does not match decoded per-API events"};
      }
    }
    result_.statistics = std::move(*decoded_statistics);
    if (callbacks_.on_statistics) {
      callbacks_.on_statistics(*result_.statistics);
    }
  }

  void process_end_of_trace(std::span<const std::byte> payload) {
    require_capture_scope("EndOfTrace appears before CaptureScope");
    noleax::trace::RecordCursor cursor{payload, maximum_record_size_};
    std::optional<noleax::trace::EndOfTrace> decoded_end;
    bool skipped_unknown = false;
    while (const auto record = cursor.next()) {
      auto end = noleax::trace::decode_end_of_trace_record(*record);
      if (!end.has_value()) {
        skipped_unknown = true;
        continue;
      }
      if (decoded_end.has_value() || result_.end_of_trace.has_value()) {
        throw TraceAnalysisError{"trace contains more than one EndOfTrace record"};
      }
      decoded_end = *end;
    }
    if (skipped_unknown) {
      mark_unknown_record_skipped();
    }
    if (!decoded_end.has_value()) {
      return;
    }
    if (decoded_end->final_monotonic_ticks < result_.file_header.monotonic_origin) {
      throw TraceAnalysisError{"EndOfTrace monotonic time precedes the trace origin"};
    }
    if (decoded_end->final_sequence < result_.known_sequence_end ||
        decoded_end->final_monotonic_ticks < result_.known_monotonic_end) {
      throw TraceAnalysisError{"EndOfTrace precedes decoded event or Loss bounds"};
    }

    completeness_->observe_end_of_trace(*decoded_end);
    result_.end_of_trace = *decoded_end;
    if (callbacks_.on_end_of_trace) {
      callbacks_.on_end_of_trace(*result_.end_of_trace);
    }
  }

  void include_known_bounds(const RecordBounds& bounds) noexcept {
    if (bounds.sequence_end > result_.known_sequence_end.value()) {
      result_.known_sequence_end = noleax::trace::Sequence{bounds.sequence_end};
    }
    result_.known_monotonic_end = std::max(result_.known_monotonic_end, bounds.maximum_ticks);
  }

  void include_future_event_range(const noleax::trace::ChunkDescriptor& descriptor) noexcept {
    if (descriptor.sequence_end > result_.known_sequence_end) {
      result_.known_sequence_end = descriptor.sequence_end;
    }
  }

  void require_capture_scope(const char* message) const {
    if (!capture_scope_.has_value() || !completeness_.has_value()) {
      throw TraceAnalysisError{message};
    }
  }

  void synchronize_reader_understanding() {
    if (reader_.partially_understood() && !reader_partial_marked_) {
      reader_partial_marked_ = true;
      may_have_unknown_events_ = true;
      mark_partially_understood();
    }
  }

  void mark_unknown_event_data() {
    may_have_unknown_events_ = true;
    mark_unknown_record_skipped();
  }

  void mark_unknown_record_skipped() {
    if (completeness_.has_value()) {
      completeness_->mark_unknown_record_skipped();
    } else {
      pending_unknown_record_ = true;
    }
  }

  void mark_partially_understood() {
    if (completeness_.has_value()) {
      completeness_->mark_partially_understood_format();
    } else {
      pending_partial_format_ = true;
    }
  }

  void mark_trace_truncated() {
    if (completeness_.has_value()) {
      completeness_->mark_trace_truncated();
    } else {
      pending_truncated_ = true;
    }
  }

  void apply_pending_completeness() {
    if (pending_unknown_record_) {
      completeness_->mark_unknown_record_skipped();
    }
    if (pending_partial_format_) {
      completeness_->mark_partially_understood_format();
    }
    if (pending_truncated_) {
      completeness_->mark_trace_truncated();
    }
  }

  noleax::trace::TraceReader reader_;
  const EventStreamCallbacks& callbacks_;
  std::uint32_t maximum_record_size_;
  EventStreamResult result_;
  std::optional<noleax::trace::CaptureScope> capture_scope_;
  std::optional<noleax::trace::CompletenessTracker> completeness_;
  std::unordered_set<noleax::trace::ApiId> custom_hook_api_ids_;
  std::unordered_map<noleax::trace::ApiId, std::uint64_t> events_per_api_;
  std::unordered_map<std::uint64_t, ModuleState> module_states_;
  std::map<std::uint64_t, std::uint64_t> live_modules_;
  std::unordered_set<std::uint64_t> stack_ids_;
  std::uint64_t previous_module_ticks_{0};
  std::uint64_t previous_event_sequence_{0};
  std::uint64_t previous_event_ticks_{0};
  bool saw_event_{false};
  bool saw_end_chunk_{false};
  bool may_have_unknown_events_{false};
  bool reader_partial_marked_{false};
  bool pending_unknown_record_{false};
  bool pending_partial_format_{false};
  bool pending_truncated_{false};
};

}  // namespace

EventStreamResult analyze_event_stream(std::istream& input, const EventStreamCallbacks& callbacks,
                                       EventStreamOptions options) {
  return EventStreamDecoder{input, callbacks, options}.run();
}

}  // namespace noleax::analyzer
