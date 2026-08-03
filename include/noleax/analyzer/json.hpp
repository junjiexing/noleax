#pragma once

#include <cstdint>
#include <iosfwd>
#include <stdexcept>

#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/outstanding.hpp"
#include "noleax/analyzer/presentation.hpp"
#include "noleax/analyzer/stacks.hpp"
#include "noleax/trace/completeness.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {

inline constexpr std::uint32_t kAnalysisJsonSchemaVersion = 1U;

class JsonFormatError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class JsonWriter {
 public:
  explicit JsonWriter(std::ostream& output);

  JsonWriter(const JsonWriter&) = delete;
  JsonWriter& operator=(const JsonWriter&) = delete;
  JsonWriter(JsonWriter&&) = delete;
  JsonWriter& operator=(JsonWriter&&) = delete;

  void begin_events(const noleax::trace::FileHeader& header,
                    const noleax::trace::CaptureScope& scope, const AnalysisFilter& filter);
  void write_event(const noleax::trace::Event& event, const EventPresentation& presentation = {});
  void write_loss(const noleax::trace::LossRecord& loss);
  void finish_events(const FilteredEventsResult& result);

  void write_outstanding(const OutstandingResult& result, const AnalysisFilter& filter,
                         const EventPresentationResolver& resolver = {});

  void write_event_stacks(const EventsStacksResult& result, const AnalysisFilter& filter,
                          const EventPresentationResolver& resolver = {});
  void write_leak_stacks(const LeaksStacksResult& result, const AnalysisFilter& filter,
                         const EventPresentationResolver& resolver = {});

 private:
  enum class State : std::uint8_t {
    kReady,
    kEvents,
    kFinished,
  };

  void write_document_prefix(const char* mode, const noleax::trace::FileHeader& header,
                             const noleax::trace::CaptureScope& scope,
                             const AnalysisFilter& filter);
  void write_event_object(const noleax::trace::Event& event, const EventPresentation& presentation);
  void write_event_payload(const noleax::trace::Event& event);
  void write_stack(const noleax::trace::Event& event, const EventPresentation& presentation);
  void write_summary(const EventStreamResult& trace);
  void write_completeness(const noleax::trace::CompletenessReport& completeness);
  void write_record_separator();
  void require_state(State expected, const char* operation) const;
  void ensure_output() const;

  std::ostream& output_;
  State state_{State::kReady};
  bool first_record_{true};
  std::uint64_t written_event_count_{0};
  std::uint64_t written_loss_count_{0};
  noleax::trace::FileHeader header_;
  noleax::trace::CaptureScope capture_scope_;
};

[[nodiscard]] FilteredEventsResult analyze_events_to_json(
    std::istream& input, std::ostream& output, const AnalysisFilter& filter,
    const EventMetadataResolver& filter_resolver = {},
    const EventPresentationResolver& presentation_resolver = {},
    EventStreamOptions stream_options = {}, FilteredEventsWindow window = {});

[[nodiscard]] OutstandingResult analyze_outstanding_to_json(
    std::istream& input, std::ostream& output, OutstandingWindow window,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver = {},
    const EventPresentationResolver& presentation_resolver = {},
    EventStreamOptions stream_options = {});

[[nodiscard]] EventsStacksResult analyze_event_stacks_to_json(
    std::istream& input, std::ostream& output, StacksWindow window, StacksSort sort,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver = {},
    const EventPresentationResolver& presentation_resolver = {},
    EventStreamOptions stream_options = {});

[[nodiscard]] LeaksStacksResult analyze_leak_stacks_to_json(
    std::istream& input, std::ostream& output, OutstandingWindow window, StacksSort sort,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver = {},
    const EventPresentationResolver& presentation_resolver = {},
    EventStreamOptions stream_options = {});

}  // namespace noleax::analyzer
