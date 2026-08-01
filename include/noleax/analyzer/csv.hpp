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

inline constexpr std::uint32_t kAnalysisCsvSchemaVersion = 1U;

class CsvFormatError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class CsvWriter {
 public:
  explicit CsvWriter(std::ostream& output);

  CsvWriter(const CsvWriter&) = delete;
  CsvWriter& operator=(const CsvWriter&) = delete;
  CsvWriter(CsvWriter&&) = delete;
  CsvWriter& operator=(CsvWriter&&) = delete;

  void begin_events(const noleax::trace::FileHeader& header,
                    const noleax::trace::CaptureScope& scope);
  void write_event(const noleax::trace::Event& event, const EventPresentation& presentation = {});
  void write_loss(const noleax::trace::LossRecord& loss);
  void finish_events(const FilteredEventsResult& result);

  void write_outstanding(const OutstandingResult& result,
                         const EventPresentationResolver& resolver = {});

  void write_event_stacks(const EventsStacksResult& result,
                          const EventPresentationResolver& resolver = {});
  void write_leak_stacks(const LeaksStacksResult& result,
                         const EventPresentationResolver& resolver = {});

 private:
  enum class State : std::uint8_t {
    kReady,
    kEvents,
    kFinished,
  };

  void write_event_row(const noleax::trace::Event& event, const EventPresentation& presentation);
  void write_loss_row(const noleax::trace::LossRecord& loss);
  void write_event_summary(const FilteredEventsResult& result);
  void write_outstanding_row(const MemoryGeneration& generation,
                             const EventPresentation& presentation);
  void write_outstanding_summary(const OutstandingResult& result);
  void write_event_stacks_row(const EventsStacksGroup& group, std::uint64_t rank,
                              const EventPresentation& presentation);
  void write_event_stacks_summary(const EventsStacksResult& result);
  void write_leak_stacks_row(const LeaksStacksGroup& group, std::uint64_t rank,
                             const EventPresentation& presentation);
  void write_leak_stacks_summary(const LeaksStacksResult& result);
  void require_state(State expected, const char* operation) const;
  void ensure_output() const;

  std::ostream& output_;
  State state_{State::kReady};
  std::uint64_t written_event_count_{0};
  std::uint64_t written_loss_count_{0};
  noleax::trace::FileHeader header_;
  noleax::trace::CaptureScope capture_scope_;
};

[[nodiscard]] FilteredEventsResult analyze_events_to_csv(
    std::istream& input, std::ostream& output, const AnalysisFilter& filter,
    const EventMetadataResolver& filter_resolver = {},
    const EventPresentationResolver& presentation_resolver = {},
    EventStreamOptions stream_options = {});

[[nodiscard]] OutstandingResult analyze_outstanding_to_csv(
    std::istream& input, std::ostream& output, OutstandingWindow window,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver = {},
    const EventPresentationResolver& presentation_resolver = {},
    EventStreamOptions stream_options = {});

[[nodiscard]] EventsStacksResult analyze_event_stacks_to_csv(
    std::istream& input, std::ostream& output, StacksWindow window, StacksSort sort,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver = {},
    const EventPresentationResolver& presentation_resolver = {},
    EventStreamOptions stream_options = {});

[[nodiscard]] LeaksStacksResult analyze_leak_stacks_to_csv(
    std::istream& input, std::ostream& output, OutstandingWindow window, StacksSort sort,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver = {},
    const EventPresentationResolver& presentation_resolver = {},
    EventStreamOptions stream_options = {});

}  // namespace noleax::analyzer
