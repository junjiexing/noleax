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

struct ConsoleOptions {
  bool use_color{false};
};

using ConsoleStackFrame = ResolvedStackFrame;
using ConsoleStackStatus = StackCaptureStatus;
using ConsoleEventMetadata = EventPresentation;
using ConsoleMetadataResolver = EventPresentationResolver;

class ConsoleFormatError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class ConsoleWriter {
 public:
  explicit ConsoleWriter(std::ostream& output, ConsoleOptions options = {});

  ConsoleWriter(const ConsoleWriter&) = delete;
  ConsoleWriter& operator=(const ConsoleWriter&) = delete;
  ConsoleWriter(ConsoleWriter&&) = delete;
  ConsoleWriter& operator=(ConsoleWriter&&) = delete;

  void begin_events(const noleax::trace::FileHeader& header,
                    const noleax::trace::CaptureScope& scope);
  void write_event(const noleax::trace::Event& event, const ConsoleEventMetadata& metadata = {});
  void write_loss(const noleax::trace::LossRecord& loss);
  void finish_events(const FilteredEventsResult& result);

  void write_outstanding(const OutstandingResult& result,
                         const ConsoleMetadataResolver& resolver = {});

  void write_event_stacks(const EventsStacksResult& result,
                          const ConsoleMetadataResolver& resolver = {});
  void write_leak_stacks(const LeaksStacksResult& result,
                         const ConsoleMetadataResolver& resolver = {});

 private:
  enum class State : std::uint8_t {
    kReady,
    kEvents,
    kFinished,
  };

  void write_preamble(const char* title, const noleax::trace::FileHeader& header,
                      const noleax::trace::CaptureScope& scope);
  void write_event_header(const noleax::trace::Event& event, const ConsoleEventMetadata& metadata);
  void write_event_payload(const noleax::trace::Event& event);
  void write_stack(const noleax::trace::Event& event, const ConsoleEventMetadata& metadata);
  void write_common_summary(const EventStreamResult& trace);
  void write_completeness(const noleax::trace::CompletenessReport& completeness);
  void require_state(State expected, const char* operation) const;
  void ensure_output() const;

  std::ostream& output_;
  ConsoleOptions options_;
  State state_{State::kReady};
  std::optional<noleax::trace::FileHeader> header_;
  std::optional<noleax::trace::CaptureScope> capture_scope_;
  std::uint64_t written_event_count_{0};
  std::uint64_t written_loss_count_{0};
};

[[nodiscard]] FilteredEventsResult analyze_events_to_console(
    std::istream& input, std::ostream& output, const AnalysisFilter& filter,
    const EventMetadataResolver& filter_resolver = {},
    const ConsoleMetadataResolver& console_resolver = {}, ConsoleOptions console_options = {},
    EventStreamOptions stream_options = {});

[[nodiscard]] OutstandingResult analyze_outstanding_to_console(
    std::istream& input, std::ostream& output, OutstandingWindow window,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver = {},
    const ConsoleMetadataResolver& console_resolver = {}, ConsoleOptions console_options = {},
    EventStreamOptions stream_options = {});

[[nodiscard]] EventsStacksResult analyze_event_stacks_to_console(
    std::istream& input, std::ostream& output, StacksWindow window, StacksSort sort,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver = {},
    const ConsoleMetadataResolver& console_resolver = {}, ConsoleOptions console_options = {},
    EventStreamOptions stream_options = {});

[[nodiscard]] LeaksStacksResult analyze_leak_stacks_to_console(
    std::istream& input, std::ostream& output, OutstandingWindow window, StacksSort sort,
    const AnalysisFilter& filter, const EventMetadataResolver& filter_resolver = {},
    const ConsoleMetadataResolver& console_resolver = {}, ConsoleOptions console_options = {},
    EventStreamOptions stream_options = {});

}  // namespace noleax::analyzer
