#pragma once

#include <cstdint>
#include <functional>
#include <iosfwd>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/trace/event.hpp"

namespace noleax::analyzer {

struct AnalysisFilterCriteria {
  std::optional<std::uint64_t> minimum_size;
  std::optional<std::uint64_t> maximum_size;
  std::vector<noleax::trace::EventOperation> operations;
  std::vector<std::uint64_t> thread_ids;
  std::vector<std::string> api_names;
  std::vector<std::string> module_patterns;
  std::vector<std::string> stack_module_patterns;
  std::vector<std::uint64_t> allocation_ids;
  std::vector<noleax::trace::EventStatus> statuses;
};

struct EventMetadata {
  std::optional<std::string> api_name;
  std::optional<std::string> api_module;
  std::vector<std::string> stack_modules;
};

using EventMetadataResolver = std::function<EventMetadata(const noleax::trace::Event&)>;

class AnalysisFilterError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class AnalysisFilter {
 public:
  AnalysisFilter() = default;
  explicit AnalysisFilter(AnalysisFilterCriteria criteria);

  [[nodiscard]] const AnalysisFilterCriteria& criteria() const noexcept;
  [[nodiscard]] bool empty() const noexcept;
  [[nodiscard]] bool requires_metadata() const noexcept;
  [[nodiscard]] bool matches_event(const noleax::trace::Event& event,
                                   const EventMetadata& metadata = {}) const;
  [[nodiscard]] bool matches_event(const noleax::trace::Event& event,
                                   const EventMetadataResolver& resolver) const;
  [[nodiscard]] bool matches_generation(const MemoryGeneration& generation,
                                        const EventMetadata& metadata = {}) const;
  [[nodiscard]] bool matches_generation(const MemoryGeneration& generation,
                                        const EventMetadataResolver& resolver) const;

 private:
  AnalysisFilterCriteria criteria_;
};

struct FilteredEventsResult {
  EventStreamResult trace;
  std::uint64_t matched_event_count{0};
  std::uint64_t filtered_event_count{0};
};

[[nodiscard]] FilteredEventsResult analyze_filtered_events(
    std::istream& input, const AnalysisFilter& filter, const EventStreamCallbacks& callbacks = {},
    const EventMetadataResolver& resolver = {}, EventStreamOptions options = {});

}  // namespace noleax::analyzer
