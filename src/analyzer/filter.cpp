#include "noleax/analyzer/filter.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/generation_tracker.hpp"
#include "noleax/trace/event.hpp"

namespace noleax::analyzer {
namespace {

template <typename Value>
[[nodiscard]] bool contains(const std::vector<Value>& values, const Value& value) {
  return std::find(values.begin(), values.end(), value) != values.end();
}

[[nodiscard]] char normalize_module_character(char value) noexcept {
  if (value == '\\') {
    return '/';
  }
  if (value >= 'A' && value <= 'Z') {
    return static_cast<char>(value + ('a' - 'A'));
  }
  return value;
}

[[nodiscard]] bool module_glob_matches(std::string_view pattern, std::string_view value) noexcept {
  std::size_t pattern_index = 0U;
  std::size_t value_index = 0U;
  std::size_t star_index = std::string_view::npos;
  std::size_t retry_value_index = 0U;

  while (value_index < value.size()) {
    if (pattern_index < pattern.size() &&
        (pattern[pattern_index] == '?' || normalize_module_character(pattern[pattern_index]) ==
                                              normalize_module_character(value[value_index]))) {
      ++pattern_index;
      ++value_index;
      continue;
    }
    if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
      star_index = pattern_index;
      ++pattern_index;
      retry_value_index = value_index;
      continue;
    }
    if (star_index == std::string_view::npos) {
      return false;
    }
    pattern_index = star_index + 1U;
    value_index = ++retry_value_index;
  }

  while (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
    ++pattern_index;
  }
  return pattern_index == pattern.size();
}

[[nodiscard]] std::string_view module_basename(std::string_view module) noexcept {
  const auto separator = module.find_last_of("/\\");
  return separator == std::string_view::npos ? module : module.substr(separator + 1U);
}

[[nodiscard]] bool pattern_matches_module(std::string_view pattern,
                                          std::string_view module) noexcept {
  const bool pattern_has_path = pattern.find_first_of("/\\") != std::string_view::npos;
  return module_glob_matches(pattern, pattern_has_path ? module : module_basename(module));
}

[[nodiscard]] bool any_pattern_matches(const std::vector<std::string>& patterns,
                                       std::string_view module) noexcept {
  return std::any_of(patterns.begin(), patterns.end(), [module](const std::string& pattern) {
    return pattern_matches_module(pattern, module);
  });
}

[[nodiscard]] bool metadata_matches(const AnalysisFilterCriteria& criteria,
                                    const EventMetadata& metadata) {
  if (!criteria.api_names.empty() &&
      (!metadata.api_name.has_value() || !contains(criteria.api_names, *metadata.api_name))) {
    return false;
  }
  if (!criteria.module_patterns.empty() &&
      (!metadata.api_module.has_value() ||
       !any_pattern_matches(criteria.module_patterns, *metadata.api_module))) {
    return false;
  }
  if (!criteria.stack_module_patterns.empty()) {
    const bool matched =
        std::any_of(metadata.stack_modules.begin(), metadata.stack_modules.end(),
                    [&criteria](const std::string& module) {
                      return any_pattern_matches(criteria.stack_module_patterns, module);
                    });
    if (!matched) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] std::optional<std::uint64_t> event_size(const noleax::trace::Event& event) noexcept {
  return std::visit(
      [&event](const auto& payload) -> std::optional<std::uint64_t> {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, noleax::trace::AllocationEvent> ||
                      std::is_same_v<Payload, noleax::trace::ReallocationEvent>) {
          return payload.requested_size;
        } else if constexpr (std::is_same_v<Payload, noleax::trace::VmAllocateEvent>) {
          return noleax::trace::call_succeeded(event.header.status) ? payload.result_size
                                                                    : payload.requested_size;
        } else if constexpr (std::is_same_v<Payload, noleax::trace::VmFreeEvent>) {
          return payload.region_size;
        } else if constexpr (std::is_same_v<Payload, noleax::trace::MapEvent>) {
          return payload.view_size;
        } else {
          return std::nullopt;
        }
      },
      event.payload);
}

[[nodiscard]] bool size_matches(const AnalysisFilterCriteria& criteria,
                                std::optional<std::uint64_t> size) noexcept {
  if (!criteria.minimum_size.has_value() && !criteria.maximum_size.has_value()) {
    return true;
  }
  if (!size.has_value()) {
    return false;
  }
  return (!criteria.minimum_size.has_value() || *size >= *criteria.minimum_size) &&
         (!criteria.maximum_size.has_value() || *size <= *criteria.maximum_size);
}

[[nodiscard]] bool allocation_id_matches(const std::vector<std::uint64_t>& ids,
                                         const noleax::trace::Event& event) {
  if (ids.empty()) {
    return true;
  }
  return std::visit(
      [&ids](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, noleax::trace::AllocationEvent> ||
                      std::is_same_v<Payload, noleax::trace::FreeEvent>) {
          return payload.allocation_id.is_valid() && contains(ids, payload.allocation_id.value());
        } else if constexpr (std::is_same_v<Payload, noleax::trace::ReallocationEvent>) {
          return (payload.old_allocation_id.is_valid() &&
                  contains(ids, payload.old_allocation_id.value())) ||
                 (payload.new_allocation_id.is_valid() &&
                  contains(ids, payload.new_allocation_id.value()));
        } else {
          return false;
        }
      },
      event.payload);
}

[[nodiscard]] bool common_event_fields_match(const AnalysisFilterCriteria& criteria,
                                             const noleax::trace::Event& event) {
  return (criteria.operations.empty() ||
          contains(criteria.operations, noleax::trace::event_operation(event.payload))) &&
         (criteria.thread_ids.empty() || contains(criteria.thread_ids, event.header.thread_id)) &&
         (criteria.statuses.empty() || contains(criteria.statuses, event.header.status));
}

void validate_names(const std::vector<std::string>& values, const char* subject) {
  if (std::any_of(values.begin(), values.end(),
                  [](const std::string& value) { return value.empty(); })) {
    throw AnalysisFilterError{std::string{subject} + " must not contain an empty value"};
  }
}

void checked_increment(std::uint64_t& value, const char* subject) {
  if (value == std::numeric_limits<std::uint64_t>::max()) {
    throw AnalysisFilterError{std::string{subject} + " count overflow"};
  }
  ++value;
}

}  // namespace

AnalysisFilter::AnalysisFilter(AnalysisFilterCriteria criteria) : criteria_{std::move(criteria)} {
  if (criteria_.minimum_size.has_value() && criteria_.maximum_size.has_value() &&
      *criteria_.minimum_size > *criteria_.maximum_size) {
    throw AnalysisFilterError{"minimum size must not exceed maximum size"};
  }
  validate_names(criteria_.api_names, "API names");
  validate_names(criteria_.module_patterns, "module patterns");
  validate_names(criteria_.stack_module_patterns, "stack module patterns");
}

const AnalysisFilterCriteria& AnalysisFilter::criteria() const noexcept { return criteria_; }

bool AnalysisFilter::empty() const noexcept {
  return !criteria_.minimum_size.has_value() && !criteria_.maximum_size.has_value() &&
         criteria_.operations.empty() && criteria_.thread_ids.empty() &&
         criteria_.api_names.empty() && criteria_.module_patterns.empty() &&
         criteria_.stack_module_patterns.empty() && criteria_.allocation_ids.empty() &&
         criteria_.statuses.empty();
}

bool AnalysisFilter::requires_metadata() const noexcept {
  return !criteria_.api_names.empty() || !criteria_.module_patterns.empty() ||
         !criteria_.stack_module_patterns.empty();
}

bool AnalysisFilter::matches_event(const noleax::trace::Event& event,
                                   const EventMetadata& metadata) const {
  return common_event_fields_match(criteria_, event) &&
         size_matches(criteria_, event_size(event)) &&
         allocation_id_matches(criteria_.allocation_ids, event) &&
         metadata_matches(criteria_, metadata);
}

bool AnalysisFilter::matches_event(const noleax::trace::Event& event,
                                   const EventMetadataResolver& resolver) const {
  if (!common_event_fields_match(criteria_, event) || !size_matches(criteria_, event_size(event)) ||
      !allocation_id_matches(criteria_.allocation_ids, event)) {
    return false;
  }
  if (!requires_metadata()) {
    return true;
  }
  if (!resolver) {
    throw AnalysisFilterError{"API and module filters require an event metadata resolver"};
  }
  return metadata_matches(criteria_, resolver(event));
}

bool AnalysisFilter::matches_generation(const MemoryGeneration& generation,
                                        const EventMetadata& metadata) const {
  if (!common_event_fields_match(criteria_, generation.created_by) ||
      !size_matches(criteria_, generation.size) || !metadata_matches(criteria_, metadata)) {
    return false;
  }
  return criteria_.allocation_ids.empty() ||
         (generation.kind == GenerationKind::kHeapAllocation &&
          generation.allocation_id.is_valid() &&
          contains(criteria_.allocation_ids, generation.allocation_id.value()));
}

bool AnalysisFilter::matches_generation(const MemoryGeneration& generation,
                                        const EventMetadataResolver& resolver) const {
  if (!common_event_fields_match(criteria_, generation.created_by) ||
      !size_matches(criteria_, generation.size) ||
      (!criteria_.allocation_ids.empty() &&
       (generation.kind != GenerationKind::kHeapAllocation ||
        !generation.allocation_id.is_valid() ||
        !contains(criteria_.allocation_ids, generation.allocation_id.value())))) {
    return false;
  }
  if (!requires_metadata()) {
    return true;
  }
  if (!resolver) {
    throw AnalysisFilterError{"API and module filters require an event metadata resolver"};
  }
  return metadata_matches(criteria_, resolver(generation.created_by));
}

FilteredEventsResult analyze_filtered_events(std::istream& input, const AnalysisFilter& filter,
                                             const FilteredEventCallback& on_event,
                                             const EventMetadataResolver& resolver,
                                             EventStreamOptions options) {
  if (filter.requires_metadata() && !resolver) {
    throw AnalysisFilterError{"API and module filters require an event metadata resolver"};
  }

  FilteredEventsResult result;
  EventStreamCallbacks callbacks;
  callbacks.on_event = [&filter, &on_event, &resolver, &result](const noleax::trace::Event& event) {
    if (!filter.matches_event(event, resolver)) {
      checked_increment(result.filtered_event_count, "filtered event");
      return;
    }
    checked_increment(result.matched_event_count, "matched event");
    if (on_event) {
      on_event(event);
    }
  };
  result.trace = analyze_event_stream(input, callbacks, options);
  return result;
}

}  // namespace noleax::analyzer
