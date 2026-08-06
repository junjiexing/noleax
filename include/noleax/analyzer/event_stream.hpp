#pragma once

#include <cstdint>
#include <functional>
#include <iosfwd>
#include <optional>
#include <stdexcept>

#include "noleax/trace/completeness.hpp"
#include "noleax/trace/custom_hook.hpp"
#include "noleax/trace/event.hpp"
#include "noleax/trace/memory_snapshot.hpp"
#include "noleax/trace/module.hpp"
#include "noleax/trace/stack.hpp"
#include "noleax/trace/trace_reader.hpp"
#include "noleax/trace/wire_format.hpp"

namespace noleax::analyzer {

struct EventStreamOptions {
  noleax::trace::TraceReaderOptions reader_options;
  std::uint32_t maximum_record_size{noleax::trace::kDefaultMaximumRecordSize};
};

struct EventStreamCallbacks {
  std::function<void(const noleax::trace::FileHeader&)> on_file_header;
  std::function<void(const noleax::trace::CaptureScope&)> on_capture_scope;
  std::function<void(const noleax::trace::CustomHookDefinition&)> on_custom_hook_definition;
  std::function<void(const noleax::trace::CustomHookFailure&)> on_custom_hook_failure;
  std::function<void(const noleax::trace::ModuleLoad&)> on_module_load;
  std::function<void(const noleax::trace::ModuleUnload&)> on_module_unload;
  std::function<void(const noleax::trace::StackDefinition&)> on_stack_definition;
  std::function<void(const noleax::trace::Event&)> on_event;
  std::function<void(const noleax::trace::LossRecord&)> on_loss;
  std::function<void(const noleax::trace::MemoryCounters&)> on_memory_counters;
  std::function<void(const noleax::trace::MemoryMap&)> on_memory_map;
  std::function<void(const noleax::trace::CaptureStatistics&)> on_statistics;
  std::function<void(const noleax::trace::EndOfTrace&)> on_end_of_trace;
};

struct EventStreamResult {
  noleax::trace::FileHeader file_header;
  noleax::trace::CaptureScope capture_scope;
  std::vector<noleax::trace::CustomHookDefinition> custom_hooks;
  std::vector<noleax::trace::CustomHookFailure> custom_hook_failures;
  std::optional<noleax::trace::CaptureStatistics> statistics;
  std::optional<noleax::trace::EndOfTrace> end_of_trace;
  noleax::trace::CompletenessReport completeness = noleax::trace::CompletenessReport::from_mask(0U);
  noleax::trace::Sequence known_sequence_end;
  std::uint64_t known_monotonic_end{0};
  std::uint64_t event_count{0};
  std::uint64_t module_load_count{0};
  std::uint64_t module_unload_count{0};
  std::uint64_t stack_definition_count{0};
  std::uint64_t loss_record_count{0};
  std::uint64_t memory_counters_count{0};
  std::uint64_t memory_map_count{0};
  std::uint64_t bytes_read{0};
  bool truncated{false};
  bool partially_understood{false};
};

class TraceAnalysisError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

[[nodiscard]] EventStreamResult analyze_event_stream(std::istream& input,
                                                     const EventStreamCallbacks& callbacks = {},
                                                     EventStreamOptions options = {});

}  // namespace noleax::analyzer
