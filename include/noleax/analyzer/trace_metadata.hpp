#pragma once

#include <iosfwd>
#include <memory>

#include "noleax/analyzer/event_stream.hpp"
#include "noleax/analyzer/filter.hpp"
#include "noleax/analyzer/presentation.hpp"
#include "noleax/analyzer/symbolizer.hpp"
#include "noleax/trace/event.hpp"

namespace noleax::analyzer {

class TraceMetadata final {
 public:
  explicit TraceMetadata(const SymbolizerOptions& symbolizer_options = {});
  ~TraceMetadata();

  TraceMetadata(const TraceMetadata&) = delete;
  TraceMetadata& operator=(const TraceMetadata&) = delete;
  TraceMetadata(TraceMetadata&&) = delete;
  TraceMetadata& operator=(TraceMetadata&&) = delete;

  [[nodiscard]] EventStreamResult scan(std::istream& input, EventStreamOptions options = {});
  [[nodiscard]] EventMetadata metadata(const noleax::trace::Event& event) const;
  [[nodiscard]] EventPresentation presentation(const noleax::trace::Event& event) const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace noleax::analyzer
