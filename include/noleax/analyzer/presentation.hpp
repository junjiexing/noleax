#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "noleax/trace/event.hpp"

namespace noleax::analyzer {

struct ResolvedStackFrame {
  noleax::trace::Address absolute_address{0};
  std::optional<std::string> module_name;
  std::optional<std::uint64_t> module_offset;
  std::optional<std::string> symbol_name;
  std::optional<std::uint64_t> symbol_offset;
};

enum class StackCaptureStatus : std::uint8_t {
  kComplete,
  kTruncatedByDepth,
  kUnwindFailed,
  kUnavailable,
};

struct EventPresentation {
  std::optional<std::string> api_name;
  std::optional<std::string> api_module;
  std::optional<StackCaptureStatus> stack_status;
  std::vector<ResolvedStackFrame> stack_frames;
};

using EventPresentationResolver = std::function<EventPresentation(const noleax::trace::Event&)>;

}  // namespace noleax::analyzer
