#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "noleax/trace/identifiers.hpp"

namespace noleax::trace {

enum class StackCaptureStatus : std::uint8_t {
  kComplete,
  kTruncatedByDepth,
  kUnwindFailed,
  kUnavailable,
};

struct StackFrame {
  ModuleId module_id;
  std::uint64_t module_offset{0U};
  std::uint64_t absolute_address{0U};
  std::uint32_t flags{0U};

  bool operator==(const StackFrame&) const = default;
};

struct StackDefinition {
  StackId stack_id;
  StackCaptureStatus status{StackCaptureStatus::kUnavailable};
  std::vector<StackFrame> frames;

  bool operator==(const StackDefinition&) const = default;
};

class StackValidationError final : public std::invalid_argument {
 public:
  using std::invalid_argument::invalid_argument;
};

void validate_stack_definition(const StackDefinition& definition);

}  // namespace noleax::trace
