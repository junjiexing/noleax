#include "noleax/trace/stack.hpp"

#include <cstddef>

namespace noleax::trace {
namespace {

[[nodiscard]] bool is_known_status(StackCaptureStatus status) noexcept {
  switch (status) {
    case StackCaptureStatus::kComplete:
    case StackCaptureStatus::kTruncatedByDepth:
    case StackCaptureStatus::kUnwindFailed:
    case StackCaptureStatus::kUnavailable:
      return true;
  }
  return false;
}

}  // namespace

void validate_stack_definition(const StackDefinition& definition) {
  if (!definition.stack_id) {
    throw StackValidationError{"stack definition requires a nonzero stack_id"};
  }
  if (!is_known_status(definition.status)) {
    throw StackValidationError{"stack definition status is not supported"};
  }
  const bool has_frames = !definition.frames.empty();
  if ((definition.status == StackCaptureStatus::kComplete ||
       definition.status == StackCaptureStatus::kTruncatedByDepth) != has_frames) {
    throw StackValidationError{"successful stack definition must contain frames"};
  }
  if ((definition.status == StackCaptureStatus::kUnwindFailed ||
       definition.status == StackCaptureStatus::kUnavailable) &&
      has_frames) {
    throw StackValidationError{"unavailable stack definition must not contain frames"};
  }
  for (const StackFrame& frame : definition.frames) {
    if (frame.absolute_address == 0U) {
      throw StackValidationError{"stack frame requires a nonzero absolute address"};
    }
    if (!frame.module_id && frame.module_offset != 0U) {
      throw StackValidationError{"stack frame without a module must have a zero module offset"};
    }
    if (frame.flags != 0U) {
      throw StackValidationError{"stack frame flags are not supported in V1"};
    }
  }
}

}  // namespace noleax::trace
