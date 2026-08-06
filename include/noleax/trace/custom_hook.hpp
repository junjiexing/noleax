#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

#include "noleax/trace/identifiers.hpp"

namespace noleax::trace {

// Custom symbol hooks occupy their own API ID range so their events never collide with the
// built-in Windows hook registry IDs.
inline constexpr ApiId kCustomHookApiIdBase = 0x1000U;

struct CustomHookDefinition {
  ApiId api_id{0U};
  std::string module_name;
  std::string label;

  bool operator==(const CustomHookDefinition&) const = default;
};

// Which role of a custom hook point failed to install; kPoint covers failures that prevented
// every role of the point from installing (for example the module never loaded).
enum class CustomHookFailureRole : std::uint8_t {
  kAlloc = 0,
  kRealloc = 1,
  kFree = 2,
  kPoint = 255,
};

enum class CustomHookFailureReason : std::uint8_t {
  kModuleNotLoaded = 1,
  kExportNotFound = 2,
  kForwardedExport = 3,
  kInvalidRva = 4,
  kWrongSignature = 5,
  kImageIdentityMismatch = 6,
  kBackendUnavailable = 7,
  kOther = 255,
};

// One custom hook install failure, recorded in the metadata chunk so the analyzer can show
// exactly which hook point or role is missing from the capture.
struct CustomHookFailure {
  std::string module;
  CustomHookFailureRole role{CustomHookFailureRole::kPoint};
  CustomHookFailureReason reason{CustomHookFailureReason::kOther};
  std::string detail;

  bool operator==(const CustomHookFailure&) const = default;
};

class CustomHookValidationError final : public std::invalid_argument {
 public:
  using std::invalid_argument::invalid_argument;
};

void validate_custom_hook_definition(const CustomHookDefinition& definition);
void validate_custom_hook_failure(const CustomHookFailure& failure);

}  // namespace noleax::trace
