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

class CustomHookValidationError final : public std::invalid_argument {
 public:
  using std::invalid_argument::invalid_argument;
};

void validate_custom_hook_definition(const CustomHookDefinition& definition);

}  // namespace noleax::trace
