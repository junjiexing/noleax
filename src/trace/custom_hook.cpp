#include "noleax/trace/custom_hook.hpp"

#include <string>
#include <string_view>

namespace noleax::trace {
namespace {

void validate_string(std::string_view value, const char* field) {
  if (value.empty()) {
    throw CustomHookValidationError{std::string{field} + " must not be empty"};
  }
  if (value.find('\0') != std::string_view::npos) {
    throw CustomHookValidationError{std::string{field} + " must not contain NUL"};
  }
}

}  // namespace

void validate_custom_hook_definition(const CustomHookDefinition& definition) {
  if (definition.api_id < kCustomHookApiIdBase) {
    throw CustomHookValidationError{"custom hook api_id is outside the custom hook ID range"};
  }
  validate_string(definition.module_name, "custom hook module name");
  validate_string(definition.label, "custom hook label");
}

}  // namespace noleax::trace
