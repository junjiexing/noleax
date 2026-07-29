#pragma once

#include <stdexcept>

#include "support/json_dom.hpp"

namespace noleax::testing {

class JsonSchemaValidationError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

void validate_json_schema(const JsonValue& instance, const JsonValue& schema);

}  // namespace noleax::testing
