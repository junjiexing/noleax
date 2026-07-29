#include "support/json_schema.hpp"

#include <cstddef>
#include <optional>
#include <regex>
#include <string>
#include <string_view>

#include "support/json_dom.hpp"

namespace noleax::testing {
namespace {

constexpr std::size_t kMaximumSchemaDepth = 256U;

using ValidationFailure = std::optional<std::string>;

[[nodiscard]] ValidationFailure failure(std::string_view path, std::string_view message) {
  return std::string{path} + ": " + std::string{message};
}

[[nodiscard]] bool matches_type(const JsonValue& instance, std::string_view type) {
  if (type == "null") {
    return instance.type() == JsonType::kNull;
  }
  if (type == "boolean") {
    return instance.type() == JsonType::kBoolean;
  }
  if (type == "number") {
    return instance.type() == JsonType::kNumber;
  }
  if (type == "integer") {
    return instance.is_integer();
  }
  if (type == "string") {
    return instance.type() == JsonType::kString;
  }
  if (type == "array") {
    return instance.type() == JsonType::kArray;
  }
  if (type == "object") {
    return instance.type() == JsonType::kObject;
  }
  throw JsonSchemaValidationError{"test schema contains unsupported type '" + std::string{type} +
                                  "'"};
}

[[nodiscard]] std::string decode_json_pointer_token(std::string_view token) {
  std::string result;
  result.reserve(token.size());
  for (std::size_t index = 0U; index < token.size(); ++index) {
    if (token[index] != '~') {
      result.push_back(token[index]);
      continue;
    }
    if (index + 1U >= token.size()) {
      throw JsonSchemaValidationError{"test schema contains an invalid JSON pointer escape"};
    }
    ++index;
    if (token[index] == '0') {
      result.push_back('~');
    } else if (token[index] == '1') {
      result.push_back('/');
    } else {
      throw JsonSchemaValidationError{"test schema contains an invalid JSON pointer escape"};
    }
  }
  return result;
}

[[nodiscard]] const JsonValue& resolve_reference(const JsonValue& root,
                                                 std::string_view reference) {
  if (reference == "#") {
    return root;
  }
  if (!reference.starts_with("#/")) {
    throw JsonSchemaValidationError{"test schema uses a non-local $ref"};
  }

  const JsonValue* current = &root;
  std::size_t begin = 2U;
  while (begin <= reference.size()) {
    const std::size_t separator = reference.find('/', begin);
    const std::size_t end = separator == std::string_view::npos ? reference.size() : separator;
    const auto token = decode_json_pointer_token(reference.substr(begin, end - begin));
    if (current->type() != JsonType::kObject) {
      throw JsonSchemaValidationError{"test schema $ref traverses a non-object value"};
    }
    const auto item = current->object_items().find(token);
    if (item == current->object_items().end()) {
      throw JsonSchemaValidationError{"test schema contains an unresolved $ref"};
    }
    current = &item->second;
    if (separator == std::string_view::npos) {
      break;
    }
    begin = separator + 1U;
  }
  return *current;
}

[[nodiscard]] ValidationFailure validate_value(const JsonValue& instance, const JsonValue& schema,
                                               const JsonValue& root, std::string_view path,
                                               std::size_t depth);

[[nodiscard]] ValidationFailure validate_type(const JsonValue& instance, const JsonValue& type,
                                              std::string_view path) {
  if (type.type() == JsonType::kString) {
    return matches_type(instance, type.scalar()) ? ValidationFailure{}
                                                 : failure(path, "type does not match schema");
  }
  if (type.type() != JsonType::kArray) {
    throw JsonSchemaValidationError{"test schema type must be a string or array"};
  }
  for (const auto& candidate : type.array_items()) {
    if (candidate.type() != JsonType::kString) {
      throw JsonSchemaValidationError{"test schema type array must contain strings"};
    }
    if (matches_type(instance, candidate.scalar())) {
      return {};
    }
  }
  return failure(path, "type does not match any schema alternative");
}

[[nodiscard]] ValidationFailure validate_one_of(const JsonValue& instance,
                                                const JsonValue& alternatives,
                                                const JsonValue& root, std::string_view path,
                                                std::size_t depth) {
  if (alternatives.type() != JsonType::kArray || alternatives.array_items().empty()) {
    throw JsonSchemaValidationError{"test schema oneOf must be a non-empty array"};
  }
  std::size_t matches = 0U;
  for (const auto& alternative : alternatives.array_items()) {
    if (!validate_value(instance, alternative, root, path, depth + 1U).has_value()) {
      ++matches;
    }
  }
  return matches == 1U ? ValidationFailure{}
                       : failure(path, "oneOf must match exactly one alternative");
}

[[nodiscard]] ValidationFailure validate_object(const JsonValue& instance, const JsonValue& schema,
                                                const JsonValue& root, std::string_view path,
                                                std::size_t depth) {
  if (instance.type() != JsonType::kObject) {
    return {};
  }

  const JsonValue* properties = nullptr;
  if (schema.contains("properties")) {
    properties = &schema.at("properties");
    if (properties->type() != JsonType::kObject) {
      throw JsonSchemaValidationError{"test schema properties must be an object"};
    }
    for (const auto& [name, property_schema] : properties->object_items()) {
      const auto item = instance.object_items().find(name);
      if (item == instance.object_items().end()) {
        continue;
      }
      const auto child_path = std::string{path} + "/" + name;
      if (auto result =
              validate_value(item->second, property_schema, root, child_path, depth + 1U)) {
        return result;
      }
    }
  }

  if (schema.contains("required")) {
    const auto& required = schema.at("required");
    if (required.type() != JsonType::kArray) {
      throw JsonSchemaValidationError{"test schema required must be an array"};
    }
    for (const auto& name : required.array_items()) {
      if (name.type() != JsonType::kString) {
        throw JsonSchemaValidationError{"test schema required entries must be strings"};
      }
      if (!instance.contains(name.scalar())) {
        return failure(path, "required property '" + name.scalar() + "' is missing");
      }
    }
  }

  if (!schema.contains("additionalProperties")) {
    return {};
  }
  const auto& additional = schema.at("additionalProperties");
  for (const auto& [name, value] : instance.object_items()) {
    if (properties != nullptr && properties->contains(name)) {
      continue;
    }
    if (additional.type() == JsonType::kBoolean) {
      if (!additional.boolean_value()) {
        return failure(path, "additional property '" + name + "' is not allowed");
      }
      continue;
    }
    const auto child_path = std::string{path} + "/" + name;
    if (auto result = validate_value(value, additional, root, child_path, depth + 1U)) {
      return result;
    }
  }
  return {};
}

[[nodiscard]] ValidationFailure validate_value(const JsonValue& instance, const JsonValue& schema,
                                               const JsonValue& root, std::string_view path,
                                               std::size_t depth) {
  if (depth > kMaximumSchemaDepth) {
    throw JsonSchemaValidationError{"test schema recursion exceeds its limit"};
  }
  if (schema.type() == JsonType::kBoolean) {
    return schema.boolean_value() ? ValidationFailure{}
                                  : failure(path, "false schema rejected value");
  }
  if (schema.type() != JsonType::kObject) {
    throw JsonSchemaValidationError{"test schema node must be an object or boolean"};
  }

  if (schema.contains("$ref")) {
    const auto& reference = schema.at("$ref");
    if (reference.type() != JsonType::kString) {
      throw JsonSchemaValidationError{"test schema $ref must be a string"};
    }
    if (auto result = validate_value(instance, resolve_reference(root, reference.scalar()), root,
                                     path, depth + 1U)) {
      return result;
    }
  }
  if (schema.contains("type")) {
    if (auto result = validate_type(instance, schema.at("type"), path)) {
      return result;
    }
  }
  if (schema.contains("const") && instance != schema.at("const")) {
    return failure(path, "value does not match const");
  }
  if (schema.contains("enum")) {
    const auto& values = schema.at("enum");
    if (values.type() != JsonType::kArray) {
      throw JsonSchemaValidationError{"test schema enum must be an array"};
    }
    bool found = false;
    for (const auto& value : values.array_items()) {
      found = found || instance == value;
    }
    if (!found) {
      return failure(path, "value is not present in enum");
    }
  }
  if (schema.contains("oneOf")) {
    if (auto result = validate_one_of(instance, schema.at("oneOf"), root, path, depth)) {
      return result;
    }
  }
  if (schema.contains("pattern") && instance.type() == JsonType::kString) {
    const auto& pattern = schema.at("pattern");
    if (pattern.type() != JsonType::kString) {
      throw JsonSchemaValidationError{"test schema pattern must be a string"};
    }
    try {
      if (!std::regex_search(instance.scalar(), std::regex{pattern.scalar()})) {
        return failure(path, "string does not match pattern");
      }
    } catch (const std::regex_error&) {
      throw JsonSchemaValidationError{"test schema contains an invalid pattern"};
    }
  }
  if (schema.contains("items") && instance.type() == JsonType::kArray) {
    const auto& item_schema = schema.at("items");
    for (std::size_t index = 0U; index < instance.array_items().size(); ++index) {
      const auto child_path = std::string{path} + "/" + std::to_string(index);
      if (auto result = validate_value(instance.array_items()[index], item_schema, root, child_path,
                                       depth + 1U)) {
        return result;
      }
    }
  }
  return validate_object(instance, schema, root, path, depth);
}

}  // namespace

void validate_json_schema(const JsonValue& instance, const JsonValue& schema) {
  if (auto result = validate_value(instance, schema, schema, "$", 0U)) {
    throw JsonSchemaValidationError{*result};
  }
}

}  // namespace noleax::testing
