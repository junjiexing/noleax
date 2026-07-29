#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace noleax::testing {

enum class JsonType : std::uint8_t {
  kNull,
  kBoolean,
  kNumber,
  kString,
  kArray,
  kObject,
};

class JsonParseError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class JsonValue {
 public:
  using Array = std::vector<JsonValue>;
  using Object = std::map<std::string, JsonValue, std::less<>>;

  [[nodiscard]] static JsonValue null();
  [[nodiscard]] static JsonValue boolean(bool value);
  [[nodiscard]] static JsonValue number(std::string value);
  [[nodiscard]] static JsonValue string(std::string value);
  [[nodiscard]] static JsonValue array(Array value);
  [[nodiscard]] static JsonValue object(Object value);

  [[nodiscard]] JsonType type() const noexcept;
  [[nodiscard]] bool boolean_value() const;
  [[nodiscard]] const std::string& scalar() const;
  [[nodiscard]] const Array& array_items() const;
  [[nodiscard]] const Object& object_items() const;
  [[nodiscard]] const JsonValue& at(std::string_view key) const;
  [[nodiscard]] bool contains(std::string_view key) const;
  [[nodiscard]] std::uint64_t unsigned_value() const;
  [[nodiscard]] std::int64_t signed_value() const;
  [[nodiscard]] bool is_integer() const noexcept;

  bool operator==(const JsonValue&) const = default;

 private:
  explicit JsonValue(JsonType type);

  JsonType type_{JsonType::kNull};
  bool boolean_{false};
  std::string scalar_;
  Array array_;
  Object object_;
};

[[nodiscard]] JsonValue parse_json(std::string_view input);

}  // namespace noleax::testing
