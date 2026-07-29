#include "support/json_dom.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace noleax::testing {
namespace {

constexpr std::size_t kMaximumDepth = 256U;

[[nodiscard]] bool is_digit(char value) noexcept { return value >= '0' && value <= '9'; }

[[nodiscard]] unsigned int hex_digit(char value) {
  if (value >= '0' && value <= '9') {
    return static_cast<unsigned int>(value - '0');
  }
  if (value >= 'a' && value <= 'f') {
    return static_cast<unsigned int>(value - 'a') + 10U;
  }
  if (value >= 'A' && value <= 'F') {
    return static_cast<unsigned int>(value - 'A') + 10U;
  }
  throw JsonParseError{"JSON Unicode escape contains a non-hexadecimal digit"};
}

void append_utf8(std::string& output, std::uint32_t code_point) {
  if (code_point <= 0x7fU) {
    output.push_back(static_cast<char>(code_point));
  } else if (code_point <= 0x7ffU) {
    output.push_back(static_cast<char>(0xc0U | (code_point >> 6U)));
    output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
  } else if (code_point <= 0xffffU) {
    output.push_back(static_cast<char>(0xe0U | (code_point >> 12U)));
    output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
    output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
  } else {
    output.push_back(static_cast<char>(0xf0U | (code_point >> 18U)));
    output.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3fU)));
    output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
    output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
  }
}

class Parser {
 public:
  explicit Parser(std::string_view input) : input_{input} {}

  [[nodiscard]] JsonValue parse() {
    skip_whitespace();
    auto value = parse_value(0U);
    skip_whitespace();
    if (position_ != input_.size()) {
      fail("unexpected data after the JSON value");
    }
    return value;
  }

 private:
  [[nodiscard]] JsonValue parse_value(std::size_t depth) {
    if (depth > kMaximumDepth) {
      fail("JSON nesting exceeds the test parser limit");
    }
    if (position_ >= input_.size()) {
      fail("unexpected end of JSON input");
    }
    switch (input_[position_]) {
      case 'n':
        consume_literal("null");
        return JsonValue::null();
      case 't':
        consume_literal("true");
        return JsonValue::boolean(true);
      case 'f':
        consume_literal("false");
        return JsonValue::boolean(false);
      case '"':
        return JsonValue::string(parse_string());
      case '[':
        return parse_array(depth + 1U);
      case '{':
        return parse_object(depth + 1U);
      default:
        if (input_[position_] == '-' || is_digit(input_[position_])) {
          return JsonValue::number(parse_number());
        }
        fail("invalid JSON value");
    }
  }

  [[nodiscard]] JsonValue parse_array(std::size_t depth) {
    ++position_;
    skip_whitespace();
    JsonValue::Array result;
    if (consume_if(']')) {
      return JsonValue::array(std::move(result));
    }
    while (true) {
      skip_whitespace();
      result.push_back(parse_value(depth));
      skip_whitespace();
      if (consume_if(']')) {
        return JsonValue::array(std::move(result));
      }
      require(',');
    }
  }

  [[nodiscard]] JsonValue parse_object(std::size_t depth) {
    ++position_;
    skip_whitespace();
    JsonValue::Object result;
    if (consume_if('}')) {
      return JsonValue::object(std::move(result));
    }
    while (true) {
      skip_whitespace();
      if (position_ >= input_.size() || input_[position_] != '"') {
        fail("JSON object key must be a string");
      }
      auto key = parse_string();
      skip_whitespace();
      require(':');
      skip_whitespace();
      auto value = parse_value(depth);
      if (!result.emplace(std::move(key), std::move(value)).second) {
        fail("JSON object contains a duplicate key");
      }
      skip_whitespace();
      if (consume_if('}')) {
        return JsonValue::object(std::move(result));
      }
      require(',');
    }
  }

  [[nodiscard]] std::string parse_string() {
    require('"');
    std::string result;
    while (position_ < input_.size()) {
      const unsigned char byte = static_cast<unsigned char>(input_[position_++]);
      if (byte == '"') {
        return result;
      }
      if (byte < 0x20U) {
        fail("JSON string contains an unescaped control character");
      }
      if (byte != '\\') {
        result.push_back(static_cast<char>(byte));
        continue;
      }
      if (position_ >= input_.size()) {
        fail("JSON string ends after an escape character");
      }
      const char escape = input_[position_++];
      switch (escape) {
        case '"':
        case '\\':
        case '/':
          result.push_back(escape);
          break;
        case 'b':
          result.push_back('\b');
          break;
        case 'f':
          result.push_back('\f');
          break;
        case 'n':
          result.push_back('\n');
          break;
        case 'r':
          result.push_back('\r');
          break;
        case 't':
          result.push_back('\t');
          break;
        case 'u':
          append_unicode_escape(result);
          break;
        default:
          fail("JSON string contains an unsupported escape sequence");
      }
    }
    fail("unterminated JSON string");
  }

  void append_unicode_escape(std::string& output) {
    std::uint32_t code_point = read_hex_quad();
    if (code_point >= 0xd800U && code_point <= 0xdbffU) {
      if (position_ + 2U > input_.size() || input_[position_] != '\\' ||
          input_[position_ + 1U] != 'u') {
        fail("JSON high surrogate is not followed by a low surrogate");
      }
      position_ += 2U;
      const std::uint32_t low = read_hex_quad();
      if (low < 0xdc00U || low > 0xdfffU) {
        fail("JSON high surrogate is followed by an invalid low surrogate");
      }
      code_point = 0x10000U + ((code_point - 0xd800U) << 10U) + (low - 0xdc00U);
    } else if (code_point >= 0xdc00U && code_point <= 0xdfffU) {
      fail("JSON contains an unpaired low surrogate");
    }
    append_utf8(output, code_point);
  }

  [[nodiscard]] std::uint32_t read_hex_quad() {
    if (position_ + 4U > input_.size()) {
      fail("JSON Unicode escape is truncated");
    }
    std::uint32_t result = 0U;
    for (std::size_t index = 0U; index < 4U; ++index) {
      result = (result << 4U) | hex_digit(input_[position_++]);
    }
    return result;
  }

  [[nodiscard]] std::string parse_number() {
    const std::size_t begin = position_;
    static_cast<void>(consume_if('-'));
    if (position_ >= input_.size()) {
      fail("JSON number is truncated");
    }
    if (consume_if('0')) {
      if (position_ < input_.size() && is_digit(input_[position_])) {
        fail("JSON number contains a leading zero");
      }
    } else {
      if (input_[position_] < '1' || input_[position_] > '9') {
        fail("JSON number has an invalid integer part");
      }
      while (position_ < input_.size() && is_digit(input_[position_])) {
        ++position_;
      }
    }
    if (consume_if('.')) {
      if (position_ >= input_.size() || !is_digit(input_[position_])) {
        fail("JSON number has an invalid fraction");
      }
      while (position_ < input_.size() && is_digit(input_[position_])) {
        ++position_;
      }
    }
    if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
      ++position_;
      if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) {
        ++position_;
      }
      if (position_ >= input_.size() || !is_digit(input_[position_])) {
        fail("JSON number has an invalid exponent");
      }
      while (position_ < input_.size() && is_digit(input_[position_])) {
        ++position_;
      }
    }
    return std::string{input_.substr(begin, position_ - begin)};
  }

  void consume_literal(std::string_view literal) {
    if (input_.substr(position_, literal.size()) != literal) {
      fail("invalid JSON literal");
    }
    position_ += literal.size();
  }

  void skip_whitespace() {
    while (position_ < input_.size() && (input_[position_] == ' ' || input_[position_] == '\t' ||
                                         input_[position_] == '\r' || input_[position_] == '\n')) {
      ++position_;
    }
  }

  [[nodiscard]] bool consume_if(char value) {
    if (position_ < input_.size() && input_[position_] == value) {
      ++position_;
      return true;
    }
    return false;
  }

  void require(char value) {
    if (!consume_if(value)) {
      fail("JSON punctuation is missing");
    }
  }

  [[noreturn]] void fail(const char* message) const {
    throw JsonParseError{std::string{message} + " at byte " + std::to_string(position_)};
  }

  std::string_view input_;
  std::size_t position_{0};
};

}  // namespace

JsonValue::JsonValue(JsonType type) : type_{type} {}

JsonValue JsonValue::null() { return JsonValue{JsonType::kNull}; }

JsonValue JsonValue::boolean(bool value) {
  JsonValue result{JsonType::kBoolean};
  result.boolean_ = value;
  return result;
}

JsonValue JsonValue::number(std::string value) {
  JsonValue result{JsonType::kNumber};
  result.scalar_ = std::move(value);
  return result;
}

JsonValue JsonValue::string(std::string value) {
  JsonValue result{JsonType::kString};
  result.scalar_ = std::move(value);
  return result;
}

JsonValue JsonValue::array(Array value) {
  JsonValue result{JsonType::kArray};
  result.array_ = std::move(value);
  return result;
}

JsonValue JsonValue::object(Object value) {
  JsonValue result{JsonType::kObject};
  result.object_ = std::move(value);
  return result;
}

JsonType JsonValue::type() const noexcept { return type_; }

bool JsonValue::boolean_value() const {
  if (type_ != JsonType::kBoolean) {
    throw JsonParseError{"JSON value is not a boolean"};
  }
  return boolean_;
}

const std::string& JsonValue::scalar() const {
  if (type_ != JsonType::kNumber && type_ != JsonType::kString) {
    throw JsonParseError{"JSON value is not a number or string"};
  }
  return scalar_;
}

const JsonValue::Array& JsonValue::array_items() const {
  if (type_ != JsonType::kArray) {
    throw JsonParseError{"JSON value is not an array"};
  }
  return array_;
}

const JsonValue::Object& JsonValue::object_items() const {
  if (type_ != JsonType::kObject) {
    throw JsonParseError{"JSON value is not an object"};
  }
  return object_;
}

const JsonValue& JsonValue::at(std::string_view key) const {
  const auto item = object_items().find(key);
  if (item == object_.end()) {
    throw JsonParseError{"JSON object does not contain key '" + std::string{key} + "'"};
  }
  return item->second;
}

bool JsonValue::contains(std::string_view key) const {
  return object_items().find(key) != object_.end();
}

std::uint64_t JsonValue::unsigned_value() const {
  if (!is_integer() || (!scalar_.empty() && scalar_.front() == '-')) {
    throw JsonParseError{"JSON value is not an unsigned integer"};
  }
  std::uint64_t result = 0U;
  const auto parsed = std::from_chars(scalar_.data(), scalar_.data() + scalar_.size(), result);
  if (parsed.ec != std::errc{} || parsed.ptr != scalar_.data() + scalar_.size()) {
    throw JsonParseError{"JSON unsigned integer is out of range"};
  }
  return result;
}

std::int64_t JsonValue::signed_value() const {
  if (!is_integer()) {
    throw JsonParseError{"JSON value is not an integer"};
  }
  std::int64_t result = 0;
  const auto parsed = std::from_chars(scalar_.data(), scalar_.data() + scalar_.size(), result);
  if (parsed.ec != std::errc{} || parsed.ptr != scalar_.data() + scalar_.size()) {
    throw JsonParseError{"JSON signed integer is out of range"};
  }
  return result;
}

bool JsonValue::is_integer() const noexcept {
  return type_ == JsonType::kNumber && scalar_.find_first_of(".eE") == std::string::npos;
}

JsonValue parse_json(std::string_view input) { return Parser{input}.parse(); }

}  // namespace noleax::testing
