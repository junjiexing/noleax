#include "support/csv_table.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace noleax::testing {
namespace {

class Parser {
 public:
  explicit Parser(std::string_view input) : input_{input} {}

  [[nodiscard]] std::vector<std::vector<std::string>> parse() {
    std::vector<std::vector<std::string>> records;
    while (position_ < input_.size()) {
      records.push_back(parse_record());
    }
    if (records.empty()) {
      fail("CSV input does not contain a header");
    }
    return records;
  }

 private:
  [[nodiscard]] std::vector<std::string> parse_record() {
    std::vector<std::string> fields;
    while (true) {
      fields.push_back(parse_field());
      if (position_ >= input_.size()) {
        return fields;
      }
      if (input_[position_] == ',') {
        ++position_;
        continue;
      }
      if (input_[position_] == '\r' && position_ + 1U < input_.size() &&
          input_[position_ + 1U] == '\n') {
        position_ += 2U;
        return fields;
      }
      fail("CSV field is not followed by a comma or CRLF");
    }
  }

  [[nodiscard]] std::string parse_field() {
    if (position_ < input_.size() && input_[position_] == '"') {
      return parse_quoted_field();
    }
    const std::size_t begin = position_;
    while (position_ < input_.size() && input_[position_] != ',' && input_[position_] != '\r' &&
           input_[position_] != '\n') {
      if (input_[position_] == '"') {
        fail("unquoted CSV field contains a quote");
      }
      ++position_;
    }
    if (position_ < input_.size() && input_[position_] == '\n') {
      fail("CSV record uses LF without CR");
    }
    return std::string{input_.substr(begin, position_ - begin)};
  }

  [[nodiscard]] std::string parse_quoted_field() {
    ++position_;
    std::string result;
    while (position_ < input_.size()) {
      const char character = input_[position_++];
      if (character != '"') {
        result.push_back(character);
        continue;
      }
      if (position_ < input_.size() && input_[position_] == '"') {
        result.push_back('"');
        ++position_;
        continue;
      }
      if (position_ < input_.size() && input_[position_] != ',' && input_[position_] != '\r') {
        fail("quoted CSV field has trailing data");
      }
      return result;
    }
    fail("quoted CSV field is not terminated");
  }

  [[noreturn]] void fail(const char* message) const {
    throw CsvParseError{std::string{message} + " at byte " + std::to_string(position_)};
  }

  std::string_view input_;
  std::size_t position_{0U};
};

}  // namespace

std::size_t CsvTable::column(std::string_view name) const {
  for (std::size_t index = 0U; index < header.size(); ++index) {
    if (header[index] == name) {
      return index;
    }
  }
  throw CsvParseError{"CSV header does not contain column '" + std::string{name} + "'"};
}

const std::string& CsvTable::at(std::size_t row, std::string_view column_name) const {
  if (row >= rows.size()) {
    throw CsvParseError{"CSV row index is out of range"};
  }
  return rows[row][column(column_name)];
}

CsvTable parse_csv(std::string_view input) {
  auto records = Parser{input}.parse();
  CsvTable table;
  table.header = std::move(records.front());
  records.erase(records.begin());
  if (table.header.empty()) {
    throw CsvParseError{"CSV header is empty"};
  }
  for (std::size_t index = 0U; index < table.header.size(); ++index) {
    if (table.header[index].empty()) {
      throw CsvParseError{"CSV header contains an empty column name"};
    }
    for (std::size_t previous = 0U; previous < index; ++previous) {
      if (table.header[previous] == table.header[index]) {
        throw CsvParseError{"CSV header contains a duplicate column name"};
      }
    }
  }
  for (const auto& row : records) {
    if (row.size() != table.header.size()) {
      throw CsvParseError{"CSV row width does not match its header"};
    }
  }
  table.rows = std::move(records);
  return table;
}

}  // namespace noleax::testing
