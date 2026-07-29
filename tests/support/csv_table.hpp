#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace noleax::testing {

class CsvParseError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct CsvTable {
  std::vector<std::string> header;
  std::vector<std::vector<std::string>> rows;

  [[nodiscard]] std::size_t column(std::string_view name) const;
  [[nodiscard]] const std::string& at(std::size_t row, std::string_view column_name) const;
};

[[nodiscard]] CsvTable parse_csv(std::string_view input);

}  // namespace noleax::testing
