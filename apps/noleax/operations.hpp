#pragma once

#include <stdexcept>
#include <string>

#include "noleax/config/configuration.hpp"

namespace noleax::app {

class ApplicationError final : public std::runtime_error {
 public:
  ApplicationError(int exit_code, const std::string& message);
  [[nodiscard]] int exit_code() const noexcept;

 private:
  int exit_code_{1};
};

[[nodiscard]] int execute_operation(const noleax::config::Configuration& configuration);

}  // namespace noleax::app
