#pragma once

#include <cstdint>
#include <exception>
#include <filesystem>
#include <optional>
#include <string>

#include "noleax/config/configuration.hpp"

namespace noleax::cli {

enum class MetaCommand : std::uint8_t {
  kNone,
  kValidateConfig,
  kPrintEffectiveConfig,
};

class CommandLineExit final : public std::exception {
 public:
  CommandLineExit(int exit_code, std::string standard_output, std::string standard_error);

  [[nodiscard]] int exit_code() const noexcept;
  [[nodiscard]] const std::string& standard_output() const noexcept;
  [[nodiscard]] const std::string& standard_error() const noexcept;
  [[nodiscard]] const char* what() const noexcept override;

 private:
  int exit_code_;
  std::string standard_output_;
  std::string standard_error_;
  std::string message_;
};

struct ParsedCommandLine {
  std::optional<std::filesystem::path> config_path;
  config::ConfigurationOverrides overrides;
  MetaCommand meta_command{MetaCommand::kNone};
  std::string top_level_help;
};

[[nodiscard]] ParsedCommandLine parse_command_line(int argc, const char* const* argv,
                                                   const std::filesystem::path& current_directory);

}  // namespace noleax::cli
