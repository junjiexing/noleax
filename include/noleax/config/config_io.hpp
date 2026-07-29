#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>

#include "noleax/config/configuration.hpp"

namespace noleax::config {

class ConfigError final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

[[nodiscard]] std::filesystem::path normalize_path(std::string_view input,
                                                   const std::filesystem::path& base_directory);
[[nodiscard]] std::string path_to_utf8(const std::filesystem::path& path);
[[nodiscard]] ConfigurationOverrides load_toml_config(const std::filesystem::path& config_path);
void validate_configuration(const Configuration& configuration);
[[nodiscard]] std::string serialize_effective_config(const Configuration& configuration);

}  // namespace noleax::config
