#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "noleax/cli/command_line.hpp"
#include "noleax/config/config_io.hpp"
#include "noleax/config/configuration.hpp"
#include "operations.hpp"

namespace {

int run_application(int argc, const char* const* argv) {
  try {
    const auto command_line =
        noleax::cli::parse_command_line(argc, argv, std::filesystem::current_path());

    auto configuration = noleax::config::make_default_configuration();
    if (command_line.config_path.has_value()) {
      const auto file_overrides = noleax::config::load_toml_config(*command_line.config_path);
      noleax::config::apply_overrides(configuration, file_overrides,
                                      noleax::config::ValueSource::kConfig);
    } else if (command_line.meta_command != noleax::cli::MetaCommand::kNone) {
      throw noleax::config::ConfigError{"--config is required for config commands"};
    }
    noleax::config::apply_overrides(configuration, command_line.overrides,
                                    noleax::config::ValueSource::kCommandLine);

    if (!configuration.operation.value.has_value() &&
        command_line.meta_command == noleax::cli::MetaCommand::kNone) {
      std::cout << command_line.top_level_help;
      return 1;
    }

    noleax::config::validate_configuration(configuration);
    if (command_line.meta_command == noleax::cli::MetaCommand::kValidateConfig) {
      std::cout << "configuration is valid\n";
      return 0;
    }
    if (command_line.meta_command == noleax::cli::MetaCommand::kPrintEffectiveConfig) {
      std::cout << noleax::config::serialize_effective_config(configuration);
      return 0;
    }
    return noleax::app::execute_operation(configuration);
  } catch (const noleax::cli::CommandLineExit& exit) {
    std::cout << exit.standard_output();
    std::cerr << exit.standard_error();
    return exit.exit_code();
  } catch (const noleax::config::ConfigError& error) {
    std::cerr << "error: " << error.what() << '\n';
    return 1;
  } catch (const noleax::app::ApplicationError& error) {
    std::cerr << "error: " << error.what() << '\n';
    return error.exit_code();
  } catch (const std::exception& error) {
    std::cerr << "error: " << error.what() << '\n';
    return 1;
  }
}

#if defined(_WIN32)
[[nodiscard]] std::string wide_to_utf8(std::wstring_view value) {
  if (value.empty()) {
    return {};
  }
  if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    throw std::runtime_error{"command line argument is too long"};
  }

  const int input_size = static_cast<int>(value.size());
  const int output_size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                              input_size, nullptr, 0, nullptr, nullptr);
  if (output_size <= 0) {
    throw std::runtime_error{"cannot convert a command line argument to UTF-8; Windows error " +
                             std::to_string(GetLastError())};
  }

  std::string result(static_cast<std::size_t>(output_size), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), input_size, result.data(),
                          output_size, nullptr, nullptr) != output_size) {
    throw std::runtime_error{"cannot convert a command line argument to UTF-8; Windows error " +
                             std::to_string(GetLastError())};
  }
  return result;
}
#endif

}  // namespace

#if defined(_WIN32)
int wmain(int argc, wchar_t* argv[]) {
  try {
    std::vector<std::string> utf8_arguments;
    utf8_arguments.reserve(static_cast<std::size_t>(argc));
    for (int index = 0; index < argc; ++index) {
      utf8_arguments.push_back(wide_to_utf8(argv[index]));
    }

    std::vector<const char*> argument_pointers;
    argument_pointers.reserve(utf8_arguments.size());
    for (const auto& argument : utf8_arguments) {
      argument_pointers.push_back(argument.c_str());
    }
    return run_application(static_cast<int>(argument_pointers.size()), argument_pointers.data());
  } catch (const std::exception& error) {
    std::cerr << "error: " << error.what() << '\n';
    return 1;
  }
}
#else
int main(int argc, char* argv[]) { return run_application(argc, argv); }
#endif
