#include <CLI/CLI.hpp>
#include <iostream>
#include <string>

#include "noleax/version.hpp"

int main(int argc, char* argv[]) {
  CLI::App app{"Hook-based memory event capture and analysis tool", "noleax"};
  app.set_version_flag("--version", std::string{noleax::version_string()});

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& error) {
    return app.exit(error);
  }

  if (argc == 1) {
    std::cout << app.help();
  }

  return 0;
}
