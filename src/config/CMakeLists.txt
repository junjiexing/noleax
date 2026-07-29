add_library(noleax-config STATIC
  configuration.cpp
  configuration_validation.cpp
  effective_config.cpp
  toml_config.cpp
  value_parser.cpp
)

add_library(noleax::config ALIAS noleax-config)

target_include_directories(noleax-config
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

find_package(tomlplusplus CONFIG REQUIRED)
target_link_libraries(noleax-config PRIVATE tomlplusplus::tomlplusplus)

noleax_set_project_warnings(noleax-config)
