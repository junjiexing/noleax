add_library(noleax-config STATIC
  value_parser.cpp
)

add_library(noleax::config ALIAS noleax-config)

target_include_directories(noleax-config
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

noleax_set_project_warnings(noleax-config)
