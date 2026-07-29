add_library(noleax-cli STATIC
  command_line.cpp
)

add_library(noleax::cli ALIAS noleax-cli)

target_include_directories(noleax-cli
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

target_link_libraries(noleax-cli
  PUBLIC
    noleax::config
  PRIVATE
    CLI11::CLI11
    noleax::core
)

noleax_set_project_warnings(noleax-cli)
