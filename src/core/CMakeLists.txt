add_library(noleax-core STATIC
  version.cpp
)

add_library(noleax::core ALIAS noleax-core)

target_include_directories(noleax-core
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

noleax_set_project_warnings(noleax-core)
