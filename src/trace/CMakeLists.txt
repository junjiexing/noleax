add_library(noleax-trace STATIC
  event.cpp
)

add_library(noleax::trace ALIAS noleax-trace)

target_include_directories(noleax-trace
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

noleax_set_project_warnings(noleax-trace)
