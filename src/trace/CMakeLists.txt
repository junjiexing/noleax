add_library(noleax-trace STATIC
  completeness.cpp
  event.cpp
  trace_reader.cpp
  trace_writer.cpp
  wire_format.cpp
)

add_library(noleax::trace ALIAS noleax-trace)

target_include_directories(noleax-trace
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

find_package(lz4 CONFIG REQUIRED)
find_package(zstd CONFIG REQUIRED)
target_link_libraries(noleax-trace
  PRIVATE
    lz4::lz4
    zstd::libzstd
)

noleax_set_project_warnings(noleax-trace)
