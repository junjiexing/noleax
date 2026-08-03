add_library(noleax-analyzer STATIC
  console.cpp
  csv.cpp
  event_stream.cpp
  filter.cpp
  generation_tracker.cpp
  json.cpp
  outstanding.cpp
  stacks.cpp
  symbolizer.cpp
  time.cpp
  trace_metadata.cpp
  utf8.cpp
  window.cpp
)

add_library(noleax::analyzer ALIAS noleax-analyzer)

target_include_directories(noleax-analyzer
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

target_link_libraries(noleax-analyzer
  PUBLIC
    noleax::trace
)

if(WIN32)
  target_link_libraries(noleax-analyzer PRIVATE dbghelp)
endif()

noleax_set_project_warnings(noleax-analyzer)
