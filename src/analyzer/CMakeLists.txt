add_library(noleax-analyzer STATIC
  event_stream.cpp
  generation_tracker.cpp
  outstanding.cpp
  time.cpp
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

noleax_set_project_warnings(noleax-analyzer)
