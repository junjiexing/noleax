add_executable(noleax
  main.cpp
  operations.cpp
)

target_link_libraries(noleax
  PRIVATE
    noleax::analyzer
    noleax::cli
    noleax::controller
    noleax::core
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # The custom-hook *_sym locator resolution reads target modules with the analyzer's ELF
  # reader, whose header lives next to its implementation (mirrors the unit test setup).
  target_include_directories(noleax PRIVATE "${PROJECT_SOURCE_DIR}/src/analyzer")
endif()

noleax_set_project_warnings(noleax)
