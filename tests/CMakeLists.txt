find_package(Catch2 3 CONFIG REQUIRED)

add_executable(noleax-unit-tests
  unit/version_test.cpp
)

target_link_libraries(noleax-unit-tests
  PRIVATE
    Catch2::Catch2WithMain
    noleax::core
)

noleax_set_project_warnings(noleax-unit-tests)

include(Catch)
catch_discover_tests(noleax-unit-tests)

add_test(NAME cli.version COMMAND noleax --version)
set_tests_properties(cli.version PROPERTIES
  PASS_REGULAR_EXPRESSION "0\\.1\\.0-dev")

add_test(NAME cli.help COMMAND noleax --help)
set_tests_properties(cli.help PROPERTIES
  PASS_REGULAR_EXPRESSION "Hook-based memory event capture")

if(WIN32)
  add_executable(noleax-agent-smoke
    integration/agent_smoke.cpp
  )
  noleax_set_project_warnings(noleax-agent-smoke)

  add_test(NAME agent.load-and-link-hoox
    COMMAND noleax-agent-smoke "$<TARGET_FILE:noleax-agent>")
endif()
