find_package(Catch2 3 CONFIG REQUIRED)
find_package(lz4 CONFIG REQUIRED)
find_package(zstd CONFIG REQUIRED)

add_executable(noleax-unit-tests
  support/csv_table.cpp
  support/json_dom.cpp
  support/json_schema.cpp
  support/synthetic_trace.cpp
  unit/analyzer_event_stream_test.cpp
  unit/console_test.cpp
  unit/csv_test.cpp
  unit/filter_test.cpp
  unit/generation_tracker_test.cpp
  unit/json_test.cpp
  unit/outstanding_test.cpp
  unit/symbolizer_test.cpp
  unit/time_test.cpp
  unit/command_line_test.cpp
  unit/completeness_test.cpp
  unit/configuration_test.cpp
  unit/event_test.cpp
  unit/record_codec_test.cpp
  unit/synthetic_trace_test.cpp
  unit/trace_reader_test.cpp
  unit/trace_writer_test.cpp
  unit/value_parser_test.cpp
  unit/version_test.cpp
)

target_link_libraries(noleax-unit-tests
  PRIVATE
    Catch2::Catch2WithMain
    noleax::analyzer
    noleax::cli
    noleax::config
    noleax::core
    noleax::trace
    lz4::lz4
    zstd::libzstd
)

target_include_directories(noleax-unit-tests PRIVATE "${PROJECT_SOURCE_DIR}/tests")

target_compile_definitions(noleax-unit-tests PRIVATE
  NOLEAX_TEST_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
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

add_test(NAME config.validate
  COMMAND noleax --config "${PROJECT_SOURCE_DIR}/tests/fixtures/valid-doctor.toml" config validate)
set_tests_properties(config.validate PROPERTIES
  PASS_REGULAR_EXPRESSION "configuration is valid")

add_test(NAME config.print-effective
  COMMAND noleax --config "${PROJECT_SOURCE_DIR}/tests/fixtures/valid-doctor.toml" config print-effective)
set_tests_properties(config.print-effective PROPERTIES
  PASS_REGULAR_EXPRESSION "operation = \"doctor\" # source: config")

if(WIN32)
  add_library(noleax-symbolizer-fixture SHARED
    integration/symbolizer_fixture.cpp
  )
  noleax_set_project_warnings(noleax-symbolizer-fixture)
  if(MSVC)
    target_compile_options(noleax-symbolizer-fixture PRIVATE /Od /Zi)
    target_link_options(noleax-symbolizer-fixture PRIVATE /DEBUG:FULL /OPT:NOREF /OPT:NOICF)
  endif()

  add_dependencies(noleax-unit-tests noleax-symbolizer-fixture)
  target_compile_definitions(noleax-unit-tests PRIVATE
    NOLEAX_SYMBOL_FIXTURE_PATH="$<TARGET_FILE:noleax-symbolizer-fixture>"
  )

  add_executable(noleax-agent-smoke
    integration/agent_smoke.cpp
  )
  noleax_set_project_warnings(noleax-agent-smoke)

  add_test(NAME agent.load-and-link-hoox
    COMMAND noleax-agent-smoke "$<TARGET_FILE:noleax-agent>")
endif()
