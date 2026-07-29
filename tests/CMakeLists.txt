find_package(Catch2 3 CONFIG REQUIRED)
find_package(lz4 CONFIG REQUIRED)
find_package(zstd CONFIG REQUIRED)

add_executable(noleax-unit-tests
  support/csv_table.cpp
  support/json_dom.cpp
  support/json_schema.cpp
  support/synthetic_trace.cpp
  unit/analyzer_event_stream_test.cpp
  unit/bounded_mpsc_queue_test.cpp
  unit/console_test.cpp
  unit/csv_test.cpp
  unit/filter_test.cpp
  unit/generation_tracker_test.cpp
  unit/json_test.cpp
  unit/outstanding_test.cpp
  unit/replacement_lifecycle_test.cpp
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
  target_sources(noleax-unit-tests PRIVATE
    unit/hook_guard_test.cpp
    unit/hook_backend_test.cpp
    unit/stack_capture_test.cpp
    unit/stack_dictionary_test.cpp
  )
  target_link_libraries(noleax-unit-tests PRIVATE noleax::hook-backend)

  add_library(noleax-hook-backend-fixture SHARED
    integration/hook_backend_fixture.cpp
  )
  noleax_set_project_warnings(noleax-hook-backend-fixture)
  if(MSVC)
    target_link_options(noleax-hook-backend-fixture PRIVATE /OPT:NOICF)
  endif()

  add_dependencies(noleax-unit-tests noleax-hook-backend-fixture)
  target_compile_definitions(noleax-unit-tests PRIVATE
    NOLEAX_HOOK_FIXTURE_PATH="$<TARGET_FILE:noleax-hook-backend-fixture>"
  )

  add_library(noleax-rtl-allocate-heap-hook-harness SHARED
    integration/rtl_allocate_heap_hook_harness.cpp
  )
  target_link_libraries(noleax-rtl-allocate-heap-hook-harness PRIVATE
    noleax::hook-backend
  )
  noleax_set_project_warnings(noleax-rtl-allocate-heap-hook-harness)

  add_executable(noleax-rtl-allocate-heap-trace-writer-test
    integration/rtl_allocate_heap_trace_writer_test.cpp
  )
  target_link_libraries(noleax-rtl-allocate-heap-trace-writer-test PRIVATE
    noleax::hook-backend
    noleax::analyzer
  )
  noleax_set_project_warnings(noleax-rtl-allocate-heap-trace-writer-test)

  add_executable(noleax-rtl-allocate-heap-quiescence-test
    integration/rtl_allocate_heap_quiescence_test.cpp
  )
  target_link_libraries(noleax-rtl-allocate-heap-quiescence-test PRIVATE
    noleax::hook-backend
  )
  noleax_set_project_warnings(noleax-rtl-allocate-heap-quiescence-test)

  add_test(NAME hook.rtl-allocate-heap-quiescence-race
    COMMAND noleax-rtl-allocate-heap-quiescence-test
  )
  set_tests_properties(hook.rtl-allocate-heap-quiescence-race PROPERTIES
    LABELS "hook;windows;rtl-heap;quiescence;race;stress"
    PASS_REGULAR_EXPRESSION "^status=ok "
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  add_executable(noleax-rtl-allocate-heap-module-retention-test
    integration/rtl_allocate_heap_module_retention_test.cpp
  )
  noleax_set_project_warnings(noleax-rtl-allocate-heap-module-retention-test)
  add_dependencies(
    noleax-rtl-allocate-heap-module-retention-test
    noleax-rtl-allocate-heap-hook-harness
  )

  add_test(NAME hook.rtl-allocate-heap-module-retention
    COMMAND noleax-rtl-allocate-heap-module-retention-test
      "$<TARGET_FILE:noleax-rtl-allocate-heap-hook-harness>"
  )
  set_tests_properties(hook.rtl-allocate-heap-module-retention PROPERTIES
    LABELS "hook;windows;rtl-heap;quiescence;unload"
    PASS_REGULAR_EXPRESSION "^status=ok module-retained=1"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  foreach(trace_mode IN ITEMS empty normal queue-limit file-limit)
    add_test(NAME hook.rtl-allocate-heap-trace-writer-${trace_mode}
      COMMAND noleax-rtl-allocate-heap-trace-writer-test
        "${trace_mode}"
        "$<TARGET_FILE_DIR:noleax-rtl-allocate-heap-trace-writer-test>/rtl-allocate-heap-${trace_mode}.nlx"
    )
    set_tests_properties(hook.rtl-allocate-heap-trace-writer-${trace_mode} PROPERTIES
      LABELS "hook;trace;writer;windows;rtl-heap;stress"
      RUN_SERIAL TRUE
      TIMEOUT 120
    )
  endforeach()

  set(noleax_rtl_heap_baseline_arguments
    --threads 4
    --iterations 2000
    --rounds 2
    --seed 5642812718451281972
  )

  function(noleax_add_rtl_heap_baseline target test_suffix runtime)
    add_executable(${target}
      targets/rtl_heap_baseline.cpp
    )
    noleax_set_project_warnings(${target})
    if(MSVC)
      set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_LIBRARY "${runtime}")
    endif()

    add_test(NAME hook.rtl-heap-baseline-${test_suffix}
      COMMAND ${target} ${noleax_rtl_heap_baseline_arguments}
    )
    set_tests_properties(hook.rtl-heap-baseline-${test_suffix} PROPERTIES
      LABELS "hook;stress;windows;rtl-heap;baseline"
      PASS_REGULAR_EXPRESSION "^status=ok version=1 "
      RUN_SERIAL TRUE
      TIMEOUT 60
    )
  endfunction()

  noleax_add_rtl_heap_baseline(
    noleax-rtl-heap-baseline-md
    md
    "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
  )
  noleax_add_rtl_heap_baseline(
    noleax-rtl-heap-baseline-mt
    mt
    "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_dependencies(
    noleax-rtl-heap-baseline-md
    noleax-rtl-allocate-heap-hook-harness
  )
  add_dependencies(
    noleax-rtl-heap-baseline-mt
    noleax-rtl-allocate-heap-hook-harness
  )

  foreach(test_suffix IN ITEMS md mt)
    add_test(NAME hook.rtl-allocate-heap-passthrough-${test_suffix}
      COMMAND noleax-rtl-heap-baseline-${test_suffix}
        ${noleax_rtl_heap_baseline_arguments}
        --hook-harness "$<TARGET_FILE:noleax-rtl-allocate-heap-hook-harness>"
    )
    set_tests_properties(hook.rtl-allocate-heap-passthrough-${test_suffix} PROPERTIES
      LABELS "hook;stress;windows;rtl-heap;passthrough"
      PASS_REGULAR_EXPRESSION "^status=ok version=1 "
      RUN_SERIAL TRUE
      TIMEOUT 60
    )
  endforeach()

  add_test(NAME hook.rtl-heap-baseline.compare-crt
    COMMAND "${CMAKE_COMMAND}"
      "-DNOLEAX_BASELINE_MD=$<TARGET_FILE:noleax-rtl-heap-baseline-md>"
      "-DNOLEAX_BASELINE_MT=$<TARGET_FILE:noleax-rtl-heap-baseline-mt>"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CompareRtlHeapBaselines.cmake"
  )
  set_tests_properties(hook.rtl-heap-baseline.compare-crt PROPERTIES
    LABELS "hook;stress;windows;rtl-heap;baseline"
    PASS_REGULAR_EXPRESSION "Matching Rtl heap baseline"
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_test(NAME hook.rtl-allocate-heap-passthrough.compare-baseline
    COMMAND "${CMAKE_COMMAND}"
      "-DNOLEAX_BASELINE_MD=$<TARGET_FILE:noleax-rtl-heap-baseline-md>"
      "-DNOLEAX_BASELINE_MT=$<TARGET_FILE:noleax-rtl-heap-baseline-mt>"
      "-DNOLEAX_HOOK_HARNESS=$<TARGET_FILE:noleax-rtl-allocate-heap-hook-harness>"
      -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CompareRtlAllocateHeapPassthrough.cmake"
  )
  set_tests_properties(hook.rtl-allocate-heap-passthrough.compare-baseline PROPERTIES
    LABELS "hook;stress;windows;rtl-heap;passthrough"
    PASS_REGULAR_EXPRESSION "RtlAllocateHeap passthrough matches both baselines"
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

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
