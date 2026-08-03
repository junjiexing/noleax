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
  unit/ipc_protocol_test.cpp
  unit/outstanding_test.cpp
  unit/stacks_test.cpp
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
  unit/trace_metadata_test.cpp
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
    noleax::ipc
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
    unit/controller_diagnostics_test.cpp
    unit/controller_process_test.cpp
    unit/entrypoint_injector_test.cpp
    unit/ipc_named_pipe_test.cpp
    unit/hook_guard_test.cpp
    unit/hook_backend_test.cpp
    unit/patch_rendezvous_test.cpp
    unit/pe_patch_test.cpp
    unit/stack_capture_test.cpp
    unit/stack_dictionary_test.cpp
    unit/windows_hook_registry_test.cpp
  )
  target_link_libraries(noleax-unit-tests PRIVATE noleax::hook-backend)
  target_link_libraries(noleax-unit-tests PRIVATE noleax::controller)
  target_link_libraries(noleax-unit-tests PRIVATE Shell32)

  add_executable(noleax-controller-target
    targets/controller_target.cpp
  )
  noleax_set_project_warnings(noleax-controller-target)

  add_executable(noleax-cli-e2e-target
    targets/cli_e2e_target.cpp
  )
  noleax_set_project_warnings(noleax-cli-e2e-target)

  add_executable(noleax-capture-benchmark-target
    targets/capture_benchmark_target.cpp
  )
  noleax_set_project_warnings(noleax-capture-benchmark-target)

  add_executable(noleax-cli-end-to-end-test
    integration/cli_end_to_end_test.cpp
    support/csv_table.cpp
    support/json_dom.cpp
  )
  target_include_directories(noleax-cli-end-to-end-test PRIVATE "${PROJECT_SOURCE_DIR}/tests")
  target_link_libraries(noleax-cli-end-to-end-test PRIVATE noleax::controller)
  noleax_set_project_warnings(noleax-cli-end-to-end-test)

  add_dependencies(noleax-cli-end-to-end-test noleax noleax-agent noleax-cli-e2e-target)
  add_test(NAME cli.end-to-end-trace-analyze
    COMMAND noleax-cli-end-to-end-test
      "$<TARGET_FILE:noleax>"
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-cli-e2e-target>"
      "$<TARGET_FILE_DIR:noleax-cli-end-to-end-test>/cli-e2e"
  )
  set_tests_properties(cli.end-to-end-trace-analyze PROPERTIES
    LABELS "cli;controller;agent;run;attach;trace;analyzer;outstanding;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok run=1 attach=1 hijack=1 entrypoint=1 patch=1 static=1 agent=1 outstanding=1 console=1 json=1 csv=1 stacks=1 errors=1"
    RUN_SERIAL TRUE
    TIMEOUT 90
  )

  add_executable(noleax-cli-recovery-test
    integration/cli_recovery_test.cpp
    support/json_dom.cpp
  )
  target_include_directories(noleax-cli-recovery-test PRIVATE "${PROJECT_SOURCE_DIR}/tests")
  target_link_libraries(noleax-cli-recovery-test PRIVATE
    noleax::controller
    noleax::trace
  )
  noleax_set_project_warnings(noleax-cli-recovery-test)
  add_dependencies(noleax-cli-recovery-test noleax)

  add_test(NAME cli.trace-recovery-compatibility
    COMMAND noleax-cli-recovery-test
      "$<TARGET_FILE:noleax>"
      "$<TARGET_FILE_DIR:noleax-cli-recovery-test>/cli-recovery"
  )
  set_tests_properties(cli.trace-recovery-compatibility PROPERTIES
    LABELS "cli;trace;analyzer;recovery;compatibility;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok truncated=1 corrupt=1 future-minor=1 future-major=1 unknown-record=1 retained-events=3 exit-codes=2,4"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  find_program(NOLEAX_PWSH_EXECUTABLE NAMES pwsh REQUIRED)
  add_test(NAME docs.windows-x64-examples
    COMMAND "${NOLEAX_PWSH_EXECUTABLE}" -NoProfile
      -File "${PROJECT_SOURCE_DIR}/scripts/Test-DocumentationExamples.ps1"
      -NoleaxPath "$<TARGET_FILE:noleax>"
      -AgentPath "$<TARGET_FILE:noleax-agent>"
      -TargetPath "$<TARGET_FILE:noleax-cli-e2e-target>"
  )
  set_tests_properties(docs.windows-x64-examples PROPERTIES
    LABELS "docs;examples;cli;run;trace;analyzer;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok configs=3 capture=1 events=1 outstanding=1 patch=1 hijack=1"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_test(NAME package.windows-x64-smoke
      COMMAND "${NOLEAX_PWSH_EXECUTABLE}" -NoProfile
        -File "${PROJECT_SOURCE_DIR}/scripts/Test-NoleaxPackage.ps1"
        -BuildDirectory "${CMAKE_BINARY_DIR}"
        -TargetPath "$<TARGET_FILE:noleax-cli-e2e-target>"
        -SkipBuild
    )
    set_tests_properties(package.windows-x64-smoke PROPERTIES
      LABELS "package;install;cpack;licenses;cli;run;trace;analyzer;windows"
      PASS_REGULAR_EXPRESSION
        "^status=ok stage=1 archive=1 workflows=2 images=[0-9]+/[0-9]+ licenses=6 sha256=1"
      RUN_SERIAL TRUE
      TIMEOUT 180
    )
  endif()

  add_test(NAME cli.trace-untrusted-corpus
    COMMAND "${NOLEAX_PWSH_EXECUTABLE}" -NoProfile
      -File "${PROJECT_SOURCE_DIR}/scripts/Test-UntrustedTraces.ps1"
      -Preset "windows-x64-release"
      -MutationCount 8
      -TimeoutMilliseconds 5000
      -NoleaxPath "$<TARGET_FILE:noleax>"
      -RecoveryToolPath "$<TARGET_FILE:noleax-cli-recovery-test>"
      -ReportPath "$<TARGET_FILE_DIR:noleax-cli-recovery-test>/untrusted-corpus-report.json"
      -SkipBuild
  )
  set_tests_properties(cli.trace-untrusted-corpus PROPERTIES
    LABELS "cli;trace;analyzer;security;mutation;untrusted;windows"
    PASS_REGULAR_EXPRESSION
      "status=passed cases=86 timeouts=0 unexpected=0"
    RUN_SERIAL TRUE
    TIMEOUT 180
  )

  add_dependencies(noleax-unit-tests noleax-agent noleax-controller-target)
  target_compile_definitions(noleax-unit-tests PRIVATE
    NOLEAX_TEST_AGENT_PATH="$<TARGET_FILE:noleax-agent>"
    NOLEAX_TEST_CONTROLLER_TARGET_PATH="$<TARGET_FILE:noleax-controller-target>"
  )

  if(MSVC OR (WIN32 AND CMAKE_CXX_COMPILER_ID MATCHES "Clang"))
    enable_language(ASM_MASM)
  endif()

  add_executable(noleax-entrypoint-launch-test
    integration/entrypoint_launch_test.cpp
  )
  target_link_libraries(noleax-entrypoint-launch-test PRIVATE
    noleax::analyzer
    noleax::controller
  )
  noleax_set_project_warnings(noleax-entrypoint-launch-test)

  add_test(NAME controller.entrypoint-launch
    COMMAND noleax-entrypoint-launch-test
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-controller-target>"
      "$<TARGET_FILE_DIR:noleax-entrypoint-launch-test>/entrypoint-launch.nlx"
      "$<TARGET_FILE_DIR:noleax-entrypoint-launch-test>/entrypoint-launch.ready"
  )
  set_tests_properties(controller.entrypoint-launch PROPERTIES
    LABELS "controller;agent;ipc;injection;entrypoint;launch;trace;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok kind=entrypoint ready-before-main=1 state=finalized events=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 90
  )

  add_executable(noleax-entrypoint-rollback-test
    integration/entrypoint_rollback_test.cpp
  )
  target_link_libraries(noleax-entrypoint-rollback-test PRIVATE
    noleax::controller
  )
  noleax_set_project_warnings(noleax-entrypoint-rollback-test)

  add_test(NAME controller.entrypoint-rollback
    COMMAND noleax-entrypoint-rollback-test
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-injector-no-bootstrap>"
      "$<TARGET_FILE:noleax-controller-target>"
      "$<TARGET_FILE_DIR:noleax-entrypoint-rollback-test>/entrypoint-rollback"
  )
  set_tests_properties(controller.entrypoint-rollback PROPERTIES
    LABELS "controller;agent;injection;entrypoint;rollback;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok reject=1 ready-timeout=1 entry-restored=1"
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_executable(noleax-pe-patch-e2e-test
    integration/pe_patch_e2e_test.cpp
  )
  target_link_libraries(noleax-pe-patch-e2e-test PRIVATE
    noleax::analyzer
    noleax::controller
  )
  noleax_set_project_warnings(noleax-pe-patch-e2e-test)
  add_dependencies(noleax-pe-patch-e2e-test noleax-agent noleax-controller-target)

  add_executable(noleax-standalone-capture-test
    integration/standalone_capture_test.cpp
  )
  target_link_libraries(noleax-standalone-capture-test PRIVATE
    noleax::analyzer
    noleax::controller
  )
  noleax_set_project_warnings(noleax-standalone-capture-test)
  add_dependencies(noleax-standalone-capture-test noleax-agent noleax-controller-target)

  add_test(NAME agent.standalone-capture
    COMMAND noleax-standalone-capture-test
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-controller-target>"
      "$<TARGET_FILE_DIR:noleax-standalone-capture-test>/standalone"
      "$<TARGET_FILE_DIR:noleax-standalone-capture-test>/standalone-pipe.nlx"
  )
  set_tests_properties(agent.standalone-capture PROPERTIES
    LABELS "agent;capture;static-pe-patch;standalone;trace;windows"
    PASS_REGULAR_EXPRESSION "status=ok standalone=1 sibling=1 env=1 disabled=1 pipe=1"
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_test(NAME controller.static-pe-patch
    COMMAND noleax-pe-patch-e2e-test
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-controller-target>"
      "$<TARGET_FILE_DIR:noleax-pe-patch-e2e-test>/pe-patch"
      "$<TARGET_FILE_DIR:noleax-pe-patch-e2e-test>/pe-patch.nlx"
  )
  set_tests_properties(controller.static-pe-patch PROPERTIES
    LABELS "controller;agent;ipc;injection;static-pe-patch;pe;patch;launch;trace;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok patched=1 standalone=1 capture=1 rejected=1 events=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_executable(noleax-register-workload-target
    targets/register_workload_target.cpp
    targets/register_workload.asm
  )
  noleax_set_project_warnings(noleax-register-workload-target)

  add_executable(noleax-thread-hijack-launch-test
    integration/thread_hijack_launch_test.cpp
  )
  target_link_libraries(noleax-thread-hijack-launch-test PRIVATE
    noleax::analyzer
    noleax::controller
  )
  noleax_set_project_warnings(noleax-thread-hijack-launch-test)

  add_test(NAME controller.thread-hijack-launch
    COMMAND noleax-thread-hijack-launch-test
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-controller-target>"
      "$<TARGET_FILE_DIR:noleax-thread-hijack-launch-test>/thread-hijack-launch.nlx"
      "$<TARGET_FILE_DIR:noleax-thread-hijack-launch-test>/thread-hijack-launch.ready"
  )
  set_tests_properties(controller.thread-hijack-launch PROPERTIES
    LABELS "controller;agent;ipc;injection;thread-hijack;launch;trace;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok kind=launch-hijack ready-before-main=1 state=finalized events=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 90
  )

  add_executable(noleax-thread-hijack-attach-test
    integration/thread_hijack_attach_test.cpp
  )
  target_link_libraries(noleax-thread-hijack-attach-test PRIVATE
    noleax::analyzer
    noleax::controller
  )
  noleax_set_project_warnings(noleax-thread-hijack-attach-test)
  add_dependencies(noleax-thread-hijack-attach-test noleax-register-workload-target)

  add_test(NAME controller.thread-hijack-attach
    COMMAND noleax-thread-hijack-attach-test
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-injector-no-bootstrap>"
      "$<TARGET_FILE:noleax-register-workload-target>"
      "$<TARGET_FILE_DIR:noleax-thread-hijack-attach-test>/thread-hijack-attach"
  )
  set_tests_properties(controller.thread-hijack-attach PROPERTIES
    LABELS "controller;agent;ipc;injection;thread-hijack;attach;rollback;context;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok baseline=1 attach=1 reject=1 timeout=1 digest=4 events=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 300
  )

  add_library(noleax-slow-bootstrap-agent SHARED
    targets/slow_bootstrap_agent.cpp
  )
  set_target_properties(noleax-slow-bootstrap-agent PROPERTIES PREFIX "")
  noleax_set_project_warnings(noleax-slow-bootstrap-agent)

  add_executable(noleax-thread-hijack-timeout-test
    integration/thread_hijack_timeout_test.cpp
  )
  target_link_libraries(noleax-thread-hijack-timeout-test PRIVATE
    noleax::controller
  )
  noleax_set_project_warnings(noleax-thread-hijack-timeout-test)
  add_dependencies(noleax-thread-hijack-timeout-test noleax-slow-bootstrap-agent)

  add_test(NAME controller.thread-hijack-timeout
    COMMAND noleax-thread-hijack-timeout-test
      "$<TARGET_FILE:noleax-slow-bootstrap-agent>"
      "$<TARGET_FILE_DIR:noleax-thread-hijack-timeout-test>/hijack-timeout-work"
  )
  set_tests_properties(controller.thread-hijack-timeout PROPERTIES
    LABELS "controller;injection;thread-hijack;timeout;windows"
    PASS_REGULAR_EXPRESSION "^status=ok waited=1 forced=1"
    RUN_SERIAL TRUE
    TIMEOUT 90
  )

  add_test(NAME cli.doctor
    COMMAND noleax doctor
      --agent "$<TARGET_FILE:noleax-agent>"
      --target "$<TARGET_FILE:noleax-controller-target>"
  )
  set_tests_properties(cli.doctor PROPERTIES
    LABELS "cli;controller;doctor;windows"
    PASS_REGULAR_EXPRESSION
      "agent-image: x64 PE32"
  )

  add_executable(noleax-controller-lifecycle-target
    targets/controller_lifecycle_target.cpp
  )
  noleax_set_project_warnings(noleax-controller-lifecycle-target)

  add_library(noleax-injector-no-bootstrap SHARED
    integration/injector_no_bootstrap.cpp
  )
  noleax_set_project_warnings(noleax-injector-no-bootstrap)

  add_executable(noleax-controller-launch-test
    integration/controller_launch_test.cpp
  )
  target_link_libraries(noleax-controller-launch-test PRIVATE
    noleax::analyzer
    noleax::controller
  )
  noleax_set_project_warnings(noleax-controller-launch-test)

  add_test(NAME controller.suspended-launch-ready
    COMMAND noleax-controller-launch-test
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-controller-target>"
      "$<TARGET_FILE_DIR:noleax-controller-launch-test>/controller-launch.nlx"
      "$<TARGET_FILE_DIR:noleax-controller-launch-test>/controller-launch.ready"
  )
  set_tests_properties(controller.suspended-launch-ready PROPERTIES
    LABELS "controller;agent;ipc;injection;remote-thread;launch;trace;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok kind=launch ready-before-main=1 state=finalized events=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  add_executable(noleax-controller-attach-test
    integration/controller_attach_test.cpp
  )
  target_link_libraries(noleax-controller-attach-test PRIVATE
    noleax::analyzer
    noleax::controller
  )
  noleax_set_project_warnings(noleax-controller-attach-test)

  add_test(NAME controller.runtime-attach
    COMMAND noleax-controller-attach-test
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-controller-target>"
      "$<TARGET_FILE_DIR:noleax-controller-attach-test>/controller-attach.nlx"
      "$<TARGET_FILE_DIR:noleax-controller-attach-test>/controller-attach.ready"
  )
  set_tests_properties(controller.runtime-attach PROPERTIES
    LABELS "controller;agent;ipc;injection;remote-thread;attach;trace;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok kind=attach preexisting-unknown=1 state=finalized events=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  add_executable(noleax-controller-attach-unload-test
    integration/controller_attach_unload_test.cpp
  )
  target_link_libraries(noleax-controller-attach-unload-test PRIVATE
    noleax::analyzer
    noleax::controller
  )
  noleax_set_project_warnings(noleax-controller-attach-unload-test)

  add_test(NAME controller.attach-unload-on-stop
    COMMAND noleax-controller-attach-unload-test
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-controller-target>"
      "$<TARGET_FILE_DIR:noleax-controller-attach-unload-test>/attach-unload"
      "$<TARGET_FILE_DIR:noleax-controller-attach-unload-test>/attach-unload.ready"
  )
  set_tests_properties(controller.attach-unload-on-stop PROPERTIES
    LABELS "controller;agent;injection;attach;unload;windows"
    PASS_REGULAR_EXPRESSION "^status=ok live=1 direct=1"
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_executable(noleax-controller-lifecycle-test
    integration/controller_lifecycle_test.cpp
  )
  target_link_libraries(noleax-controller-lifecycle-test PRIVATE
    noleax::analyzer
    noleax::controller
  )
  noleax_set_project_warnings(noleax-controller-lifecycle-test)

  add_test(NAME controller.capture-lifecycle
    COMMAND noleax-controller-lifecycle-test
      "$<TARGET_FILE:noleax-agent>"
      "$<TARGET_FILE:noleax-controller-lifecycle-target>"
      "$<TARGET_FILE_DIR:noleax-controller-lifecycle-test>/controller-lifecycle.nlx"
      "$<TARGET_FILE_DIR:noleax-controller-lifecycle-test>/controller-lifecycle.ready"
  )
  set_tests_properties(controller.capture-lifecycle PROPERTIES
    LABELS "controller;agent;ipc;lifecycle;in-flight;stress;trace;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok lifecycle=finalized queries=[2-9][0-9]* active-stop=1 idempotent=1 conserved=1 events=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  add_executable(noleax-injector-rollback-test
    integration/injector_rollback_test.cpp
  )
  target_link_libraries(noleax-injector-rollback-test PRIVATE
    noleax::controller
    Psapi
  )
  noleax_set_project_warnings(noleax-injector-rollback-test)

  add_test(NAME controller.remote-thread-rollback
    COMMAND noleax-injector-rollback-test
      "$<TARGET_FILE:noleax-injector-no-bootstrap>"
      "$<TARGET_FILE:noleax-controller-target>"
      "$<TARGET_FILE_DIR:noleax-injector-rollback-test>/injector-rollback.ready"
  )
  set_tests_properties(controller.remote-thread-rollback PROPERTIES
    LABELS "controller;injection;remote-thread;rollback;windows"
    PASS_REGULAR_EXPRESSION
      "^status=ok rollback=1 module-unloaded=1 main-suspended=1 attempts=8 handles-stable=1"
    RUN_SERIAL TRUE
    TIMEOUT 30
  )

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

  add_executable(noleax-rtl-heap-trace-writer-test
    integration/rtl_heap_trace_writer_test.cpp
  )
  target_link_libraries(noleax-rtl-heap-trace-writer-test PRIVATE
    noleax::hook-backend
    noleax::analyzer
  )
  noleax_set_project_warnings(noleax-rtl-heap-trace-writer-test)

  add_executable(noleax-nt-virtual-memory-trace-writer-test
    integration/nt_virtual_memory_trace_writer_test.cpp
  )
  target_link_libraries(noleax-nt-virtual-memory-trace-writer-test PRIVATE
    noleax::hook-backend
    noleax::analyzer
  )
  noleax_set_project_warnings(noleax-nt-virtual-memory-trace-writer-test)

  add_executable(noleax-windows-native-profile-test
    integration/windows_native_profile_test.cpp
  )
  target_link_libraries(noleax-windows-native-profile-test PRIVATE
    noleax::hook-backend
    noleax::analyzer
  )
  noleax_set_project_warnings(noleax-windows-native-profile-test)

  add_test(NAME hook.windows-native-profile
    COMMAND noleax-windows-native-profile-test
      "$<TARGET_FILE_DIR:noleax-windows-native-profile-test>/windows-native-profile.nlx"
  )
  set_tests_properties(hook.windows-native-profile PROPERTIES
    LABELS "hook;trace;writer;windows;profile;registry;filter;statistics;quiescence;stress"
    PASS_REGULAR_EXPRESSION
      "^status=ok profile=windows-native apis=9 events=[0-9]+ filtered=[1-9][0-9]* stable=1 writer-before-revert=1 operations=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 180
  )

  add_library(noleax-module-generation-fixture SHARED
    integration/module_generation_fixture.cpp
  )
  noleax_set_project_warnings(noleax-module-generation-fixture)
  if(MSVC)
    target_compile_options(noleax-module-generation-fixture PRIVATE /Od /Zi)
    target_link_options(noleax-module-generation-fixture PRIVATE /DEBUG:FULL /OPT:NOREF /OPT:NOICF)
  endif()

  add_executable(noleax-module-generation-trace-test
    integration/module_generation_trace_test.cpp
  )
  target_link_libraries(noleax-module-generation-trace-test PRIVATE
    noleax::hook-backend
    noleax::analyzer
  )
  noleax_set_project_warnings(noleax-module-generation-trace-test)
  add_dependencies(noleax-module-generation-trace-test noleax-module-generation-fixture)

  add_test(NAME hook.module-generation-trace
    COMMAND noleax-module-generation-trace-test
      "$<TARGET_FILE:noleax-module-generation-fixture>"
      "$<TARGET_FILE_DIR:noleax-module-generation-trace-test>/module-generation.nlx"
  )
  set_tests_properties(hook.module-generation-trace PROPERTIES
    LABELS "hook;trace;writer;windows;module;generation;unload;reload;symbolizer"
    PASS_REGULAR_EXPRESSION
      "^status=ok loads=2 unload=1 base-reuse=1 relative-stack=1 symbolized=1 events=[0-9]+"
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_executable(noleax-module-tracker-test
    integration/module_tracker_test.cpp
  )
  target_link_libraries(noleax-module-tracker-test PRIVATE noleax::hook-backend)
  noleax_set_project_warnings(noleax-module-tracker-test)
  add_dependencies(noleax-module-tracker-test noleax-module-generation-fixture)
  add_test(NAME hook.module-tracker-bounded-queue
    COMMAND noleax-module-tracker-test "$<TARGET_FILE:noleax-module-generation-fixture>"
  )
  set_tests_properties(hook.module-tracker-bounded-queue PROPERTIES
    LABELS "hook;windows;module;loader;queue;overflow"
    PASS_REGULAR_EXPRESSION
      "^status=ok initial=[0-9]+ queued=2 dropped=4 load=1 unload=1"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  add_test(NAME hook.nt-virtual-memory-trace-writer
    COMMAND noleax-nt-virtual-memory-trace-writer-test
      "$<TARGET_FILE_DIR:noleax-nt-virtual-memory-trace-writer-test>/nt-virtual-memory.nlx"
  )
  set_tests_properties(hook.nt-virtual-memory-trace-writer PROPERTIES
    LABELS "hook;trace;writer;windows;nt-vm;generation;remote"
    PASS_REGULAR_EXPRESSION "^status=ok events=[0-9]+ reserve=1 commit=1 decommit=1 "
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_test(NAME hook.nt-section-view-unmatched-trace
    COMMAND noleax-nt-virtual-memory-trace-writer-test --unmatched
      "$<TARGET_FILE_DIR:noleax-nt-virtual-memory-trace-writer-test>/nt-section-unmatched.nlx"
  )
  set_tests_properties(hook.nt-section-view-unmatched-trace PROPERTIES
    LABELS "hook;trace;writer;windows;nt-vm;generation;unmap;unmatched"
    PASS_REGULAR_EXPRESSION "^status=ok unmatched=1 events=[0-9]+"
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_test(NAME hook.rtl-heap-trace-writer-lifecycle
    COMMAND noleax-rtl-heap-trace-writer-test
      "$<TARGET_FILE_DIR:noleax-rtl-heap-trace-writer-test>/rtl-heap-lifecycle.nlx"
  )
  set_tests_properties(hook.rtl-heap-trace-writer-lifecycle PROPERTIES
    LABELS "hook;trace;writer;windows;rtl-heap;free;lifecycle;cross-thread"
    PASS_REGULAR_EXPRESSION "^status=ok events=[0-9]+ alloc-free=1 realloc=5 cross-thread=1 "
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_executable(noleax-rtl-allocate-heap-quiescence-test
    integration/rtl_allocate_heap_quiescence_test.cpp
  )
  target_link_libraries(noleax-rtl-allocate-heap-quiescence-test PRIVATE
    noleax::hook-backend
  )
  noleax_set_project_warnings(noleax-rtl-allocate-heap-quiescence-test)

  add_executable(noleax-rtl-free-heap-quiescence-test
    integration/rtl_free_heap_quiescence_test.cpp
  )
  target_link_libraries(noleax-rtl-free-heap-quiescence-test PRIVATE
    noleax::hook-backend
  )
  noleax_set_project_warnings(noleax-rtl-free-heap-quiescence-test)

  add_executable(noleax-rtl-reallocate-heap-quiescence-test
    integration/rtl_reallocate_heap_quiescence_test.cpp
  )
  target_link_libraries(noleax-rtl-reallocate-heap-quiescence-test PRIVATE
    noleax::hook-backend
  )
  noleax_set_project_warnings(noleax-rtl-reallocate-heap-quiescence-test)

  add_executable(noleax-rtl-heap-lifecycle-quiescence-test
    integration/rtl_heap_lifecycle_quiescence_test.cpp
  )
  target_link_libraries(noleax-rtl-heap-lifecycle-quiescence-test PRIVATE
    noleax::hook-backend
  )
  noleax_set_project_warnings(noleax-rtl-heap-lifecycle-quiescence-test)

  add_executable(noleax-nt-virtual-memory-quiescence-test
    integration/nt_virtual_memory_quiescence_test.cpp
  )
  target_link_libraries(noleax-nt-virtual-memory-quiescence-test PRIVATE
    noleax::hook-backend
  )
  target_compile_definitions(noleax-nt-virtual-memory-quiescence-test PRIVATE
    $<$<BOOL:${NOLEAX_WINDOWS_HARDENED_TESTING}>:NOLEAX_WINDOWS_HARDENED_TESTING=1>
  )
  noleax_set_project_warnings(noleax-nt-virtual-memory-quiescence-test)

  add_executable(noleax-rtl-allocate-heap-reinstall-test
    integration/rtl_allocate_heap_reinstall_test.cpp
  )
  target_link_libraries(noleax-rtl-allocate-heap-reinstall-test PRIVATE
    noleax::hook-backend
  )
  noleax_set_project_warnings(noleax-rtl-allocate-heap-reinstall-test)

  add_executable(noleax-rtl-heap-lifecycle-reinstall-test
    integration/rtl_heap_lifecycle_reinstall_test.cpp
  )
  target_link_libraries(noleax-rtl-heap-lifecycle-reinstall-test PRIVATE
    noleax::hook-backend
  )
  noleax_set_project_warnings(noleax-rtl-heap-lifecycle-reinstall-test)

  add_executable(noleax-nt-virtual-memory-reinstall-test
    integration/nt_virtual_memory_reinstall_test.cpp
  )
  target_link_libraries(noleax-nt-virtual-memory-reinstall-test PRIVATE
    noleax::hook-backend
  )
  noleax_set_project_warnings(noleax-nt-virtual-memory-reinstall-test)

  add_executable(noleax-patch-pc-guard-test
    integration/patch_pc_guard_test.cpp
  )
  target_link_libraries(noleax-patch-pc-guard-test PRIVATE
    noleax::hook-backend
  )
  noleax_set_project_warnings(noleax-patch-pc-guard-test)

  if(MSVC)
    add_executable(noleax-rtl-free-heap-contract-test
      integration/rtl_free_heap_contract_test.cpp
    )
    target_link_libraries(noleax-rtl-free-heap-contract-test PRIVATE
      noleax::hook-backend
    )
    noleax_set_project_warnings(noleax-rtl-free-heap-contract-test)

    add_test(NAME hook.rtl-free-heap-contract
      COMMAND noleax-rtl-free-heap-contract-test
    )
    set_tests_properties(hook.rtl-free-heap-contract PROPERTIES
      LABELS "hook;windows;rtl-heap;free;contract"
      PASS_REGULAR_EXPRESSION "^status=ok cases=4 outermost=4 recursive=1 internal=1 "
      RUN_SERIAL TRUE
      TIMEOUT 60
    )

    add_executable(noleax-rtl-free-heap-fail-fast-test
      integration/rtl_free_heap_fail_fast_test.cpp
    )
    target_link_libraries(noleax-rtl-free-heap-fail-fast-test PRIVATE
      noleax::hook-backend
    )
    noleax_set_project_warnings(noleax-rtl-free-heap-fail-fast-test)

    add_test(NAME hook.rtl-free-heap-fail-fast-contract
      COMMAND noleax-rtl-free-heap-fail-fast-test
    )
    set_tests_properties(hook.rtl-free-heap-fail-fast-contract PROPERTIES
      LABELS "hook;windows;rtl-heap;free;contract;fail-fast;isolated"
      PASS_REGULAR_EXPRESSION "^status=ok cases=3 exit=0xc0000374 baseline=hooked"
      RUN_SERIAL TRUE
      TIMEOUT 180
    )

    add_executable(noleax-rtl-reallocate-heap-contract-test
      integration/rtl_reallocate_heap_contract_test.cpp
    )
    target_link_libraries(noleax-rtl-reallocate-heap-contract-test PRIVATE
      noleax::hook-backend
    )
    noleax_set_project_warnings(noleax-rtl-reallocate-heap-contract-test)

    add_test(NAME hook.rtl-reallocate-heap-contract
      COMMAND noleax-rtl-reallocate-heap-contract-test
    )
    set_tests_properties(hook.rtl-reallocate-heap-contract PROPERTIES
      LABELS "hook;windows;rtl-heap;reallocate;contract;generation"
      PASS_REGULAR_EXPRESSION "^status=ok cases=4 move=1 "
      RUN_SERIAL TRUE
      TIMEOUT 120
    )

    add_executable(noleax-rtl-reallocate-heap-fail-fast-test
      integration/rtl_reallocate_heap_fail_fast_test.cpp
    )
    target_link_libraries(noleax-rtl-reallocate-heap-fail-fast-test PRIVATE
      noleax::hook-backend
    )
    noleax_set_project_warnings(noleax-rtl-reallocate-heap-fail-fast-test)

    add_test(NAME hook.rtl-reallocate-heap-fail-fast-contract
      COMMAND noleax-rtl-reallocate-heap-fail-fast-test
    )
    set_tests_properties(hook.rtl-reallocate-heap-fail-fast-contract PROPERTIES
      LABELS "hook;windows;rtl-heap;reallocate;contract;fail-fast;isolated"
      PASS_REGULAR_EXPRESSION "^status=ok cases=3 exits=0x[0-9a-f]+,0x[0-9a-f]+,0x[0-9a-f]+ baseline=hooked"
      RUN_SERIAL TRUE
      TIMEOUT 180
    )

    add_executable(noleax-rtl-heap-lifecycle-contract-test
      integration/rtl_heap_lifecycle_contract_test.cpp
    )
    target_link_libraries(noleax-rtl-heap-lifecycle-contract-test PRIVATE
      noleax::hook-backend
    )
    noleax_set_project_warnings(noleax-rtl-heap-lifecycle-contract-test)

    add_test(NAME hook.rtl-heap-lifecycle-contract
      COMMAND noleax-rtl-heap-lifecycle-contract-test
    )
    set_tests_properties(hook.rtl-heap-lifecycle-contract PROPERTIES
      LABELS "hook;windows;rtl-heap;create;destroy;contract;generation;seh"
      PASS_REGULAR_EXPRESSION "^status=ok create=4 destroy=2 exception-mode=matched "
      RUN_SERIAL TRUE
      TIMEOUT 120
    )

    add_executable(noleax-nt-virtual-memory-contract-test
      integration/nt_virtual_memory_contract_test.cpp
    )
    target_link_libraries(noleax-nt-virtual-memory-contract-test PRIVATE
      noleax::hook-backend
    )
    noleax_set_project_warnings(noleax-nt-virtual-memory-contract-test)

    add_test(NAME hook.nt-virtual-memory-contract
      COMMAND noleax-nt-virtual-memory-contract-test
    )
    set_tests_properties(hook.nt-virtual-memory-contract PROPERTIES
      LABELS "hook;windows;nt-vm;allocate;free;contract;generation;recursion"
      PASS_REGULAR_EXPRESSION "^status=ok reserve=1 commit=1 decommit=1 release=1 "
      RUN_SERIAL TRUE
      TIMEOUT 120
    )

    add_executable(noleax-nt-section-view-contract-test
      integration/nt_section_view_contract_test.cpp
    )
    target_link_libraries(noleax-nt-section-view-contract-test PRIVATE
      noleax::hook-backend
    )
    noleax_set_project_warnings(noleax-nt-section-view-contract-test)

    add_test(NAME hook.nt-section-view-contract
      COMMAND noleax-nt-section-view-contract-test
    )
    set_tests_properties(hook.nt-section-view-contract PROPERTIES
      LABELS "hook;windows;nt-vm;map;unmap;contract;generation;remote;recursion"
      PASS_REGULAR_EXPRESSION "^status=ok pagefile=1 file=1 offset=1 multi-view=1 wrapper=1 remote=1 "
      RUN_SERIAL TRUE
      TIMEOUT 180
    )

    add_executable(noleax-rtl-destroy-heap-isolation-test
      integration/rtl_destroy_heap_isolation_test.cpp
    )
    target_link_libraries(noleax-rtl-destroy-heap-isolation-test PRIVATE
      noleax::hook-backend
    )
    noleax_set_project_warnings(noleax-rtl-destroy-heap-isolation-test)

    add_test(NAME hook.rtl-destroy-heap-isolation
      COMMAND noleax-rtl-destroy-heap-isolation-test
    )
    set_tests_properties(hook.rtl-destroy-heap-isolation PROPERTIES
      LABELS "hook;windows;rtl-heap;destroy;contract;fail-fast;isolated"
      PASS_REGULAR_EXPRESSION "^status=ok cases=3 exits=0x[0-9a-f]+,0x[0-9a-f]+,0x[0-9a-f]+ baseline=hooked"
      RUN_SERIAL TRUE
      TIMEOUT 180
    )
  endif()

  add_test(NAME hook.rtl-allocate-heap-quiescence-race
    COMMAND noleax-rtl-allocate-heap-quiescence-test
  )

  add_test(NAME hook.rtl-free-heap-quiescence-race
    COMMAND noleax-rtl-free-heap-quiescence-test
  )
  set_tests_properties(hook.rtl-free-heap-quiescence-race PROPERTIES
    LABELS "hook;windows;rtl-heap;free;quiescence;race;stress"
    PASS_REGULAR_EXPRESSION "^status=ok "
    RUN_SERIAL TRUE
    TIMEOUT 60
  )
  add_test(NAME hook.rtl-reallocate-heap-quiescence-race
    COMMAND noleax-rtl-reallocate-heap-quiescence-test
  )
  set_tests_properties(hook.rtl-reallocate-heap-quiescence-race PROPERTIES
    LABELS "hook;windows;rtl-heap;reallocate;quiescence;race;stress"
    PASS_REGULAR_EXPRESSION "^status=ok "
    RUN_SERIAL TRUE
    TIMEOUT 60
  )
  add_test(NAME hook.rtl-heap-lifecycle-quiescence-race
    COMMAND noleax-rtl-heap-lifecycle-quiescence-test
  )
  set_tests_properties(hook.rtl-heap-lifecycle-quiescence-race PROPERTIES
    LABELS "hook;windows;rtl-heap;create;destroy;quiescence;race;stress"
    PASS_REGULAR_EXPRESSION "^status=ok "
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_test(NAME hook.nt-virtual-memory-quiescence-race
    COMMAND noleax-nt-virtual-memory-quiescence-test
  )
  set_tests_properties(hook.nt-virtual-memory-quiescence-race PROPERTIES
    LABELS "hook;windows;nt-vm;allocate;free;quiescence;race;stress"
    PASS_REGULAR_EXPRESSION "^status=ok operations=[0-9]+ thread_creations=[0-9]+ "
    RUN_SERIAL TRUE
    TIMEOUT 120
  )

  add_test(NAME hook.patch-pc-guard
    COMMAND noleax-patch-pc-guard-test
  )
  set_tests_properties(hook.patch-pc-guard PROPERTIES
    LABELS "hook;windows;quiescence;pc-guard"
    PASS_REGULAR_EXPRESSION "^status=ok blocked=1"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )
  set_tests_properties(hook.rtl-allocate-heap-quiescence-race PROPERTIES
    LABELS "hook;windows;rtl-heap;quiescence;race;stress"
    PASS_REGULAR_EXPRESSION "^status=ok "
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  if(MSVC)
    add_executable(noleax-rtl-allocate-heap-exception-test
      integration/rtl_allocate_heap_exception_test.cpp
    )
    target_link_libraries(noleax-rtl-allocate-heap-exception-test PRIVATE
      noleax::hook-backend
    )
    noleax_set_project_warnings(noleax-rtl-allocate-heap-exception-test)

    add_test(NAME hook.rtl-allocate-heap-seh-contract
      COMMAND noleax-rtl-allocate-heap-exception-test
    )
    set_tests_properties(hook.rtl-allocate-heap-seh-contract PROPERTIES
      LABELS "hook;windows;rtl-heap;seh;contract"
      PASS_REGULAR_EXPRESSION "^status=ok exception=0x[0-9a-f]+ last_error=[0-9]+ event=1 cleanup=1"
      RUN_SERIAL TRUE
      TIMEOUT 60
    )

    add_executable(noleax-rtl-reallocate-heap-exception-test
      integration/rtl_reallocate_heap_exception_test.cpp
    )
    target_link_libraries(noleax-rtl-reallocate-heap-exception-test PRIVATE
      noleax::hook-backend
    )
    noleax_set_project_warnings(noleax-rtl-reallocate-heap-exception-test)

    add_test(NAME hook.rtl-reallocate-heap-seh-contract
      COMMAND noleax-rtl-reallocate-heap-exception-test
    )
    set_tests_properties(hook.rtl-reallocate-heap-seh-contract PROPERTIES
      LABELS "hook;windows;rtl-heap;reallocate;seh;contract"
      PASS_REGULAR_EXPRESSION "^status=ok exception=0x[0-9a-f]+ last_error=[0-9]+ event=1 old-valid=1 cleanup=1"
      RUN_SERIAL TRUE
      TIMEOUT 60
    )
  endif()

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
    PASS_REGULAR_EXPRESSION "^status=ok module-released=1"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  add_test(NAME hook.rtl-allocate-heap-reinstall
    COMMAND noleax-rtl-allocate-heap-reinstall-test
  )
  set_tests_properties(hook.rtl-allocate-heap-reinstall PROPERTIES
    LABELS "hook;windows;rtl-heap;quiescence;rendezvous;reinstall;unload"
    PASS_REGULAR_EXPRESSION "^status=ok first=[1-9][0-9]* second=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  add_test(NAME hook.rtl-heap-lifecycle-reinstall
    COMMAND noleax-rtl-heap-lifecycle-reinstall-test
  )
  set_tests_properties(hook.rtl-heap-lifecycle-reinstall PROPERTIES
    LABELS "hook;windows;rtl-heap;lifecycle;quiescence;rendezvous;reinstall;unload"
    PASS_REGULAR_EXPRESSION "^status=ok first=[1-9][0-9]* second=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  add_test(NAME hook.nt-virtual-memory-reinstall
    COMMAND noleax-nt-virtual-memory-reinstall-test
  )
  set_tests_properties(hook.nt-virtual-memory-reinstall PROPERTIES
    LABELS "hook;windows;nt-vm;quiescence;rendezvous;reinstall;unload"
    PASS_REGULAR_EXPRESSION "^status=ok first=[1-9][0-9]* second=[1-9][0-9]*"
    RUN_SERIAL TRUE
    TIMEOUT 60
  )

  foreach(trace_mode IN ITEMS empty normal queue-limit file-limit exception)
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
    target_link_libraries(${target} PRIVATE Advapi32)
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
  target_include_directories(noleax-agent-smoke PRIVATE "${PROJECT_SOURCE_DIR}/include")
  noleax_set_project_warnings(noleax-agent-smoke)

  add_test(NAME agent.load-and-link-hoox
    COMMAND noleax-agent-smoke "$<TARGET_FILE:noleax-agent>")

  if(NOLEAX_WINDOWS_HARDENED_TESTING)
    find_program(NOLEAX_DUMPBIN_EXECUTABLE NAMES dumpbin REQUIRED)
    foreach(mitigation_target IN ITEMS
        noleax
        noleax-agent
        noleax-controller-target
        noleax-controller-lifecycle-target
        noleax-cli-e2e-target
        noleax-capture-benchmark-target
        noleax-cli-end-to-end-test
        noleax-cli-recovery-test
        noleax-controller-launch-test
        noleax-controller-attach-test
        noleax-controller-lifecycle-test
        noleax-injector-rollback-test
        noleax-register-workload-target
        noleax-thread-hijack-launch-test
        noleax-thread-hijack-attach-test
        noleax-entrypoint-launch-test
        noleax-entrypoint-rollback-test
        noleax-pe-patch-e2e-test
        noleax-rtl-heap-baseline-md
        noleax-rtl-heap-baseline-mt
        noleax-rtl-allocate-heap-hook-harness
        noleax-rtl-allocate-heap-trace-writer-test
        noleax-rtl-heap-trace-writer-test
        noleax-rtl-allocate-heap-quiescence-test
        noleax-rtl-free-heap-quiescence-test
        noleax-rtl-reallocate-heap-quiescence-test
        noleax-rtl-heap-lifecycle-quiescence-test
        noleax-nt-virtual-memory-quiescence-test
        noleax-rtl-free-heap-contract-test
        noleax-rtl-free-heap-fail-fast-test
        noleax-rtl-reallocate-heap-contract-test
        noleax-rtl-reallocate-heap-fail-fast-test
        noleax-rtl-heap-lifecycle-contract-test
        noleax-rtl-destroy-heap-isolation-test
        noleax-nt-virtual-memory-contract-test
        noleax-nt-section-view-contract-test
        noleax-nt-virtual-memory-trace-writer-test
        noleax-windows-native-profile-test
        noleax-module-generation-fixture
        noleax-module-generation-trace-test
        noleax-module-tracker-test
        noleax-rtl-allocate-heap-exception-test
        noleax-rtl-reallocate-heap-exception-test)
      add_test(NAME hook.windows-mitigations.${mitigation_target}
        COMMAND "${CMAKE_COMMAND}"
          "-DNOLEAX_DUMPBIN=${NOLEAX_DUMPBIN_EXECUTABLE}"
          "-DNOLEAX_IMAGE=$<TARGET_FILE:${mitigation_target}>"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/VerifyWindowsImageMitigations.cmake"
      )
      set_tests_properties(hook.windows-mitigations.${mitigation_target} PROPERTIES
        LABELS "hook;windows;mitigations;cfg;cet"
        PASS_REGULAR_EXPRESSION "CFG/CET metadata verified"
      )
    endforeach()
  endif()
endif()
