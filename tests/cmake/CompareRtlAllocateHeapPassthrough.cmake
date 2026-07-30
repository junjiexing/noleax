foreach(required IN ITEMS NOLEAX_BASELINE_MD NOLEAX_BASELINE_MT NOLEAX_HOOK_HARNESS)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "${required} is required.")
  endif()
endforeach()

set(arguments
  --threads 4
  --iterations 2000
  --rounds 2
  --seed 5642812718451281972
)

function(run_workload executable use_hook output_variable)
  set(command "${executable}" ${arguments})
  if(use_hook)
    list(APPEND command --hook-harness "${NOLEAX_HOOK_HARNESS}")
  endif()
  execute_process(
    COMMAND ${command}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_STRIP_TRAILING_WHITESPACE
    TIMEOUT 60
  )
  if(NOT result STREQUAL "0")
    message(FATAL_ERROR "${executable} failed (${result}): ${error}")
  endif()
  if(NOT error STREQUAL "")
    message(FATAL_ERROR "${executable} wrote to stderr: ${error}")
  endif()
  if(NOT output MATCHES "^status=ok version=1 ")
    message(FATAL_ERROR "${executable} produced an invalid summary: ${output}")
  endif()
  if(output MATCHES "\n")
    message(FATAL_ERROR "${executable} produced more than one stdout line: ${output}")
  endif()
  set(${output_variable} "${output}" PARENT_SCOPE)
endfunction()

run_workload("${NOLEAX_BASELINE_MD}" FALSE baseline_md)
run_workload("${NOLEAX_BASELINE_MT}" FALSE baseline_mt)
run_workload("${NOLEAX_BASELINE_MD}" TRUE hooked_md)
run_workload("${NOLEAX_BASELINE_MT}" TRUE hooked_mt)

if(NOT baseline_md STREQUAL baseline_mt)
  message(FATAL_ERROR "Unhooked CRT baselines differ:\nMD: ${baseline_md}\nMT: ${baseline_mt}")
endif()
if(NOT hooked_md STREQUAL baseline_md)
  message(FATAL_ERROR "Hooked MD differs from baseline:\nbase: ${baseline_md}\nhook: ${hooked_md}")
endif()
if(NOT hooked_mt STREQUAL baseline_mt)
  message(FATAL_ERROR "Hooked MT differs from baseline:\nbase: ${baseline_mt}\nhook: ${hooked_mt}")
endif()

message(STATUS "RtlAllocateHeap passthrough matches both baselines: ${baseline_md}")
