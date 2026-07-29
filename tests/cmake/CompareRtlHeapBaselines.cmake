if(NOT DEFINED NOLEAX_BASELINE_MD OR NOT DEFINED NOLEAX_BASELINE_MT)
  message(FATAL_ERROR "Both baseline executable paths are required.")
endif()

set(arguments
  --threads 4
  --iterations 2000
  --rounds 2
  --seed 5642812718451281972
)

function(run_baseline executable output_variable)
  execute_process(
    COMMAND "${executable}" ${arguments}
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

run_baseline("${NOLEAX_BASELINE_MD}" md_output)
run_baseline("${NOLEAX_BASELINE_MT}" mt_output)

if(NOT md_output STREQUAL mt_output)
  message(FATAL_ERROR "Dynamic and static CRT baselines differ:\nMD: ${md_output}\nMT: ${mt_output}")
endif()

message(STATUS "Matching Rtl heap baseline: ${md_output}")
