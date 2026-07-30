foreach(required IN ITEMS NOLEAX_DUMPBIN NOLEAX_IMAGE)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "${required} is required.")
  endif()
endforeach()

if(NOT EXISTS "${NOLEAX_IMAGE}")
  message(FATAL_ERROR "Image does not exist: ${NOLEAX_IMAGE}")
endif()

execute_process(
  COMMAND "${NOLEAX_DUMPBIN}" /headers "${NOLEAX_IMAGE}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE headers
  ERROR_VARIABLE error
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_STRIP_TRAILING_WHITESPACE
)
if(NOT result STREQUAL "0")
  message(FATAL_ERROR "dumpbin failed for ${NOLEAX_IMAGE} (${result}): ${error}")
endif()

if(NOT headers MATCHES "Control Flow Guard")
  message(FATAL_ERROR "Control Flow Guard metadata is missing: ${NOLEAX_IMAGE}")
endif()
if(NOT headers MATCHES "CET compatible")
  message(FATAL_ERROR "CET compatibility metadata is missing: ${NOLEAX_IMAGE}")
endif()

message(STATUS "CFG/CET metadata verified: ${NOLEAX_IMAGE}")
