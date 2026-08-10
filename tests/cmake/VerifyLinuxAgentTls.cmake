# Asserts the agent DSO contains no dynamic-model TLS references. A __tls_get_addr
# call can allocate on first use and would recurse into the hooked allocators
# (docs/HOOK_GUARD.md, Linux section); the agent is built with
# -ftls-model=initial-exec so every TLS access must resolve against the static
# block. Once the agent runtime links the guard, this also covers its state.
if(NOT DEFINED AGENT_PATH)
  message(FATAL_ERROR "AGENT_PATH is required")
endif()

find_program(READELF_EXECUTABLE NAMES readelf REQUIRED)

execute_process(
  COMMAND "${READELF_EXECUTABLE}" --dyn-syms -W "${AGENT_PATH}"
  OUTPUT_VARIABLE dynamic_symbols
  RESULT_VARIABLE readelf_result
)
if(NOT readelf_result EQUAL 0)
  message(FATAL_ERROR "readelf --dyn-syms failed on ${AGENT_PATH}")
endif()
if(dynamic_symbols MATCHES "__tls_get_addr")
  message(FATAL_ERROR
    "${AGENT_PATH} references __tls_get_addr: the agent must be built with "
    "-ftls-model=initial-exec (dynamic TLS can allocate and recurse into hooks)")
endif()

execute_process(
  COMMAND "${READELF_EXECUTABLE}" -r -W "${AGENT_PATH}"
  OUTPUT_VARIABLE relocations
  RESULT_VARIABLE readelf_relocs_result
)
if(NOT readelf_relocs_result EQUAL 0)
  message(FATAL_ERROR "readelf -r failed on ${AGENT_PATH}")
endif()
if(relocations MATCHES "R_X86_64_TLS_GD|R_X86_64_TLS_LD")
  message(FATAL_ERROR
    "${AGENT_PATH} contains general/local-dynamic TLS relocations; expected "
    "initial-exec (R_X86_64_TPOFF*) only")
endif()

message(STATUS "${AGENT_PATH} uses no dynamic-model TLS")
