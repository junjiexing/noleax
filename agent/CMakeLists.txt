add_library(noleax-hook-backend STATIC
  hook_guard.cpp
  hook_backend.cpp
)

if(WIN32)
  target_sources(noleax-hook-backend PRIVATE
    windows/rtl_allocate_heap_hook.cpp
    windows/rtl_allocate_heap_trace_writer.cpp
    windows/rtl_create_heap_hook.cpp
    windows/rtl_destroy_heap_hook.cpp
    windows/rtl_free_heap_hook.cpp
    windows/rtl_reallocate_heap_hook.cpp
    windows/rtl_heap_hooks.cpp
    windows/stack_capture.cpp
    windows/stack_dictionary.cpp
  )
endif()

add_library(noleax::hook-backend ALIAS noleax-hook-backend)

target_include_directories(noleax-hook-backend
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

target_link_libraries(noleax-hook-backend
  PRIVATE
    hoox::hoox
    noleax::trace
)

noleax_set_project_warnings(noleax-hook-backend)

add_library(noleax-agent SHARED
  agent.cpp
)

target_link_libraries(noleax-agent
  PRIVATE
    noleax::hook-backend
    noleax::core
)

target_compile_definitions(noleax-agent PRIVATE NOLEAX_AGENT_BUILD)
noleax_set_project_warnings(noleax-agent)

set_target_properties(noleax-agent PROPERTIES
  OUTPUT_NAME "noleax-agent"
  PREFIX ""
)
