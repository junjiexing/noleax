add_library(noleax-hook-backend STATIC
  hook_guard.cpp
  hook_backend.cpp
  patch_rendezvous.cpp
)

if(WIN32)
  target_sources(noleax-hook-backend PRIVATE
    windows/custom_symbol_hooks.cpp
    windows/module_tracker.cpp
    windows/nt_memory_hooks.cpp
    windows/rtl_allocate_heap_hook.cpp
    windows/rtl_allocate_heap_trace_writer.cpp
    windows/rtl_create_heap_hook.cpp
    windows/rtl_destroy_heap_hook.cpp
    windows/rtl_free_heap_hook.cpp
    windows/rtl_reallocate_heap_hook.cpp
    windows/rtl_heap_hooks.cpp
    windows/stack_capture.cpp
    windows/stack_dictionary.cpp
    windows/windows_memory_hooks.cpp
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
    noleax-hoox
    noleax::trace
)

if(WIN32)
  target_link_libraries(noleax-hook-backend PRIVATE Psapi)
endif()

noleax_set_project_warnings(noleax-hook-backend)

add_library(noleax-agent SHARED
  agent.cpp
)

if(WIN32)
  target_sources(noleax-agent PRIVATE
    windows/agent_runtime.cpp
  )
endif()

target_link_libraries(noleax-agent
  PRIVATE
    noleax::hook-backend
    noleax::core
    noleax::config
    noleax::ipc
)

if(WIN32)
  target_link_libraries(noleax-agent PRIVATE bcrypt)
endif()

target_compile_definitions(noleax-agent PRIVATE NOLEAX_AGENT_BUILD)
noleax_set_project_warnings(noleax-agent)

if(WIN32)
  # No incremental link thunks: the patch rendezvous must see every replacement's real entry
  # inside the ".nlxhk" section, not a .text ILT stub.
  target_link_options(noleax-agent PRIVATE "LINKER:/INCREMENTAL:NO")
endif()

set_target_properties(noleax-agent PROPERTIES
  OUTPUT_NAME "noleax-agent"
  PREFIX ""
)
