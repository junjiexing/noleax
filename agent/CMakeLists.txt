add_library(noleax-hook-backend STATIC
  hook_guard.cpp
  hook_backend.cpp
  patch_rendezvous.cpp
)

if(WIN32)
  target_sources(noleax-hook-backend PRIVATE
    windows/custom_symbol_hooks.cpp
    windows/memory_snapshot.cpp
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

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(noleax-hook-backend PRIVATE
    linux/module_tracker.cpp
    linux/stack_capture.cpp
    linux/trace_writer.cpp
    # Platform-neutral code under the windows path; hoisting to the shared namespace is
    # deferred to a Windows-CI-verified change.
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

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(noleax-agent PRIVATE
    linux/agent_runtime.cpp
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

if(NOT WIN32)
  # The hook guard's thread state must be reachable without __tls_get_addr: that helper
  # can allocate on first use, which would recurse into the very allocator hooks the
  # guard protects (same crash class as the Windows TEB incident, see HOOK_GUARD.md).
  # LD_PRELOAD loads the agent at startup, so the static-TLS block is always available.
  target_compile_options(noleax-hook-backend PRIVATE -ftls-model=initial-exec)
  target_compile_options(noleax-agent PRIVATE -ftls-model=initial-exec)
  # dladdr1/RTLD_DL_LINKMAP (patch rendezvous) are GNU extensions.
  target_compile_definitions(noleax-hook-backend PRIVATE _GNU_SOURCE)
  target_link_libraries(noleax-hook-backend PRIVATE ${CMAKE_DL_LIBS})
endif()

if(WIN32)
  # No incremental link thunks: the patch rendezvous must see every replacement's real entry
  # inside the ".nlxhk" section, not a .text ILT stub.
  target_link_options(noleax-agent PRIVATE "LINKER:/INCREMENTAL:NO")
endif()

set_target_properties(noleax-agent PROPERTIES
  OUTPUT_NAME "noleax-agent"
  PREFIX ""
)
