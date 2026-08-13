add_library(noleax-controller STATIC)

if(WIN32)
  target_sources(noleax-controller PRIVATE
    controller.cpp
    windows/diagnostics.cpp
    windows/entrypoint_injector.cpp
    windows/injection_common.cpp
    windows/pe_patch.cpp
    windows/process.cpp
    windows/remote_injector.cpp
    windows/thread_hijack_injector.cpp
    windows/thread_suspension.cpp
  )
  target_link_libraries(noleax-controller PRIVATE bcrypt Psapi)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(noleax-controller PRIVATE
    linux/controller.cpp
    linux/diagnostics.cpp
    linux/ptrace_injector.cpp
    # Also compiled into the hook backend for the agent; the injector's patch-window
    # sweep resolves `_sym` custom hook targets with the same self-contained scanner.
    ${PROJECT_SOURCE_DIR}/agent/linux/elf_symbol_lookup.cpp
  )
else()
  target_sources(noleax-controller PRIVATE
    controller_stub.cpp
  )
endif()

add_library(noleax::controller ALIAS noleax-controller)

target_include_directories(noleax-controller
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

target_link_libraries(noleax-controller
  PUBLIC
    noleax::ipc
)

noleax_set_project_warnings(noleax-controller)
