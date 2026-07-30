add_library(noleax-controller STATIC)

if(WIN32)
  target_sources(noleax-controller PRIVATE
    controller.cpp
    windows/diagnostics.cpp
    windows/process.cpp
    windows/remote_injector.cpp
    windows/thread_suspension.cpp
  )
  target_link_libraries(noleax-controller PRIVATE bcrypt Psapi)
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
