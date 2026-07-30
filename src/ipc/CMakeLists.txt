add_library(noleax-ipc STATIC
  protocol.cpp
)

if(WIN32)
  target_sources(noleax-ipc PRIVATE
    windows/named_pipe.cpp
  )
endif()

add_library(noleax::ipc ALIAS noleax-ipc)

target_include_directories(noleax-ipc
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

noleax_set_project_warnings(noleax-ipc)
