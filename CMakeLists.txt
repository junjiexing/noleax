cmake_minimum_required(VERSION 3.25)

project(
  noleax
  VERSION 0.1.0
  DESCRIPTION "Hook-based memory event capture and analysis tool"
  LANGUAGES C CXX
)

option(NOLEAX_BUILD_TESTS "Build Noleax tests" ON)
option(NOLEAX_WARNINGS_AS_ERRORS "Treat project warnings as errors" ON)
option(NOLEAX_ENABLE_CLANG_TIDY "Run clang-tidy while compiling project sources" OFF)
option(NOLEAX_WINDOWS_HARDENED_TESTING
  "Build Windows test images with CFG and CET compatibility metadata" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOLEAX_WINDOWS_HARDENED_TESTING)
  if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "NOLEAX_WINDOWS_HARDENED_TESTING requires MSVC on Windows.")
  endif()
  add_compile_options(/guard:cf)
  add_link_options(/guard:cf /CETCOMPAT)
  add_compile_definitions(NOLEAX_WINDOWS_HARDENED_TESTING=1)
endif()

if(NOLEAX_ENABLE_CLANG_TIDY)
  find_program(NOLEAX_CLANG_TIDY_EXECUTABLE NAMES clang-tidy REQUIRED)
  set(CMAKE_CXX_CLANG_TIDY
    "${NOLEAX_CLANG_TIDY_EXECUTABLE};--config-file=${PROJECT_SOURCE_DIR}/.clang-tidy"
  )
  if(MSVC)
    list(APPEND CMAKE_CXX_CLANG_TIDY "--extra-arg=/EHsc")
  endif()
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(NoleaxWarnings)

find_package(CLI11 CONFIG REQUIRED)
find_package(hoox CONFIG REQUIRED)

add_subdirectory(src/core)
add_subdirectory(src/config)
add_subdirectory(src/cli)
add_subdirectory(src/trace)
add_subdirectory(src/analyzer)
add_subdirectory(apps/noleax)
add_subdirectory(agent)

if(NOLEAX_BUILD_TESTS)
  include(CTest)
  enable_testing()
  add_subdirectory(tests)
endif()

include(GNUInstallDirs)
install(TARGETS noleax noleax-agent
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
