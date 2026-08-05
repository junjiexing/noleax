cmake_minimum_required(VERSION 3.25)

project(
  noleax
  VERSION 0.3.0
  DESCRIPTION "Hook-based memory event capture and analysis tool"
  LANGUAGES C CXX
)

option(NOLEAX_BUILD_TESTS "Build Noleax tests" ON)
option(NOLEAX_WARNINGS_AS_ERRORS "Treat project warnings as errors" ON)
option(NOLEAX_ENABLE_CLANG_TIDY "Run clang-tidy while compiling project sources" OFF)
option(NOLEAX_WINDOWS_HARDENED_TESTING
  "Build Windows test images with CFG and CET compatibility metadata" OFF)

if(MSVC OR (WIN32 AND CMAKE_CXX_COMPILER_ID MATCHES "Clang"))
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

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

add_subdirectory(third_party/hoox)

add_subdirectory(src/core)
add_subdirectory(src/ipc)
add_subdirectory(src/controller)
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

install(FILES
  "${PROJECT_SOURCE_DIR}/README.md"
  "${PROJECT_SOURCE_DIR}/BUILDING.md"
  "${PROJECT_SOURCE_DIR}/LICENSE"
  "${PROJECT_SOURCE_DIR}/SECURITY.md"
  "${PROJECT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md"
  DESTINATION ".")

# The release package ships only usage documentation, renamed for readability;
# internal design documents stay in the repository.
install(FILES "${PROJECT_SOURCE_DIR}/docs/QUICKSTART.md" DESTINATION "docs" RENAME "quickstart.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/TROUBLESHOOTING.md" DESTINATION "docs" RENAME "troubleshooting.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/CLI.md" DESTINATION "docs" RENAME "cli.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/CONFIG.md" DESTINATION "docs" RENAME "config.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/CONSOLE_OUTPUT.md" DESTINATION "docs" RENAME "console-output.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/JSON_OUTPUT.md" DESTINATION "docs" RENAME "json-output.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/CSV_OUTPUT.md" DESTINATION "docs" RENAME "csv-output.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/TRACE_FORMAT.md" DESTINATION "docs" RENAME "trace-format.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/TRACE_RECOVERY.md" DESTINATION "docs" RENAME "trace-recovery.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/SYMBOLIZATION.md" DESTINATION "docs" RENAME "symbolization.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/SYMBOLS.md" DESTINATION "docs" RENAME "symbols.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/STATIC_PE_PATCH.md" DESTINATION "docs" RENAME "static-pe-patch.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/WINDOWS_HOOK_PROFILES.md" DESTINATION "docs" RENAME "hook-profiles.md")
install(FILES "${PROJECT_SOURCE_DIR}/docs/ROADMAP.md" DESTINATION "docs" RENAME "roadmap.md")
install(FILES
  "${PROJECT_SOURCE_DIR}/docs/schema/noleax-analysis-v1.schema.json"
  "${PROJECT_SOURCE_DIR}/docs/schema/noleax-analysis-v2.schema.json"
  "${PROJECT_SOURCE_DIR}/docs/schema/noleax-symbols-v1.schema.json"
  DESTINATION "docs/schema")
install(DIRECTORY "${PROJECT_SOURCE_DIR}/examples/" DESTINATION "examples")

if(NOT DEFINED VCPKG_INSTALLED_DIR OR NOT DEFINED VCPKG_TARGET_TRIPLET)
  message(FATAL_ERROR "Noleax packaging requires the vcpkg manifest toolchain.")
endif()

set(NOLEAX_VCPKG_SHARE_DIR
  "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/share")
foreach(NOLEAX_THIRD_PARTY_PACKAGE IN ITEMS
    catch2
    cli11
    lz4
    tomlplusplus
    zstd)
  set(NOLEAX_THIRD_PARTY_COPYRIGHT
    "${NOLEAX_VCPKG_SHARE_DIR}/${NOLEAX_THIRD_PARTY_PACKAGE}/copyright")
  if(NOT EXISTS "${NOLEAX_THIRD_PARTY_COPYRIGHT}")
    message(FATAL_ERROR
      "Missing vcpkg copyright file for ${NOLEAX_THIRD_PARTY_PACKAGE}: "
      "${NOLEAX_THIRD_PARTY_COPYRIGHT}")
  endif()
  install(FILES "${NOLEAX_THIRD_PARTY_COPYRIGHT}"
    DESTINATION "licenses"
    RENAME "${NOLEAX_THIRD_PARTY_PACKAGE}.txt")
endforeach()

# hoox is vendored (third_party/hoox); ship its license texts from there in the
# same combined form vcpkg_install_copyright produced before. Normalize to LF so
# the installed bytes do not depend on the checkout's core.autocrlf setting.
file(READ "${PROJECT_SOURCE_DIR}/third_party/hoox/COPYING" NOLEAX_HOOX_COPYING)
file(READ "${PROJECT_SOURCE_DIR}/third_party/hoox/NOTICE" NOLEAX_HOOX_NOTICE)
file(WRITE "${CMAKE_BINARY_DIR}/hoox-copyright-raw.txt"
  "${NOLEAX_HOOX_COPYING}\n${NOLEAX_HOOX_NOTICE}")
configure_file("${CMAKE_BINARY_DIR}/hoox-copyright-raw.txt"
  "${CMAKE_BINARY_DIR}/hoox-copyright.txt" @ONLY NEWLINE_STYLE LF)
install(FILES "${CMAKE_BINARY_DIR}/hoox-copyright.txt"
  DESTINATION "licenses"
  RENAME "hoox.txt")

if(WIN32)
  if(VCPKG_TARGET_TRIPLET MATCHES "^arm64-")
    set(NOLEAX_PACKAGE_PLATFORM "windows-arm64")
  elseif(VCPKG_TARGET_TRIPLET MATCHES "^x86-")
    set(NOLEAX_PACKAGE_PLATFORM "windows-x86")
  else()
    set(NOLEAX_PACKAGE_PLATFORM "windows-x64")
  endif()
elseif(APPLE)
  set(NOLEAX_PACKAGE_PLATFORM "macos-${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(NOLEAX_PACKAGE_PLATFORM "linux-${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_NAME "noleax")
set(CPACK_PACKAGE_VENDOR "Noleax contributors")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME
  "noleax-${PROJECT_VERSION}-${NOLEAX_PACKAGE_PLATFORM}")
set(CPACK_PACKAGE_DIRECTORY "${CMAKE_BINARY_DIR}/package")
set(CPACK_PACKAGE_CHECKSUM "SHA256")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ON)
set(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/README.md")
set(CPACK_VERBATIM_VARIABLES ON)
include(CPack)
