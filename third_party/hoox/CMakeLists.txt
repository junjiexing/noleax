# Third-party single-file build: hoox amalgamation (see README.md). Kept free of
# project warnings, clang-tidy and formatting so upstream refreshes stay clean.
add_library(noleax-hoox STATIC hoox.c)

target_include_directories(noleax-hoox PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

# Opt-in upstream feature: scan suspended thread instruction pointers against
# patched byte ranges during patch writes.
target_compile_definitions(noleax-hoox PRIVATE HOOX_WINDOWS_PATCH_PC_GUARD)

if(NOT WIN32)
  # The amalgamation uses POSIX.1-2008 and GNU extensions (usleep, recursive
  # pthread mutexes, syscall, mprotect); the project's strict -std=c17 build
  # hides their declarations unless the feature test macro is set.
  target_compile_definitions(noleax-hoox PRIVATE _GNU_SOURCE)
endif()

set_target_properties(noleax-hoox PROPERTIES
  C_CLANG_TIDY ""
  CXX_CLANG_TIDY ""
)
