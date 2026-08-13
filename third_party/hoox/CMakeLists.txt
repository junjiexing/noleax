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
  # Signal-driven peer parking around patch writes (hoox_peer_park_*), so
  # multi-byte patches on Linux get the same no-thread-in-transit guarantee
  # the Windows PC guard provides.
  target_compile_definitions(noleax-hoox PRIVATE HOOX_POSIX_PATCH_PC_GUARD)
  # v0.2.3 added a _Thread_local flag (external thread suspension); the agent
  # DSO must not carry dynamic-model TLS (__tls_get_addr can allocate and
  # recurse into the hooked allocators), so build with initial-exec like the
  # agent itself (tests/cmake/VerifyLinuxAgentTls.cmake enforces this).
  target_compile_options(noleax-hoox PRIVATE -ftls-model=initial-exec)
endif()

set_target_properties(noleax-hoox PROPERTIES
  C_CLANG_TIDY ""
  CXX_CLANG_TIDY ""
)
