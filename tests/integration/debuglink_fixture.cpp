// Split-debug fixture for the .gnu_debuglink symbolizer tests. The library is built once,
// then objcopy produces a stripped runtime image (dynamic exports only) and a .debug
// companion holding the full .symtab. `debuglink_internal` is hidden: it never reaches
// .dynsym, so resolving it proves the debug file's .symtab was actually used.

#include <cstdint>

#if defined(__GNUC__)
__attribute__((noinline))
#endif
std::int32_t
debuglink_exported(std::int32_t value) {
  return value * 3 + 1;
}

#if defined(__GNUC__)
__attribute__((noinline, visibility("hidden")))
#endif
std::int32_t
debuglink_internal(std::int32_t value) {
  return value * 5 - 7;
}
