// Second, deliberately different fixture body: its .debug companion carries a different
// Build ID, so offering it as the first fixture's debug file must fail identity checks.

#include <cstdint>

#if defined(__GNUC__)
__attribute__((noinline))
#endif
std::int32_t
debuglink_foreign(std::int32_t value) {
  return value - 11;
}
