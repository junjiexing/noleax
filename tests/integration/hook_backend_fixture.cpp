#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bit>
#include <cstdint>

#define NOLEAX_HOOK_FIXTURE_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)

namespace {

volatile std::uint64_t fixture_salt = 0x6e6f6c6561785034ULL;

}  // namespace

NOLEAX_HOOK_FIXTURE_EXPORT std::uint64_t WINAPI
noleax_hook_fixture_transform(std::uint64_t left, std::uint64_t right) noexcept {
  std::uint64_t result = left ^ fixture_salt;
  result = std::rotl(result, 17) + right * 0x9e3779b97f4a7c15ULL;
  result ^= std::rotr(right + fixture_salt, 11);
  return result + 0x243f6a8885a308d3ULL;
}

NOLEAX_HOOK_FIXTURE_EXPORT std::uint64_t WINAPI
noleax_hook_fixture_combine(std::uint64_t left, std::uint64_t right) noexcept {
  std::uint64_t result = right ^ fixture_salt;
  result = std::rotr(result, 23) + left * 0xbf58476d1ce4e5b9ULL;
  result ^= std::rotl(left + fixture_salt, 7);
  return result + 0x13198a2e03707344ULL;
}
