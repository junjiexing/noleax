#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>

extern "C" __declspec(dllexport) std::uint32_t noleax_test_fixture() noexcept { return 1U; }
