#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstdint>

using AllocateFunction = void*(NTAPI*)(void* heap, unsigned long flags, std::size_t size);

#if defined(_MSC_VER)
#define NOLEAX_FIXTURE_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)
#else
#define NOLEAX_FIXTURE_EXPORT extern "C" __declspec(dllexport) __attribute__((noinline))
#endif

NOLEAX_FIXTURE_EXPORT void* noleax_module_generation_allocate(AllocateFunction allocate, void* heap,
                                                              std::size_t size) {
  void* const result = allocate(heap, 0U, size);
  if (result != nullptr && size != 0U) {
    *static_cast<volatile std::uint8_t*>(result) = 0x5AU;
  }
  return result;
}

#undef NOLEAX_FIXTURE_EXPORT
