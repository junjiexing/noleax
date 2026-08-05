// Fixture allocator for custom symbol hook tests. The DLL is built three times with different
// module names (a/b/c) so each hook point can use a distinct argument mapping without tripping
// the duplicate-module validation. Every allocation routes through the hooked ntdll heap APIs,
// so an active capture exercises the guard's recursion suppression.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

// Hook targets must have a relocator-friendly prologue on every toolchain and optimization
// level: the hoox online relocator refuses to relocate across a CALL, and an optimized build
// can emit the first call just a few bytes into the function (a release build's my_free had
// its first call at offset 9 and was rejected with wrong_signature on the release CI).
// Optimization is irrelevant for a test fixture, but the optimize pragma alone did not change
// the release codegen enough, so every hook target additionally starts with two volatile
// stores. Volatile stores cannot be elided or moved past the first call, which keeps the entry
// call-free for well over the required hook size on any toolchain.
#if defined(_MSC_VER)
#pragma optimize("", off)
#endif

#if defined(_MSC_VER)
#define NOLEAX_FIXTURE_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)
#define NOLEAX_FIXTURE_HIDDEN extern "C" __declspec(noinline)
#else
#define NOLEAX_FIXTURE_EXPORT extern "C"
#define NOLEAX_FIXTURE_HIDDEN extern "C"
#endif

// Two volatile stores anchored to a live value: keeps the first real call away from the entry
// point so the checked relocator always has enough contiguous non-call bytes to work with.
#define NOLEAX_FIXTURE_PROLOGUE_ANCHOR(value)                                  \
  do {                                                                         \
    volatile std::uintptr_t noleax_fixture_anchor_a = (std::uintptr_t)(value); \
    volatile std::uintptr_t noleax_fixture_anchor_b =                          \
        noleax_fixture_anchor_a ^ static_cast<std::uintptr_t>(0x9E3779B9ULL);  \
    static_cast<void>(noleax_fixture_anchor_b);                                \
  } while (0)

NOLEAX_FIXTURE_EXPORT void* NTAPI my_malloc(void* arena, std::size_t size) {
  // An arena-style first parameter exercises argument mapping: size_arg = 1 here matches
  // my_realloc's size position, and the extra parameter is ignored by the hook.
  NOLEAX_FIXTURE_PROLOGUE_ANCHOR(size);
  static_cast<void>(arena);
  return HeapAlloc(GetProcessHeap(), 0, size);
}

NOLEAX_FIXTURE_EXPORT void NTAPI my_free(void* pointer) {
  NOLEAX_FIXTURE_PROLOGUE_ANCHOR(pointer);
  static_cast<void>(HeapFree(GetProcessHeap(), 0, pointer));
}

NOLEAX_FIXTURE_EXPORT void* NTAPI my_realloc(void* pointer, std::size_t size) {
  NOLEAX_FIXTURE_PROLOGUE_ANCHOR(size);
  if (pointer == nullptr) {
    return HeapAlloc(GetProcessHeap(), 0, size);
  }
  return HeapReAlloc(GetProcessHeap(), 0, pointer, size);
}

NOLEAX_FIXTURE_EXPORT void* NTAPI my_calloc(std::size_t count, std::size_t size) {
  NOLEAX_FIXTURE_PROLOGUE_ANCHOR(size);
  if (count != 0U && size > static_cast<std::size_t>(~0ULL) / count) {
    return nullptr;
  }
  return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, count * size);
}

NOLEAX_FIXTURE_EXPORT int NTAPI my_xalloc(void** out, std::size_t size) {
  NOLEAX_FIXTURE_PROLOGUE_ANCHOR(size);
  if (out == nullptr) {
    return 1;
  }
  *out = HeapAlloc(GetProcessHeap(), 0, size);
  return *out == nullptr ? 1 : 0;
}

NOLEAX_FIXTURE_EXPORT void NTAPI my_free_size(void* pointer, std::size_t size) {
  NOLEAX_FIXTURE_PROLOGUE_ANCHOR(pointer);
  static_cast<void>(size);
  static_cast<void>(HeapFree(GetProcessHeap(), 0, pointer));
}

// Not exported: located through the PDB public symbol (or a baked RVA) instead. The
// my_malloc_internal/my_free_internal pair exists so the target can exercise it.
NOLEAX_FIXTURE_HIDDEN void* NTAPI my_internal_alloc(std::size_t size) {
  NOLEAX_FIXTURE_PROLOGUE_ANCHOR(size);
  return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

NOLEAX_FIXTURE_HIDDEN void NTAPI my_internal_free(void* pointer) {
  NOLEAX_FIXTURE_PROLOGUE_ANCHOR(pointer);
  static_cast<void>(HeapFree(GetProcessHeap(), 0, pointer));
}

NOLEAX_FIXTURE_EXPORT void* NTAPI my_malloc_internal(std::size_t size) {
  NOLEAX_FIXTURE_PROLOGUE_ANCHOR(size);
  return my_internal_alloc(size);
}

NOLEAX_FIXTURE_EXPORT void NTAPI my_free_internal(void* pointer) {
  NOLEAX_FIXTURE_PROLOGUE_ANCHOR(pointer);
  my_internal_free(pointer);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, void*) { return TRUE; }
