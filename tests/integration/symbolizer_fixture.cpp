#if defined(_MSC_VER)
#define NOLEAX_FIXTURE_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)
#else
#define NOLEAX_FIXTURE_EXPORT extern "C"
#endif

NOLEAX_FIXTURE_EXPORT int noleax_symbolizer_fixture_target(int value) { return value * 3 + 7; }
