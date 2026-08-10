#pragma once

// Hook replacement and gate code lives in the dedicated ".nlxhk" section so the patch
// rendezvous can prove no thread is executing it before trampolines and module references
// are released (docs/HOOK_QUIESCENCE.md). MSVC places a region of functions with the
// code_seg push/pop pragmas; GCC/Clang on ELF need a per-function section attribute
// instead. Wrap the region with the PUSH/POP pair and annotate every function definition
// inside it with NOLEAX_HOOK_SECTION.
#if defined(_MSC_VER)
#define NOLEAX_HOOK_SECTION
#define NOLEAX_HOOK_SECTION_PUSH _Pragma("code_seg(push, \".nlxhk\")")
#define NOLEAX_HOOK_SECTION_POP _Pragma("code_seg(pop)")
#else
#define NOLEAX_HOOK_SECTION __attribute__((section(".nlxhk")))
#define NOLEAX_HOOK_SECTION_PUSH
#define NOLEAX_HOOK_SECTION_POP
#endif
