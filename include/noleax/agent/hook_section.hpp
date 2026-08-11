#pragma once

// Hook replacement and gate code lives in the dedicated ".nlxhk" section so the patch
// rendezvous can prove no thread is executing it before trampolines and module references
// are released (docs/HOOK_QUIESCENCE.md). MSVC places a region of functions with the
// code_seg push/pop pragmas; GCC/Clang on ELF need a per-function section attribute
// instead. Wrap the region with the PUSH/POP pair and annotate every function definition
// inside it with NOLEAX_HOOK_SECTION.
//
// ELF note: every vague-linkage (inline) function in a named section makes the whole
// section a linkonce group keyed on one of its symbols, and the linker dedups groups by
// signature. That is correct only when the colliding TUs carry identical content. Hook
// replacements are TU-unique, so they must never share a group with the shared inline
// lifecycle helpers — on ELF those helpers therefore live in the sibling ".nlxhk.imm"
// section (same rendezvous coverage; the region resolver matches the ".nlxhk" prefix).
#if defined(_MSC_VER)
#define NOLEAX_HOOK_SECTION
#define NOLEAX_HOOK_SECTION_PUSH _Pragma("code_seg(push, \".nlxhk\")")
#define NOLEAX_HOOK_SECTION_POP _Pragma("code_seg(pop)")
#define NOLEAX_HOOK_IMM_SECTION
#define NOLEAX_HOOK_IMM_SECTION_PUSH _Pragma("code_seg(push, \".nlxhk\")")
#define NOLEAX_HOOK_IMM_SECTION_POP _Pragma("code_seg(pop)")
#else
#define NOLEAX_HOOK_SECTION __attribute__((section(".nlxhk")))
#define NOLEAX_HOOK_SECTION_PUSH
#define NOLEAX_HOOK_SECTION_POP
#define NOLEAX_HOOK_IMM_SECTION __attribute__((section(".nlxhk.imm")))
#define NOLEAX_HOOK_IMM_SECTION_PUSH
#define NOLEAX_HOOK_IMM_SECTION_POP
#endif
