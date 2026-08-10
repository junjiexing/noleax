# Vendored hoox amalgamation

Single-file build of [hoox](https://github.com/junjiexing/hoox), the inline-hook
library used by the noleax agent. These files are upstream release artifacts;
edit only to carry reviewed local deviations (listed below) until they land
upstream and a new release is vendored.

- Upstream version: **v0.2.0** (release asset `hoox-v0.2.0-amalgamation.zip`)
- `hoox.c` SHA512 (pristine upstream): `7b7924c685a8328f12eac008566fbc63ca8ac88947f4d4a6556e7d5306a605872d666ccdc3d8326ee101caa1bb296d6926a76bb87fdb6a9e55974f2de93530f2`
- `hoox.h` SHA512 (pristine upstream): `0b1915b31658218082d4dacae81cca6d694bcda964c1b454f89ee658a7c292e1f514192f752cb54ac1c2e0c35cc68f0214294a1892e7bcee2e3a2b98a23eb53a`

## Local deviations (destined for upstream)

1. **x86-64 FAST near-redirect fallback** (`hoox.c`, interceptor backend):
   `hoox_interceptor_replace_fast` plans a worst-case 16-byte absolute redirect
   and rejects targets with shorter clean prologues. glibc offers many such
   targets (syscall stubs like `munmap`, jump-only aliases like `memalign`).
   When checked relocation of the 16-byte window fails for a FAST interceptor,
   hoox now falls back to a 5-byte near jump into a slice allocated within
   rel32 range; the slice head holds the absolute jump to the replacement
   (emitted at activation time, when the replacement address is assigned).
   Previously working targets are unaffected.
2. **Linux peer parking** (`hoox.c`/`hoox.h`, `hoox_peer_park_begin` /
   `hoox_peer_park_all_clear_of` / `hoox_peer_park_end`): signal-driven
   stop-the-world for Linux. Peers are `tgkill`'d a dedicated real-time signal
   (default `SIGRTMIN+6`, overridable via `HOOX_PEER_PARK_SIGNAL`); the handler
   records the interrupted RIP and spins until released. Fail-closed on
   blocked signals, enumeration failure, or wait-budget overrun; performs no
   heap allocation while peers are parked.
3. **POSIX patch PC guard** (`hoox.c`, opt-in `HOOX_POSIX_PATCH_PC_GUARD`):
   wires peer parking into `hoox_memory_patch_code_pages_guarded` so Linux
   patch writes get the same no-thread-in-transit guarantee the Windows
   `HOOX_WINDOWS_PATCH_PC_GUARD` provides, including the release-and-retry
   loop when a parked thread's PC sits inside a guard range.

## Build integration

`CMakeLists.txt` in this directory compiles `hoox.c` into the `noleax-hoox`
static target with `HOOX_WINDOWS_PATCH_PC_GUARD` defined (thread-PC scan during
patch writes; off by default upstream). Platform and architecture macros are
auto-detected from the compiler (`_WIN32`, `_M_X64`); non-Windows builds define
`_GNU_SOURCE` so the POSIX backends get full declarations under `-std=c17`.

## Updating

1. Download `hoox-v<version>-amalgamation.zip` from the hoox release page.
2. Replace `hoox.c`, `hoox.h`, `COPYING` and `NOTICE` with the archive contents.
3. Update the version and SHA512 values above and review the resulting diff.
