# Vendored hoox amalgamation

Single-file build of [hoox](https://github.com/junjiexing/hoox), the inline-hook
library used by the noleax agent. These files are upstream release artifacts;
edit only to carry reviewed local deviations until they land upstream and a new
release is vendored. There are currently no local deviations.

- Upstream version: **v0.2.1** (release asset `hoox-v0.2.1-amalgamation.zip`)
- `hoox.c` SHA512 (pristine upstream): `927d0ed40d4a2ec93d316b8d5d50100b67e1580d486e265b2b94156b12a9b5321a1787cefce2529bb31677e419a2349dae081868f10e952eee11f7a02f9742ca`
- `hoox.h` SHA512 (pristine upstream): `3a8fc440bc35e69c0e5afe8bbff872ec0385af9084ca36522824fd76f703f8039b2295fecda965ae788a541ce4ad2fa7efb14e8b5e5747879ecce12819902462`

SHA512 values are computed over the pristine release asset as published (CRLF
line endings); the vendored copies are checked in with LF line endings.

## Build integration

`CMakeLists.txt` in this directory compiles `hoox.c` into the `noleax-hoox`
static target. Windows builds define `HOOX_WINDOWS_PATCH_PC_GUARD` (thread-PC
scan during patch writes; off by default upstream), non-Windows builds define
`HOOX_POSIX_PATCH_PC_GUARD` (its Linux counterpart, parking peer threads in a
signal handler) plus `_GNU_SOURCE` so the POSIX backends get full declarations
under `-std=c17`.

## Updating

1. Download `hoox-v<version>-amalgamation.zip` from the hoox release page.
2. Replace `hoox.c`, `hoox.h`, `COPYING` and `NOTICE` with the archive contents,
   converting `hoox.c`/`hoox.h` to LF line endings.
3. Update the version and SHA512 values above and review the resulting diff.
