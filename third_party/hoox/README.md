# Vendored hoox amalgamation

Single-file build of [hoox](https://github.com/junjiexing/hoox), the inline-hook
library used by the noleax agent. These files are upstream release artifacts;
edit only to carry reviewed local deviations until they land upstream and a new
release is vendored. There are currently no local deviations.

- Upstream version: **v0.2.3** (release asset `hoox-v0.2.3-amalgamation.zip`)
- `hoox.c` SHA512 (pristine upstream): `b9e1438aa92abf8d3783ed1120f60981f6418b6edd640b07e71d611f95e0e06cbaacc01c6c145a975752fe7cd6f1b0e85ed36c1da4cf02feec1b933a3ad6624a`
- `hoox.h` SHA512 (pristine upstream): `6e03a7bd350e1851a3cbfaca0e052e12179377d454e83c393241c8b749967d9c6428aa13025d4641bdf8a21561d11758a90f1832bda27824901865f9a72955d6`

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
