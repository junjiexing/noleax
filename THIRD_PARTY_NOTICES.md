# Noleax third-party notices

This release candidate incorporates or uses the software listed below. The complete copyright and
license text recorded by the locked vcpkg build is distributed beside this file in `licenses/`.
Those files are part of the release archive and take precedence over this summary.

Noleax's own license has not yet been selected. This third-party notice does not grant permission to
redistribute Noleax itself; public distribution remains blocked until the repository license is
approved.

| Component | Version | Use | License selected for this build | Full text |
|---|---:|---|---|---|
| Catch2 | 3.15.3 | Development and tests only; not linked into the shipped runtime | Boost Software License 1.0 | `licenses/catch2.txt` |
| CLI11 | 2.6.2 | Command-line parsing | BSD-3-Clause | `licenses/cli11.txt` |
| Hoox | 0.1.1 | Inline hook backend | wxWindows Library Licence 3.1 | `licenses/hoox.txt` |
| LZ4 | 1.10.0 | Trace compression | BSD-2-Clause | `licenses/lz4.txt` |
| toml++ | 3.4.0 | TOML configuration parsing | MIT | `licenses/tomlplusplus.txt` |
| Zstandard | 1.5.7 | Trace compression | BSD-3-Clause option | `licenses/zstd.txt` |

## Hoox modifications and attribution

Noleax consumes the upstream `v0.1.1` tag from <https://github.com/junjiexing/hoox>. The vcpkg
overlay applies three reviewable patches:

- `install-rules.patch` adds CMake install/export rules.
- `windows-fls-lifecycle.patch` clears Hoox's private Windows FLS key during deinitialization.
- `windows-rwx-patch-quiescence.patch` suspends peer threads while applying or reverting the
  Windows x64 multi-byte patch.

Hoox is extracted and adapted from frida-gum and preserves the upstream attribution to Ole André
Vadla Ravnås and contributors. Its compact instruction decoder is informed by Microsoft Detours and
contains the applicable Microsoft MIT notice. The complete Hoox COPYING and NOTICE content,
including these attributions, is reproduced in `licenses/hoox.txt`.

## Binary distribution notes

CLI11 and toml++ are compiled from headers. Hoox, LZ4, Zstandard and the Microsoft C/C++ runtime are
linked statically. Microsoft runtime code remains governed by the Visual Studio build-tools terms
and is not relicensed by Noleax. Windows system libraries are not redistributed.
