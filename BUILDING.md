# Building Noleax

## Windows x64 prerequisites

- Windows 10 or Windows 11 x64.
- Visual Studio 2022 with Desktop development with C++.
- CMake 3.25 or newer.
- Ninja.
- Git.
- vcpkg at the baseline recorded in vcpkg.json.

The vcpkg executable and package cache are local tools and must not be committed to this repository.

## Prepare vcpkg

Example local setup:

~~~powershell
git clone https://github.com/microsoft/vcpkg.git _temp/vcpkg
git -C _temp/vcpkg checkout 9d7f79f56ae1a9b4704d6a7fb8237e347a974133
.\_temp\vcpkg\bootstrap-vcpkg.bat -disableMetrics
$env:VCPKG_ROOT = (Resolve-Path .\_temp\vcpkg).Path
~~~

Enter the repository's developer environment:

~~~powershell
.\scripts\Enter-NoleaxDevShell.ps1
~~~

The script discovers Visual Studio and selects the newest installed MSVC toolset. This keeps the project compiler aligned with the toolset selected by vcpkg when several MSVC versions are installed.

## Configure, build, and test

Debug:

~~~powershell
cmake --preset windows-x64-debug
cmake --build --preset windows-x64-debug
ctest --preset windows-x64-debug
~~~

Release:

~~~powershell
cmake --preset windows-x64-release
cmake --build --preset windows-x64-release
ctest --preset windows-x64-release
~~~

Windows CFG/CET hardened gate：

~~~powershell
cmake --preset windows-x64-hardened
cmake --build --preset windows-x64-hardened
ctest --preset windows-x64-hardened
~~~

完整 hook hardening 压力和管理员 Application Verifier/Page Heap 验收见
[docs/WINDOWS_HOOK_HARDENING.md](docs/WINDOWS_HOOK_HARDENING.md)。

The first configure installs manifest dependencies into build/<preset>/vcpkg_installed. The Hoox overlay port pins v0.1.1 and verifies its source archive hash.

## Formatting and static analysis

The formatting check requires clang-format 18:

~~~powershell
.\scripts\Check-Format.ps1
~~~

clang-tidy is opt-in for local builds and runs automatically in the Debug CI job:

~~~powershell
cmake --preset windows-x64-debug -DNOLEAX_ENABLE_CLANG_TIDY=ON
cmake --build --preset windows-x64-debug
~~~

The Windows Rtl Heap unhooked baselines can be run independently with:

~~~powershell
ctest --preset windows-x64-debug -L baseline --output-on-failure
~~~

These tests compare deterministic `/MD` and `/MT` workload summaries. See
[docs/RTL_HEAP_BASELINE.md](docs/RTL_HEAP_BASELINE.md) for the workload and longer stress commands.

## Output

- build/<preset>/bin/noleax.exe
- build/<preset>/bin/noleax-agent.dll
- build/<preset>/bin/noleax-unit-tests.exe
- build/<preset>/bin/noleax-rtl-heap-baseline-md.exe
- build/<preset>/bin/noleax-rtl-heap-baseline-mt.exe

## Clean builds

Build directories are disposable. Remove only the specific build/<preset> directory after verifying its resolved path is inside this repository.

## Other platforms

The source layout and toolchain are prepared for additional platforms, but V1 support and CI currently cover Windows x64 only.
