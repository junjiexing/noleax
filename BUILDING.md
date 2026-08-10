# Building Noleax

## Windows x64 prerequisites

- Windows 10 or Windows 11 x64.
- Visual Studio 2022 with Desktop development with C++.
- CMake 3.25 or newer.
- Ninja.
- Git.
- vcpkg at the baseline recorded in vcpkg.json.

The vcpkg executable and package cache are local tools and must not be committed to this repository.

## Linux x64 prerequisites

- Linux x86-64 with glibc (developed and tested on recent Ubuntu LTS).
- GCC 13+ or Clang 17+.
- CMake 3.25 or newer.
- Ninja.
- Git.
- vcpkg at the baseline recorded in vcpkg.json.

Linux support is under construction (docs/LINUX_PORT_PLAN.md): the platform-neutral
components build and are tested, `analyze` and `config` work, and the capture commands
(`run`/`attach`/`patch`/`symbols`/`doctor`) fail fast with exit code 5 until their
milestones land.

## Local release-candidate package

After a Release build, generate and validate the self-contained Windows x64 ZIP with:

~~~powershell
cpack --config .\build\windows-x64-release\CPackConfig.cmake -G ZIP
pwsh -NoProfile -File .\scripts\Test-NoleaxPackage.ps1 -SkipBuild
~~~

The archive and its SHA-256 companion are written below the ignored `build` directory. They are
local test artifacts, not approved releases. Packaging details and redistribution blockers are in
[docs/PACKAGING.md](docs/PACKAGING.md).

## Prepare vcpkg

Example local setup (Windows, PowerShell):

~~~powershell
git clone https://github.com/microsoft/vcpkg.git _temp/vcpkg
git -C _temp/vcpkg checkout 9d7f79f56ae1a9b4704d6a7fb8237e347a974133
.\_temp\vcpkg\bootstrap-vcpkg.bat -disableMetrics
$env:VCPKG_ROOT = (Resolve-Path .\_temp\vcpkg).Path
~~~

Linux equivalent:

~~~sh
git clone https://github.com/microsoft/vcpkg.git _temp/vcpkg
git -C _temp/vcpkg checkout 9d7f79f56ae1a9b4704d6a7fb8237e347a974133
./_temp/vcpkg/bootstrap-vcpkg.sh -disableMetrics
export VCPKG_ROOT="$(pwd)/_temp/vcpkg"
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

Windows CFG/CET hardened preset：

~~~powershell
cmake --preset windows-x64-hardened
cmake --build --preset windows-x64-hardened
ctest --preset windows-x64-hardened
~~~

Linux (Debug or Release):

~~~sh
cmake --preset linux-x64-release
cmake --build --preset linux-x64-release
ctest --preset linux-x64-release
~~~

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

These tests compare deterministic `/MD` and `/MT` workload summaries.

## Output

Windows:

- build/<preset>/bin/noleax.exe
- build/<preset>/bin/noleax-agent.dll
- build/<preset>/bin/noleax-unit-tests.exe
- build/<preset>/bin/noleax-rtl-heap-baseline-md.exe
- build/<preset>/bin/noleax-rtl-heap-baseline-mt.exe

Linux:

- build/<preset>/bin/noleax
- build/<preset>/bin/noleax-agent.so
- build/<preset>/bin/noleax-unit-tests

## Clean builds

Build directories are disposable. Remove only the specific build/<preset> directory after verifying its resolved path is inside this repository.

## Other platforms

Windows x64 and Linux x64 (glibc) build in CI. Linux currently ships the platform-neutral
components only: `analyze`/`config` are fully functional, while the capture commands fail
fast with exit code 5 (see docs/LINUX_PORT_PLAN.md for the port plan). macOS has no
support timeline.
