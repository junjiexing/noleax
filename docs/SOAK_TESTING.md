# Windows x64 soak testing

`scripts/Test-NoleaxSoak.ps1` is the repeatable P8 stability gate. Each repetition exercises:

- suspended launch and remote-thread injection;
- runtime attach;
- capture stop/drain/revert conservation;
- the complete nine-API `windows-native` hook profile;
- run, attach, trace reading, events/outstanding analysis, and console/JSON/CSV output.

Run the release gate from a Visual Studio developer environment:

```powershell
pwsh -File scripts/Test-NoleaxSoak.ps1 -Preset windows-x64-release -Repetitions 10
```

For a longer unattended run, increase `-Repetitions`. `-PerTestTimeoutSeconds` bounds every child
CTest invocation so a hang becomes a deterministic failure. `-SkipBuild` is available only when the
requested preset is already configured and built.

The script writes a timestamped JSON report below `_temp/reports` by default. The report records the
commit, dirty-worktree state, host, elapsed time, every test result, and captured CTest output. This
directory is intentionally ignored by Git. Use `-ReportPath` to select a different local destination.

Acceptance requires all checks to pass, no timeout/crash, and no analyzer or conservation failure.
The checked-in P8 RC report records the exact command and aggregate result; raw reports remain local
because they include machine-specific paths and environment details.
