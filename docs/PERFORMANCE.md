# Windows x64 capture performance

`scripts/Measure-NoleaxCapture.ps1` is the reproducible P8 performance harness. It runs the same
deterministic NT Heap workload without injection and with these capture configurations:

| Case | Maximum stack depth | Compression |
|---|---:|---|
| default | 64 | LZ4 |
| stack-16 | 16 | LZ4 |
| stack-32 | 32 | LZ4 |
| compression-none | 64 | none |
| compression-zstd1 | 64 | Zstd level 1 |

The target measures only its workload interval, after agent readiness and before capture shutdown.
Every captured run must preserve the baseline checksum, operation count, and requested byte count.
The script then analyzes every trace and requires complete allocation lifecycle data, full format
understanding, no truncation, zero dropped events, and at least the expected workload event count.
An isolated stack-capture failure may produce exit code 2 without invalidating timing; it is retained
as a per-run completeness issue in the report instead of being hidden.

Run the release benchmark from a Visual Studio developer environment:

```powershell
pwsh -File scripts/Measure-NoleaxCapture.ps1 -Preset windows-x64-release
```

The default is one warm-up plus three measured repetitions per case. Increase `-Repetitions` for a
more stable local comparison. The default workload stays below the bounded event queue's saturation
point; queue-overflow behavior is covered by dedicated stress tests. Timestamped raw workloads,
traces, and JSON reports are written below the ignored `_temp` directory. Results are host-specific
and are a baseline for regression and human acceptance, not a universal performance guarantee.

Changing a product default requires a reviewed benchmark report. P8 does not automatically select a
faster option if it weakens stack detail, trace size, or compatibility.
