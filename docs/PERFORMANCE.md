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

## P8 reference result

Commit `74dbf03` was measured on 2026-07-30 using Windows 10.0.19045 x64 with 24 logical
processors. The clean-worktree run used one warm-up and three measured repetitions, 13,500 heap
operations and 15,619,170 requested bytes per repetition. All 15 measured traces were complete with
zero dropped events.

| Case | Median target time | Baseline ratio | Median trace size |
|---|---:|---:|---:|
| uninstrumented | 4.752 ms | 1.000x | n/a |
| default | 7.766 ms | 1.634x | 410,192 B |
| stack-16 | 7.854 ms | 1.653x | 411,146 B |
| stack-32 | 6.725 ms | 1.415x | 411,205 B |
| compression-none | 6.058 ms | 1.275x | 1,644,913 B |
| compression-zstd1 | 5.732 ms | 1.206x | 183,038 B |

These short target intervals are useful for comparing this host, but they do not justify a default
change by themselves. LZ4 remains the V1 default: `none` produced roughly four times the trace size,
and selecting Zstd from one short host run would need broader CPU and workload validation. Stack
depth 64 remains the default because the smaller depths did not materially reduce trace size and
discard diagnostic detail.

## P8.7 static-runtime candidate result

The final technical gate repeated the benchmark at clean commit `e819ece` after the RC changed to
`/MT` and `x64-windows-static`. It used the same Windows 10.0.19045 x64 host, workload, warm-up and
three measured repetitions. All 15 captured traces were complete with zero dropped events.

| Case | Median target time | Baseline ratio | Median trace size |
|---|---:|---:|---:|
| uninstrumented | 3.100 ms | 1.000x | n/a |
| default | 4.619 ms | 1.490x | 413,467 B |
| stack-16 | 4.617 ms | 1.489x | 413,369 B |
| stack-32 | 4.677 ms | 1.509x | 414,075 B |
| compression-none | 4.999 ms | 1.613x | 1,664,877 B |
| compression-zstd1 | 4.681 ms | 1.510x | 186,439 B |

The short intervals vary enough that results from separate runs must not be treated as a precise
before/after comparison. The candidate still keeps LZ4 and 64 frames: uncompressed output was about
four times larger, Zstd needs broader workload/CPU validation before becoming the default, and
smaller stacks discard diagnostic detail without a consistent timing benefit. Human acceptance of
the candidate overhead remains a release checklist item.
