# Trace recovery and compatibility

V1 treats trace input as untrusted and separates recoverable incompleteness from incompatible or
corrupt input.

| Input condition | Analysis behavior | Exit code |
|---|---|---:|
| Complete V1 trace | Normal result | 0 |
| Truncated tail after complete chunks | Preserve complete chunks; mark truncated and incomplete | 2 |
| Unknown record, chunk, or compatible future minor extension | Skip framed data; mark partially understood | 2 |
| Capture loss or missing stack detail | Preserve understood events; report exact completeness issues | 2 |
| CRC mismatch or malformed framing | Reject input; do not emit a completed result | 4 |
| Unsupported future major version | Reject as incompatible | 4 |

`cli.trace-recovery-compatibility` is the CLI-level compatibility contract. It creates traces with a truncated
final chunk, an unknown event record, a future minor header extension, a corrupt final chunk, and a
future major version. The first three must retain the event from the last completed event chunk in
valid JSON. Hard failures must not contain a completed completeness summary.

The reader bounds header, chunk, record, decompression-ratio, and allocation sizes before allocating
or decoding. A trace that exits with 2 is usable only with its reported limitations; it must not be
presented as a definitive leak result. Exit 4 means the analysis result is unusable.

## Partial traces and the writer error tail (Linux agent, H2)

The Linux agent never writes the requested trace path directly. It streams into `<path>.partial` and
atomically renames it to `<path>` only after a successful EndOfTrace, flush, and close. A `.nlx` at
the final path is therefore always file-level complete; anything else stays a `.partial`:

- A target that is SIGKILLed or crashes mid-capture leaves the `.partial` at the last completed
  flush. The agent flushes the stream at capture start (header + capture scope) and on every
  `trace.flush_interval` tick, so the residue decodes as a trace with a missing tail
  (`missing-end-of-trace`, exit 2).
- A writer failure (disk full, I/O error, flush or close failure) stops the capture. The agent
  releases the reserved file tail and makes one best-effort error tail: a
  `Loss(writer-error/writer)` record estimating the consumed-but-unwritten events, per-API
  Statistics up to the failure point (every such event accounted as dropped, so
  `observed = successful + failed` and `written + filtered + dropped = observed` still hold), and an
  abnormal EndOfTrace (`normal_stop=false`, `writer-error` and `abnormal-stop` completeness issues).
  The `.partial` is left in place on purpose.
- If the error tail itself fails (the disk stays full), the `.partial` simply ends after the last
  good chunk; the agent reports both the original error and the tail failure (result fields
  `error_message` / `tail_error_message`, plus phase, errno, file offset, and chunk type of the
  first failure) and prints one `noleax-agent: trace writer failed: ...` line on stderr.

Analyzing a `.partial` needs no special flag — `noleax analyze trace.nlx.partial` works like any
other input and reports the recorded incompleteness with exit 2. The run/attach summary falls back
to the `.partial` automatically when the final path does not exist.
