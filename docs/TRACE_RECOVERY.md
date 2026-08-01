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
