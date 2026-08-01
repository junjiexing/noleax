# Security policy

Noleax V1 is a Windows x64 release candidate, not a published stable release. Its core operation is
deliberately invasive: it injects native code and installs hooks in a selected process. Run it only
on processes and machines you are authorized to inspect.

## Reporting a vulnerability

Do not post exploit details, sensitive traces, process dumps, or target paths in a public issue.
Report them privately to the repository owner through the private channel used for this project.
Before any public release, the owner must publish a durable security contact or enable the hosting
provider's private vulnerability-reporting feature.

Include the Noleax commit/version, Windows build and architecture, exact command, relevant exit code,
and the smallest sanitized reproducer. A trace can contain addresses, module paths, process metadata,
and allocation behavior; treat it as potentially sensitive.

## Trust boundaries

- The `noleax` executable, matching `noleax-agent.dll`, configuration, selected target, output paths,
  local symbol paths, and explicitly configured symbol servers are trusted inputs.
- Trace bytes are structurally untrusted. The reader bounds headers, chunks, records, decompression,
  and allocations, and returns 2 for understood incomplete data or 4 for invalid/incompatible input.
- Trace module paths are not fully inert: the offline Windows symbolizer may ask DbgHelp to parse an
  existing local image named by the trace. Analyze hostile traces in a low-privilege sandbox and do
  not configure symbol servers unless network access is intended.
- A process that the current Windows token cannot open with the required rights is outside the
  supported scope. Noleax does not bypass ACLs, UAC, protected-process policy, or architecture checks.

## Operational safeguards

- V1 supports only `remote-thread`. Thread hijack, entrypoint-code injection, and static PE patching
  are deferred TODOs and return unsupported instead of silently falling back.
- The agent path is absolute and must identify a regular file. Controller and agent authenticate the
  local named-pipe session with a system-generated 128-bit token and verify each other's process ID.
- Remote bootstrap memory is written as data and code is changed from writable to executable/read;
  it is not left RWX. A timed-out remote thread retains its parameter memory to avoid use-after-free.
- IPC framing, payload sizes, request IDs, ABI versions, timeouts, and state transitions are checked.
- Trace size is bounded. A user-selected trace or analysis output path may be truncated; never point
  an output option at data that must be preserved.
- Symbol networking is disabled by default. It occurs only with explicit `--symbol-server` or config.
- Incomplete analysis is not a definitive leak verdict. Always inspect the completeness state and
  exit code before acting on a result.
