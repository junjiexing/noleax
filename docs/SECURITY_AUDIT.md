# P8 Windows x64 security audit

> Review date: 2026-07-30
>
> Scope: V1 Windows x64 controller, agent, IPC, trace writer/reader, analyzer, all four run
> injection methods (remote-thread, thread-hijack, entrypoint-code, static-pe-patch), static PE
> patch and supported packaging
>
> Excluded: custom symbol hook DSL, non-x64 architectures, Linux, macOS; the P7 injection
> strategies carry their own security analyses in THREAD_HIJACK_INJECTION.md,
> ENTRYPOINT_INJECTION.md and STATIC_PE_PATCH.md.

## 1. Result

No untreated high-severity finding remains in the reviewed V1 scope. One medium-severity IPC
hardening item was fixed during P8: bootstrap ABI v2 now carries the controller PID, the agent checks
the named-pipe server PID, and the controller independently checks the client PID and 128-bit session
token. Remaining medium risks are explicit trust decisions around native injection, trace-selected
local images passed to DbgHelp, and unsigned local development artifacts.

This review does not authorize public distribution. The repository license, public security contact,
code signing policy, and final human RC acceptance remain release gates.

## 2. Reviewed boundaries

### Injection and permissions

`run` creates the target suspended; `attach` opens an existing process using Windows-defined process,
thread and VM rights. Failures remain Windows access failures and are reported without attempting a
privilege bypass. Only matching native x64 targets are supported. The remote loader resolves the
target's own `ntdll`, uses an absolute agent path, writes a small x64 bootstrap stub as RW data, changes
it to RX, flushes the instruction cache and waits with a deadline. Timeout paths retain remote memory
rather than freeing memory still reachable by a running remote thread.

Injection necessarily grants the agent the target's identity and filesystem access. The trace path is
therefore opened by the target process, not by a privileged broker. Users must select a path writable
by the target and must not use an existing file they need to preserve.

### Controller/agent IPC

- `BCryptGenRandom` creates a 128-bit session token used in the one-instance pipe name and AgentHello.
- `PIPE_REJECT_REMOTE_CLIENTS` rejects network clients and `FILE_FLAG_FIRST_PIPE_INSTANCE` prevents a
  second server instance.
- Bootstrap ABI v2 binds the expected controller PID. The client checks the server PID; the server
  checks the target/client PID, token, ABI, architecture, pointer width and request IDs.
- Frames have fixed magic/version, a bounded payload, reserved-bit checks, exact reads and per-operation
  deadlines. Partial malicious frames are cancelled and classified as timeout/error.
- If control disappears while hooks are live, the agent stops recording but deliberately keeps code
  resident; it does not attempt unsafe physical teardown without controller-coordinated suspension.

The pipe uses the Windows default local DACL. Random naming, first-instance creation, local-only mode,
token validation and bidirectional PID binding provide defense in depth. An attacker with sufficient
rights to read/modify the target or replace project binaries is already inside the trusted local-user
boundary and can inject independently.

### Hook and trace output

Hook replacements avoid general allocation and symbol APIs, preserve required ABI/error state, use
recursion guards and coordinate quiescence before teardown. CFG/CET builds, ABI differential tests,
fail-fast parity, race tests, Application Verifier and soak tests cover the supported API set.

The writer enforces the configured file limit and records loss/incompleteness. It never turns loss into
a complete verdict. Trace files contain raw addresses, module identity/path data, thread IDs, sizes and
allocation timing; confidentiality is the user's responsibility.

### Untrusted trace analysis

Before allocating, the reader caps file/chunk headers, stored and decoded chunk sizes, record size and
compression expansion ratio. It validates byte order, versions, reserved fields, sequence ranges,
CRC32C and LZ4/Zstd decode results. Compatible unknown framed data is skipped and marked partially
understood; corruption and incompatible major versions return 4. Complete chunks preceding a truncated
tail are retained with exit code 2.

DbgHelp runs only in the analyzer with `SYMOPT_SECURE`, no prompts, exact-symbol/identity checks and no
implicit symbol server. However, a trace can name an existing local image which DbgHelp will parse.
This is a residual medium risk for deliberately hostile traces; use OS sandboxing/low privilege. A
future hardening option may disable all trace-path image loading while retaining module+offset output.

## 3. Findings

| ID | Severity | Finding | Resolution |
|---|---|---|---|
| SA-01 | Medium | Agent did not explicitly bind the pipe server to the controller PID | Fixed by bootstrap ABI v2 and bidirectional PID tests |
| SA-02 | High if absent | Malicious sizes/compression could cause excessive allocation or decode work | Existing hard caps and ratio checks; unit and mutation corpus coverage |
| SA-03 | Medium | Trace-selected local image is parsed by DbgHelp | Residual documented; secure flags, identity checks, no implicit network, sandbox guidance |
| SA-04 | Medium | Native agent could be replaced before use in an unsigned development tree | Trusted artifact boundary; absolute path and package smoke; signing policy required before public release |
| SA-05 | Low | Explicit output paths are opened with truncation | Documented destructive boundary; input/output equality rejected for analysis |
| SA-06 | Low | Timed-out injection may retain a small remote allocation | Intentional UAF prevention; deterministic error and rollback tests |
| SA-07 | Low | Trace and logs disclose process layout and behavior | Documented as sensitive; no automatic upload or symbol networking |
| SA-08 | Low | Unsupported P7 methods could be mistaken for available hardening paths | Deterministic exit 5; V1 docs and doctor report remote-thread only |

## 4. Automated evidence

- `cli.trace-recovery-compatibility`: truncated, corrupt, future-minor, future-major and unknown-record
  behavior, including exit 2/4 and completed-chunk retention.
- `cli.trace-untrusted-corpus`: deterministic header flips, truncations and random mutations. Every
  analyzer runs in a separate process with a hard timeout; accepted exits are only 0, 2 and 4, and
  successful/incomplete JSON must parse.
- Named-pipe tests cover client/server PID queries, connection timeout and a partial malicious frame.
- Controller run/attach/E2E tests prove bootstrap v2 and bidirectional identity checks in real targets.
- The hardened suite and P8 soak remain the crash/ABI/quiescence evidence for actual hooks.

The clean `4397e5b` formal corpus used 10 truncations, 68 header bit flips and 128 deterministic
random mutations: 206/206 completed without crash or hang, with 0 timeouts, 0 unexpected exits and a
75 ms maximum process time. Exit distribution was 44 complete, 6 incomplete and 156 invalid-input;
no exit outside 0/2/4 occurred.

The P8.7 final clean-worktree repetition at commit `e819ece` used the same 206 cases and exit
distribution. It again completed with 0 timeouts and 0 unexpected exits; maximum process time was
42 ms. This repetition also ran after the RC switched to the static runtime/package configuration.

Raw mutation reports and generated corpus files live under ignored `_temp` paths. The P8 RC report
records the clean-commit aggregate so machine-specific paths and potentially sensitive bytes are not
committed.

## 5. Residual release gates

1. Select the repository license and confirm third-party redistribution terms.
2. Publish a private security contact/reporting path.
3. Decide whether official binaries require Authenticode signing and how hashes are published.
4. Run the package on a clean Windows x64 machine or VM without the build tree.
5. Obtain explicit human acceptance of the performance baseline and RC checklist.

The AI technical security gate is complete. These residual items remain human release blockers and
are tracked in [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md); this audit does not authorize a tag or
public distribution.
