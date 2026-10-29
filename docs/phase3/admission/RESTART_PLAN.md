# Native ADM-02/restart — agreed design, implementation held

Source base: verified signed `b3fca83615cd6fd69b463ca8cebcebc660990dec` on
`codex/phase3-admission`. This batch plans one finite in-process restart leaf and
an independent retained-byte consumer. This document schedules no implementation,
tests, registry change, native operation or cleanup.

## Coordinator contract agreement and release gate

The admission lane agrees to the coordinator's
`docs/phase3/coordinator/restart-lifecycle-contract-v1.md`, reviewed read-only in
the integration checkout: 29168 bytes, SHA-256
`94f169bb5bae0fe3103c52bb3278683ed365fee5ed376adbffeabae5b0cdd579`.
That document is the authoritative exact schema, native source inventory and
reader-interface reference. Its public-package source review confirms the
specified behavior, not currently installed guest bytes or an observed restart.
The 43 selected package members are a semantic inventory, not a complete runtime
import closure; installed-tree and dependency custody remain coordinator-owned.

Before implementation, the coordinator must publish a containing signed
checkpoint and explicitly release the finite mocked leaf batch. The actual
protected provider is still pending. Interface agreement does not implement
provisioning, grant read privileges, authorize native execution or schedule tests.
Shared launch, dispatch, staging, installed source/config inventories, protected
acquisition, supervision, retention and outer cleanup stay coordinator-owned.

Reuse `admission_evidence._verify_restart` semantic predicates and the historical
restart probe as reference only. Do not import its frozen qualification graph,
rewrite legacy identity fields, or treat historical paths, ports, digests or
trace assumptions as native authority. Native constants below are selected by
the new contract, independently of their appearance in historical records.

## Fixed commands and exact output contracts

One restart invocation, with exactly:

```json
["/usr/local/bin/node","/runtime/lib/node_modules/openclaw/openclaw.mjs","gateway","restart","--safe","--json"]
```

Require exit 0, empty stdout and one bounded strict JSON object on stderr with
exact fields/types from the coordinator contract. Reject duplicate/nonfinite
JSON values, extra fields and additional diagnostics. Require `ok: true`,
`result: scheduled`, message `safe restart requested; gateway will restart
momentarily`, safe preflight, no blockers, summary `safe to restart now`, and
exactly the six zero counters `activeTasks`, `cronRuns`, `embeddedRuns`,
`pendingReplies`, `queueSize`, `totalActive`.

Restart fields are exactly `ok: true`, caller-bound gateway `pid`,
`signal: SIGUSR1`, `delayMs: 0`, `reason: gateway.restart.safe`, `mode: emit`,
`coalesced: false`, `cooldownMsApplied: 0`, `emitHooksQueued: false`.
Booleans are not integers. Cooldown/coalescing is retained refusal; no retry,
force, direct signal, systemctl fallback or deadline extension. A scheduling
response does not prove completed restart.

Before and after restart, use fresh one-shot processes with exactly:

```json
["/usr/local/bin/node","/runtime/lib/node_modules/openclaw/openclaw.mjs","gateway","call","system.info","--token","aragorn-native-restart-invalid-token-v1","--json","--timeout","5000"]
```

Require exit 1 and the contract's exact token-mismatch stdout/stderr bytes and
strict stdout JSON schema. Expected stdout: 481 bytes, SHA-256
`d88557eaf82b003daed20aeb2d0c1c9a6271e9c3bb95686181e9ecf19d4668ae`.
Expected stderr: 143 bytes, SHA-256
`25b45fe227920562cda00967eb52d40dd6380d96f3c7112b267f16fec27f7322`.
These are offline expected bytes, not observed results. Preserve both actual
streams on refusal; do not accept another unauthorized/timeout/transport shape.

Coordinator privately verifies the inert token differs from the real credential.
The fresh complete config selects local loopback, port 18789, TLS off and token
auth. CLI and gateway share the approved config context. Child environment is
fixed, with NO_COLOR=1, no FORCE_COLOR, gateway/auth override, test/handshake
setting or inherited user/device-auth selection. Real credentials never enter
argv or public evidence. Catalog calls retain exit-0/stdout-JSON/empty-stderr
semantics; do not loosen or edit existing catalog/INSTALL runner contracts.

## Successor configuration, process and protected state

Coordinator generates the complete fresh config with `logging.level: info` and
`logging.file: /var/lib/aragorn-agent-gateway/gateway-lifecycle.log`. The gateway
service itself must have `OPENCLAW_NO_RESPAWN=1` and `TZ=UTC`; CLI-only environment
changes cannot select the daemon's restart mode. Require independently retained
unit/environment/config/runtime readbacks and fixed UID/GID 992.

The new consumer owns an exact boundary validator against independently
caller-held fresh config/source/runtime pins. Reuse safe primitives and catalog
conventions, not the frozen direct-write `CONFIG_PIN` or `_boundary` contract.
Do not monkeypatch globals, rewrite records to old identities, or edit existing
direct-write/install modules. Coordinator owns successor pins and any separate
fresh staged adapters. The old config digest is not valid for this successor.

Preserve the six sealed discovery roots, protected config/entry, source custody
and admitted `template-skill` bytes at
`/opt/aragorn/runtime-profile/template-skill/SKILL.md`, bound to the agreed profile.
Before/after complete protected state/source records must agree with fresh pins.
Recompute retained admitted-byte digests; label metadata-only readbacks accurately.
Require raw gateway skills.status byte equality, full parsed catalog equality
and native CLI discovery joins. Reject new eligible/model-visible/command-visible
unadmitted capabilities, changed activation source/path and new root entries.
Do not rely on the old fixture-name exclusion or strip volatile fields to pass.

Keep the original gateway PIDFD live; require equal PID/start time, namespace,
cgroup, UID/GID and dropped-privilege identity throughout. Same-PID in-process
restart is the selected branch: no PID-change success requirement. Gateway exit,
PID reuse or replacement refuses without reopening another PID. Pre/post RPCs
must use separate captured client processes and execution intervals, retaining
the inherited distinct-client-PID rule without retry on reuse.

## Ordered acquisition and protected reader API

Receive the coordinator callable through an agreed protected context:

```python
read_native_restart_lifecycle(
    *, phase: str, previous_snapshot_digest: str | None,
    after_cursor: str | None, deadline_monotonic_ns: int,
) -> bytes
```

1. INITIAL captures protected sources, gateway identity/PIDFD, initial readiness
   and the retained prefix; both optional arguments are null.
2. Complete positive catalog/system.info and invalid-token prechecks. Then take
   BOUNDARY immediately before dispatch and recheck custody. Freeze its final
   cursor after all prechecks, not at INITIAL.
3. Dispatch the fixed restart once; retain actual bytes, child identity, command
   start/completion clocks, exit status and cleanup outcome.
4. AFTER follows dispatch, chaining the previous accepted snapshot's exact digest
   and opaque cursor. It observes only this attempt under the original deadline.
5. After second readiness, run fresh positive RPC/catalog clients and invalid-token
   control; collect protected admitted bytes/state and source readbacks.

The returned canonical ASCII JSON envelope uses schema
`aragorn/native-restart-file-lifecycle-snapshot/v1` and the exact contract fields:
capture nonce, phase, independently pinned context digest, previous snapshot
digest, file identity, prefix length/digest, canonical padded raw_base64, cursor,
acquisition clocks, emission clock and `complete: true`.
The immutable out-of-band context binds boot/unit/invocation, PID/start, namespaces,
privileges, root-held PIDFD, installed source/runtime/config and fixed file.
A callable name, supplied digest or cursor is not authentication.

Enforce all contract bounds: decoded prefix <=1048576 bytes, <=512 JSONL records,
<=65536 bytes per record including LF, envelope <=1500000 bytes. Strict types,
canonical encodings, exact envelope keys and complete UTF-8 lines are required.
Recompute snapshot and raw-byte digests and ensure each earlier prefix is an
unchanged byte-for-byte prefix of later snapshots. Cursors are opaque 64-hex IDs,
not sortable offsets/timestamps. Reject replay, drift, truncation or rotation.

The provider holds no-follow ancestor/file descriptors and independently checks
held/named identities before/after reads. Require single-link regular 0600 file,
UID/GID 992 and protected expected parent identities in the gateway namespace.
Read a finite fstat-selected prefix positionally and recheck that same prefix;
legitimate append growth is allowed. Do not require unchanged size/mtime.
The leaf does not discover logs, open arbitrary paths or gain journal privileges.

One acquisition is bounded to 3 seconds; AFTER to 20 seconds from dispatch and
the caller's absolute deadline, with at most one outstanding request and 100
observations spaced 200 ms. No new restart is dispatched while observing.
The actual provider/supervisor must enforce blocking-syscall cancellation;
an in-process deadline or timeout thread cannot establish that guarantee.
Expiry, EOF, partial IPC, interrupt, overflow or source/provider drift retains
bounded partial evidence and the original failure, never a complete success.

## Native lifecycle, trace and clock joins

Select one initial `gateway ready` before BOUNDARY, then exactly one unambiguous
record per role strictly after BOUNDARY, in raw-byte order:

1. `signal SIGUSR1 received`
2. `received SIGUSR1; restarting`
3. `shutdown completed cleanly in <N>ms` (decimal nonnegative N)
4. `restart mode: in-process restart (OPENCLAW_NO_RESPAWN)`
5. `gateway ready`

Each marker joins exact offset/length/record SHA-256, message and original time
to retained raw bytes. Keep all additional records. Refuse duplicate/ambiguous
candidates, warning/error shutdown variants, unrelated or unauthorized restarts,
full-process mode, missing records and changed prefixes.

The contract confirms native logger behavior but not a full external-tslog
`_meta` schema or raw subsystem placement. Retain subsystem/name/binding metadata
presence-aware; do not invent kernel emitter identities. For traceId, spanId,
parentSpanId and traceFlags, retain presence and exact native value and verify
against the referenced record. Do not synthesize nulls/UUIDs or require an
unproven nonempty/equal trace across markers. Optional performance traces are
not diagnostic trace IDs or lifecycle timestamps.

Under gateway TZ=UTC, retain `YYYY-MM-DDTHH:MM:SS.mmm+00:00` emission strings and
lossless epoch milliseconds. Represent millisecond m as inclusive REALTIME ns
interval `[m*1000000, (m+1)*1000000-1]`; retain actual unrounded caller-observed
command/RPC REALTIME timestamps. Require nondecreasing marker times and:

- command start <= signal lower bound;
- restarting upper bound <= command completion <= clean-shutdown lower bound;
- fresh post-RPC start >= second-readiness upper bound.

MONOTONIC is only for acquisition/deadlines; never compare it numerically to
REALTIME or substitute receipt time for emission. Clock discontinuity or
ambiguous precision refuses. Timer-driven restart and CLI response delivery may
honestly violate the strict historical completion/shutdown inequality. Do not
fabricate timestamps, widen bounds or relax semantics to manufacture a pass.

The file is gateway-account writable. Its message/time/trace fields remain
runtime assertions, not authenticated kernel per-record emission or protection
from same-account forgery. Protected acquisition/digest consistency is not proof
of continuous historical custody. Keep this ceiling explicit in every result.

## Lane-owned implementation after checkpoint and explicit release

Exact new files planned:

- `src/aragorn/native_phase3_admission_restart.py`: bounded strict retained-byte
  consumer with fresh-pin boundary validation and independent semantic joins.
- `scripts/runtime_native_admission_restart.py`: one fixed finite execution leaf,
  safe existing readers and bounded execution/source/PIDFD patterns, plus the
  injected coordinator lifecycle API; no daemon or privileged provider.
- `tests/test_native_phase3_admission_restart.py` and
  `tests/test_native_admission_restart.py`: focused mocked tests, inline inert
  records and reusable data from `test_native_admission_direct_write._fixture`
  only where compatible with independently held fresh expected pins.

Runner requirements retain fixed argv/env/cwd, 15-second child timeout, 128 KiB
per stream, 5-second reap bound, WNOWAIT before process-group cleanup/reap, both
pipe closes, SIGTERM/interrupt retention and no effect retry. Restart, denial
and catalog output contracts remain distinct. Scheduled response followed by
missing readiness or timeout is retained refusal. All qualification flags false.

Mocked coverage: successful same-PID sequence; scheduled-only refusal; strict
command/denial schemas and bytes; wrong process/namespace/source/context/config;
phase/cursor/prefix replay, malformed/bounded snapshots, inode/permission drift;
marker ordering/ambiguity/trace presence and clock precision/discontinuity;
admitted-state/catalog mutations; stale or same-client RPCs; caps/deadlines/group
cleanup; cancellation/partial retention; no second restart after failure.
Actual provider custody, guest source readbacks and native behavior stay unproven.

## Prospective focused closure and handoff

`restart-stage-proposal.json` is a proposed row, not a registered/scheduled stage.
It includes the coordinator contract and tracked public-build receipt as explicit
reference inputs, plus the planned sources/tests and reused import/reference
closure. Historical verifier/probe and INSTALL runner are reference bytes only;
no historical verifier graph or INSTALL test-module import is planned. The new
consumer may reuse direct-write safe primitives and canonical JSON helpers;
its boundary validation is independently owned against fresh pins. The leaf may
reuse safe direct-write reader primitives, never its frozen `_boundary` contract.
No provider implementation is imported by this prospective mocked API graph.

The closure is prospective until actual code/imports exist. After explicit
release, submit all actual direct/transitive imports, fixtures and reference
inputs for coordinator review before registration/scheduling. Any new provider,
fixture or schema dependency requires closure revision. `needs: []` proposes
only the new focused mocked checks, not reruns of old stages. Pipeline runner
and requirements lock remain automatic inputs. Preserve every original result;
never copy/reset cache or retry an unchanged failed/interrupted fingerprint.

After coordinator scheduling and a reviewed passing batch, retain actual results,
commit only exact batch-owned paths with `git commit -S`, verify signature/state
and hand off hash/paths/results/remaining gates. This planning update is a
separately authorized docs-only signed commit of these two planning files;
`.lavish` assets remain local and unchanged.

Original helper PASS:
`sha256:0d3692546c31cc2733070f93f85a83a7ee6cd13b45f1d93b8974b53c6cd105c2`.
Original INSTALL leaf PASS:
`sha256:62afde843001570524bafaed58dfcfab678f3a2dd1ac9e61712e7ff0a8217882`.
These are retained results, not new checks or claimed reuse for new behavior.
The October 9 fixture-cleanup hold remains unresolved.

1. Shared startup/capture/listener integration: unresolved.
2. Admission and RUN/measurement implementation: current work; restart release held.
3. Independent verifier inventory, then freeze: pending.
4. Final acceptance: blocked until prerequisites close.
