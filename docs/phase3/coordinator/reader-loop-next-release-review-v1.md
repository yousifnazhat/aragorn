# Reader-loop next release: reviewed seam and unresolved acquisition

Review base: signed/published `8ce7c8aa858f7b7b24e24bd8543e7ef7ce4406b5`.
This source review releases no new implementation path, check or live operation.
The current RUN listener assignment remains unchanged.

## Accepted narrow direction

Use a real bounded nonblocking pipe reader with a checkpoint of the actual
consuming loop. The historical reference
`benchmark/evidence/reference/tetragon-isolated-exec-exit-smoke-v1-2026-09-13.py.txt:94`
contains fixed `tetra getevents`, stdout/stderr selectors and 65536-byte reads.
It ran through Docker in a separate VM and is not current native stream custody.
Source search across native/common modules, staging/materialization scripts and
service files found no current native `tetra`/`getevents` launch integration.

`src/aragorn/runtime_tetragon_process.py:265` supplies the existing single-record
parser. A separately released public wrapper could reuse it under its exact
source pin. Do not call `normalize_process_capture` for an ongoing loop: that API
requires closed/quiescent capture and reported counters. Never manufacture EOF,
quiescence, events or zero loss to satisfy it.

Keep the broker contract's 16384-byte checkpoint artifact bound. A manifest can
pin separately retained raw batch bytes, exact LF-record/byte counts, contiguous
stream offsets, stream identity, prior checkpoint, sequence and BOOTTIME read /
publication brackets. Root's protected acquisition must independently verify the
actual raw readback before using that manifest. External replay receives those
same original bytes. The bounded authenticated wire envelope alone establishes
neither raw custody nor sensor health.

The independent checkpoint consumer must not import the producer or private
record parser. Its bounded claims are framing/count/digest/sequence consistency,
challenged loop progress and retained error/backlog/loss-reference joins. Full
vendor execution identity and parent-graph attribution remain separate semantics.

Candidate bounds are reads/records <=65536 bytes, batches <=262144 bytes and
256 records, session lifetime <=4 MiB/4096 records. These are proposed fail-closed
bounds, not measured campaign compatibility. Exhaustion, malformed input, EOF,
descriptor change, parser/delivery failure or unaccounted partial records poison
the stream; no silent discard, rotation, reset or automatic recovery is allowed.

Only the actual loop can ACK: receive challenge, perform a subsequent real read,
reach EAGAIN without partial/undelivered bytes, durably publish/read back its
checkpoint, then advance sequence and send the frozen response. Idle input yields
an empty checkpoint, not synthetic telemetry. A hung loop cannot ACK. Idle pipe
responsiveness cannot prove upstream subscription or sensor responsiveness.

## Decisions required before source release

1. Pin actual reader/bridge/sensor processes, accounts, installed source/builds,
   sole pipe writer, bridge socket-to-sensor join and reconnect/retry accounting.
   The candidate Tetragon source commit
   `1de2ed8ebea18e56257dc59597aa13bf8f0e471e` is not installed-binary evidence.
2. Freeze separate reader-owned raw storage and protected Root readback, proposed
   `/var/lib/aragorn-phase3-reader-events`, including batch counts, publication
   ordering and cancellation. Keep the existing root-only ReaderStore inaccessible.
3. Define fresh second-phase checkpoint acquisition while reusing the original ACK;
   never issue a second BEFORE_FIRST_EFFECT challenge after connect.
4. Bind the complete applicable loss inventory. `runtime_tetragon_loss.py:216`
   preserves unknown/reset/increased counters; sparse BPF data is not zero.
   `runtime_tetragon_stats_map.py:577` is non-atomic, and
   `runtime_tetragon_program_map.py:275` covers selected exit linkage. Upstream
   queues and ignored encoder-write errors still require explicit treatment.

All source anchors above are review evidence only. No implementation or test
stage is released until Root fixes these decisions, supplies exact paths and
publishes the contract. Root protocol/journal implementation and the existing
Admission/RUN/Workloads assignments continue independently.

## 13 October checkpoint update and next connected release

Provider v6 and `tetragon-stream-loss-decisions-v1.md` now decide the three-role
reader/bridge/sensor boundary, one physical dial/stream accounting and complete
loss scope. `reader-checkpoint-contract-v1.md` fixes raw storage, Root archive,
original-ACK-preserving phase-two direction and UNKNOWN loss ceiling. Actual
acquisition/archive plus independent byte replay are implemented and passed the
one reviewed 53-method stage, fingerprint
`sha256:091fd6c1739b55e7fae680a4612fd81bdb1d43e2007cf8ded86715855692c67e`.
Those implementation decisions supersede the corresponding proposals above;
actual bridge/sensor/source acquisition and the consuming loop remain absent.

The next release must connect the actual pipe-consuming writer and a Root session
owner in one bounded path: ReaderListener -> independent owned-reader evidence
replay -> checkpoint acquisition -> independent checkpoint replay, then one
protected refresh command and new checkpoint readback. Do not release another
standalone manifest builder or a synthetic responder. RUN's transport first needs
the two fixes in `reader-transport-source-review-v1.md` and reviewed signed delivery.

Proposed Root-owned paths, **not source-released yet**:

```text
src/aragorn/native_phase3_run_reader_checkpoint.py
src/aragorn/native_phase3_run_reader_checkpoint_session.py
tests/test_native_phase3_run_reader_checkpoint.py
tests/test_native_phase3_run_reader_checkpoint_session.py
```

Before release Root must publish the complete caller and descriptor contract:

1. Exact independently pinned loop/stream provisioning, reader/bridge/observer
   identities, inherited FD custody, fixed entrypoint and launch dependencies.
   No arbitrary path, command or truth callback substitutes for acquisition.
2. Define the predecessor pin as the previous manifest digest, available to both
   writer and Root; retain the separate Root acquisition pin. This is the selected
   direction for the future connected contract, not evidence of a current chain.
3. Define how the protected FD5 command first binds original evidence/summary/
   connection pins, which are absent from the frozen challenge. Root derives them
   from independent replay of its actual owned result. No new challenge/ACK.
4. Reserve a separately provisioned reader-to-Root completion pipe (proposed FD8)
   for one bounded atomic notice after receipt fsync/readback and closing custody.
   A manifest's appearance is too early. This signals availability only; Root
   invokes acquisition once and never retries a failed acquisition. Pin exact
   notice schema, both pipe ends, byte budget and original wait deadline.
5. Freeze FD7 cancellation/EOF, stderr retention/refusal and partial-record/read
   handling. Reserve a final real EAGAIN slot within 64 reads; no dropping tails,
   silent EOF/quiescence, reset, reconnect or new deadline after ambiguity.
6. Resolve record semantics explicitly: `runtime_tetragon_process.py:_event`
   supports only process_exec/process_exit and rejects other variants and loss
   notifications. A public wrapper cannot be relabeled all-event coverage. Any
   process-only stream restriction must be in the protected source/loss inventory;
   file/network/credential families need their actual complete paths. Preserve
   original bytes and keep vendor-record semantics independent from byte replay.

No additional worktree is requested for this not-yet-ready split. Root can reuse
available internal owners after the precise caller/loop contract is published.
The separate DNS acquisition split is ready and already requested at published
base `0b819f3e953aff0c879298d96d76c9d35e2f7590`; operator creation remains unconfirmed.

Remaining Phase 3 sequence: (1) complete protected providers, (2) wire all required
admission/RUN/action and paired-task paths, (3) close the 48-entry inventory and
freeze source/loaded identity, (4) separately release the final campaign, replay,
qualification evaluation and approved cleanup. Operational holds remain.

## Connected v8 source release

Original signed RUN transport `5193a2fcdd0cb4173ddeeaa7188aa74fd2c7b09f` is
integrated with its reviewed first 30-check PASS. The signed v8 checkpoint now
approves `reader-session-contract-v1.md` and releases the four previously reserved
writer/session source/test paths to two exact internal Root owners. Syntax-only
record preservation, FD7/FD8 custody, predecessor/refresh joins, the bounded
post-ACK peer-close wait and actual startup/completion retention are resolved.
No stage is scheduled until stable source and full closure review. Actual
launcher/service/source/upstream/loss integration remains a separate dependency.
External RUN retains the ready DNS assignment under v7; the previous additional
DNS worktree request is superseded. No extra worktree is currently requested.
