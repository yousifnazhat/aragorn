# Fixed native upload-disabled INSTALL leaf

Base: signed combined checkpoint
`371cea7318f0e1326539de0e0e3ac8bdbec9cc4e`, fast-forwarded in the admission
worktree with both source/test drafts preserved byte-for-byte.

## Implementation and boundaries

`scripts/runtime_native_admission_install.py` wraps the existing
`record_native_admission_install` and independently replays its completed record.
It does not modify the recorder, its schema, the catalog command implementation,
frozen predecessors or shared orchestration.

The native caller must already have entered the owned gateway mount namespace
and dropped to UID/GID/groups 992. The leaf requires Linux, matching real/effective/
saved identities, no capabilities, NoNewPrivs, the exact owned container cgroup,
fixed installed source locations and the fixture token. A held PIDFD and repeated
native gateway observations bind PID/start time, mount namespace, cgroup and
privileges before/after boundary reads and command execution. There is no numeric
PID fallback after liveness/identity failure. Four caller-pinned root-owned 0444
source files are read using the existing protected no-follow reader conventions
before each command and after recording.

The separate runner allows only the four existing catalog argv values and the
fixed non-force upload INSTALL argv. Catalog commands require exit 0; the upload
denial requires exit 1. The existing catalog runner is unchanged. Each child uses
a new session, explicit environment and closed stdin. Both pipes have separate
128 KiB caps, with at most one extra retained byte for overflow detection. A
15-second monotonic deadline covers pipe collection and leader exit. Raw token
echo or nonempty stderr refuses; partial failure reports contain byte counts and
digests, not diagnostic streams.

The leaf requires default SIGCHLD handling. WNOWAIT observes child exit without
reaping the owned leader. Its process group is killed before the leader is reaped,
including successful commands, so descendants retaining the group are cleaned
up. Failure paths still attempt group cleanup, bounded five-second reaping and
both pipe closes. Lost child custody refuses without signaling a potentially
reused PID. This is process-group cleanup, not proof against descendants escaping
the group or a substitute for outer fixture cleanup.

The outer leaf envelope retains source observations, gateway identity, the
recorder's complete/partial observation, command failure metadata and cleanup
failures. Interruptions preserve the envelope on `_native_install_leaf`; the CLI
emits it and returns 130. Other refusals return 126. A complete bounded observation
returns 0, with every qualification flag still false. Cleanup failure cannot be
reported as success. Only the inner observation is consumed by the existing
INSTALL verifier; the outer source/liveness envelope is not independent host
attestation.

The CLI temporarily converts SIGTERM to an interruption around the full probe
and restores the previous handler on exit. Its mocked cancellation check runs
through command-group cleanup, recorder post-readbacks and partial JSON output.
Default SIGCHLD handling remains required for child custody.

## Focused stage proposal and scheduling

The exact proposed registry row is [install-leaf-stage.json](install-leaf-stage.json).
Only `test_native_admission_install_leaf` is selected. Its nine repository inputs
include both reused test fixtures and their native reader import; all other
imports are standard library. Runner and requirements lock are automatically
bound by the existing pipeline. The proposed `needs: []` avoids executing old
test stages merely because this test imports their inert fixture builders.

Before edits, the old recorder stage was checked with `status`, yielding
`SKIP_PASS` at
`sha256:0d3692546c31cc2733070f93f85a83a7ee6cd13b45f1d93b8974b53c6cd105c2`.
No cache record was copied or changed. Coordinator review required a SIGTERM
retention fix before scheduling; that change and its mocked cancellation check
were reviewed before any execution. The coordinator then registered only the
proposed row, verified the nine-input closure and scheduled one invocation.

Actual result: **PASS, 17 tests, first execution**. Only the new selected stage
ran; no unchanged stage or previous failure was rerun.

- Command: `/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-admission-install-leaf`
- Fingerprint and post-fingerprint: `sha256:62afde843001570524bafaed58dfcfab678f3a2dd1ac9e61712e7ff0a8217882`
- Retained result: `.aragorn/phase3-pipeline/native-admission-install-leaf/62afde843001570524bafaed58dfcfab678f3a2dd1ac9e61712e7ff0a8217882/result.json`
- Test log: 3,120 bytes; `sha256:fbc5b25d3353a70b3e43efb23bc13a09ec137cdf8d988a4f02d61ffff3a75b14`
- Test runner reports 17 methods in 0.021 seconds; this is not native latency or
  an acceptance performance result.

The mocked checks cover exit-code separation, fixed argv, dropped privilege and
source custody, gateway liveness/identity/mount mismatch, capped stdout/stderr,
deadline before/after EOF, group cleanup before reaping, child-custody loss,
cleanup failure, secret redaction, recording/replay composition and interrupted
partial retention. All subprocess, process signal, PIDFD and native reader
operations are mocked. No test authorizes a live operation.

## Integration handoff

Coordinator-owned work remains: bind the new script and verifier pins into the common dispatcher, deployed source
inventories and staging; supply the verified namespace/privilege-dropping launch;
compose outer capture, private retention and exact fixture cleanup. No live
launch, VM operation, service activation or historical replay is requested here.
The recorded October 9 cleanup/evidence hold is unchanged.

The reviewed batch contains exactly five paths: the new script, its new test,
this handoff, `install-leaf-stage.json`, and the coordinator-authored row in
`benchmark/phase3-pipeline-v1.json`. It is signed once after the focused PASS;
the verified commit hash is handed to the coordinator separately to avoid a
self-referential hash in this checkpoint. Further admission implementation is
held until the next combined checkpoint. No shared-dispatch, staging, installed
source-inventory or outer capture/cleanup change is included.

1. Shared startup/capture/listener integration: unresolved.
2. Admission and RUN/measurement implementation: current work.
3. Independent verifier inventory, then freeze: pending.
4. Final acceptance: blocked until prerequisites close.
