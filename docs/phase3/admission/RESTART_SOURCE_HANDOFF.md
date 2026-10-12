# Native RESTART source handoff — focused mocked PASS

Base: `55a87ea1f7ab3924ade5fa629935ffc03962ba05` on
`codex/phase3-admission`. The coordinator subsequently approved source and the
nine-input closure, supplied signed registry-only parent
`d0e62576c1b6a32aead7af4b673364cfb7a95017`, and scheduled one focused mocked run.
That run passed; its actual retained result is recorded below. No live operation
or cleanup was performed. Existing historical modules, planning files and
`.lavish` assets are unchanged. The October 9 fixture-cleanup hold remains unresolved.

## Stable lane files for coordinator review

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `scripts/runtime_native_admission_restart.py` | 17355 | `3ffb57e072c265aa13475753717b7c5a71a19cf776940a5b772422109d6a83f4` |
| `src/aragorn/native_phase3_admission_restart.py` | 23485 | `8d3dff5f362e634db9086c3e0072d2be9d5c5aa1b77737ce765586c5ea244e00` |
| `tests/test_native_admission_restart.py` | 17212 | `d091756cc8a5b72bd952c2885e2c00f1f76f710a378d6600f91487e556cd0335` |
| `tests/test_native_phase3_admission_restart.py` | 15135 | `487ad18fcf52151623afd1096297a0287a13050ea4d6b332d9bb848e66ef63a3` |

The other two new lane files are this handoff and `restart-source-stage.json`.
The latter is a proposed focused row, not registration or scheduling authority.
All six files form the authorized lane-owned signed batch after the reviewed
focused pass. Its resulting commit hash and signature verification are reported
separately to avoid a self-referential commit claim. The registry stays in its
coordinator-owned signed parent.

## Implemented finite interfaces

Producer:

```python
run_restart_probe(*, expected_bindings, read_native_restart_lifecycle) -> dict
```

Consumer:

```python
verify_native_admission_restart(
    raw: bytes, *, expected_raw_digest: str, expected_bindings: dict,
) -> dict
```

The producer is a callable-only leaf; it has no CLI to choose a provider, no
listener, daemon, launch/staging helper or live-operation fallback. It freezes
bindings before acquisition, checks native nonroot/dropped privileges and fixed
module locations, holds one gateway PIDFD, and checks gateway process identity,
mount/PID/user/time namespaces and actual daemon `OPENCLAW_NO_RESPAWN=1,TZ=UTC`.
The caller owns the process environment, private credential and protected launch.

`expected_bindings` has exactly these independently held values:

- `container`, `gateway` (PID/start/cgroup/mount/UID/GID/CapEff/NoNewPrivs),
  and `namespaces` (`mnt`, `pid`, `user`, `time`).
- Fresh `capture_nonce`, `context_digest`, `runtime_inventory_digest`.
- Fresh `config_digest`, `entry_digest`, `admitted_digest`.
- `source_pins`, exactly the six installed Python paths in consumer `SOURCE_PATHS`.

These are not extracted from returned evidence. The coordinator must resolve
`context_digest` through its protected inventory to boot/unit/InvocationID,
process/namespaces/privileges, fixed lifecycle inode/path, source/runtime/config
and nonce, and bind it to these same caller values. Matching digest strings alone
do not prove the resolution or installed full-tree custody. The opaque runtime
inventory digest is an external custody reference, not a locally measured tree.
The same independent bindings and retained-byte pin go to the consumer.

The new validator owns its fresh-pin boundary. It reuses safe no-follow file,
tree, procfs and catalog primitives; it never calls historical `_boundary` or
`validate_boundary`, rewrites historical boundary records, or changes CONFIG_PIN.
Metadata readback hashes admitted bytes during acquisition; it does not retain
those bytes or prove uninterrupted inode custody. Source files must be root-owned
0444; admitted/config/entry and the six discovery roots must be read-only.

INITIAL must contain unique readiness before any command. Positive catalogs and
exact invalid-token control complete before BOUNDARY. The final cursor freezes
immediately before dispatch, followed by custody/source rechecks. The single
safe restart has the exact confirmed stderr response. AFTER uses the original
20-second-from-dispatch deadline and chains the accepted snapshot digest/cursor.
The provider owns its bounded observation loop, file descriptors, prefix reread,
phase/nonce ledger and supervision; the leaf does not poll/retry an effect.

Each returned envelope and raw prefix is retained, bounded and independently
parsed. Actual local call intervals bracket the provider's acquisition interval.
The consumer checks canonical envelope/base64, context/file identity, phase chain,
unchanged prefixes, offsets/lengths/digests, ordered native markers and exact
presence-aware traces. It preserves unknown native metadata in original bytes
without inventing an external-tslog schema or authenticated kernel emitter.
Fresh post-ready clients, exact denial controls, protected state and raw/full
catalog equality are required. Nonadmitted gateway entries need explicit false
activation flags; native list names must join the gateway inventory. Gateway PID
stays the same; command clients are separate captured processes.

Commands use fixed argv/env/cwd, nonblocking capped stdout/stderr, a 15-second
execution deadline, WNOWAIT ownership, process-group kill before bounded 5-second
reap and both pipe closes. Custody is checked again before signaling, including
failure paths; lost child custody never triggers a numeric-PID fallback. Denial
controls remove the real token environment and preserve exit-1 exact bytes;
catalog and restart exit-0/output channels remain distinct.

## Failures, clocks and claim limits

Complete command-channel bytes up to each 128 KiB cap remain in the returned
private observation, including rejected schema/exit results. On command timeout,
overflow or interruption, the exception carries `_native_restart_command`; the
leaf retains that bounded partial row. It never retries the restart or repairs
state. REFUSED does not mean a scheduled restart had no effect or was rolled back.

A provider may expose `partial_bytes: bytes` on a raised exception. The leaf
retains at most 1500000 of those bytes with a truncation label in `partial`, never
in the accepted snapshot chain. Unsupported/missing partial bytes cannot be
invented: coordinator transport/supervisor must retain any inaccessible original
IPC fragments independently. Returned malformed/late snapshots are retained before
refusal. Cancellation/EOF/oversize/provider errors preserve the first failure;
SIGTERM/interrupt carry `_native_restart_leaf` after cleanup for outer retention.
Ordinary provider exceptions, including the public NativeRestartError class,
are wrapped as `LIFECYCLE_PROVIDER_FAILED` with the original exception chained
as the cause; arbitrary provider exception text never becomes the retained reason.
BaseException interruptions remain unchanged and carry the retained leaf result.

The leaf installs/restores a SIGTERM handler and must be called in the exclusively
owned main thread with default SIGCHLD disposition and no competing child reaper.
No in-process timeout can bound a stuck filesystem syscall or provider callback.
Actual provider/root supervision, durable partial retention and cancellation
uncertainty remain coordinator prerequisites for native use. Caller-returned
objects are not durable retention or public-safe publication; there is no automatic
stdout export, CAS write, credential redaction or private artifact publication.

The consumer applies the contract's exact REALTIME interval inequalities without
rounding command times or widening emitter precision. Each command clock sample
retains MONOTONIC-before/REALTIME/MONOTONIC-after. A common offset interval must fit
all samples to reject an observed discontinuity; this is a bracket consistency
check, not conversion of lifecycle time to MONOTONIC or a causal comparison across
domains. Undetected changes between samples remain possible: continuous clock
stability requires independent custody. As agreed, delayed CLI completion may
honestly refuse the strict restarting/completion/shutdown ordering.

Lifecycle log fields remain gateway-account runtime assertions, vulnerable to
same-account forgery. Protected reader custody and matching source/config pins
do not by themselves authenticate each emitter. OBSERVED and replay success are
bounded local joins only; every qualification flag remains false. No telemetry
health, active-session consumption, ADM-02 acceptance or production claim is made.

## Complete source/test/import closure

`restart-source-stage.json` lists exactly the nine repository inputs used by
the selected mocked behavior: both new modules, both new test modules, the old
direct-write reader/consumer/test fixture, package initializer and canonical helper. There are no external Python dependencies beyond the
standard library. Repository-local import edges are:

- New leaf -> new consumer, old direct-write reader, `aragorn/__init__.py`,
  `oci_worker_protocol.py`. Its installed fallback imports the same old reader
  from `/opt/aragorn`; it does not load another source implementation.
- New consumer -> old direct-write consumer and `oci_worker_protocol.py`.
- Old reader -> old direct-write consumer and `oci_worker_protocol.py`.
- Old consumer -> `oci_worker_protocol.py`; that module and package initializer
  have no further repository-local imports.
- New consumer tests -> new consumer, canonical helper and old direct-write test
  data helpers; the old test module imports the old reader/consumer/helper.
- New leaf tests -> new leaf and new consumer test fixture; all transitive imports
  are included above. No old test class/module is selected for execution.

There are no separate fixtures: all new records are explicitly inert inline
Python data. The historical restart verifier/probe and installed public-build
receipt, reviewed INSTALL runner, fixed gateway unit, coordinator contract,
ownership/release document and admission plan remain review evidence outside
the behavioral inputs: selected tests neither import nor read them. No historical
verifier dependency graph is invoked. The proposed row and this handoff are also
excluded from behavioral inputs so recording actual results does not invalidate
their own fingerprint. This removes ten reference-only inputs from the original
source proposal, as directed by coordinator closure review. The pipeline automatically
adds `scripts/phase3_pipeline.py` and `requirements-worker.lock` and fingerprints
its reviewed stage/environment/dependency definition.

Registered and explicitly scheduled stage: `native-admission-restart`, `needs: []`,
timeout 120 seconds, selecting only `test_native_phase3_admission_restart` and
`test_native_admission_restart`. Coordinator reviewed the nine input hashes and
confirmed no prior attempt before releasing this one run. Registry SHA-256:
`8d2fe37899a164c5ea6cc23194f397a18815758882dc3d5b069fca65c8697b75`.
No previous PASS is relabeled as covering this new behavior.

## Review performed and remaining handoff

Static Python AST/import and whitespace review preceded the one authorized run:

```text
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-admission-restart
```

Actual result: PASS, exit 0, 26 tests in 0.079 seconds. This was a new execution,
not cache reuse. Pre/post fingerprint both equal:
`sha256:70b1548feb59a4bd38673bb01cd9d52a78e26c31ebca95a1f5d47f7588b335b8`.

Retained original attempt directory in the admission worktree:
`.aragorn/phase3-pipeline/native-admission-restart/70b1548feb59a4bd38673bb01cd9d52a78e26c31ebca95a1f5d47f7588b335b8/`.

- `result.json`: SHA-256 `daba0933cc6c7127575d21c8313f9405d75ae4e83557f24d9c013a80fc31b8a9`.
- `stderr.log`: 4828 bytes, SHA-256 `1e53d2ec633b6cdf9e96681bb08f62b9af185b0fb1d14a46b8ca1e0da8f6c07a`.
- `stdout.log`: 0 bytes, SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

The pipeline's original preflight/started/result/log files remain in place; no
cache record is copied or altered. No other stage, historical suite, unchanged
retry, live operation or broader check ran. Existing passes and retained evidence
are untouched. The nine behavioral input bytes are unchanged after execution;
this result update affects only the excluded handoff. A mocked PASS verifies
these local joins/refusals, not actual provider custody or native deployment.

Coordinator still owns actual protected provider/transport, source/runtime/config
selection and inventories, private launch and credential context, independent
custody, supervision/retention, integration dispatch, registry/scheduling and cleanup.
No shared change is requested within this lane. The concrete integration tasks
above must close before a native attempt, separately from mocked source checking.

1. Shared startup/capture/listener integration: unresolved.
2. Admission and RUN/measurement implementation: current work; finite restart mocked batch passed.
3. Independent verifier inventory, then freeze: pending.
4. Final acceptance: blocked until prerequisites close.
