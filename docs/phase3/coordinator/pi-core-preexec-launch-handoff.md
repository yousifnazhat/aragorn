# D2 protected pre-execution launch handoff

Source-only implementation for the additive Node-observed launch path. This lane
ran no tests, imports, compiler, gate, Node worker, ptrace, service, VM or Git
operation. The coordinator owns review, focused pipeline execution and release.
No D2 or Phase 3 exit is claimed.

## Reuse and changed interfaces

The existing confined configuration, held admission plan, installed runtime
inventory, native unit/PIDFD custody, bootstrap exchange and owned cleanup remain
the only launch path. Optional `source_observation` and
`source_observation_digest` fields select configuration schema v3. Omission
retains the legacy command/configuration pin and provider-unavailable default.

The profile is `aragorn/pi-core-node-source-profile/v1`, with exact `pins`,
`sources`, `required_sources` and `loader_files`. Its six pins bind gate, Node,
producer, Node observer, source inventory and loader inventory. Source inventory
and loader inventory include installed file identities and must be prepared from
the actual protected installation; this batch does not invent those values.
Required source consumption is distinct from the broader allowed source/load
inventory. Canonical absolute inventory paths are data, not argv: scoped npm
package names and normal spaces are supported, while control bytes, empty/dot
segments and overlong paths refuse. Runtime/deployment identity comes from the held plan, avoiding a
self-referential configuration/deployment pin. The snapshot is copied before
admission and checked again before arming.

The additive command is the fixed protected `observer/source-gate`, followed by
the same Node and entrypoint paths. The gate recreates exactly the prior
credential-free `HOME=/nonexistent` and runtime-only `PATH`. No task, model,
provider key or endpoint enters argv/environment. Authenticated START and the
existing held request configuration still provide IPC information.

## Gate artifact, not an implicit build

`packaging/pi-core/source-gate.c` is a freestanding arm64 gate: validate fixed
argv; unshare/close every inherited descriptor >=3; stop the same process before
Node; execute exactly the fixed Node/entrypoint once with the fixed environment.
No libc, dynamic loader, source reading, fallback or retry is part of the gate.
This is source, not a built or measured executable.

The existing Linux builder can optionally ingest an externally built gate using
`--source-gate`, `--source-gate-receipt` and an independently approved
`--source-gate-receipt-digest`. All three are required together. Receipt schema
`aragorn/pi-core-source-gate-build/v1` pins target `linux-arm64-static`, exact
source and ELF bytes, compiler identity and build-command identity, and records
`runtime_executed: false`. Canonical receipt bytes must match the external pin.
The ingested binary must be ELF64 arm64 ET_EXEC with no interpreter/dynamic
segment, valid load bounds, no writable/executable load and a file-backed
executable entrypoint. It is included in the existing deployment inventory and
rechecked after existing TypeScript assembly. No new generic builder is added.

A matching receipt is not independent proof of source-to-binary reproduction.
Reviewed compiler/build provenance and exact artifact construction remain a
prerequisite. Missing, malformed or substituted gate artifact/provenance refuses
the observed plan; it never silently falls back to direct Node.

ABI sources consulted: [Linux arm64 generic syscall numbers](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/asm-generic/unistd.h)
and [close_range semantics](https://man7.org/linux/man-pages/man2/close_range.2.html).
No target syscall was executed.

## Tracer and cleanup custody

After the existing native supervisor captures the exact new unit/PIDFD, but
before accepting HELLO, it calls the dedicated-owner factory:

```python
start_node_observer(owned, profile,
    operation_deadline=original_operation_deadline,
    cleanup_deadline=original_deadline)
```

Only the exact `PiSourceObserver` façade for the same `owned` object is retained.
Arming failure retains that façade through the exception's `observer` attribute.
The request-channel object is not replaced: the coordinator's native-custody
change uses `owned.source_observer` without breaking service custody identity.

Observed workers explicitly use `KillSignal=SIGKILL`, independently read back as
the exact numeric service property. This disposable-worker-only policy makes the
first owned stop immediate; an ordinary ptrace stop cannot consume the entire
five-second reserve waiting for SIGTERM escalation, and no held effect is resumed
to deliver a termination signal. Legacy plans keep their previous semantics.
Cleanup announces `begin_owned_stop(deadline)` before the sole owned systemd stop,
then `shutdown_after_owned_stop(deadline)` drains captured task exits before the
supervisor waits for PIDFD death/unit absence. The tracer must join and close its
owned handles before that method returns. On failure, `CLEANUP_HOLD` preserves
native handles and resources; no automatic stop/effect retry or deadline extension
is introduced. Gate-release syscall pairing is owned by the Node observer, not
inferred by native launch. Captures retain a source-acquisition-only authority
label, not a V8-execution or qualification claim.

## New focused checks and coordinator closure

`tests/test_pi_core_preexec_launch.py` has **46 new test methods**. They cover
profile/configuration pins, role separation, protected gate inventory/provenance,
ELF-input rejection, existing builder ingestion, capture/arm/HELLO ordering,
failed observer retention, exact immediate-stop readback, cleanup ordering,
original budgets and handle holds.
They reuse inert fixture setup from existing tests without collecting old test
classes. Authored ELF bytes only exercise parsing; they are never deployed.

Owned implementation closure:

- `src/aragorn/pi_core_confined_launch.py`
- `src/aragorn/pi_core_native_supervisor.py`
- `packaging/pi-core/source-gate.c`
- `scripts/build_pi_core_linux.py`
- `tests/test_pi_core_preexec_launch.py`

The focused module imports existing fixture helpers in
`tests/test_pi_core_confined_launch.py`, `tests/test_pi_core_native_supervisor.py`
and `tests/test_pi_core_linux_build.py`, plus actual observer/factory APIs from
`pi_core_source_observer.py` and `pi_core_node_source_observer.py`. Registry inputs must
include those and their actual transitive source imports. The coordinator's eight
new native-custody tests may share the reviewed stage. No broad suite, historical
recapture, real process or kernel trace is required for these authored checks.

## Remaining gates

1. Review and run only the affected/new pipeline stage after all lane interfaces
   are frozen. Exact success reuse remains coordinator-owned.
2. Produce/review the gate binary and prepare the exact installed source/loader
   identity profile; complete raw evidence/collector custody. The existing
   service-role documents do not define the caller-held worker launch config.
3. Prove actual Node loading, thread stops, health progress and cleanup on the
   exact separately authorized disposable deployment. Source acquisition is not
   arbitrary in-memory JavaScript execution proof; timing remains unmeasured.
4. Finish protected provider/recovery/pilot, D3 coverage, D4 inventory/freeze and
   separately authorized D5 fresh qualification. This offline batch closes none
   of those execution gates.

Coordinator validation is now recorded in
[batch 18](pi-core-preexec-node-batch-18.md): all 54 distinct launch/custody cases
passed, with only the two diagnosed fixture-exception errors repeated.
