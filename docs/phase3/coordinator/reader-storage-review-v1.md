# Reader storage provider review and selected check

Contract: `reader-storage-provider-contract-v1.md`, published in signed checkpoint
`22c05de348c1585ab9bdf17bf8cc1ba119c7f53d`. Root owns the three additive paths.
Two read-only source reviews completed before registration. Both confirmed fixed
root-only custody, exclusive permanent claims keyed independently of connection
epoch, immutable evidence, write/fsync/readback ordering, failure residue and no
usable reader on retention or cleanup failure. Existing sources remain unchanged.

Stable new SHA-256 inputs:

```text
24dbd8cdba584a55e7a787952dfa5a12d96c8b040973537c569dd52f582aba98  src/aragorn/native_phase3_run_reader_store.py
66cce03e029441d01bd7de72f67da0bd927259a292be28e3e5555a0b0a353fe1  src/aragorn/native_phase3_run_reader_acquisition.py
c29a46af5085495af54f1edd85e694bcafdb2e857e2522d657a23a7451348b43  tests/test_native_phase3_run_reader_store.py
```

Root inspected actual AST imports for all twelve repository files. The registered
closure is the three above plus `src/aragorn/` files `__init__.py`,
`native_phase3_run_reader_response.py`, `native_phase3_run_acquisition.py`,
`native_phase3_clock_domain.py`, `runtime_process_profile.py`,
`runtime_action_broker.py`, `runtime_action_observation_publisher.py`,
`runtime_action_decision.py` and `oci_worker_protocol.py`. Other imports are stdlib.
There are no generated sources, external fixtures, historical test imports or
undeclared read paths. The pipeline retains their actual hashes and its own
runner/lock/interpreter/environment binding with the result.

The 16 new methods cover durable callback ordering, claim duplicates across
connection epochs, partial/corrupt/existing targets, partial writes and sync
failures, permanent evidence residue, named/held directory and file replacement,
symlink/hardlink/owner/mode/size/readback, bounds and one-shot failures,
fork/thread/closed reuse, cleanup ambiguity, fresh issuance and independent epoch
pin, real frozen leaf refusal/retention wiring, failure evidence and withholding
the reader on cleanup failure. Syscalls use an in-memory filesystem, fabricated
epoch and mocked borrowed connection. Successful leaf callbacks are mocked; two
cases invoke the existing leaf only through a deliberate peer refusal. No real
protected directory, socket, process observation or Linux ACK is exercised.

Root schedules only this new stage in the coordinator worktree:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-phase3-run-reader-store
```

Registry: `needs: []`, timeout 120s, exactly one new test module. Inspect existing
stage state first, retain its actual result/fingerprint and diagnose any failure
before a changed-input/environment retry. Do not rerun HTTP staging, composition
or frozen reader checks. Source-review fixes were made before this first execution:
withhold the result until cleanup completes, recheck directory custody around
readback, and use distinct challenge-bound evidence in two mocked acquisitions.

This is a durable provider and owning caller. Actual accepted transport,
root-directory provisioning, real telemetry read-loop checkpoint, loss/program/map
acquisition, deployment identities and broker wiring remain open. No claim of
sensor health, acquisition authenticity, effect authority or qualification follows.
