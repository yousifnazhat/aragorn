# Retained acquisition projection — reviewed and focused checks passed

Base: verified signed `371cea7318f0e1326539de0e0e3ac8bdbec9cc4e`.
Branch: `codex/phase3-run-health`. Local inert contract and ownership were agreed
by coordinator task `01a12dd9-a3af-7a10-9a3e-66b049477354` before implementation.
See ACQUISITION_RECORD_PROPOSAL.md for the exact agreed record shape and bounds.

## Lane delta and review

- `native_phase3_run_acquisition.py`: pure bounded canonical raw-record projection
  to the existing progress window. Exact caller pins and nested joins, readbacks,
  sender/clock chronology, per-series loss and conservative submission state.
- `native_phase3_run_acquisition_verify.py`: independently parses and reconstructs
  raw joins, compares exact projected bytes, then calls existing verify_progress.
  It imports no acquisition producer, its helpers or the progress producer.
- `test_native_phase3_run_acquisition.py`: ten focused inert test methods, with
  independently specified expected windows; no existing fixture imports or I/O
  except source inspection of the consumer's declared import boundary.
- Two new lane docs retain the agreed contract, closure and batch status.
- Coordinator authored the single new registry row and explicitly authorized
  including it with these five lane-owned paths in this six-path signed batch.
  The lane made no shared registry edits; historical stage rows are unchanged.

No pre-existing callers are changed. Existing progress producer/verifier, their
three successful checks, shared runtime/staging and formal schemas are unchanged.
Review covers canonical/size/count/type boundaries, every nested binding including
partial inputs, exact BEFORE_FIRST_EFFECT, sender and epoch discontinuities,
chronology, loss-reset masking, overflow and submission truth table. Missing
submission refuses because no checked_ns exists. A refusal conveys no effect
verdict; integration must keep possible submitted effects INDETERMINATE.

## Exact coordinator-registered stage and closure

```json
{
  "id": "native-run-acquisition-records",
  "description": "Only inert retained acquisition projection and independent raw joins; no live custody or enforcement",
  "tests": ["test_native_phase3_run_acquisition"],
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_run_acquisition.py",
    "src/aragorn/native_phase3_run_acquisition_verify.py",
    "src/aragorn/native_phase3_run_progress.py",
    "src/aragorn/native_phase3_run_progress_verify.py",
    "tests/test_native_phase3_run_acquisition.py"
  ],
  "needs": [],
  "timeout_seconds": 30
}
```

Standard-library closure: hashlib, json, re, ast, copy, inspect, unittest and their
interpreter-owned transitive modules. No third-party dependencies, shared fixture
imports, scripts, services or external commands. Runner also binds its own code,
requirements-worker.lock, interpreter/toolchain and controlled environment.
Coordinator reviewed the stable source, all ten methods and complete closure,
registered the single stage, verified the registry, then explicitly scheduled
one execution in this original RUN worktree. No test was invoked directly or
through an unregistered stage; the coordinator did not duplicate this run.

Selected command executed once after coordinator scheduling:
`/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-run-acquisition-records`

Existing progress PASS remains fingerprint
`sha256:1ebdd044c7dd535f86f7fba19322a03a6254e96a8aa81adac0ca153eeb5a7226`.
Its closure is unchanged; no rerun or copied cache. New acquisition stage PASS:
10 test methods, 0.023 seconds reported by unittest; retained stage interval
0.305634 seconds; exit code 0. Pre/post fingerprints both:
`sha256:c135daacf0473b0d2e80cc6f6ebc4671c429a2a3681c3e51433db46abe057ead`.
Evidence directory:
`.aragorn/phase3-pipeline/native-run-acquisition-records/c135daacf0473b0d2e80cc6f6ebc4671c429a2a3681c3e51433db46abe057ead/`.
Retained stderr.log: 1713 bytes,
`sha256:b57b80e6b02f1fa410626b82995e7b17516db004b644cce0d5d9594ff3d915c8`.
stdout.log is empty. No failed or interrupted attempt occurred in this batch,
and no historical result was removed. Reuse this exact success while its closure
is unchanged. Any future failure remains retained, never automatically retried.

## Out-of-scope interfaces and gaps

Coordinator must provide actual reader checkpoint acknowledgements and bounded
protected transport; monitor-held process/peer/clock/program/map readbacks; scoped
loss acquisition with unknown values retained; and serialized broker intent/state
records with one-use challenges. This slice checks retained consistency, not those
acquisition sources' authenticity, applicability or custody. Pinning fabricated
records does not make them live evidence. No new acquisition-custody consumer or
complete sensor-health/attribution proof is claimed.

The BEFORE_FIRST_EFFECT binding does not authorize post-connect HTTP continuation.
That requires separate policy/consumer design and coordinator integration. This
consumer always preserves the existing progress verdict's INDETERMINATE after
submission. It does not establish pre-effect blocking, rollback, response
completion, sensor health or RUN qualification. All claim flags remain false.

## Batch checkpoint and remaining Phase 3 steps

Complete: coordinator contract/source/closure review, registration/scheduling and
the first focused run. Commit exactly the five lane files plus coordinator-authored
registry row with git commit -S; verify signature and inspect working-tree state.
The post-commit report supplies the hash, avoiding a self-referential checkpoint.
Further implementation waits for the next combined checkpoint. No capture, VM,
service, private-evidence or cleanup operation ran. Cleanup approval remains
unresolved; all historical evidence remains untouched. Leave this commit local.

1. Resolve shared runtime integration and retained-evidence/cleanup hold; HTTP94
   credential/import/startup/listener work remains coordinator-owned.
2. Complete admission, RUN event/response/attribution and workload implementation;
   this lane adds retained-record consistency only, not a live sensor reader.
3. Complete independent verifier inventory and same-deployment custody, then freeze.
4. Final same-deployment 31-case and 100-attempt/100-pair acceptance/replay/cleanup
   remains blocked; no qualification flag changes.
