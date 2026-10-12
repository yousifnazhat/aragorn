# RUN reader-progress slice — reviewed and focused-check passed

Base: `eb13d0d3eb0d7c29e613c25570cd47fafe6baffb`.
Lane: `codex/phase3-run-health`. Date: 2026-10-11.

## Scope and review

This is the smallest missing meaningful-health boundary: a pure finite decision
over one closed reader-challenge window and an independent retained-input
consumer. The existing watchdog explicitly limits itself to accepted-health
wall-clock expiry, and the existing loss parser explicitly disclaims reader
progress. Neither implementation is copied or changed. There are no existing
callers of the new functions, no exports/configuration changes, no new dependency,
and no deployment integration. Existing runtime/staging files remain unchanged;
the coordinator added only this leaf's pipeline registration.

`evaluate_progress(raw, expected_epoch=..., expected_challenge=...)` consumes at
most 4096 canonical JSON bytes. The window schema and exact fields are defined in
the implementation. Times use integer CLOCK_BOOTTIME nanoseconds; the deadline
is exclusive and freshness expires at age >= max_age_ns. Missing acknowledgement
or unchanged reader sequence reports no progress, a decreasing sequence reports
a reset, and late acknowledgement and stale progress are separate failures.
Missing loss counters are unknown, decreases are reset, and increases are loss.
A stable nonzero baseline is retained, not rewritten to zero; this only concerns
the selected window and says nothing about earlier delivery completeness.

Every health failure yields HOLD_UNSUBMITTED only when input explicitly says
NOT_SUBMITTED. SUBMITTED and UNKNOWN always yield INDETERMINATE, including when
all progress checks are clear. No result proves blocking, suspension, absence of
residue, delivery completeness or meaningful sensor health. A clear window yields
CONTINUE_OTHER_GATES, never authorization. Malformed inputs raise ValueError;
the integrating caller must fail closed and preserve any submitted ambiguity.

`verify_progress` independently parses pinned raw bytes, validates caller-held
epoch/challenge/digest pins and reconstructs reasons and disposition. It imports
no producer, collector or response implementation, and rejects changed claim
ceilings. Checks use manually specified expected decisions for both paths.
These are development semantics, not a new authoritative campaign schema.

Static review covered exact shape/canonical bytes, strict integer types, bounds,
epoch/challenge/clock binding, missing/reset/loss data, exclusive time boundaries,
all three submission states, independent consumer imports and false claim flags.
All three new focused test methods passed once after coordinator registration.
This completes the checked inert leaf, not deployed sensor-health enforcement.

## Registered pipeline stage (coordinator-reviewed)

```json
{
  "id": "native-run-reader-progress",
  "description": "Only inert closed reader-challenge window decisions and independent replay; no acquisition, enforcement or qualification.",
  "tests": ["test_native_phase3_run_progress"],
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_run_progress.py",
    "src/aragorn/native_phase3_run_progress_verify.py",
    "tests/test_native_phase3_run_progress.py"
  ],
  "needs": [],
  "timeout_seconds": 30
}
```

Import closure: the four files above plus standard-library hashlib, json, re and
unittest; no fixture files, external commands, services or third-party packages.
The runner binds its own code/toolchain/settings. Coordinator reviewed the exact
closure and confirmed that this leaf needs no historical scheduling prerequisites.
No existing success covered these new behavioral inputs; the first run passed.
No historical result or cache record was copied, altered or rerun.

Executed once after registration and explicit coordinator scheduling:
`/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-run-reader-progress`
(Positional stage selector confirmed by reading the current runner.)

Three test methods cover 36 outcome/state combinations, malformed/unbound input
rejection in both paths, and consumer-forgery/pin rejection. Result: **PASS**, 3
tests, with matching fingerprint and post-fingerprint:
`sha256:1ebdd044c7dd535f86f7fba19322a03a6254e96a8aa81adac0ca153eeb5a7226`.
Retained evidence directory:
`.aragorn/phase3-pipeline/native-run-reader-progress/1ebdd044c7dd535f86f7fba19322a03a6254e96a8aa81adac0ca153eeb5a7226/`.
Test log (`stderr.log`, 576 bytes) digest:
`sha256:2412dca2a600214f7df78a3c9d034ef5e0e93c3e572672d222f3182ff6d26362`.
No failures or prior evidence were removed. Reuse this exact result while its
closure is unchanged; do not run unittest directly or broaden suites.

## Concrete coordinator integration requirements — not changed here

- Shared sensor reader/staging: acquire acknowledgements from the actual read loop,
  including idle polls; an independent timer heartbeat is insufficient. Bind each
  fresh unpredictable challenge to a protected epoch containing boot, process start,
  deployed reader/config identities and counter scope. The expected pins must come
  from caller-held protected authority, never the submitted window itself.
- Shared broker/control boundary (`runtime_action_broker.py` and successors): hold
  the existing serialization boundary while reading protected window/submission
  state and checking immediately before submission. Bind max_age/deadline policy;
  reject stale/replayed challenges. Do not infer NOT_SUBMITTED from a missing receipt.
  This leaf has no persisted replay state and its clear result cannot be cached as
  ongoing health. Any acquisition/parse/interruption after submission stays ambiguous.
- Sensor loss acquisition (`runtime_tetragon_loss.py` reuse): prove applicability,
  stable counter inventory and producer continuity before projecting a counter into
  this leaf. Missing families or unsupported metrics must remain null/unknown;
  do not turn the parser's zero selected deltas into complete sensor-health proof.
- Response/watchdog composition (`runtime_health_watchdog.py`,
  `runtime_response_service.py` and finite successors): use protected pending latch
  and retained termination/mask evidence for actual suspension. A gate disposition
  is not response completion. Retain INDETERMINATE across in-flight response failure.
- Coordinator registered and ran the leaf through
  `benchmark/phase3-pipeline-v1.json`; the runner itself is unchanged.
  Shared staging/source pins and qualification consumers remain unchanged.
  Future integration changes require their own focused checks and full closure.

## Remaining lane scope

RUN-01 causal attribution and blocking of unattributed attempts remain open.
RUN-02 now has this checked inert finite health sub-boundary only; actual acquisition,
revocation/pre-effect enforcement and integrated response evidence remain open.
No coverage is claimed for the seven event classes: skill activation/completion;
tool attempt/result; process/ancestry; file operations; network/DNS;
credential/canary access; exposed prompt/context/memory mutation.
No new completion is claimed for the six responses: alert/retain; pre-effect block;
terminate process tree; quarantine digest; revoke future starts; isolate egress or
suspend high-risk operations. Existing implementations need same-deployment
independent consumer coverage; no historical check is silently promoted here.

## Checkpoint and four-step roadmap

- Tests run: three new methods, once each; all passed. Historical stages run: zero.
  No test result was promoted to deployment or RUN qualification.
- Signed batch scope: the two source files, test, coordinator registration and
  this checkpoint. The containing commit's verified hash and working-tree state
  are recorded in the coordinator's post-commit checkpoint. Leave it local for
  source integration; do not restart the checked leaf to populate another cache.
- October 9 capture digest remains
  `sha256:f9ec835d0c1bbc3418961cb617d9b8391d87bcdc03bc2c112165bbd716a9990e`.
  No evidence copied; no live state inspected or modified. Cleanup approval remains
  unresolved. All qualification flags stay false.

1. Integration/cleanup hold unresolved; HTTP94 repair belongs to coordinator.
2. This lane: finite reader-progress implementation and consumer checked; source
   integration pending. Remaining RUN/event/response/attribution is not complete.
3. Combined verifier inventory and deployment freeze pending.
4. Final acceptance blocked; no capture or acceptance campaign authorized here.
