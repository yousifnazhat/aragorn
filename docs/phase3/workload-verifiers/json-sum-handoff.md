# JSON-sum paired-task leaf: reviewed and focused-check passed

2026-10-11. Branch `codex/phase3-workload-verifiers`, base
`eb13d0d3eb0d7c29e613c25570cd47fafe6baffb`.
Status: implementation and complete input closure reviewed; **six focused checks
passed once**. No paired sample, native capture or qualification result.

## Scope and interface

Smallest selected missing callback: `BENIGN_JSON_SUM`, reusing
`phase3_reference_tasks.execute_reference_task` and its exact fabricated input.
Lane-owned files, plus the coordinator-owned stage registration, are changed:

- `src/aragorn/native_phase3_workload_json_sum_contract.py`
- `src/aragorn/native_phase3_workload_json_sum.py`
- `src/aragorn/native_phase3_workload_json_sum_verify.py`
- `tests/test_native_phase3_workload_json_sum.py`
- this checkpoint/handoff.
- `benchmark/phase3-pipeline-v1.json` (only the new stage).

The producer exports top-level `execute(request, mark)` and the independent
consumer exports top-level `verify(receipt_bytes, request, boundaries)`, matching
the existing collector. There are no existing callers to update in this lane.
Request keys are exactly `kind`, `mode`, `pair_id`, `task_digest`, `input_digest`,
`host_profile_digest`, `collection_digest`, `deployment_digest`. Modes are the
collector's `baseline` and `instrumented`; kind must be `task`.

`task_digest` is the canonical digest of the existing JSON-sum descriptor from
`describe_tasks(actual_reference_task_source_bytes)`, matching the development
plan builder's convention. The producer reads bounded source bytes before the
interval and refuses task/input mismatches before marking or executing. It calls
`mark("TASK_ACCEPTED")`, executes the existing task once, then calls
`mark("TASK_COMPLETED")`. These are the existing collector's in-process Linux
CLOCK_BOOTTIME marks, with no fallback, conversion or fabricated duration.
The interval includes the reference task's validation and output digest work;
it excludes descriptor/source preparation and receipt serialization. This is a
benign local task boundary, never a native broker/effect interval.

The receipt uses the existing five-key local-measurement receipt envelope.
Observation retains the descriptor and complete reference-task result. The
verifier imports neither producer nor reference-task implementation; it checks
independent fixed expectations, canonical bytes, exact request/task/input/source
descriptor bindings and strict integer interval chronology. It returns only the
collector's `completed` semantic. Existing false eligibility flags remain false.
Shared validation covers syntax/chronology only, not the computed task result.

No file is written or removed by this task. Failed execution emits no successful
receipt and never retries; the collector's partial marks remain partial. This
leaf does not add missing general failure-retention/resume behavior to the
collector. No existing runtime callers, fixtures, exports, configuration or runtime
source were changed; only the new pipeline stage was registered. No dependency was added.

## Coordinator-reviewed registration and focused result

One stage, `native-workload-json-sum`, with test module
`test_native_phase3_workload_json_sum`, `needs: []`, `timeout_seconds: 120`.
Six focused test methods passed: successful call order and mode-bound
replay; pre-execution request refusal; unsupported clock/task failure; forged
output/source/flags/request bindings; invalid timing; malformed/noncanonical
receipts. All marks/platform guards are mocked in checks. No product service,
socket, fixture or effect is activated; only the pipeline's owned test subprocess
runs. Fake test timestamps and digests never
become measurement evidence. No historical reference-task suite is requested.

Reviewed repository input closure for this stage:

```text
src/aragorn/__init__.py
src/aragorn/native_phase3_workload_json_sum_contract.py
src/aragorn/native_phase3_workload_json_sum.py
src/aragorn/native_phase3_workload_json_sum_verify.py
src/aragorn/phase3_reference_tasks.py
src/aragorn/native_phase3_http_fixture.py
src/aragorn/native_phase3_http_canary_contract.py
src/aragorn/runtime_process_profile.py
src/aragorn/runtime_action_broker.py
src/aragorn/runtime_action_decision.py
src/aragorn/runtime_action_observation_publisher.py
src/aragorn/oci_worker_protocol.py
tests/test_native_phase3_workload_json_sum.py
```

The fixed test input is inline; no external fixture is read. The transitive HTTP
fixture/process imports come from the reused reference task, even though this
pure task never calls them. The runner owns its interpreter/toolchain/execution
fingerprints in addition to this closure. Collector/replay are read-only API
references, not imported by this focused stage; integration checks need their
own complete coordinator-reviewed closures when dispatch is added.

Executed once after registration and explicit coordinator scheduling:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-workload-json-sum
```

Result: **PASS**, 6 tests. Fingerprint and post-fingerprint match:
`sha256:9d5945fdbad517531b6cc61d32645596ded265683cbf82504651274557f16a82`.
Retained evidence directory:
`.aragorn/phase3-pipeline/native-workload-json-sum/9d5945fdbad517531b6cc61d32645596ded265683cbf82504651274557f16a82/`.
Test log (`stderr.log`, 1,130 bytes) digest:
`sha256:0c1950e1b69631bd35e61f9bb46f38d3609e7f6b04a40326901becb811b2b116`.
No historical stage executed, and no prior success/failure evidence was altered
or copied. The registry addition needs no historical scheduling prerequisites.
The runner accepts positional stage IDs. Reuse the exact result while its closure
is unchanged; do not run the unselected pipeline or invoke unittest directly.

## Out-of-scope integration and remaining work

- Completed coordinator step: register/schedule only this new stage in
  `benchmark/phase3-pipeline-v1.json`; first focused run passed. No runner change.
- Coordinator: source/dependency pins, staging, installed source custody and
  trusted deployment/host `identity_reader`. Reading task source for a descriptor
  is not proof that those bytes match the loaded code; frozen source custody
  remains mandatory. No shared source inventory changed.
- Coordinator: dispatch from the collector/replay to the exact task and verifier;
  keep the native HTTP collector separate from these controller-clock marks.
  No `phase3_measurement_collector.py` or replay edit made.
- Coordinator: prove actual baseline/instrumented environment selection and
  equal task/input/host bindings. A request mode label does not switch sensors or
  prove overhead. Do not call the full campaign collector to exercise this leaf.
- Lane follow-ups: other three benign callbacks, DNS/truncate/unlink and separate
  unattributed workload paths, independent timing/attribution/sink-residue joins.
  This pure-task consumer cannot certify either action family or negative control.
- Coordinator: HTTP94 credential/import repair and existing cleanup hold.
  Admission/RUN consumers remain in their assigned lanes.

This checked slice is ready for source integration after its signed commit is
verified. Commit scope is exactly the six paths above, including the coordinator
registration. The containing commit's verified hash and working-tree state are
recorded in the coordinator's post-commit checkpoint; no self-referential hash is
embedded here. Leave the commit local for integration. These checks do not establish
real overhead or installed-source custody.

## Four-step checkpoint

1. Integration/cleanup hold unresolved. The October 9 checkpoint remains the
   authority; no live-state refresh, private retention, cleanup or retry occurred.
2. This lane's JSON-sum callback/verifier is checked; source integration pending.
   Remaining workloads and paired tasks are incomplete.
3. Combined independent verifier inventory and deployment freeze pending.
4. Final acceptance blocked; every qualification flag remains false.
