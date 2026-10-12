# BENIGN_LINE_COUNT: reviewed and focused checks passed

Branch: `codex/phase3-workload-verifiers`. Parent:
`43c0decd2bba922f482002bb24ca7207296efeee` (signature verified this session).
The common ownership base remains `eb13d0d3eb0d7c29e613c25570cd47fafe6baffb`.
Implementation and 13-path closure reviewed; seven focused checks passed once.
No real paired sample or qualification result was produced.

## Delta and interface

Commit scope: four new lane-owned paths plus coordinator registration:

- `src/aragorn/native_phase3_workload_line_count.py`
- `src/aragorn/native_phase3_workload_line_count_verify.py`
- `tests/test_native_phase3_workload_line_count.py`
- this handoff.
- `benchmark/phase3-pipeline-v1.json` (only the new stage).

The producer exports `execute(request, mark)` and the independent consumer exports
`verify(receipt_bytes, request, boundaries)`, using the same collector envelopes
and request keys as JSON-sum. The producer reuses the existing reference task
with exactly `b"amber\nbirch\ncedar\ndelta\n"`; the consumer independently requires
`{"line_count": 4}`, the exact descriptor/result, canonical bytes and digest joins.
It imports neither producer nor reference-task implementation.

Reuse the unchanged `native_phase3_workload_json_sum_contract` syntax/chronology
validators; their existing `JSON_SUM_*` validation error identifiers remain as-is.
Task-specific refusals use `LINE_COUNT_*`. No generic framework or second copy of
the validators was added. No existing callers, tests, fixtures, exports, config,
source inventories were edited. The coordinator registered only the new stage.

The producer validates task/input bindings before marking, calls the existing
task exactly once between TASK_ACCEPTED and TASK_COMPLETED, and preserves the
collector's in-process Linux CLOCK_BOOTTIME marks without conversion or fallback.
The interval includes reference-task validation/output hashing, excluding source
preparation and receipt serialization. Exceptions never emit a successful receipt
or trigger retry. This pure task performs no native effect or file mutation.
As with JSON-sum, trusted source custody, actual instrumentation selection and
host/deployment identity remain external requirements; completion is the only
returned semantic, and existing eligibility flags remain false.

## Coordinator registration and focused result

Registered only `native-workload-line-count` with:

- tests: `["test_native_phase3_workload_line_count"]`
- needs: `[]`
- timeout_seconds: `120`
- inputs: the exact repository closure below.

```text
src/aragorn/__init__.py
src/aragorn/native_phase3_workload_json_sum_contract.py
src/aragorn/native_phase3_workload_line_count.py
src/aragorn/native_phase3_workload_line_count_verify.py
src/aragorn/phase3_reference_tasks.py
src/aragorn/native_phase3_http_fixture.py
src/aragorn/native_phase3_http_canary_contract.py
src/aragorn/runtime_process_profile.py
src/aragorn/runtime_action_broker.py
src/aragorn/runtime_action_decision.py
src/aragorn/runtime_action_observation_publisher.py
src/aragorn/oci_worker_protocol.py
tests/test_native_phase3_workload_line_count.py
```

The transitive fixture/process imports are inherited from the reference task;
none of their runtime operations is called. Test inputs are inline. The pipeline
additionally fingerprints its runner/toolchain/execution environment. No external
fixture or test helper is required. Seven inert methods cover both modes and
exact call order, pre-mark refusal, unsupported clock/task failure, same-input
SHA-256 task substitution, forged receipts/request bindings, invalid intervals,
and malformed/noncanonical receipts. Test clocks and identities are fabricated
and never retained as samples. No product service, socket or VM is activated.

Executed once after coordinator registration and explicit scheduling:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-workload-line-count
```

Result: **PASS, seven methods, one execution**, exit code 0.
Fingerprint and post-fingerprint: `sha256:79464c1432034d5d5a0298be6c1645e328dba1859bd75c5611fb73fb55480d0b`.
Elapsed pipeline interval: 0.326507 seconds.
Retained directory: `.aragorn/phase3-pipeline/native-workload-line-count/79464c1432034d5d5a0298be6c1645e328dba1859bd75c5611fb73fb55480d0b/`.
`stderr.log`: 1347 bytes,
`sha256:c76fa3cbee9d966476c38ad8702823b2980bb825b9d1bdd0f11b2c993d0905d3`.
No retries or additional stages ran. The pipeline returned normally; no product
resources required cleanup. Do not bypass the pipeline or rerun unchanged inputs.
The unchanged JSON-sum closure/result is retained, not rerun: its committed
handoff records PASS, six checks, fingerprint
`sha256:9d5945fdbad517531b6cc61d32645596ded265683cbf82504651274557f16a82`.
That historical result is not a line-count test result; its private cache was
not copied or modified. No old failure or successful stage was rerun.

## Coordinator handoff and signed batch

Coordinator completed `benchmark/phase3-pipeline-v1.json` registration/scheduling
in this original workload worktree. Coordinator retains
collector/replay dispatch, installed source/dependency pins, identity reader and
baseline/instrumented environment proof. No out-of-scope edit was made. Preserve
the native HTTP clock/effect path separately; these local callback marks must
not be relabeled broker timing or causal/sink evidence.

This completed checked batch includes exactly the five paths above. Sign with
`git commit -S`, verify with `git verify-commit HEAD`, and inspect working-tree
state. The containing commit hash is reported after commit verification rather
than embedded in itself. Coordinator integration and a lane fast-forward to the
combined signed checkpoint must precede BENIGN_SHA256. Guarded copy/readback is
a later batch. No push is authorized here.

## Four-step status

1. Integration/cleanup approval hold unresolved; retained first-activation
   checkpoint and evidence untouched. No live-state refresh or operation.
2. JSON-sum evidence preserved; line-count seven checks passed once. Integration
   pending. SHA-256/copy callbacks and remaining workloads/joins remain incomplete.
3. Combined independent verifier inventory and deployment freeze pending.
4. Final acceptance blocked; qualification flags remain false.
