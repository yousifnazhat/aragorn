# BENIGN_SHA256: reviewed and focused checks passed

Parent: `371cea7318f0e1326539de0e0e3ac8bdbec9cc4e`, combined coordinator
checkpoint. Original workload worktree fast-forwarded cleanly and HEAD signature
verified before this batch. Line-count batch `7bf76a462efcf45c024c4faa8adf7cf2cee5d2ca`
and its signed merge remain ancestors. Guarded copy/readback is a later batch.

## Scope and interface

Signed batch scope: four new lane-owned paths plus coordinator registration:

- `src/aragorn/native_phase3_workload_sha256.py`
- `src/aragorn/native_phase3_workload_sha256_verify.py`
- `tests/test_native_phase3_workload_sha256.py`
- this handoff.
- `benchmark/phase3-pipeline-v1.json` (only native-workload-sha256).

Top-level `execute(request, mark)` reuses `execute_reference_task` for
BENIGN_SHA256 on the exact fabricated `lines_text` bytes. Source/task/input
bindings are validated before marking. TASK_ACCEPTED and TASK_COMPLETED surround
one actual in-process task invocation, using the collector's Linux CLOCK_BOOTTIME
marks without conversion or fallback. The interval includes task validation and
result hashing, excludes source preparation/receipt serialization, and does not
represent a native broker/effect interval. No retries or mutations occur.

Top-level independent `verify(receipt_bytes, request, boundaries)` imports
neither producer nor reference-task implementation. It independently computes
SHA-256 of the exact fixed input and checks canonical descriptor/result bytes,
request/task/input/source bindings and strict interval chronology. Output is a
bare lowercase 64-hex hash in `output.sha256`; input/output document digests keep
their `sha256:` prefixes. Only `completed` semantics are returned. Existing false
eligibility flags stay false. The unchanged JSON-sum contract validators are
reused; their syntax/chronology error identifiers remain `JSON_SUM_*`.

No existing runtime callers, exports, config, fixtures or source pins changed.
Collector/replay dispatch, identity reader, installed source custody and real
baseline/instrumented selection remain coordinator work. A mode label alone is
not instrumentation proof. This consumer establishes no attribution/sink residue.

## Registered stage and reviewed closure

Stage `native-workload-sha256`; tests `["test_native_phase3_workload_sha256"]`;
needs `[]`; timeout_seconds `120`. Coordinator reviewed and registered only this stage, then explicitly scheduled one execution.

```text
src/aragorn/__init__.py
src/aragorn/native_phase3_workload_json_sum_contract.py
src/aragorn/native_phase3_workload_sha256.py
src/aragorn/native_phase3_workload_sha256_verify.py
src/aragorn/phase3_reference_tasks.py
src/aragorn/native_phase3_http_fixture.py
src/aragorn/native_phase3_http_canary_contract.py
src/aragorn/runtime_process_profile.py
src/aragorn/runtime_action_broker.py
src/aragorn/runtime_action_decision.py
src/aragorn/runtime_action_observation_publisher.py
src/aragorn/oci_worker_protocol.py
tests/test_native_phase3_workload_sha256.py
```

The 13-path closure includes the reference task's transitive fixture/process
imports, though their runtime operations are never called. Inputs are inline;
no external fixture/test helper. Runner/toolchain/environment fingerprints remain
pipeline-owned. Eight inert methods cover both modes and exact call order,
pre-mark refusal, unsupported clock/task failure, same-input line-count
substitution, forged receipts/bindings, invalid clocks, self-consistent forged
hash/descriptor, and malformed/noncanonical/hash-format refusals. Test marks are
fabricated and never measurement evidence. No product service/socket/VM runs.

Executed once after coordinator scheduling:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-workload-sha256
```

Result: **PASS, eight methods, one execution**, exit code 0.
Fingerprint and post-fingerprint match: `sha256:5c26a3df4d6f464ba8458d7ef60139bcc7e74c3f473044654edc3b22739c779f`.
Elapsed pipeline interval: 0.327679 seconds.
Retained directory: `.aragorn/phase3-pipeline/native-workload-sha256/5c26a3df4d6f464ba8458d7ef60139bcc7e74c3f473044654edc3b22739c779f/`.
`stderr.log`: 1474 bytes,
`sha256:469562fa647c8a86e9f6af3bf835b9e899037eef2321cb6d08b6ec2c2f249d82`.
No retry or additional stage ran. The pipeline returned normally; no product
resources required cleanup. No prior stage was rerun. Retain JSON-sum's exact PASS
fingerprint `sha256:9d5945fdbad517531b6cc61d32645596ded265683cbf82504651274557f16a82`
and line-count's exact PASS fingerprint
`sha256:79464c1432034d5d5a0298be6c1645e328dba1859bd75c5611fb73fb55480d0b`.
They do not establish SHA-256 correctness. Their caches/evidence remain untouched.
No automatic retry or broad suite is requested.

## Handoff and four-step status

Coordinator supplied the one registry row in this original workload worktree.
Implementation, eight methods and complete closure were reviewed before execution.
This completed checked batch contains exactly the five paths above. Inspect the
staged diff, commit with `git commit -S`, verify with `git verify-commit HEAD` and
inspect state. The verified containing hash is reported after commit rather than
embedded in itself. Keep the commit local for coordinator integration. Hold
copy/readback until the next combined checkpoint; do not perform integration,
source inventory or collector/identity changes in this lane.

1. Combined source integration advanced; cleanup approval/HTTP94 live proof
   remain unresolved. No retained evidence or hold changed.
2. JSON-sum and line-count evidence retained; SHA-256 eight checks passed once,
   coordinator integration pending.
   Guarded copy/readback and remaining workload/attribution/residue work remain.
3. Combined verifier inventory and deployment freeze pending.
4. Final acceptance blocked; all qualification flags remain false.
