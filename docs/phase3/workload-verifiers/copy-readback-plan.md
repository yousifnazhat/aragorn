# BENIGN_COPY_READBACK — proposal, no execution scheduled

Base: `b3fca83615cd6fd69b463ca8cebcebc660990dec`, current clean lane HEAD
before this planning-only change. No implementation, registry modification,
fixture creation, test run or live operation is authorized by this plan.

## Proposed new implementation files

- `src/aragorn/native_phase3_workload_copy_readback.py`: fixed-input execution leaf; no product deadline guarantee.
- `src/aragorn/native_phase3_workload_copy_readback_verify.py`: independent retained-file consumer.
- `tests/test_native_phase3_workload_copy_readback.py`: focused inert checks.
- `docs/phase3/workload-verifiers/copy-readback-handoff.md`: later batch result/checkpoint.

Current deliverables are this plan, `copy-readback-stage.json` (proposal only)
and `copy-readback-plan.html` (local review draft, excluded from this commit).
Existing runtime sources stay read-only. No alternative copy implementation or shared framework is proposed.

## Agreed coordinator interface — implementation still held

Lane review agrees with [protected context contract v1](../coordinator/copy-readback-context-contract-v1.md),
read read-only in the coordinator checkout. Reviewed document SHA-256:
`e7603891206595999ea9cc2a857768e69be7099ad836210c1711bb0b646b3a50`.
The link becomes available here after coordinator checkpoint integration; no copy
of the coordinator-owned draft is introduced in this lane.

The agreement fixes these prerequisites for the future provider:

- Top-level protected dispatch independently resolves producer and consumer
  context by the canonical eight-key request digest and exact request bytes.
  Immutable root-owned inventory binds directory identity/name, fixture,
  deployed-source digest and independently selected environment digest.
- Source-pinned fixed ancestry and protected readers establish directory
  provenance; the coordinator retains exclusive custody and caller FD lifetime.
  Consumer expectations are independently resolved, never selected by a receipt.
- Before producer dispatch, a durable request-keyed O_EXCL claim is consumed with
  file/parent fsync and protected readback. Failed, partial or ambiguous claims
  remain spent. Every execution, including each pair half, uses a distinct
  private directory identity retained in the coordinator mapping.
- Cancellation stops further dispatch and preserves claims, directories and
  partial output. Uncertainty remains until the exact owned guest worker is
  confirmed stopped; killing a host client is insufficient. Supervision is
  coordinator-owned and is not implemented by this agreement.
- Retained-file replay requires the original directory, protected mapping and
  still-valid fixture/process/namespace context, before separately authorized
  cleanup. Receipt-only or relocated post-cleanup replay is not provided.

No concrete provider or product liveness mechanism is claimed present. Publication
of the containing signed checkpoint and an explicit coordinator implementation
release are still required for the finite mocked leaf. Stage registration and
execution require separate actual-import/closure review and scheduling. This
commit records design agreement only; it releases no code or tests.

## Interfaces and coordinator prerequisite

```python
execute(request, mark, *, copy_directory_fd,
        expected_copy_directory_identity, expected_fixture) -> bytes
verify(receipt_bytes, request, boundaries, *, copy_directory_fd,
       expected_copy_directory_identity, expected_fixture) -> dict
```

Reuse the existing exact request and boundary validators in
`native_phase3_workload_json_sum_contract`. Request keys and the five-key
collector receipt envelope stay unchanged; FD numbers are process-local context,
never portable request identifiers. Context is keyword-only and caller-held.
The coordinator must bind it to this exact collection/pair/mode/deployment.
Snapshot expected dictionaries before use; do not mutate caller objects.

These are context-requiring leaves, not drop-in generic collector callbacks yet.
The existing collector calls execute with two arguments and verify with three;
it also rejects closures/partials as source-pinned callbacks. Coordinator-owned
source-pinned top-level dispatch must resolve protected per-execution context.
No global mutable FD registry, callback factory, request-schema change, partial,
or collector/replay edit belongs in this lane. The agreed dispatch contract above
still requires coordinator implementation before end-to-end integration. Offline replay needs the retained directory and
its independent custody mapping; receipt bytes alone cannot verify file residue.

## Producer sequence and actual timing

1. Validate request, fixed descriptor/source/input bindings, Linux BOOTTIME
   availability and explicit context types. Reuse the genuine task descriptor.
2. Mark TASK_ACCEPTED with the supplied collector mark, then invoke exactly once:
   `execute_reference_task("BENIGN_COPY_READBACK", fixed_input_bytes,
   copy_directory_fd=..., expected_copy_directory_identity=...,
   expected_fixture=...)`.
3. Mark TASK_COMPLETED only after that operation returns successfully, including
   its final directory/fixture/descriptor-close guards. No fallback clock,
   controller/native clock conversion, retry or synthesized duration.
4. Outside the measured interval, observe retained `allowed-copy.txt` relative
   to the pinned directory FD; record exact directory identity, fixture binding
   and retained-file identity. Recheck custody before emitting receipt. Producer
   observation cannot substitute for independent consumer checks.

The fixed input is `b"Aragorn Phase 3 benign copy/readback data.\n"`. Expected
output is exact byte length, lowercase SHA-256 of those bytes and
`readback_equal: true`. Receipt observation extends the prior task/result pair
with a bounded `retained_file` record: fixed basename, directory identity,
fixture canonical digest, and file device/inode/mode/uid/gid/nlink/size/
mtime_ns/ctime_ns. No absolute path or raw private fixture configuration exported.
Binding a fixture digest is not attestation. Validate exact field types; booleans
must not pass as integers. All inherited qualification flags remain false.

## Independent consumer and conservative custody rules

The consumer imports neither producer nor reference-task implementation. It
independently constructs the fixed descriptor/output expectations and verifies
canonical bounded receipt bytes, request/task/input/source descriptor digests,
actual supplied marks and strict chronology, as in the checked SHA-256 consumer.
It independently reuses `owned_http_fixture` for fixture guards; it must not call
the producer's file observer or private reference-task guard functions.

Validate the caller-held directory FD and expected five-field identity
(device/inode/mode/uid/gid), require private mode 0700/current root ownership under
the fixture guard, duplicate the FD and check both original and duplicate.
Open only literal `allowed-copy.txt` with O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC
relative to that held directory. O_NONBLOCK avoids FIFO blocking before type
validation. Require a regular file, mode 0600, current root owner/group, nlink=1,
and exact expected size. Compare opened fstat to non-following named stat, the
receipt's retained-file identity, and before/after read snapshots including
mtime/ctime. Read at most expected length+1; require exact bytes, hash and output.
Recheck original/duplicate directory, named/open file, fixture and final closes.
Close only descriptors created by this consumer; never close caller-owned FDs.

Any missing/replaced file, symlink, hardlink, nonregular node, size/content change,
metadata mismatch, short/extra read, fixture change or close/final-guard failure
raises/refuses completion. Preserve an original exception and attach final-custody
failure information rather than masking it. Never emit completed=true from a
finally block. Even after both marks exist, observation/custody failure invalidates
completion. Neither component overwrites, unlinks, truncates or repairs residue.
Partial output stays for coordinator custody and cleanup; no automatic retry.

Claim ceiling: the existing copy operation closes its file FD before returning
and does not export its inode. The receipt therefore records post-task retention
identity, not provable uninterrupted inode continuity from O_EXCL creation.
A byte-identical replacement before initial observation cannot be ruled out by
this leaf. Exclusive directory custody and provenance must be established by the
coordinator; stronger continuity would require a separately reviewed shared-task
interface change. Do not infer it from a matching final hash. A fixture guard
also does not prove an arbitrary passed FD belongs inside that fixture; that
FD's provenance and writer exclusion are coordinator responsibilities.

## Fresh directory rule and coordinator-owned work

Each execution gets a distinct private directory identity and held FD, including
baseline and instrumented halves. Keep earlier directory handles/residue retained
so the coordinator can reject identity reuse, not just a reused FD number.
O_EXCL refusal for an existing allowed-copy.txt remains a failure. Never remove
it, allocate a replacement automatically, or retry to turn a failure into PASS.

Provisioning, ancestry/provenance, lifetime, exclusive custody, cleanup, source
identity, collector/replay dispatch and real baseline/instrumented environment
selection remain coordinator-owned. A new FD number or mode label is not proof
of a fresh directory or instrumentation. Cross-execution freshness needs the
coordinator's retained mapping; the leaf cannot enforce global uniqueness alone.

## Product liveness remains a coordinator prerequisite

Finite input bytes and receipt records do not bound product wall time. The reused
copy task performs blocking write/fsync/read calls, and the existing collector
has no callback timeout. The proposed stage timeout of 120 seconds bounds the
test process only; it is not a product deadline or cancellation guarantee.
The agreed contract assigns product supervision and cancellation custody to the
coordinator, including retained partial output and descriptors after interruption.
The actual provider/supervision implementation remains pending.
Do not introduce a timeout thread, retry, or deadline-bounded execution claim.
The agreed protected dispatch and post-task custody limits above remain required;
contract publication and explicit release are still pending. No deadline is promised.

## Proposed focused stage — no execution authority

`native-workload-copy-readback`; test module
`test_native_phase3_workload_copy_readback`; needs []; timeout_seconds 120.
The prospective 13-path closure is in adjacent `copy-readback-stage.json`.
It anticipates transitive reference-task fixture/process imports; no external
test fixture or shared test infrastructure is proposed. The closure is not final
until actual implementation imports exist and are re-reviewed before registration. Runner/toolchain fingerprints remain pipeline-owned.

Prepare 12 focused inert test methods covering: (1) both modes/call order and real fixed
copy delegation using scratch FDs with mocked fixture guard; (2) malformed or
wrong task/input/context refusal; (3) failed task has no completion; (4) reused
directory/existing target refuses and retains bytes; (5) consumer independent of
producer and checks exact receipt/output; (6) symlink/hardlink/nonregular refusal;
(7) inode/named-file substitution; (8) directory/fixture custody change;
(9) short/extra/changed content or metadata; (10) final guard/close failure
preserves primary error and caller FDs; (11) invalid marks/canonical/types;
(12) receipts from distinct pair/mode/directory contexts cannot be interchanged.

These are future inert checks only: temporary test-owned scratch directories,
mocked native fixture/root/clock boundaries, no real owned native fixture or
service. Scratch cleanup must retain assertions about non-overwrite behavior;
it is not product cleanup authority. Do not claim the test suite proves the
coordinator's global freshness, host provenance or actual instrumentation.

After implementation and full review, coordinator registers/schedules only this
stage in the original worktree. Until then: zero executions, no fingerprint,
no checked batch or signed implementation commit. Preserve prior exact PASS
fingerprints unchanged: JSON-sum 9d5945fdbad517531b6cc61d32645596ded265683cbf82504651274557f16a82;
line-count 79464c1432034d5d5a0298be6c1645e328dba1859bd75c5611fb73fb55480d0b;
SHA-256 5c26a3df4d6f464ba8458d7ef60139bcc7e74c3f473044654edc3b22739c779f.
No historical reruns, cache copying, automatic retry or live operations.

## Four-step status

1. Source checkpoint integrated; cleanup approval/HTTP94 live proof unresolved.
2. Three pure task callbacks checked; guarded copy/readback planned only.
   Remaining workload, attribution and residue paths are incomplete.
3. Independent verifier inventory and deployment freeze pending.
4. Final acceptance blocked; no qualification flag changes.
