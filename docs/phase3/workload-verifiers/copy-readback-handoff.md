# BENIGN_COPY_READBACK — reviewed and focused checks passed

Source assignment: 2026-10-12. Implementation base:
`55a87ea1f7ab3924ade5fa629935ffc03962ba05`, branch
`codex/phase3-workload-verifiers`. Implements the published context contract and
accepted plan. Separate coordinator registration/scheduling authorized the single
focused inert run recorded below. Commit parent is the verified registry-only
`d69d92d800635453b1162227b630a3922a371f23`; no native execution is authorized.

## Exact change scope

Four new lane-owned paths:

- `src/aragorn/native_phase3_workload_copy_readback.py`
- `src/aragorn/native_phase3_workload_copy_readback_verify.py`
- `tests/test_native_phase3_workload_copy_readback.py`
- this handoff.

Existing runtime sources, plan, proposal, collector and replay are unchanged.
Registry registration is in the separate signed coordinator parent; it is not
part of this four-path lane commit.
The pre-existing untracked `copy-readback-plan.html` is preserved and excluded.
No shared exports, fixtures, configuration or new dependencies are needed for
these leaves. There are no existing callers to modify in this lane.

## Behavior and custody

`execute(request, mark, *, copy_directory_fd,
expected_copy_directory_identity, expected_fixture)` validates and snapshots the
exact request/context, opens bounded reference-task source for the descriptor,
and checks task/input bindings before marking. Under the existing fixture guard
it validates the original caller directory FD and holds its own duplicate. It
calls `execute_reference_task` exactly once, passing that held duplicate, exact
identity and a separate fixture snapshot. TASK_ACCEPTED/TASK_COMPLETED are the
actual supplied collector marks around that invocation, including its internal
final guards/closes. The duplicate resolves the same directory as the caller FD.
No task failure emits completion, no callback retries, and no residue is erased.

After the task returns, the producer observes `allowed-copy.txt` using
non-following named stat and checks private regular single-link metadata/size.
It records/rechecks the post-task identity, constructs the existing receipt
envelope, checks final directory/fixture custody and closes only its own duplicate.
It reuses the reference task's `_identity`/`_guard_directory` for producer metadata
and custody; it never duplicates the copy algorithm.

The independent `verify(raw, request, boundaries, *, copy_directory_fd,
expected_copy_directory_identity, expected_fixture)` imports neither producer
nor reference task. It validates exact canonical receipt bytes, fixed input,
expected output/task descriptor, request/context/fixture digest joins and strict
integer identities/chronology. It obtains its own duplicate of the independently
supplied directory FD, opens only literal `allowed-copy.txt` using
O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC, and checks named/opened metadata against
the retained identity. It requires regular type, 0600/current owner/group,
nlink=1, exact length and fixed bytes, reading at most expected length+1.

Before/after/final checks compare device/inode/mode/uid/gid/nlink/size/mtime_ns/
ctime_ns, the original/duplicate directory identities and the fixture. Missing,
replaced, linked, altered or wrong-context evidence refuses completion. Both
leaves preserve caller-owned FDs. Final guard/close failures refuse success and
attach failure notes to an existing primary error. No close retry occurs.
Post-task observation failure remains failure even when both marks were produced.

The returned semantic is only `completed`. False eligibility flags remain false.
The existing task closes its file FD before return: retained identity proves
post-task retention only, not uninterrupted creation-to-readback inode custody.
Finite read sizes and the proposed test timeout do not ensure product wall time.
No timeout thread, product deadline, replacement retry, overwrite or unlink was
added. The only creation/writes are the unchanged reference task's O_EXCL copy.

Coordinator must enforce independently pinned request/context mappings and
per-execution durable claims, fresh distinct directories for every execution
(including both pair halves), original FD provenance/exclusive custody/lifetime,
actual environment selection, source custody, cancellation/supervision and
still-valid retained-fixture replay. Mode labels and different FD numbers alone
are insufficient. Occupied target refuses and stays retained; the leaf has no
cross-execution ledger and cannot attest coordinator global directory uniqueness.
No changes to those coordinator-owned providers/dispatch/cleanup are included.

## Reviewed stable input closure and scheduled stage

Registered stage: `native-workload-copy-readback`.
Tests: `["test_native_phase3_workload_copy_readback"]`; needs: `[]`;
timeout_seconds: `120` (tests only). Coordinator registered and explicitly scheduled this stage once.
The prospective plan closure was re-reviewed against actual source/test imports
and their transitive local dependencies; its exact 13 paths still suffice:

```text
src/aragorn/__init__.py
src/aragorn/native_phase3_workload_json_sum_contract.py
src/aragorn/native_phase3_workload_copy_readback.py
src/aragorn/native_phase3_workload_copy_readback_verify.py
src/aragorn/phase3_reference_tasks.py
src/aragorn/native_phase3_http_fixture.py
src/aragorn/native_phase3_http_canary_contract.py
src/aragorn/runtime_process_profile.py
src/aragorn/runtime_action_broker.py
src/aragorn/runtime_action_decision.py
src/aragorn/runtime_action_observation_publisher.py
src/aragorn/oci_worker_protocol.py
tests/test_native_phase3_workload_copy_readback.py
```

The test reads reference-task source bytes for descriptors and uses inline fixed
bytes/context, no external fixtures or shared test helper. Other imports are
standard library. HTTP fixture imports pull in process/broker/decision/publisher
modules listed above; no native runtime operation is invoked by the mocked guards.
Runner/interpreter/toolchain/environment fingerprints remain pipeline-owned.
Coordinator source/closure review approved the stable bytes before registration
and scheduling. No direct unittest/compile or broader check bypass was used.

Twelve passing methods cover the planned boundaries: two fresh simultaneous
mode directories and exact task/mark order; pre-mark request/context refusal;
partial task and post-task observation failures; retained O_EXCL reuse refusal;
consumer independence and forged output; symlink/hardlink/FIFO refusal;
byte-identical inode substitution; directory/fixture changes; short/extra/wrong
bytes and post-read metadata changes; close/primary-error/caller-FD handling;
canonical/clock/boolean-metadata refusals; pair/mode/directory substitution.
These checks used disposable test-owned scratch FDs and mocked fixture/clock
boundaries. Adversarial scratch mutations are test setup, never product retries.
They do not prove a deployed context provider or product cancellation deadline.

Coordinator-requested test refinements remain within those twelve methods:
fixture failure is armed only after a successful retained-file read, covering
both final-guard-only refusal and preservation of a primary post-read error.
The producer close case tracks its first duplicate and fails only that close,
after the reference task and both marks succeed; reference-task closes remain
successful. These cases assert caller FD/residue preservation and no receipt.
Only test/handoff bytes changed; source and the 13-path closure are unchanged.

## Results and remaining work

**PASS: twelve methods, one stage execution, exit code 0.**
Command in this original workload worktree:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-workload-copy-readback
```

Fingerprint and post-fingerprint match: `sha256:bc7e9c5b46f7c44569ae94dd00fcf80aafa3b51d6ff883f985b1327e5790d8db`.
Retained directory: `.aragorn/phase3-pipeline/native-workload-copy-readback/bc7e9c5b46f7c44569ae94dd00fcf80aafa3b51d6ff883f985b1327e5790d8db/`.
Pipeline interval: 0.500241 seconds; unittest reported 0.017 seconds.
`stderr.log`: 2387 bytes,
`sha256:80dc01ad0f8377d0e4e5419cbdf6fa8ef1010a897c8a0854b538e0591bf6ff56`; stdout empty.
Original result/logs remain in this worktree. No retry or other stage ran.
The pipeline returned normally; only test-owned temporary scratch was used and
released by the tests. No real native fixture, provider, VM, service, live effect,
private retention or product cleanup ran. No historical evidence/cache was changed.
Existing PASS fingerprints remain retained without rerun:

- JSON-sum: `sha256:9d5945fdbad517531b6cc61d32645596ded265683cbf82504651274557f16a82`.
- Line-count: `sha256:79464c1432034d5d5a0298be6c1645e328dba1859bd75c5611fb73fb55480d0b`.
- SHA-256: `sha256:5c26a3df4d6f464ba8458d7ef60139bcc7e74c3f473044654edc3b22739c779f`.

This reviewed, passing batch contains exactly the four new lane paths above.
Stage those paths only, inspect the staged diff, commit -S, verify-commit HEAD
and inspect state. Report the verified containing hash after commit instead of
embedding it in itself. Registry stays in its signed parent, local HTML stays
excluded, and integration/publication remain coordinator-owned. No further work
or broader execution is implied by this focused result.

1. Shared integration remains open; HTTP94 proof/cleanup approval hold unchanged.
2. Three pure callbacks checked previously; guarded copy/readback twelve focused
   checks passed once, coordinator integration pending. Remaining workloads/attribution/residue are incomplete.
3. Combined independent verifier inventory and deployed source freeze pending.
4. Final same-deployment acceptance blocked; all qualification flags remain false.
