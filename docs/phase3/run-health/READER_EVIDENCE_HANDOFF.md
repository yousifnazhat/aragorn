# Independent reader evidence consumer — reviewed and focused checks passed

Proposal base: `27e9844e6d5f0924b79382a8a084099ee06e2ed6`.
Implementation base: verified signed published checkpoint
`d87572182584f9c106393a2ca952c69703b6da6d`, fast-forwarded by this owner on
`codex/phase3-run-health`. Both original drafts survived that fast-forward unchanged.
Owner read and agrees ownership-and-release-v2.md and reader-evidence-contract-v1.md,
including every final coordinator decision. This releases only the three assigned
paths. The accepted design below is implemented; actual closure follows it.
Coordinator source/closure review and registration are complete in signed published
`22c05de348c1585ab9bdf17bf8cc1ba119c7f53d` (lane-review-and-scheduling-v3.md).
Owner verified its signature/ancestry, fast-forwarded, rechecked all three approved
input hashes and confirmed no prior stage directory. One scheduled CLI invocation
was refused during global registry loading, before any behavior test. No provider
changes by this lane or live operations ran. The coordinator corrected the shared
runner in signed published checkpoint
`b4ffd1341e9666e4dd6afb73d322221772eb3684` and explicitly scheduled the changed-input
attempt. Owner verified its signature/ancestry, fast-forwarded preserving drafts and
rechecked unchanged approved hashes. The first behavioral execution then passed
all 14 cases. The original scheduling refusal remains recorded below.

## Agreed API and ownership

```python
verify_reader_evidence(
    evidence_raw: bytes,
    reader_raw: bytes,
    *,
    bindings: dict,
    expected_evidence_digest: str,
    expected_reader_digest: str,
    expected_observer: dict,
    expected_connection_epoch: str,
    credential_abi: str,
) -> dict
```

Only new `src/aragorn/native_phase3_run_reader_evidence_verify.py`,
`tests/test_native_phase3_run_reader_evidence_verify.py` and this handoff are owned.
The verifier imports only standard-library modules: neither the acquisition leaf,
its private parsers, the acquisition projection nor a runtime source/provider.
Tests construct Linux-format fixtures independently; they do not import a producer,
its tests, or a runtime harness to generate expected values. No shared module,
export, caller, schema, registry or existing test changes are proposed.

`bindings` is the existing exact seven independently held epoch/challenge/request/
process/clock/loss_scope/policy SHA-256 pins. Both expected raw digests are also
independently held; deriving them from candidate input is fixture behavior only.
`expected_connection_epoch` is the protected caller-held 64-lowercase-hex epoch.
`expected_observer` has exactly pid, start_time_ticks, uid, gid, time_namespace;
time_namespace has exactly device and inode. These are held outside the supplement:
never choose the expected observer by reading its reported parsed process objects.
Boot ID, CLOCK_BOOTTIME and namespace inode also join the caller-pinned epoch.
The observer PID must differ from reader PID; raw before/after stat/status must
reconstruct the same independently held observer identity. The supplement does not
prove main-thread invocation or the origin of the independently supplied identity.

## Agreed Linux credential ABI

One supported caller-selected ABI: `linux-le-ucred32-v1`. Exactly 12 bytes,
little-endian signed 32-bit PID, unsigned 32-bit UID and GID. Require positive PID
<= 2147483647 and accounts <= 4294967295. Decode byte slices explicitly; do not use
host-native struct layout, sys.byteorder or socket constants. Other ABIs refuse.
This is an explicit supported-deployment constraint, not auto-detection or a claim
that a supplied ABI label authenticates the bytes.

Retained Linux SOL_SOCKET=1 and SCM_CREDENTIALS=2 must be strict integers. Require
send_call_flags=0x4040 (DONTWAIT|NOSIGNAL), recvmsg_call_flags=0x40000040
(DONTWAIT|CMSG_CLOEXEC). Returned receive_flags may contain only EOR=0x80 and
CMSG_CLOEXEC=0x40000000. Every other flag/control type refuses, including FD-bearing
messages. The earlier macOS-host mocked acquisition fixtures use host socket
constants and are not Linux custody evidence; this stage neither reruns nor imports
them. Independent new fixtures use the agreed Linux numeric ABI.

## Exact complete-record rules

Accept only complete `ACK` or `TIMEOUT` supplements with the current evidence schema.
Refuse REFUSED, partial/missing fields, unknown/extra fields, overflow, failure or
cleanup-error state. Preserve those existing records untouched for other diagnostic
consumers; do not convert them into successful evidence verification.

Common fields are the exact 50 names frozen in the contract's final decisions; ACK
has 55 and TIMEOUT has 50 or 51. They include both before/after raw proc bundles and decoded process/namespace summaries, raw
epoch/challenge, original peer credentials, claim/readback, send flags/size/brackets,
accepted_ns and cleanup metadata. Claim attempted/confirmed and send attempted must
be literal true; health/effect/RUN flags literal false; failure_type null; cleanup
count zero, types empty, complete true. Require exactly three distinct nonnegative
signed-32-bit descriptor numbers each labeled OWNED and success literal true.
No ANCILLARY cleanup is allowed for successful exchange evidence. Descriptor
numbers are retained cleanup claims, not handles or proof that close ran; current
records do not independently bind each number to a particular resource/FD operation.

Canonical JSON must round-trip as ASCII, sorted keys, compact separators, with no
nonfinite constants or duplicate keys. Check raw pins before accepting structure.
Evidence bound: 131072 bytes. Reader summary bound: 32768 bytes. Strict canonical
base64 decoding/re-encoding is required for each embedded raw byte string. Bounds:
epoch 32768, challenge/claim/readback/response/fdinfo 4096, stat/status 16384,
boot 64, credentials 12. All structured integers are strict (no booleans), unsigned
and below 2**63 unless the stricter Linux PID/account/FD ABI bounds apply.

Independently validate exact epoch/component shapes and digests, clock/domain,
policy timeout/max-age, sorted unique loss scope and exact challenge pins, boundary,
nonce, baseline and deadline. Independently decode claim and identical claim readback
with exact schema/connection epoch/nested challenge bytes. Matching claim bytes
establish consistency only: no durable consumption or replay-exclusion proof.

Independently parse raw reader/observer stat before/after each edge and status:
PID/start ticks stable, fixed four-account UID/GID vectors, duplicate/missing required
fields refused, reader CapInh/Prm/Eff/Bnd/Amb zero and NoNewPrivs=1. Handle comm with
spaces/parentheses without taking field 22 from a naive whitespace split. Join the
reconstructed identities to each parsed process summary, independently held observer
and caller-pinned reader. Validate one exact fdinfo Pid at each edge, same reader;
raw boot bytes must equal pinned boot ID plus newline. All four namespace summaries
must exactly match the independently held device/inode and epoch inode; this checks
reported joins, not the absent raw fstat/readlink custody. Require exact observed vs
supplied-field inventories, never relabel sensor/source/map pins as fresh evidence.

Reconstruct the reader summary independently and compare its exact canonical bytes
and expected digest. Its process_before/after and clock_before/after equal the pinned
epoch objects; its peer equals decoded SO_PEERCRED; all three nested pins match.
Do not merely compare producer summaries to each other.

### ACK

Require all five packet fields: recvmsg_call_flags, response_base64, controls,
receive_flags, received_ns. Exactly one credentials control item [1,2,base64-ucred]
must match raw peer credentials and pinned reader PID/UID/GID. Independently decode
the canonical exact response schema, three pins, increasing sequence and ack_ns.
Both summary ACK and actual received_ns must match those independently decoded joins.

Require:
`issued <= before_started <= before_finished <= send_started <= send_finished
<= received <= after_started <= after_finished <= accepted < deadline`.
Also `send_started <= ack <= received`; ACK may precede send-return. Send byte count
must exactly equal raw challenge length. All timings must fit strict integer bounds.

### TIMEOUT

Require the common complete record, no response_base64, controls, receive_flags or
received_ns field. recvmsg_call_flags is optional: absent when no recvmsg was tried,
or the exact Linux value when earlier recvmsg returned EAGAIN. No packet returned
in either case. Reader summary status TIMEOUT, ack_ns/received_ns null and sequence
unchanged. Require
`issued <= before_started <= before_finished <= send_started <= send_finished
< deadline <= after_started <= after_finished <= accepted`.
No captured poll/EAGAIN transcript exists, so this establishes a consistent timeout
report, not proof that no message existed or that waits/liveness were correct.

## Result and explicit limits

Return a consistency-only result with status CONSISTENT_READER_EVIDENCE, evidence
and reader digests, reported ACK/TIMEOUT status, and literal false flags:
acquisition_authenticity_verified, sensor_health_verified, effect_authorized,
run_qualified. Invalid records raise ValueError; no effect decision or NOT_SUBMITTED
state is produced. Any later composition must retain INDETERMINATE for possible
submitted effects; post-connect authorization remains a separate policy gap.

Current supplements cannot independently prove socket preflight/nonblocking mode,
PIDFD liveness or socket-derived custody, actual syscall flags/cleanup, durable
consume-once or retention, kernel credential provenance, main-thread identity,
namespace acquisition, protected transport or meaningful reader-loop progress.
The verifier therefore adds independent raw-byte consistency, not acquisition
authenticity. Root owns protected reader/loss/program/map/broker providers and wiring.

## Reviewed focused checks and scheduling gate

Independent positive ACK fixture with ACK before send-return; TIMEOUT with and
without recvmsg invocation; mutation checks for externally held observer, epoch,
connection epoch and ABI; canonical/size/type/base64 limits; malformed/duplicate
proc fields, comm boundaries, changed starts/accounts/caps/boot/fdinfo; namespace
and supplied/observed inventory joins; challenge/claim/readback/pin tampering;
wrong/missing/duplicate credentials and ancillary FDs; Linux invocation/return flags;
ACK/TIMEOUT exact-field separation; sequence/deadline/ordering boundaries; cleanup
and partial failures; reader-summary mismatch; false authority flags; independent
consumer import isolation. Fixtures use no live syscalls/providers or producer code.

Coordinator agreement preceded implementation. Actual stable source/test hashes,
methods and full transitive import closure are submitted below before registration
or execution. Static import review confirms the three-file repository closure.
Handoff is review evidence outside behavior fingerprints.
This additive consumer changes no existing producer/verifier inputs. Preserve
original progress, acquisition and reader-response successes without cache copying
or reruns. The later shared runner change changes pipeline fingerprints; historical
results are not relabeled as successes for those new fingerprints.


## Actual implementation and full closure submission

New verifier independently parses pinned canonical evidence/reader bytes, bounded
base64 payloads, epoch/component/challenge/claim records, little-endian credentials,
proc identities and namespace summaries. It reconstructs the entire reader summary
and requires exact canonical byte equality. Strict type checks or canonical equality
exclude bool/int and float/int aliases. No host socket ABI, sys.byteorder, producer,
private parser, process/clock helper, projection or existing fixture is imported.
No existing callers, exports, schema or producer paths change.

Both TIMEOUT shapes and ACK are complete-record consistency only. In particular,
the serialized supplement exists before retain: even a complete accepted record
cannot establish durable retention or successful leaf return. The output has exactly
the eight frozen result fields, with all four claim flags false. It does not produce
a progress decision, NOT_SUBMITTED, loss counter or continuation authority.

Focused tests build records manually with literal Linux ABI values. Mutation helpers
repin candidate fixture bytes only to reach structural checks after digest checks;
externally held observer/connection/domain pins stay separately controlled. Tests
include coherent observer/namespace substitution, mutable comm/status acceptance,
malformed proc, nested pin and scalar violations, partial/extra fields, ACK before
send-return, both TIMEOUT shapes, credential/control/flag mismatches, deadline and
cleanup failures, complete summary reconstruction and consumer import isolation.
Static AST inspection parsed both new files without importing or executing them.

Exact registered stage (coordinator authored registration and execution release):

```json
{
  "id": "native-run-reader-evidence",
  "description": "Only independent Linux reader supplement byte joins; no native custody, retention, meaningful progress or effect authority",
  "tests": [
    "test_native_phase3_run_reader_evidence_verify"
  ],
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_run_reader_evidence_verify.py",
    "tests/test_native_phase3_run_reader_evidence_verify.py"
  ],
  "needs": [],
  "timeout_seconds": 30
}
```

Stable actual behavioral input inventory, SHA-256 (bare hex):

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
ee6eba09de97df0c1b2f9eeeb74e22849e56d7c876a11daf211e1d626d7abbf0  src/aragorn/native_phase3_run_reader_evidence_verify.py
cec63af8b5ff79cc3096453f8e392e74820ff82c3f905cc92a91971640a8c17b  tests/test_native_phase3_run_reader_evidence_verify.py
```

Actual repository import closure is exactly these three files. Standard-library
roots: ast, base64, copy, hashlib, inspect, json, re, unittest and interpreter-owned
transitives. Consumer source imports only base64/hashlib/json/re. Test source
inspection reads the declared verifier file. No external fixture files, generated
source, subprocess command, runtime producer, protected provider, third-party
package or other repository import. The pipeline additionally binds its own runner,
requirements-worker.lock, interpreter/toolchain and controlled environment.
Contract and this mutable handoff are review evidence outside behavior fingerprints.

The 14 focused methods, all passed on their first behavioral execution:

- `test_ack_before_send_return_and_all_result_ceilings`
- `test_both_timeout_shapes_with_nonnull_peer_and_no_packet`
- `test_exact_field_inventories_refuse_partial_extra_and_packet_timeout`
- `test_caller_pins_observer_connection_and_abi_are_not_taken_from_evidence`
- `test_raw_json_and_base64_are_bounded_canonical_and_unambiguous`
- `test_proc_decoding_ignores_mutable_fields_but_joins_raw_identity`
- `test_namespace_boot_fdinfo_and_observed_inventory_substitutions_refuse`
- `test_claim_challenge_response_and_epoch_tampering_refuse`
- `test_invalid_pinned_epoch_and_challenge_fields_are_still_rejected`
- `test_linux_credential_abi_flags_and_control_inventory`
- `test_chronology_sequence_and_strict_integer_edges`
- `test_failure_cleanup_and_false_flag_contract`
- `test_reader_summary_is_reconstructed_not_trusted`
- `test_independent_consumer_has_only_explicit_standard_library_imports`


Selected command (two scheduled CLI invocations: one pre-stage refusal, then one
changed-runner PASS):
`/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-run-reader-evidence`.
Coordinator owns the registry change; RUN made none. No stage PASS or fingerprint
was produced by the first invocation; the corrected-runner result is recorded below.
Preserve every actual failure/interruption and
diagnose before a changed-input/environment retry.
No historical check has been selected. Original successful evidence remains in
its owning worktree, preserved without copy or refresh:

- Progress: `sha256:1ebdd044c7dd535f86f7fba19322a03a6254e96a8aa81adac0ca153eeb5a7226`.
- Acquisition: `sha256:c135daacf0473b0d2e80cc6f6ebc4671c429a2a3681c3e51433db46abe057ead`.
- Reader response: `sha256:f1fab4f0fbe5eb90a0bdfebc731c576ba28f84db04e66d447767cf8150025e8b`.

Reuse those results only when actual behavioral inputs and relevant environment
match. This consumer is additive; no unrelated test rerun is requested.

## Requirement boundary and checkpoint

The bounded requirement implemented is independent verification of the specified
retained raw-byte joins against a candidate reader summary. Focused validation
passed with the corrected runner as recorded below. This does not close native
acquisition/custody or the 15-entry RUN exit:
seven event classes, six responses and RUN-01/RUN-02 still require full wired
producer/provider and independent semantic paths. Later work waits for published
concrete coordinator contracts and exact path assignments. Meaningful read-loop
progress, loss provenance/reset semantics, causal activation/request/process/cgroup/
capability attribution, pre-effect enforcement, in-flight outcomes and actual
response completion remain explicit integration/provider blockers. No timer
heartbeat substitutes for the reader loop; missing loss remains unknown. A clear
progress window continues other gates only. Possible submitted effects stay
INDETERMINATE; missing receipts never imply non-submission.

Reviewed PASS is complete. Stage only this handoff, the new verifier and its new
test; create one git commit -S, verify-commit HEAD and inspect the tree. The
post-commit report supplies the original signed hash without a self-reference.
Leave local for
coordinator integration. The original reader-response-plan.html stays untracked
and untouched. No private evidence, cleanup or live-operation approval changed.


## Actual scheduling refusal — preserved, no unchanged retry

At HEAD `22c05de348c1585ab9bdf17bf8cc1ba119c7f53d`, after approved hashes matched,
executed exactly the scheduled single-stage command above once. Exit code 2;
tool-reported command interval 0.247275375 seconds; stdout empty. Exact stderr:

```text
phase3 pipeline refused: [Errno 2] No such file or directory: 'native_phase3_admission_policy_tamper.py'
```

At that refusal, no test method executed and
`.aragorn/phase3-pipeline/native-run-reader-evidence/` did not exist; no preflight, started/result JSON, stage logs or fingerprint were
created. Do not invent a stage failure fingerprint. This handoff preserves the
CLI refusal that occurred before the runner's own retention boundary.
Refused-attempt registry SHA-256:
`7d89cade5ebe641165e31e273edbfa854fa7cfd4a045006e81c8c1072afe9302`.
Runner SHA-256:
`dd90f7902bdb805986c9579f5576775e620ba0c21c587adfaf38144864b3bf17`.

Read-only diagnosis: load_registry in scripts/phase3_pipeline.py reads every
registered input at lines 201–203. pipeline calls it at line 725 before applying
selected stage filtering and before state creation. The coordinator's combined
registration includes another lane's not-yet-committed admission source, absent
from this RUN worktree. This is a shared scheduling/environment failure, not a
behavioral failure of the new consumer. The same complete RUN input hashes remain
approved. Do not copy the other lane's drafts, mutate its worktree, edit shared
registry/runner, or retry unchanged. Coordinator received this exact diagnostic
and subsequently supplied the correction
and explicit release below. At the refusal boundary all 14 behavioral checks were
pending; the later PASS does not relabel or erase this failed CLI invocation.


## Changed-runner PASS and completed batch boundary

Published coordinator checkpoint `b4ffd1341e9666e4dd6afb73d322221772eb3684`
contains the selected-closure repair and explicit RUN execution release in
integration-checkpoint-2026-10-12-reader-storage.md. It validates the registry
schema/path/graph globally and reads only the selected transitive closure before
execution. Corrected runner SHA-256:
`46163b06a07679d157d1d37b23a8b627ea52fce1e37808753937ebbfd6edee58`.
This changed input is the documented retry reason. No lane source, test or original
success cache was altered to make the command run, and no other stage was selected.

Actual selected stage: `native-run-reader-evidence`, PASS, exit code 0; 14 unittest
methods in 0.051 seconds. Retained stage interval: 0.103891 seconds. Equal pre/post
fingerprints:
`sha256:855ae03253e17074a4ff66c5e4d060f7906cc70a2b25efadb6ca36492cd655c9`.
Retained directory:
`.aragorn/phase3-pipeline/native-run-reader-evidence/855ae03253e17074a4ff66c5e4d060f7906cc70a2b25efadb6ca36492cd655c9/`.
`stderr.log`: 2829 bytes,
`sha256:a637f2422a9806593a05f053d0a14ba634d864f9199e96920e7ad5c8e4f95c1b`.
`stdout.log`: empty,
`sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
All logs/result JSON remain in this owning worktree. No behavioral failure occurred;
one earlier global-registry CLI refusal is preserved above. No unchanged retry,
historical stage, broad suite, capture, VM/container/service, private-retention or
cleanup operation ran.

Completed: exact ACK/TIMEOUT independent raw-record consumer, source/closure review,
14 focused cases and retained results. The coordinator-owned store/caller and runner
arrived only through published signed fast-forwards and are outside this three-path
lane commit. Root integration and later concrete RUN assignments remain pending.
Matching bytes still cannot establish successful leaf return, durable retention,
PIDFD liveness, meaningful telemetry progress or effect authority. All four result
claim flags remain false. The 15-entry RUN implementation exit remains open.

1. Continue shared causal/provider wiring and retain the unresolved cleanup hold.
2. Integrate this signed slice; complete remaining admission/RUN/workload paths,
   real reader/loss/broker integration and actual unattributed control.
3. Close remaining independent semantic/source-custody gaps in the 48-entry ledger,
   then publish a freeze candidate.
4. Final same-deployment 31-case and 100-attempt/100-pair acceptance, independent
   replay and separately approved cleanup remain blocked on prerequisites/release.
