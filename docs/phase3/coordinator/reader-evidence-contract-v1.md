# Reader evidence consumer contract v1

Coordinator contract based on reviewed lane proposal SHA-256 `ca55553eb430dff8e02c127d2d2097134e964c3ac9222173afcec8fe8bd508bd`.
Base: `27e9844e6d5f0924b79382a8a084099ee06e2ed6`.
The coordinator decisions at the end override proposal wording below.
Publication releases only the listed offline implementation files after the owner
verifies and fast-forwards to the signed checkpoint. No test execution is released.

## Reviewed proposal and provider obligations

Base: `27e9844e6d5f0924b79382a8a084099ee06e2ed6` on
`codex/phase3-run-health`. This proposal precedes implementation. No tests,
registration, provider changes or live operations are scheduled by this document.

## Proposed API and ownership

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

## Linux credential ABI agreement required

Propose one supported caller-selected ABI: `linux-le-ucred32-v1`. Exactly 12 bytes,
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

Common fields are exactly the current successful leaf's evidence fields, including
both before/after raw proc bundles and decoded process/namespace summaries, raw
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

## Proposed focused checks and scheduling gate

Independent positive ACK fixture with ACK before send-return; TIMEOUT with and
without recvmsg invocation; mutation checks for externally held observer, epoch,
connection epoch and ABI; canonical/size/type/base64 limits; malformed/duplicate
proc fields, comm boundaries, changed starts/accounts/caps/boot/fdinfo; namespace
and supplied/observed inventory joins; challenge/claim/readback/pin tampering;
wrong/missing/duplicate credentials and ancillary FDs; Linux invocation/return flags;
ACK/TIMEOUT exact-field separation; sequence/deadline/ordering boundaries; cleanup
and partial failures; reader-summary mismatch; false authority flags; independent
consumer import isolation. Fixtures use no live syscalls/providers or producer code.

After coordinator agreement, submit the actual stable source/test hashes, exact
methods and full transitive import closure before any registration or execution.
Proposed closure is just package __init__, new verifier and new test; this must be
confirmed from actual code. Handoff is review evidence outside behavior fingerprint.
No existing PASS is invalidated by this additive consumer; reuse progress,
acquisition and reader-response results unchanged, without cache copying or reruns.

1. Shared runtime integration/HTTP repair and cleanup approval remain unresolved.
2. RUN adds only this proposed independent retained-evidence consumer; real protected
   reader/loss/broker providers and remaining admission/RUN/workloads stay pending.
3. Full verifier inventory and deployed custody/freeze remain pending.
4. Final 31-case and 100-attempt/100-pair acceptance remains blocked.

## Coordinator decisions and exact release

The proposed API, independently held observer and connection identity, fixed
little-endian Linux ABI, chronology and three-file ownership are accepted.
Only complete-record byte consistency is released. The following exact inventory
resolves the proposal's reference to current producer fields. Do not discover
the schema by importing or calling the producer.

There are 50 common evidence fields: these 26 fixed names,

```text
schema status claim_attempted claim_confirmed send_attempted
sensor_health_verified effect_authorized run_qualified
epoch_base64 challenge_base64 connection_epoch
observed_fields supplied_process_fields peer_credentials_base64
claim_base64 claim_readback_base64
send_started_ns send_call_flags send_finished_ns send_bytes accepted_ns
failure_type cleanup_failure_count cleanup_failure_types
cleanup_failure_types_complete descriptor_cleanup
```

plus these 12 names with each of the `before_` and `after_` prefixes:

```text
started_ns pidfd_info_base64
reader_stat_before_base64 reader_status_base64 reader_stat_after_base64
observer_stat_before_base64 observer_status_base64 observer_stat_after_base64
boot_base64 namespaces finished_ns processes
```

ACK has exactly 55 fields, adding `recvmsg_call_flags, response_base64, controls,
receive_flags, received_ns`. TIMEOUT has 50 or 51, permitting only the optional
recvmsg flag and forbidding the other four packet fields. Schema is exactly
`aragorn/native-phase3-run-reader-evidence/v1`. Both require send_finished_ns
strictly before deadline. All exact nested key inventories are:

- Epoch: `process, clock, loss_scope, policy, deployment_digest`.
- Process: `boot_id, reader_pid, reader_start_ticks, sensor_pid,
  sensor_start_ticks, reader_uid, reader_gid, sensor_uid, sensor_gid,
  reader_source_digest, sensor_source_digest, stream_digest, program_map_digest`.
- Clock: `boot_id, clock_id, time_namespace_inode`.
- Policy: `timeout_ns, max_age_ns`, positive; max_age supplies no new freshness decision.
- Challenge: `epoch_digest, request_digest, boundary, nonce, issued_ns,
  deadline_ns, sequence_before`.
- Claim: `schema, connection_epoch, challenge`.
- Each edge processes: `reader, observer`, each `pid, start_time_ticks, uid, gid`.
- Each edge namespaces: `reader, observer`, each `device, inode`.
- ACK response: `schema, epoch_digest, challenge_digest, request_digest,
  sequence_after, ack_ns`.
- Reader: `epoch_digest, challenge_digest, request_digest, process_before,
  process_after, clock_before, clock_after, peer, status, sequence_after,
  ack_ns, received_ns`; peer is non-null `pid, uid, gid`, even on TIMEOUT.

Exact arrays, including order:

```json
{"observed_fields":["reader_pid","reader_start_ticks","reader_uid","reader_gid","boot_id","clock"],"supplied_process_fields":["program_map_digest","reader_source_digest","sensor_gid","sensor_pid","sensor_source_digest","sensor_start_ticks","sensor_uid","stream_digest"]}
```

Pin and independently validate every nested field, not just equality of summaries.
Compare decoded proc identities, not entire mutable stat/status bytes. Namespace
device may be zero; inode is positive. The result has exactly `status,
evidence_digest, reader_digest, reader_status, acquisition_authenticity_verified,
sensor_health_verified, effect_authorized, run_qualified`, with the four flags
literal false and status `CONSISTENT_READER_EVIDENCE`.

Material limit: the producer serializes its supplement BEFORE retention. A
retention failure may leave complete ACK/TIMEOUT evidence while the leaf raises
and returns no reader. Matching candidate bytes proves neither successful leaf
return nor retention. Optional TIMEOUT recvmsg flags prove neither an actual
EAGAIN nor absence of a packet. No missing native event may be inferred.

Owner may implement the three proposed new files after verifying the published
signed checkpoint and confirming agreement. Submit stable source and actual
closure before one new focused stage is registered and scheduled. No producer,
provider, historical test, live operation or registry edit is released to the lane.
