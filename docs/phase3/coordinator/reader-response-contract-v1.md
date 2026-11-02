# Reader-response interface contract v1

Base: signed integration checkpoint `b3fca83615cd6fd69b463ca8cebcebc660990dec`.
Status: coordinator-supplied design API for one finite, mocked RUN-lane batch.
Release requires a signed combined checkpoint containing this contract and explicit
lane agreement. This document implements no protected endpoint, claim/retention
provider, telemetry reader, loss acquisition or broker wiring. Root owns stage
registration, closure review and scheduling; no test or live operation is scheduled here.

## Exact leaf interface and ownership

```python
acquire_reader_response(
    connection,
    *,
    epoch_raw: bytes,
    challenge_raw: bytes,
    bindings: dict,
    connection_epoch: str,
    consume_once,
    retain,
) -> dict
```

RUN owns the new leaf, its mocked test and handoff. Existing source modules,
schemas, registry, staging, consumers and frozen predecessors remain read-only.
Coordinator supplies trusted callback implementations and the accepted connection.
No listener, daemon, transport fallback, retry framework or replay ledger belongs
in the leaf. Function names and caller labels are metadata, not authentication.

`bindings` has exactly `epoch`, `challenge`, `request`, `process`, `clock`,
`loss_scope`, `policy`, each a lowercase `sha256:` digest held independently by
the caller. `epoch_raw` is canonical ASCII JSON, at most 32768 bytes, matching
the approved acquisition epoch and every component pin. `challenge_raw` is
canonical ASCII JSON, at most 4096 bytes, with exactly the existing seven fields:
`epoch_digest`, `request_digest`, `boundary`, `nonce`, `issued_ns`, `deadline_ns`,
`sequence_before`. Require matching pins, `BEFORE_FIRST_EFFECT`, a 64-lowercase-hex
nonce, strict unsigned signed-63-bit integers and the protected policy deadline.
Reject duplicate/extra fields, booleans as integers, overflow and noncanonical bytes.
`connection_epoch` is a caller-held opaque 64-lowercase-hex value, not an FD/PID or
an assertion supplied by the reader. It identifies this one accepted connection.

## Accepted connection provisioning

Coordinator provides one exclusively borrowed, accepted AF_UNIX/SOCK_SEQPACKET
connection established by the exact reader after assuming its fixed identity.
Its endpoint and permissions come from protected coordinator provisioning; the
leaf accepts no socket path. A supervisor-created socketpair is unsuitable.
SO_PASSCRED must be enabled before traffic; SO_PASSPIDFD must be disabled.
The Python socket must already have `gettimeout() == 0` and be noninheritable.
The leaf validates family/type/options, peer PID/UID/GID and sender custody before
consuming a claim. Blocking/positive-timeout sockets refuse without mode mutation.

Coordinator excludes credential-forging capabilities and unauthorized descriptor
transfer/ptrace in the applicable user/PID namespaces. Fresh reader status must
show fixed UID/GID vectors, zero CapInh/Prm/Eff/Bnd/Amb and NoNewPrivs=1.
No concurrent send/receive, dup, transfer or socket mode/timeout change is allowed
during the call. Coordinator closes/quarantines the connection after every terminal
outcome; neither it nor its connection epoch is pooled or reused.

Use unchanged `runtime_process_profile.open_peer_pidfd(connection, expected_pid)`
and `require_live_pidfd`. Require exactly one native-size SOL_SOCKET/SCM_CREDENTIALS
item per response, matching SO_PEERCRED and the caller-held reader identity.
Connection credentials alone cannot authenticate an inherited-descriptor sender.
This boundary excludes hostile root and cannot prove an authorized reader told
the truth about its sensor checkpoint or that an FD was never copied historically.

## Atomic consume-once callback

```python
consume_once(claim_raw: bytes) -> bytes
```

Canonical `claim_raw`, at most 4096 bytes, has exactly `schema`, `connection_epoch`,
`challenge`; schema is `aragorn/native-phase3-run-reader-claim/v1`, and `challenge`
is the exact seven-field object decoded from `challenge_raw`. Its nested digest
joins remain caller-pinned. Call once after preflight/readbacks, before first send.
Return byte-identical protected readback only after exclusive durable creation,
file/directory fsync and verification. Any different/partial return refuses.

The future root provider keys consumption by challenge digest, preventing reuse
on another connection; it binds the connection epoch in the stored record.
Already present, partial/corrupt or uncertain records refuse. Any callback failure
means no send and no automatic release/retry. Recovery invalidates ambiguous
outstanding challenges; absence of a record after a crash is not permission to reuse.
The callback cannot require the broker lock held by the operation being monitored.
These are provider obligations, not implemented ledger behavior in this document.

Existing protected-file/write/readback conventions are reusable. The broker's
replacing `_atomic_publish_at` and expiring consumed list are not consume-once
implementations; do not treat either as this provider without a separate change.

## Retention callback and failure boundary

```python
retain(evidence_raw: bytes, *, expected_digest: str) -> dict
# Exact acknowledgment: {"digest": expected_digest, "bytes": len(evidence_raw)}
```

Supplemental canonical evidence is bounded to 131072 bytes, independently of the
unchanged 32768-byte acquisition envelope and 4096-byte wire packets. Retain exact
response/proc bytes with lossless encoding, syscall flags, credentials, claim,
clock brackets and cleanup outcomes; never silently truncate evidence into success.
The trusted provider uses a fixed protected sink, content/readback verification
and file/directory fsync before acknowledging. The leaf validates exact fields,
digest and strict byte count; no retention path comes from the reader. Existing CAS
and protected readback/fsync primitives may be reused by a future root adapter.

Return the existing acquisition `reader` record only after required cleanup and a
valid retention acknowledgment. Refusal/interrupt/cleanup/retention failure returns
no usable reader record: raise while preserving bounded partial evidence and the
original failure plus cleanup failures. Do not retry retention or release a claim.
The caller retains any available partial evidence through its existing error path.
Retention proves persistence only; it never extends deadline or freshness policy.

## Readbacks, exchange and real-loop contract

The leaf owns fresh bounded proc/clock observations; tests patch their primitives.
Reuse process start-time/status/virtual-file helpers and suitable primitives from
`native_phase3_clock_domain` for BOOTTIME, boot and held active time namespaces.
Keep socket-derived PIDFD and observer/reader namespace FDs held across the exchange;
recheck liveness/start ticks/boot/accounts and namespace device/inode/named bindings.
Retain the actual bytes used for validation. Do not call the worker/broker-specific
clock observer wholesale or relabel supplied sensor/source/map pins as fresh reads.
The full process record retains its supplied fields; supplemental evidence must
identify the reader/clock fields actually observed and the fields supplied by authority.

Reject prequeued traffic without draining and retrying. Send the pinned challenge
as one record using MSG_DONTWAIT|MSG_NOSIGNAL. Retain send-start/end BOOTTIME brackets;
short/ambiguous send consumes the attempt and refuses. EAGAIN with no delivery may
wait for writability under the original absolute deadline, never resend a delivered record.
Poll connection and held PIDFD, then recvmsg with MSG_DONTWAIT|MSG_CMSG_CLOEXEC,
4097 payload bytes and 4096 ancillary bytes. Reject truncation, EOF, empty/oversize
payload, unexpected flags/control data and malformed/duplicate credentials.
Only MSG_EOR/close-on-exec bookkeeping may be returned. Close every delivered
SCM_RIGHTS/recognized FD-bearing descriptor before refusing; never close arbitrary
integers from unknown control payloads. The borrowed connection stays caller-owned.

Response has exactly `schema`, `epoch_digest`, `challenge_digest`, `request_digest`,
`sequence_after`, `ack_ns`; schema is `aragorn/native-phase3-run-reader-response/v1`.
Require canonical bounded bytes, strict scalars/pins and increasing sequence.
ACK requires `issued_ns <= send_started_ns <= ack_ns <= received_ns < deadline_ns`,
stable final readbacks and final acceptance before deadline; ACK may precede send-return.
Retention must succeed before return and cannot rescue an expired ACK acceptance.
Only a complete no-packet deadline with stable readbacks produces TIMEOUT with null
ack/receive and unchanged sequence. Every partial/foreign/interrupted outcome refuses.
Finite proc byte limits do not establish hard syscall cancellation or return-time bounds.

The actual reader must enqueue one challenge into its telemetry loop, then ACK only
after a subsequent bounded poll/read, successful parse and protected downstream
delivery/accounted backlog. Idle/EAGAIN may count; EOF/error/discarded records or
blocked delivery may not. Increment sequence and stamp BOOTTIME there, never in a
heartbeat/socket-handler thread. No existing publisher is this deployed sensor reader.

Coordinator later supplies genuine loss and serialized submission records and
composes with unchanged `project_acquisition`/`verify_acquisition`. Missing sources
stay pending/unknown; never fabricate zero loss or NOT_SUBMITTED. Post-connect HTTP
continuation and an independent syscall/peer-custody consumer remain separate work.
All sensor-health, completeness, attribution, latency, effect-authority and RUN/
Phase 3 qualification ceilings stay false. The evidence/cleanup hold is unchanged.
