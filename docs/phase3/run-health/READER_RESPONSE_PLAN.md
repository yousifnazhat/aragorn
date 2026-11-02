# Next RUN batch: one authenticated reader response

Planning base: `b3fca83615cd6fd69b463ca8cebcebc660990dec`.
Planning only: no implementation, registry edits, tests or live operations scheduled.
Coordinator task `01a12dd9-a3af-7a10-9a3e-66b049477354` reviewed the transport,
ownership, framing and deadline plan. Design acceptance requires the
send-start/ack chronology and pre-provisioned nonblocking Python socket below;
both corrections are incorporated. The coordinator subsequently supplied the
concrete API contract below, and RUN reviewed and agreed it. Design agreement
does not implement trusted providers or authorize implementation before release.

## Concrete coordinator API agreement

RUN read and agrees [reader-response-contract-v1.md](../coordinator/reader-response-contract-v1.md),
supplied in the main coordinator checkout. Reviewed bytes have SHA-256
`7a9592f9f885cf6e0c508a095804ccc20bed0108dd39b843592c0f60c38bc777`.
This is agreement on that document's API and obligations, not deployed evidence.
The coordinator will include it with this plan in a combined signed checkpoint;
implementation still requires that checkpoint and explicit coordinator release.

Exact leaf interface:
`acquire_reader_response(connection, *, epoch_raw, challenge_raw, bindings, connection_epoch, consume_once, retain) -> dict`.
The canonical epoch is bounded to 32768 bytes, challenge to 4096 bytes, with the
seven independently held binding pins already used by the acquisition consumer.
connection_epoch is a caller-held 64-lowercase-hex identifier for this one accepted
connection; it is neither a descriptor nor a reader-provided assertion.

`consume_once(claim_raw: bytes) -> bytes` accepts at most 4096 canonical bytes with
exact fields schema, connection_epoch, challenge. Schema is
`aragorn/native-phase3-run-reader-claim/v1`; challenge is the exact existing object.
Require byte-identical protected readback after exclusive durable creation and
file/directory fsync, before any send. Provider keys consumption by challenge
digest across connections. Partial, prior, corrupt or uncertain state refuses;
failure never releases or retries the claim. Replacing publication and expiring
replay lists do not implement this obligation.

`retain(evidence_raw: bytes, *, expected_digest: str) -> dict` accepts supplemental
canonical evidence bounded to 131072 bytes and acknowledges exactly
`{"digest": expected_digest, "bytes": len(evidence_raw)}` with a strict integer
byte count, after protected write/readback/fsync. Raw response/proc bytes are
losslessly retained alongside flags, credentials, claim, brackets and cleanup.
Return a usable reader record only after required cleanup and valid retention.
Failure raises with bounded partial evidence and the original error plus cleanup
failures; it never retries retention or supplies a successful reader record.

Fresh reader status must have fixed account vectors, zero CapInh/Prm/Eff/Bnd/Amb
and NoNewPrivs=1, with exact coordinator-held namespace and process authority.
The leaf owns actual reader/observer proc-clock readbacks, preserving which fields
were observed versus supplied. The real loop's checkpoint advancement and genuine
sensor/source/program/map/loss evidence remain coordinator obligations.

Review found no conflict with the accepted framing, nonblocking, sender/PIDFD,
ancillary cleanup, one-use, send-start chronology or partial-state requirements.
The actual trusted callbacks, endpoint, reader loop, broker latch and independent
syscall/peer-custody verifier remain absent. No implementation/test stage is released.

## Outcome and finite scope

Add one leaf that acquires a challenge response from a coordinator-provisioned
connection, authenticates the actual sender, retains bounded observations and
emits the reader portion of the existing acquisition record. It does not create
a listener, daemon, service framework, projection replacement or sensor loop.
The existing independent acquisition consumer remains the record/decision join.

Proposed new lane paths: `src/aragorn/native_phase3_run_reader_response.py`,
`tests/test_native_phase3_run_reader_response.py`, and a lane handoff. Existing
tracked modules remain read-only. Additional changes require coordinator review.

## Agreed interface ownership; provider implementation pending

| Boundary | Coordinator provides | RUN leaf owns |
|---|---|---|
| Protected transport | Already accepted, exclusively borrowed AF_UNIX SOCK_SEQPACKET connection, established by the exact reader; protected endpoint/permissions, SO_PASSCRED enabled before traffic, non-inheritable descriptors, capability/namespace restrictions | Validate socket type/options, peer credentials, per-message credentials and held socket-derived PIDFD; one exchange only |
| Sensor stream and loop | Exact sensor-stream identity; real bounded read/poll/parse/delivery checkpoint, idle polling, no heartbeat-thread substitute; sensor/program/map/loss custody | Accept only the exact challenge response with increasing checkpoint sequence; do not claim to observe the reader's loop directly |
| Challenge custody | Atomic persistent consume-once operation for epoch/request/boundary/nonce/digest; exact source of issued_ns and policy timeout; no broker-lock dependency in reader acknowledgement path | Invoke consume-once before sending; never release/retry a consumed claim after any failure |
| Process/clock authority | Caller-held process/start/source/config/clock pins; provisioned readable proc namespace; authentic sensor identity evidence | Fresh bounded reader process and observer/reader time-namespace readbacks before and after the exchange, bracketed by live-PIDFD checks |
| Retention and composition | Existing protected retention sink, remaining epoch/loss/submission records, raw-byte inventory and independent caller pins | Return/retain raw response, kernel credential readbacks, process/clock brackets and partial failures; supply only acquired reader fields |
| Broker/HTTP | Serialized submission latch and recovery policy; separate post-connect continuation policy | Never infer NOT_SUBMITTED or authorize continuation; possible submitted effects remain INDETERMINATE |

SOCK_SEQPACKET is the agreed control framing, not a decision about the sensor's
telemetry stream format. No SOCK_STREAM fallback or byte-stream framing adapter
is included. Use a connection opened by the reader, not a supervisor-created
socketpair whose connection credentials identify a different process. Coordinator
must affirm this endpoint can supply SO_PEERPIDFD on the selected kernel.

## Kernel sender and process custody

Use `runtime_process_profile.open_peer_pidfd(connection, expected_pid)` and
`require_live_pidfd(fd)` unchanged. The first helper obtains SO_PEERPIDFD, checks
its fdinfo PID, checks liveness and closes its descriptor on failure. It is not
equivalent to opening a PIDFD from an untrusted PID after the receive.

Read exact SO_PEERCRED PID/UID/GID and compare all three with caller pins. Hold the
returned PIDFD through receipt, readbacks and output validation. Recheck liveness
before/after each sensitive read and receive; retain the original error if cleanup
also fails. Close only the leaf-owned PIDFD/readback descriptors; the coordinator
owns closing/quarantining the borrowed connection after the single invocation.
No fork, process signal, reconnect or recovery loop belongs here.

Every response requires exactly one SOL_SOCKET/SCM_CREDENTIALS record of native
ucred size, with PID/UID/GID equal to SO_PEERCRED and the caller-pinned reader.
JSON sender claims never substitute. A child or other process sending through an
inherited/transferred descriptor has a different sender PID and must refuse,
including when the original peer is still alive. CLOEXEC alone does not prevent
fork inheritance. The leaf cannot prove an FD was never copied if the original
authorized process remains the sender; do not claim historical exclusive custody.

Kernel credential overrides by privileged processes are a distinct prerequisite:
coordinator provisioning must exclude relevant credential-forging capabilities
and unauthorized FD-transfer/ptrace access in the applicable user/PID namespaces.
Fresh reader status readbacks must match fixed UID/GID vectors and agreed capability
restrictions; namespace mapping must be exact, not translated from a supplied PID.
This protects against an unauthorized sender, not hostile root or a compromised
authorized reader lying about its checkpoint. Missing custody prerequisites refuse.

Bound reader `/proc` reads by existing helper limits (16 KiB status/stat), verify
start ticks and boot ID, and hold active time-namespace FDs while comparing device,
inode and named readbacks. Reader and observer must use the same CLOCK_BOOTTIME
domain. Reuse suitable primitives from runtime_process_profile and
native_phase3_clock_domain, not the worker/broker-specific public observer wholesale.
The complete import closure includes their existing transitive imports and must
be reviewed before scheduling; the known shared import-cycle repair remains shared.
Source, sensor and program/map digests remain coordinator inputs, never fabricated
from PID liveness. Retain the distinction between fresh reads and supplied pins.

## One challenge and one bounded response

Wire request is exactly the existing canonical challenge object, without a
length prefix or outer wrapper: epoch_digest, request_digest, boundary, nonce,
issued_ns, deadline_ns, sequence_before. Its digest is the expected challenge
pin; the reader echoes that digest, not a self-selected nonce. One request and
one ACK packet are each bounded to 4096 bytes. This does not reduce or replace
the existing 32768-byte retained acquisition envelope limit.

Borrowing is exclusive for the entire call: no other receiver/sender, no dup or
ownership transfer, no socket mode/timeout mutation. Use per-call nonblocking
flags AND require the borrowed Python socket already has `gettimeout() == 0`,
checked before consuming the challenge claim. Reject `None` (blocking) or any
positive timeout; never call settimeout/setblocking to repair it. Positive Python
timeouts can invoke CPython's own readiness wait despite MSG_DONTWAIT, so the
per-call flag alone is insufficient. Coordinator closes or quarantines the connection after every terminal
outcome; it is not returned to a pool or reused for another challenge.

1. Validate the exact caller-held challenge bytes/digest, epoch/request pins,
   BEFORE_FIRST_EFFECT boundary, nonce, baseline and absolute BOOTTIME deadline.
   Require gettimeout()==0, validate socket options/peer, obtain PIDFD and collect
   initial readbacks before the challenge claim; no socket mode mutation.
   Check no response is queued before issue; do not drain a stale packet and retry.
2. Call the coordinator's agreed atomic consume-once interface before first send.
   Its concrete provider remains a shared prerequisite. Claim
   includes connection epoch and request identity; crash or interrupted retention
   never makes it reusable. The leaf adds no independent replay ledger.
3. Send the pinned challenge as one record, at most 4096 bytes, with
   MSG_DONTWAIT | MSG_NOSIGNAL. Retain actual send_started_ns immediately before
   the send attempt that delivers the packet, and send_finished_ns immediately
   after return. Any short/ambiguous send consumes the attempt and refuses;
   never resend after possible delivery. EAGAIN before any send waits only within
   the same absolute budget. Reader checkpoint ack must follow challenge receipt.
4. Poll connection plus held PIDFD using remaining deadline, then receive one
   packet using recvmsg with MSG_DONTWAIT and MSG_CMSG_CLOEXEC. Payload buffer is
   4097 bytes to detect an over-limit record; control buffer is fixed and bounded
   (4096 bytes). Reject MSG_TRUNC, MSG_CTRUNC, EOF, oversized/empty payload,
   missing/duplicate/malformed credentials or any unapproved control type.
   Accept only MSG_EOR and the close-on-exec bookkeeping flag if returned by
   recvmsg; all other returned flags refuse. Only one SOL_SOCKET/SCM_CREDENTIALS
   control item is accepted, with exactly native struct ucred bytes; all other
   items refuse after required delivered-descriptor cleanup.
5. Ancillary FDs are forbidden. If recvmsg installs SCM_RIGHTS or other recognized
   FD-bearing ancillary descriptors, close all delivered descriptors before
   refusing, including on truncation/parser failure. Coordinator must disable
   automatic ancillary PIDFD passing; rely on SO_PEERPIDFD instead. Recognized
   FD-bearing messages still get cleanup if returned. Never close arbitrary
   integers from unknown control payloads. No silently ignored ancillary data.
6. Parse one canonical ASCII JSON response <=4096 bytes with exact fields:
   schema=`aragorn/native-phase3-run-reader-response/v1`, epoch_digest,
   challenge_digest, request_digest, sequence_after, ack_ns. Reject duplicate keys,
   extra fields, booleans as numbers, noncanonical encoding and integer overflow.
   Match every pin. sequence_after must exceed challenge.sequence_before.
   Require issued_ns <= actual send_started_ns <= ack_ns <= actual received_ns
   < deadline_ns for success, all in the strictly joined clock domain. Keep
   send_finished_ns separately: ACK can occur before send returns, so do not
   require send_finished_ns <= ack_ns. A timestamp predating actual send refuses;
   do not replace an old acknowledgement timestamp with receive time.
7. Recheck PIDFD, sender identity, process and clock readbacks and absolute deadline
   before producing success. No wait or syscall retry resets the BOOTTIME budget.
   A suspended observer or final readback that crosses the deadline cannot succeed.
   Reader EOF/death/restart/namespace change is refusal, never clean TIMEOUT.

The absolute budget bounds nonblocking readable/writable/PIDFD waits and acceptance.
Finite proc-read byte limits do not prove a hard return-time bound for kernel
readbacks. Any required hard cancellation guarantee must use an agreed existing
coordinator supervision boundary; it is not supplied by a unit-test timeout or
a new service introduced by this leaf.

The native leaf is deliberately stricter than the retained window's ability to
describe a late response: retain late bytes as refusal evidence, not successful
reader acquisition. Only a complete no-packet deadline with stable process/clock
readbacks can produce the existing TIMEOUT form (null ack/receive and unchanged
sequence). Partial, malformed, foreign, interrupted or cleanup-failed acquisition
stays refusal with partial evidence. No refusal conveys a blocked/effect-free claim.

## Existing consumer composition and independent limits

Produce the existing reader record with actual SO_PEER/SCM credential joins,
before/after process/clock observations, real receive timestamp and authenticated
response sequence/ack. Keep supplemental raw bytes, syscall flags, credentials,
claim receipt, timing/readback records and cleanup status in bounded retained
evidence. Kernel-installed FD numbers are cleanup facts, never reusable handles.

Coordinator composes this reader record with genuine epoch/challenge/loss and
serialized submission records. Then use existing project_acquisition and feed
the exact retained bundle/window/decision to verify_acquisition with independent
caller pins. The new leaf must not invent zero loss or NOT_SUBMITTED to make a
bundle pass. Missing prerequisites mean composition is pending, not successful.
The existing consumer must not import the acquisition leaf. It validates raw
record consistency but does not yet independently prove syscall/peer provenance;
the retained custody evidence and its eventual independent consumer stay explicit.

No wrapping of HTTP's post-connect callback: submitted/unknown outcomes remain
INDETERMINATE even with a valid acknowledgement. No sensor-health, completeness,
response-latency, attribution or RUN qualification flag is enabled by this batch.

## Proposed mocked checks — review first, nothing scheduled

Use fake socket/poll/proc/clock/claim/retention boundaries and patched existing
PIDFD helpers. Never socketpair/connect/fork/spawn, real proc reads, real PIDFDs,
services or captures. No direct unittest or pipeline execution is authorized here.

| Proposed check group | Required observations |
|---|---|
| Valid acquisition | Exact peer + message credentials, held PIDFD ordering, genuine readback mapping, one claim/send, increasing sequence; retain actual bytes then compose with fabricated owned-test inputs into existing independent consumer |
| Sender custody | Same UID/wrong PID, wrong UID/GID, inherited-child/transferred-sender PID with original alive, peer PIDFD mismatch/exit, privileged/namespace prerequisite refusal |
| Ancillary and cleanup | Missing/duplicate credential, malformed ucred, rights/PIDFD injection, truncated control/payload, delivered-FD cleanup even on failure, no closing borrowed connection or arbitrary unknown integers |
| Framing | Wrong family/type, gettimeout() None/positive refused before claim or send, zero accepted without mode mutation, prequeued packet, EOF, oversized/empty/noncanonical/duplicate-key response, unexpected schema or extra fields; no drain-and-retry |
| Deadline/identity | Deadline equality, partial send, repeated EAGAIN/EINTR under original budget, ACK predating send-start refused, ACK before send-return permitted, suspend/time jump, stale ack, sequence replay/reset, changed start ticks/boot/clock or late final readback |
| One-use/partial state | Claim already spent; claim failure means no send; interrupted send/receive/retention never releases claim; failed cleanup retains original refusal and partial evidence |
| Existing consumer join | Raw request/challenge/process/clock mutation refuses; unknown loss stays unknown; submitted/unknown remains INDETERMINATE; leaf absent from independent consumer imports |

Exact test methods, source/fixture/transitive closure and registry row will be
submitted only after interface agreement and implementation review. Preserve
the existing c135daac acquisition and 1ebdd044 progress successes unchanged.

## Planning completion and remaining gates

Coordinator accepted the corrected plan direction and supplied the concrete v1
API contract. RUN agrees that contract as recorded above. Before implementation,
the coordinator must publish the combined signed checkpoint and explicitly release
the finite mocked batch. Actual protected provisioning, trusted consume-once and
retention providers, reader checkpoint integration, genuine loss/program/map
sources, broker latch and independent custody verification remain shared gaps.
No design agreement proves those providers exist or approves live operation.
This documentation-only batch runs no behavioral tests and changes no runtime,
registry or existing PASS evidence. Sign only this plan; preserve the local HTML
unchanged. The post-commit report supplies the verified hash and working-tree state.

1. Shared runtime integration and evidence/cleanup hold remain unresolved.
2. Remaining admission/RUN/workload implementation includes this planned native
   leaf and shared real reader, loss/program/map and broker-latch prerequisites.
3. Independent verifier inventory and same-deployment custody/freeze remain open.
4. Final 31-case and 100-attempt/100-pair acceptance remains blocked.

References: local runtime_process_profile.py:94/197, native_phase3_clock_domain.py,
and native_phase3_run_acquisition_verify.py at the planning base. Linux socket
credential/message-boundary details: [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html).
Receive flags and close-on-exec semantics: [recv(2)](https://man7.org/linux/man-pages/man2/recvmsg.2.html).
