# Broker reader evidence and submission contract v1

Status: reviewed offline contract, released only by the containing signed
`provider-release-v4.md` checkpoint. That checkpoint names the base and exact
Root/Admission implementation assignments. No stage, endpoint, protected write
or operational action is released. No active lane path is assigned implicitly.

The ready scope is the exact IPC envelope and a durable broker submission
journal with independent replay. It supplies no reader, loss or health verdict.
Real provider acquisition and positive broker authorization remain gated by the
listed prerequisites. A parser accepting evidence is not a health decision.

## Ownership and ready scope

After explicit signed release, the coordinator owns only these new paths for
this slice:

- `src/aragorn/native_phase3_broker_reader_protocol.py`: strict packet codec and
  request/response binding checks, using only the standard library.
- `src/aragorn/runtime_http_run_submission.py`: exclusive immutable broker
  journal, exact state transitions and frozen acquisition submission snapshots.
- `tests/test_native_phase3_broker_reader_protocol.py`
- `tests/test_runtime_http_run_submission.py`
- `docs/phase3/coordinator/broker-reader-provider-handoff.md`

The existing Admission owner receives exactly these three new paths as an
independent support assignment after the signed release and agreement:

- `src/aragorn/native_phase3_run_submission_verify.py`: independent transcript
  consumer; standard library only, no producer/parser/runtime import.
- `tests/test_native_phase3_run_submission_verify.py`: independent fabricated
  bytes, with no producer codec, journal, fixtures or private parser imports.
- `docs/phase3/admission/SUBMISSION_REPLAY_HANDOFF.md`

Root owns this contract, registry changes, integration and source inventories.
The existing RUN listener assignment and reader-evidence consumer do not change.
Do not edit frozen broker, transport, reader response/store/acquisition or tests.

The following exact integration paths are reserved to Root, **not released** by
this slice: `src/aragorn/native_phase3_broker_reader_service.py`,
`src/aragorn/native_phase3_broker_reader_client.py`,
`scripts/materialize_runtime_http_run_guard.py`, and
`tests/test_runtime_http_run_guard.py`. Their release requires the actual provider
and deployment bindings below. A renderer is justified only for finite hooks in
the existing pinned HTTP broker and its inventory, not for a new generic framework.

## Scalar and byte rules

All records are exact-key canonical ASCII JSON: sorted keys, compact separators,
no duplicate keys, nonfinite values, extra fields or trailing bytes. `uint` means
strict integer, excluding Boolean, in `[0, 2**63)`. A `pin` is exactly
`sha256:` plus 64 lowercase hexadecimal digits. A `nonce` is 64 lowercase hex
characters representing 32 freshly generated random bytes. Base64 must decode
strictly and re-encode identically. Every bound below applies before JSON parsing
or base64 allocation; nested decoded bounds apply afterward.

`process` has exactly `pid,start_time_ticks,uid,gid`: PID is 1..2147483647,
start ticks a positive uint, accounts 0..4294967295. `namespace` has exactly
`device,inode`: device uint, inode positive uint. `clock` has exactly
`boot_id,clock_id,time_namespace`; boot ID is the lowercase canonical kernel UUID,
clock ID is `CLOCK_BOOTTIME`, and time_namespace is the namespace record.

An `artifact` is null or exactly `{"base64":str,"bytes":uint,"digest":pin}`.
Non-null artifacts require nonempty decoded bytes, exact length/digest and the
specific bound below. Its digest proves matching bytes only.

## Fixed endpoint and independent identity inputs

The only planned broker endpoint is
`/run/aragorn-phase3-broker-reader/guard.sock`, Linux AF_UNIX/SOCK_SEQPACKET.
Its separate parent is necessary: the reader's existing proposed
`/run/aragorn-phase3-reader/challenge.sock` parent belongs to the reader group,
not the broker group. Do not repurpose that parent or widen its permissions.

Provision the broker endpoint parent root:broker-GID 0710 and socket
root:broker-GID 0660. Ancestors are root-owned and not group/world writable.
Reader evidence remains root:root 0700 under `/var/lib/aragorn-phase3-reader`;
its immutable files remain 0400. The broker retains its existing non-root UID/GID.
The actual numeric broker account and service executable/source pins must come
from the reviewed deployment binding, never an incoming packet or account-name
lookup accepted without that binding. This contract does not invent those values.

The future owning client/accepted server must hold nofollow ancestry and named
socket identities, enforce nonblocking and noninheritable descriptors, set and
check PASSCRED=1/PASSPIDFD=0, validate SO_PEERCRED, socket-derived PIDFD liveness,
fresh raw process identity and boot/time namespace, and inspect each packet's
SCM_CREDENTIALS. Supported credential ABI is exactly `linux-le-ucred32-v1`:
12 bytes, signed little-endian PID32 and unsigned UID32/GID32. One credentials
item `[SOL_SOCKET=1, SCM_CREDENTIALS=2, raw]` is required. Reject all other controls
and flags except Linux EOR/CMSG_CLOEXEC; close every installed ancillary FD before
refusal. Sender flags are DONTWAIT|NOSIGNAL; receiver flags DONTWAIT|CMSG_CLOEXEC.
Kernel support and actual message-size limits are deployment prerequisites.

There is one fresh broker connection per actual request, no pooling or reconnect.
The broker generates `exchange_id` internally after expected peer validation;
this is distinct from the root-to-reader connection epoch and challenge nonce.
It closes its connection once on every terminal outcome. The root closes its
accepted connection once. Cleanup failure prohibits usable success and preserves
original/retention/cleanup failures without ambiguous close retries.

The root provider runs on its original root main thread and calls the existing
owning reader acquisition through the separately implemented accepted-reader
transport. It must never take the broker serialization lock, publish broker
health through that lock, or wait for a participant that needs it. The broker
must not execute the root-only reader store itself.

## Exact packet schemas

Request bound: 4096 bytes. Schema:
`aragorn/native-phase3-broker-reader-request/v1`.

Exact fields are `schema,exchange_id,phase,context_digest,epoch_digest,request_digest,
effect_digest,deadline_boottime_ns,previous_response_digest`.
All digest fields are pins, except previous_response_digest may be null as below.
The deadline is a positive uint. `phase` is exactly `BEFORE_CONNECT` or
`BEFORE_PAYLOAD_SEND`. The first request has a null previous response; the second
has the exact digest of the first response. The exchange, context, epoch, request,
effect and deadline are identical across both phases. No request supplies a
reader nonce, sequence, clock observation, loss count, callback or file path.

Response bound: 262144 bytes. Schema:
`aragorn/native-phase3-broker-reader-response/v1`.

Exact fields are `schema,request_packet_digest,exchange_id,phase,context_digest,
epoch_digest,request_digest,effect_digest,received_ns,finished_ns,status,error_codes,
reader_connection_epoch,bindings,reader_evidence,reader_summary,reader_retention,
loss_record,checkpoint_record,acquisition_authenticity_verified,sensor_health_verified,
effect_authorized,run_qualified,phase3_qualified`.

- All five flags ending in `_verified`, `_authorized` or `_qualified` are false:
  acquisition_authenticity_verified, sensor_health_verified, effect_authorized,
  run_qualified and phase3_qualified. No `healthy`, `allow` or replacement health
  Boolean is accepted.
- Echoed identity fields match the exact request. request_packet_digest is the
  digest of its original bytes. Timestamps are uint with
  `received_ns <= finished_ns`; usable response receipt also requires both within
  the request deadline in the independently checked same clock domain.
- status is `EVIDENCE` or `REFUSED`. EVIDENCE means the requested evidence was
  acquired/retained through the real owning source path; it is not an ACK, health
  verdict, authorization or qualification. TIMEOUT/loss/reset may legitimately
  be evidenced and must still block authorization.
- error_codes is a sorted unique list of at most 8 values from the exact enum
  below. EVIDENCE requires an empty list; REFUSED requires a nonempty list.
- reader_connection_epoch is nonce or null. bindings is null or exactly the
  seven existing pins `epoch,challenge,request,process,clock,loss_scope,policy`.
  Its epoch/request match this request. The independent reader evidence consumer
  must verify all other component joins before later health use.
- reader_evidence is an artifact bounded to 131072 decoded bytes;
  reader_summary to 32768; loss_record to 8192; checkpoint_record to 16384.
  Total packet bound still applies even when each nested artifact fits.
  reader_summary is opaque original bytes to this structural codec/journal.
  Before any real health use, the existing independent
  `verify_reader_evidence` must reconstruct and verify its exact frozen schema
  from reader_evidence against independently held observer/connection/binding
  pins. The codec cannot manufacture or trust a summary ACK/sequence/clock field.
- reader_retention is null or exactly `{"digest":pin,"bytes":uint}` and must
  match reader_evidence. It records the actual successful owning reader call's
  retained readback, not a digest calculated to excuse a failed call. The frozen
  leaf can serialize ACK-looking bytes before retention fails: those bytes may
  appear in REFUSED, with null retention and a RETENTION/CLEANUP error.
- EVIDENCE requires all four artifacts, bindings, reader connection epoch and
  reader_retention non-null. REFUSED preserves each actually available bounded
  item and uses null for unavailable items. No fabricated empty record or zero
  count fills an unavailable slot.

The loss artifact uses the frozen acquisition loss object's exact fields:
`epoch_digest,challenge_digest,request_digest,scope_digest,before,after`.
Each sample is null or `start_ns,end_ns,counters`; counters is an ordered list of
1..32 uint-or-null values. start/end are uint with start<=end; two present samples
have the same counter count. Binding pins match the response bindings, including
scope_digest=bindings.loss_scope. Missing values stay null, decreases retain
reset evidence, increases retain loss evidence. The real semantic consumer must
also establish the pinned scope's exact ordering, membership and length.
Canonical shape/pin agreement does not establish that these counts were acquired.

The checkpoint artifact remains an opaque, bounded original byte artifact at the
wire layer. Its acquisition and independent semantic schema are explicitly
unreleased prerequisites. The protocol parser cannot return a checkpoint-valid
Boolean, choose a parser from the packet, or authorize on its presence.

Exact error enum: `INPUT_REFUSED,IDENTITY_CHANGED,CLOCK_REFUSED,DEADLINE_EXPIRED,
READER_UNAVAILABLE,READER_REFUSED,LOSS_UNAVAILABLE,CHECKPOINT_UNAVAILABLE,
RETENTION_FAILED,CLEANUP_FAILED,PROTOCOL_REFUSED,INTERNAL_REFUSAL`.
These are observed failure classes, not proof that no effect happened. Malformed
or unauthenticated packets need not receive a reply; preserve bounded local
failure evidence and close. No exception text or credentials are placed on wire.
Datagram truncation, oversized messages, partial sends, unexpected EOF, replay,
out-of-order phase and late arrival refuse without message/effect retry. Waiting
for initial readiness under the original deadline is permitted; an attempted
exchange that returns ambiguous or incomplete data is never repeated.

The ready codec APIs are:

```python
validate_guard_request(raw: bytes) -> dict
validate_guard_response(raw: bytes, *, request_raw: bytes) -> dict
```

They are pure structural/binding validators and return detached parsed records;
invalid input raises ValueError. They cannot connect, acquire, publish or produce
an effect decision. A caller must separately establish actual peer identity.

## Clock and budget contract

For this bounded HTTP slice, the proposed required epoch policy is exactly
`timeout_ns=100000000,max_age_ns=200000000`. These are fixed offline contract
values, not observed performance results. A deployment using another epoch must
refuse or receive a separately reviewed contract change; no runtime override.

The existing overall HTTP monotonic deadline remains at most 0.5 seconds and is
never reset. All new readings use `clock_gettime_ns(CLOCK_MONOTONIC)` and
`clock_gettime_ns(CLOCK_BOOTTIME)`, returning strict integer nanoseconds. If the
existing caller deadline is a finite float in seconds, convert exactly once via
its integer ratio `(n,d)`: `original_deadline_ns=(n*1000000000)//d`. An integer
seconds deadline is multiplied exactly. Never round upward or subtract sampled
floating-point clocks. The original deadline value comes from the owning broker,
not a packet. At guard creation take BOOTTIME `b1`, MONOTONIC `m`, BOOTTIME `b2`;
require stable independently pinned boot/time namespace and `b1 <= b2`.
`remaining=original_deadline_ns-m` must be positive and at most 500000000. Derive wire deadline
`b1+min(remaining,500000000)` and refuse if it is already expired at b2. Retain
the bracket and original deadline. Recheck both clocks before each boundary;
neither clock's expired budget may be reset, widened or translated using an
assumed fixed offset. BOOTTIME expiration across suspend cannot extend authority.

Root may use at most 250000000 ns from its actual receipt for BEFORE_CONNECT,
100000000 ns for BEFORE_PAYLOAD_SEND, and never beyond the original wire deadline.
These caps do not promise that a filesystem syscall finishes by its deadline.
The broker independently times out; any late ACK/retention/response refuses.

The first reader window must close: before-loss ends no later than challenge
issuance; after-loss begins at or after the challenge deadline; the broker's
submission snapshot follows the after sample. An early ACK cannot shorten this
window. Before payload, reuse only the same immutable reader evidence/summary,
bindings, reader connection epoch and successful retention receipt while the
original ACK remains younger than max_age. Obtain fresh loss-after/checkpoint and
identity evidence; preserve the original before-loss baseline. No second
BEFORE_FIRST_EFFECT challenge can be issued after connect. A new payload-specific
challenge would need a different published schema and independent consumer.

No measurement claims are released. Source-integrated provider work must be
included before the existing first DECISION_FINALIZED stamp, retaining the
original REQUEST_ACCEPTED stamp. Payload revalidation gets its own additional
timestamp and cannot replace the full required interval.

## Durable broker journal and ready owning API

The fixed journal parent is the existing broker control directory
`/var/lib/aragorn-runtime-action/control`; confirm the active config resolves to
that literal. It is broker-UID:broker-GID 0700. Borrow the existing held control
and lock descriptors; do not open another lock or accept caller-selected paths.
Require the original Linux broker main process/thread, all real/effective/saved
accounts matching the independently pinned non-root broker and stable held/named
ancestry, lock and directory identities. Failed custody poisons the guard.

Matching metadata alone does not establish a held lock. Freeze the Linux v6.8
fdinfo FLOCK subset for local checking: read `/proc/self/fdinfo/<lock_fd>` as
bounded ASCII (maximum 4096 bytes), with exactly one each of `pos`, `flags`,
`mnt_id`, `ino` and one `lock` record, and no other fields. Decimal pos/mount/inode
and octal flags must be bounded nonnegative integers. The lock value, split on
ASCII spaces/tabs, must be exactly `1: FLOCK ADVISORY WRITE <pid>
<hex-major>:<hex-minor>:<decimal-inode> 0 EOF`. PID equals the current pinned broker
PID, device components equal `os.major/minor(fstat(lock_fd).st_dev)`, and both
inode values equal held/named lock inode. Reject duplicate/missing records,
unknown fields, blocked arrows, leases, POSIX/OFD/read locks or malformed bytes.
The local ordinal 1 is not a permanent lock identity. Pin mount ID for this guard.
Require O_RDWR and CLOEXEC/noninheritability; fdinfo flags must equal actual
F_GETFL flags with O_CLOEXEC added from F_GETFD. Read and join these observations
at begin and before/after each mutation and final readback. Never invoke flock
to validate or reacquire custody. Require the original broker to acquire its own
lock; inherited/foreign-owner locks refuse.

These reads prove only held-at-read state. The trusted original single-owner
broker call path must prohibit unlock/reacquire, close/reopen, dup/transfer and
concurrent use until this guard closes. Repeated fdinfo cannot detect an arbitrary
unlock/relock between observations. Retain the begin/latest raw fdinfo bytes in
bounded local custody observations and partial exception evidence. They are not
a new persistent transcript or independent lock-attestation claim. Production
integration must review the whole interval and its original finally cleanup.

ABI sources: Linux v6.8 [proc fdinfo implementation](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/proc/fd.c),
[lock record implementation](https://raw.githubusercontent.com/torvalds/linux/refs/tags/v6.8/fs/locks.c)
and [kernel fdinfo documentation](https://www.kernel.org/doc/html/v6.8/filesystems/proc.html#proc-pid-fdinfo-fd-information-about-opened-file).
This source profile is an offline parser contract; matching the deployed kernel
and mount/proc custody remains an integration prerequisite.

The context is canonical and <=8192 bytes with exactly:
`schema,request_digest,effect_digest,grant_digest,deployment_digest,epoch_digest,
broker,provider,clock,exchange_id,accepted_boottime_ns,deadline_boottime_ns,
clock_bracket`.
Schema is `aragorn/native-phase3-broker-reader-context/v1`. broker/provider are
the process records above; provider UID/GID are zero, broker UID/GID positive and
distinct from the runtime/reader identities. All named digests are pins, exchange
is nonce, and timestamps are uint. clock_bracket has exactly
`boottime_before_ns,monotonic_ns,boottime_after_ns,original_monotonic_deadline_ns`.
It records actual same-process observations used by the budget rule above.
Require `accepted_boottime_ns <= boottime_before_ns <= boottime_after_ns <=
BOUND.checked_ns < deadline_boottime_ns`. Later event timestamps never decrease;
only TERMINAL may be recorded at or after the deadline, retaining ambiguity.

The context's expected digest, broker/provider identities and clock are held
outside candidate packets. The future owning caller derives them from actual
accepted v4 grant/measurement context, protected deployment configuration and
fresh process/clock observations. Merely accepting these values as JSON arguments
is not an acquisition implementation. The ready store enforces the local actual
broker/descriptor joins; provider/deployment provenance remains a separate gate.
The existing config has expected_broker_uid but no expected_broker_gid. Join that
UID to the independently pinned context broker UID, and use the pinned context
broker GID with actual saved/effective/real GIDs and file GIDs. Do not invent a
config attribute or trust packet-supplied account identity.

```python
begin_http_submission_locked(
    control_fd: int, lock_fd: int, config,
    *, context_raw: bytes, expected_context_digest: str,
) -> SubmissionJournal

journal.record_check(phase: str, *, request_raw: bytes, response_raw: bytes)
journal.record_connect_intent()
journal.record_payload_intent()
journal.submission_snapshot() -> bytes
journal.finish(*, transport_raw: bytes | None, failure_code: str | None)
journal.final_readback()
journal.close()
```

These methods own new journal file descriptors and any new read-only nofollow
ancestor/active-namespace handles needed to hold their actual identities. Close
each owned handle once; never release or close the borrowed broker lock/control.
Context validation/custody failures raise
a bounded custom exception preserving the original error, cleanup failures,
last completed event, known intent and partial bounded bytes. Failed publication
or cleanup prohibits return as usable success. The store never returns an ALLOW
Boolean. An intent method documents the owning broker's imminent action; it
cannot treat structurally valid packets as authorization to invoke that action.

Names are `run-reader-<request hex>-context.json`,
`run-reader-<request hex>-event-<sequence>.json`, and
`run-reader-<request hex>-packet-<packet digest hex>.json`; no caller filename.
Store context first and refuse any existing context/record, including identical
bytes, links, directory or partial file. Record bytes are <=8192; request/response
packets have the bounds above; transport bytes are <=32768. All are single-link
regular broker-UID:broker-GID 0400 files, exclusively created with NOFOLLOW,
CLOEXEC, fsync(file), fsync(parent), and exact held/named readback before return.
Retain identities/descriptors for final rereads. Never overwrite, remove, rename,
recover, expire or retry a partial/existing journal. Reuse safe existing writes,
but not publication helpers that accept identical existing content.

An event has exactly `schema,context_digest,sequence,previous_digest,phase,
checked_ns,request_packet_digest,response_packet_digest,transport_digest,
failure_code,intent,effect_possible`. Schema is
`aragorn/native-phase3-broker-submission-event/v1`; sequence is 0..5, previous
digest null only at zero, checked time is actual CLOCK_BOOTTIME uint and does not
decrease. Packet/transport pins are null unless required by the phase; failure
code is null except terminal. Retain the complete original packets before the
event naming them. A maximum of six events and five packets is allowed; the
complete replay input is bounded to 786432 bytes, counted exactly as
`len(context_raw)+sum(map(len,events_raw))+sum(map(len,packets.values()))`.
Count each original byte value once, even when multiple events reference it.
The packet map has at most five unique pin keys; every key equals the digest of
its bounded value. At most two request packets, two response packets and one
transport packet are allowed, with no unreferenced extras. Nested decoded artifact
bounds still apply; they are not additional bytes in this raw transcript sum.

Exact transitions:

| Phase | Permitted successor | Evidence and submission meaning |
| --- | --- | --- |
| `BOUND` | `CONNECT_CHECKED` or `TERMINAL` | First event; packet pins null, intent=false/effect_possible=false only for this current guarded pre-connect state. |
| `CONNECT_CHECKED` | `CONNECT_INTENT` or `TERMINAL` | Exact BEFORE_CONNECT packet pair retained; both flags remain false. The owning caller must independently complete every health/policy check before choosing intent. |
| `CONNECT_INTENT` | `PAYLOAD_CHECKED` or `TERMINAL` | Durable intent=true/effect_possible=true before callback 1 returns True. No later downgrade is permitted. |
| `PAYLOAD_CHECKED` | `PAYLOAD_INTENT` or `TERMINAL` | Exact BEFORE_PAYLOAD_SEND pair referencing the first response; already SUBMITTED regardless of health outcome. |
| `PAYLOAD_INTENT` | `TERMINAL` | Durable payload intent before callback 2 returns True; flags remain true. |
| `TERMINAL` | none | After connect intent both flags are true; before intent intent=false/effect_possible=null. Opaque HTTP bytes cannot certify non-submission. |

Only CHECKED events have request/response pins; only TERMINAL may have a transport
pin/failure code. Outside TERMINAL, intent/effect_possible are literal false for
BOUND/CONNECT_CHECKED and literal true for CONNECT_INTENT/PAYLOAD_CHECKED/
PAYLOAD_INTENT. No integer substitutes or other nulls are valid. A terminal after
any intent retains true/true even when later transport reports NOT_PERFORMED.

`record_check` checks every packet echo against context, including the unchanged
wire deadline. It reads actual BOOTTIME and requires context bracket end <=
response.received_ns <= response.finished_ns <= checked_ns < wire deadline,
the exact phase duration cap, and checked_ns-response.finished_ns <200000000.
Intent methods repeat current clock/custody guards and refuse a REFUSED response,
late/expired/stale packet, changed previous response, or any phase/context/pin
substitution. BEFORE_PAYLOAD_SEND must repeat the first response's reader
evidence, summary, bindings, reader connection epoch and retention receipt
exactly; its previous response pin must match the retained first response.
Its loss baseline and epoch/challenge/request/scope bindings are unchanged;
only fresh after-loss and checkpoint artifacts may differ. Intent requires both
loss samples present, every counter non-null and every after counter equal to
its corresponding before counter. Reject missing or reset/lost counters,
retaining original evidence unchanged. These shape/value checks do not establish
real scope completeness or loss acquisition.

For BEFORE_PAYLOAD_SEND, response receipt must be at or after the retained
CONNECT_INTENT.checked_ns. For either phase, each present fresh after-loss sample
must satisfy `response.received_ns <= loss.after.start_ns <= loss.after.end_ns <=
response.finished_ns`; the first before-loss sample remains unchanged in phase
two. These are required independent replay joins as well as journal checks.
A newly wrapped old loss-after sample cannot stand in for fresh acquisition.

Packet freshness is not reader freshness. Real authorization still requires the
independent reader consumer and actual checkpoint/loss/source providers, including
the original verified ACK's own max-age; those cannot be replaced by recent packet
timestamps or record_check success. This is why production wiring remains gated.

Check repetition, skipped/reversed phase and context/packet substitution refuse.
Once intent is true it stays true through deadline, transport, retention and
cleanup failure. Durable intent must finish before an owning callback may permit
an effect. failure_code uses the IPC enum plus `POLICY_REFUSED,TRANSPORT_REFUSED,
TRANSPORT_INDETERMINATE,JOURNAL_REFUSED`. A null terminal code requires preceding
PAYLOAD_INTENT and non-null transport bytes; it records the caller's terminal
observation, not an independently verified successful HTTP effect.

This slice treats transport_raw as opaque bounded canonical original HTTP bytes.
Neither journal nor independent transcript consumer certifies NOT_SUBMITTED from
it, including from an unverified status string or false connect_attempted field.
Before durable connect intent, a terminal transcript therefore remains UNKNOWN;
after intent it remains SUBMITTED. Full independent transport semantics can be
joined later through the existing HTTP result consumer under a separate release.

submission_snapshot uses the actual held current state and clock to emit exactly
the frozen acquisition fields `epoch_digest,challenge_digest,request_digest,
checked_ns,custody,intent,effect_possible`. It requires a completed checked reader
binding; unavailable facts refuse instead of inventing a challenge digest.
The owning caller must assemble and independently verify the frozen acquisition
bundle's closed window using this actual checked timestamp before authorization;
snapshot creation itself performs no health decision. Custody EXCLUSIVE is valid only in this
uninterrupted locally checked lock interval. An independent transcript consumer
cannot use an open journal prefix or absent terminal record as NOT_SUBMITTED:
it reports known SUBMITTED if a verified intent exists, otherwise UNKNOWN.

## Owning caller integration and failure propagation

In the future exact rendered `runtime_http_broker.mediate_observed_http`, create
the journal after original replay consumption has been durably committed and
the initial policy permits continuing, while the original broker lock is held.
The shared accepted v4 context must supply the fixed expected epoch/grant/provider
bindings; missing context refuses. No optional runtime callback substitutes.

At callback 1, the fixed client acquires the BEFORE_CONNECT response, the journal
retains it, and real independent reader/checkpoint/loss/source consumers plus the
existing broker policy/revocation checks decide whether execution may continue.
First-phase progress requires NOT_SUBMITTED and no health reasons. Only then
publish connect intent and return True. Include provider work in the full first
decision timing; preserve the original acceptance boundary.

At callback 2, connect has already been attempted. Obtain the second fixed
response, retain fresh loss/checkpoint/identity evidence, recheck original ACK
age and policy, and publish payload intent only if all checks permit proceeding.
The frozen progress evaluator reports INDETERMINATE for SUBMITTED even with no
health reasons; preserve this state and separately evaluate those health reasons.
Never demand CONTINUE_OTHER_GATES here or change the snapshot to NOT_SUBMITTED.

The caller wraps the actual transport return or exception, retaining its actual
bounded observation. A second-callback refusal, short send, disconnect, late or
malformed reply, absent terminal receipt, journal uncertainty or post-intent
cleanup failure propagates as RuntimeActionEffectIndeterminate with evidence.
The original error survives alongside cleanup/retention failures. Never release
the consumed request or grant to retry. Journal close/final readback occurs before
the original broker lock cleanup; failure after known intent must also set the
outer effect-possible classification so existing finally paths cannot downgrade it.

These call sites are concrete integration obligations, not released production
wiring. Until real protected providers and their independent consumers exist,
the new journal/codec must not be installed as a successful health gate.

## Independent replay and selected validation

The independent API is:

```python
verify_submission_transcript(
    context_raw: bytes, events_raw: list[bytes], packets: dict[str, bytes],
    *, expected_context_digest: str, expected_request_digest: str,
    expected_broker: dict, expected_provider: dict, expected_clock: dict,
    expected_terminal_digest: str | None,
) -> dict
```

Validate all exact schemas, canonical bytes, bounds, identities, request/effect
joins, packet digests, phase order, sequence/previous hashes, timing and monotonic
intent independently. Decode protocol bytes independently; do not import its
producer codec or use its test fixtures. Reconstruct submission classification
and distinguish a complete terminal transcript from a consistent open prefix.
Missing packets needed by an event refuse; an expected terminal digest mismatch
refuses. A null expected terminal allows only prefix analysis, never a completed
or unsubmitted claim. An intent prefix yields SUBMITTED; otherwise UNKNOWN.

Return exactly `status,context_digest,last_event_digest,submission_state,
acquisition_authenticity_verified,sensor_health_verified,effect_authorized,
run_qualified,phase3_qualified`. status is CONSISTENT_TERMINAL_TRANSCRIPT or
CONSISTENT_OPEN_PREFIX; submission_state is SUBMITTED or UNKNOWN by this bounded
consumer, and all five flags are false. NOT_SUBMITTED is reserved for the actual
owning broker's guarded pre-connect snapshot, not retained transcript inference.
No hostile-root resistance,
OS-lock attestation, real loss completeness or sensor qualification is inferred.

Before execution, Root reviews stable source and complete actual imports,
generated-source/fixture dependencies and independent fixtures. Focused cases
must cover exact protocol/bounds/ABI labels, altered echoes/pins/order/deadlines,
refused partial ACK-shaped evidence, unknown/reset/lost loss, immutable duplicate
and partial journal publication, fsync/readback ordering, named/held substitution,
owner/mode/links, fork/thread/closed reuse, every state transition, second-guard
failure, absent/foreign/read/malformed fdinfo locks, changed flags/mount IDs,
response sampled before connect intent, copied/out-of-bracket loss-after,
accepted/bracket/BOUND chronology, missing/open terminal state,
independent replay disagreement and cleanup
ambiguity. Use mocks/fresh fabricated bytes only. Root alone registers/schedules
the newly necessary stage; no historical suite or live exchange is released.

## Remaining production prerequisites and source anchors

1. Root provider service/binary/source closure, actual broker account, service
   PID/start identity acquisition, exact protected epoch/config/grant context and
   original accepted-request timestamp propagation remain undeployed/unimplemented.
2. RUN's actual reader listener, per-request notification, stream/bridge custody,
   meaningful read-loop checkpoint and independent checkpoint schema/consumer
   remain prerequisites. This packet contract does not invent that schema.
3. Real loss/program/map before/after acquisition and complete applicability,
   including bridge/queue/delivery failures, must be assigned. A numeric loss
   object supplied by a mock or caller cannot release positive authorization.
4. Root must implement and independently review the fixed IPC client/server,
   actual credentials/PIDFD/namespace custody, socket provisioning and receive-size
   support. Numeric account/process/build values come from the actual paired
   deployment; no JSON credential or guessed installed hash satisfies them.
5. Root must establish that the fixed 100 ms window, 200 ms ACK age and provider
   phase budgets can meet the existing 0.5 second total bound without broadening
   authority. Offline tests do not establish this performance/deployment fact.
6. Only after those contracts/implementations exist may Root release finite broker
   hooks, updated units/source/identity inventories and changed composition checks.
   All operational/private-retention/cleanup holds remain explicit.

Reviewed repository anchors: `runtime_http_broker.py:253` (replay), `:285`
(two authorization callbacks), `:330` (first final decision), `:354` (indeterminate
transport), `:412` (outer cleanup); `runtime_http_action.py:37` (0.5 seconds),
`:413` (before connect), `:417` (connect), `:421` (before payload), `:423`
(unknown send count); `native_phase3_run_acquisition.py:94,:123,:133,:140`
(closed window, loss interval, reset and submission projection);
`native_phase3_run_progress.py:72` (submitted ambiguity);
`native_phase3_run_reader_store.py:82` (root-only original owner);
`runtime_broker_decision_measurement.py:114,:263,:326` (non-root broker, accepted
timestamp and finalized timestamp). All paths above are under `src/aragorn/`.
The full rendered successor and dependency closure still require integration
review; source anchors are not deployed identity evidence.

Completed by this contract: exact ready protocol/journal/replay scope and future
owning call sites. Released: only after Root signs/publishes v4. Blockers: the six
production prerequisites above. Remaining Phase 3 sequence: (1) wire real shared
providers, (2) complete/integrate all admission/RUN/workload paths, (3) finish
independent replay and deployed custody before freezing, (4) separately authorize
the final campaign, qualification evaluation and verified cleanup.
