# Connected reader loop and Root checkpoint session: contract v1

Status: **reviewed contract, source-released only by the containing signed
provider-release-v8.md checkpoint**. Root approves the decisions below and names
exact internal owners in that release. No new stage, live operation, private
retention or cleanup is authorized. Actual stable source and full dependency
closure require Root review before any selected execution. External RUN retains
its separate v7 DNS assignment; this contract grants that lane no reader paths.

The completed checkpoint acquisition/independent consumer is the dependency, not
a suite to rerun. The next slice must connect a real consuming loop, actual source
publication and the existing protected acquisition in one reviewed path. No
builder-only delivery, injected read/health callback or synthetic responder is
an implementation exit.

## Final coordinator decisions

1. Select **syntax-only NDJSON custody** for this slice. Preserve every complete
   valid JSON-object record regardless of event variant. Do not route the stream
   through the selected process-only `_event` parser or discard unknown variants.
   This replaces only the unreleased future-writer parser paragraph in
   `reader-checkpoint-contract-v1.md`; its implemented artifact schemas, limits,
   acquisition and independent consumer remain unchanged. Vendor schema,
   attribution, all-event coverage and upstream completeness remain UNKNOWN.
2. Define `previous_checkpoint_digest` as the preceding successfully acquired
   **manifest digest**, never the Root acquisition-record digest. The reader
   knows its immutable manifest; Root additionally holds the separate acquisition
   digest and uses only a successfully verified acquisition to advance its state.
3. Add reader FD8 for a publication-completion pipe. A manifest can appear before
   its publication receipt; pathname existence cannot trigger the one-shot Root
   acquisition. Completion is an availability notice after final writer custody
   and close checks, not another reader-health ACK or a substitute for readback.
4. Select FD7 as an anonymous EOF cancellation pipe. A separate pinned Root
   supervisor owns its sole writer; reader and Root session each hold an explicit
   read end. No cancellation bytes are sent. This permits cancellation observation
   without a truth callback or cross-thread descriptor close. Individual syscalls
   and the frozen accepted-reader call still have no hard return-time guarantee.
5. Release writer and Root session together to **separate internal Root owners**.
   Both must have a concrete caller path and focused composition coverage before
   either is called connected. The Root broker service, actual launcher and
   installed-source acquisition remain separately owned prerequisites, not
   evidence manufactured by these APIs.

These approved implementation choices do not establish an actual launcher,
supervisor, acquired stream inventory or installed identity. The separately
published source release determines ownership; this is not operational permission.
No additional gate framework is introduced.

## Exact paths and public APIs

Internal writer owner, coordinator worktree only:

- `src/aragorn/native_phase3_run_reader_checkpoint.py`
- `tests/test_native_phase3_run_reader_checkpoint.py`

Internal Root session owner, coordinator worktree only:

- `src/aragorn/native_phase3_run_reader_checkpoint_session.py`
- `tests/test_native_phase3_run_reader_checkpoint_session.py`

Root owns a future `docs/phase3/coordinator/reader-session-handoff.md`, this
contract, registry, launch/service/inventory and integration changes. No existing
parser, response, listener, store, broker codec, acquisition or verifier file is
assigned for modification. In particular, no process-parser wrapper is needed
for the selected syntax-only profile.

```python
run_reader_checkpoint_loop(
    *, epoch_raw: bytes, expected_epoch_digest: str,
    checkpoint_provision_raw: bytes, expected_checkpoint_provision_digest: str,
    transport_provision_raw: bytes, expected_transport_provision_digest: str,
    stream_inventory_raw: bytes, expected_stream_digest: str,
    loop_provision_raw: bytes, expected_loop_provision_digest: str,
    observer_pidfd: int, bridge_pidfd: int, supervisor_pidfd: int,
) -> dict

class ReaderCheckpointSession:
    def __init__(self, *, epoch_raw: bytes, expected_epoch_digest: str,
                 checkpoint_provision_raw: bytes, expected_checkpoint_provision_digest: str,
                 transport_provision_raw: bytes, expected_transport_provision_digest: str,
                 stream_inventory_raw: bytes, expected_stream_digest: str,
                 loop_provision_raw: bytes, expected_loop_provision_digest: str,
                 notice_write_fd: int, reader_pidfd: int, refresh_write_fd: int,
                 completion_read_fd: int, cancel_read_fd: int): ...

    def acquire_challenge(self, *, context_raw: bytes, expected_context_digest: str,
                          request_raw: bytes, admission_digest: str,
                          request_received_ns: int) -> dict: ...
    def acquire_refresh(self, *, context_raw: bytes, expected_context_digest: str,
                        request_raw: bytes, first_response_raw: bytes,
                        expected_first_response_digest: str,
                        request_received_ns: int) -> dict: ...
    def finish_request(self, *, expected_context_digest: str) -> bytes: ...
    def close(self) -> bytes: ...
```

The loop exclusively owns inherited reader FDs3..8 and the three distinct PIDFDs
at numbers >=9. It accepts no arbitrary FD map, command, endpoint, filename,
parser or callback. Session construction exclusively receives its five distinct
descriptors, each >=3. It transfers `notice_write_fd` and `reader_pidfd` once into
the actual `ReaderListener`; after transfer that owner alone closes them. The
session opens and owns its own additional process/namespace handles as needed,
never borrowing the listener's owned PIDFD or calling its private guard methods.
Record ownership before metadata reads and consume it before any close. Reject
duplicate descriptors. Never close a foreign descriptor after number reuse.

Both APIs run on their original process/main thread, never after fork or through
reentry/concurrent calls. The loop requires the expected restricted non-root
reader; the session requires the expected Root observer with all real/effective/
saved UID/GIDs zero. The source entrypoints are the functions above, called by a
future reviewed fixed launcher/provider. There is no arbitrary CLI, environment
override or import-by-packet dispatch. The launcher must supply protected bytes
and independent expected pins; hashing the arguments inside an entrypoint does
not create that authority.

## Scalars, acyclic inventories and observation limits

Use the frozen checkpoint scalar rules: exact-key canonical ASCII JSON, sorted
compact keys, no duplicate/nonfinite values, strict uint excluding Boolean,
lowercase SHA256 pins and 64-hex nonces. Existing epoch <=32768 bytes, checkpoint
and transport provisions <=8192 each, and broker context/request/response use
their published bounds and schemas unchanged. New control frames are canonical
ASCII plus exactly one LF, <=2048 bytes including LF; digest the LF too. Reject
extra records, trailing bytes, unsupported fields or duplicate keys.

New `stream_inventory_raw` is canonical ASCII <=16384 bytes, exactly:

```text
schema session_id reader bridge sensor observer supervisor clock
source_inventory_digest access_inventory_digest pipes
upstream_continuity upstream_socket_digest upstream_loss_digest
```

Schema: `aragorn/native-phase3-reader-stream-inventory/v1`. Each process uses the
frozen `pid,start_time_ticks,uid,gid` record. Reader/bridge are distinct non-root
accounts and PIDs; sensor/observer/supervisor are Root, with distinct PIDs. This
slice selects a separate supervisor and observer. Clock is exactly
`boot_id,clock_id,time_namespace`, with namespace `device,inode`, using the
checkpoint provision's BOOTTIME rules. `source_inventory_digest` and
`access_inventory_digest` are protected
deployment pins. `upstream_continuity` is UNKNOWN and both upstream digest fields
are null. Sensor/source values are **expected supplied identities**, not observed
socket, installed executable, loaded BPF or source-authenticity evidence.

The inventory deliberately contains no epoch or loop-provision digest: epoch
`process.stream_digest` already pins these bytes. This avoids a hash cycle. Join
reader/sensor PID/start/account fields to the corresponding epoch process fields.
The epoch clock is `boot_id,clock_id,time_namespace_inode`: compare shared boot
and clock IDs and map its inode to the new clock's time_namespace.inode. The new
time_namespace.device is independently provisioned/observed, never an invented
epoch field. Checkpoint provision pins the same stream, reader, observer,
session, full clock and source inventory. The access pin equals both provisions'
access_inventory_digest. Transport observer additionally has time_namespace:
compare its four process fields and that separate namespace, not whole objects
of different schemas. The aggregate source_inventory_digest cannot equal an
individual epoch reader_source_digest by assumption. Epoch source/program pins
remain supplied authority; their per-source joins await the actual pinned source-
inventory schema/launcher and installed-byte acquisition, not this inventory.

`pipes` is exactly six ordered entries NOTICE, TELEMETRY, REFRESH, STDERR,
CANCEL, COMPLETION. Each entry is exactly
`role,device,inode,mode,uid,gid,writer,readers`. Writer is one
`{"process":role,"fd":uint}`; readers is an exact list of the same endpoint shape.
Process roles are READER, BRIDGE, OBSERVER, SUPERVISOR. All six are distinct
anonymous FIFOs, Root:Root, mode FIFO0600, positive inode; their endpoints are:

| Pipe | Sole writer | Ordered readers |
| --- | --- | --- |
| NOTICE | OBSERVER, `notice_write_fd` | READER, 3 |
| TELEMETRY | BRIDGE, 1 | READER, 4 |
| REFRESH | OBSERVER, `refresh_write_fd` | READER, 5 |
| STDERR | BRIDGE, 2 | READER, 6 |
| CANCEL | SUPERVISOR, provisioned FD >=3 | READER, 7; OBSERVER, `cancel_read_fd` |
| COMPLETION | READER, 8 | OBSERVER, `completion_read_fd` |

Root-side endpoint numbers come from actual provisioning and equal the supplied
API descriptors; they are not universal constants. Reader PIDFD arguments are
not pipes and must not alias them. Notice identity equals the frozen transport
provision's notice pipe. Launch creates/transfers these descriptors once, closes
every unlisted duplicate before readiness and prohibits later duplication or
transfer. Sole-writer history is a trusted launch/source obligation; FD scans do
not establish hostile-root resistance or historical absence of copied handles.

`loop_provision_raw` is canonical ASCII <=8192 bytes, exactly:

```text
schema epoch_digest checkpoint_provision_digest transport_provision_digest
stream_digest session_id startup_deadline_ns session_deadline_ns max_requests
```

Schema: `aragorn/native-phase3-reader-loop-provision/v1`. All pins match the
independent expected arguments. Session ID is the inventory/checkpoint nonce.
Require startup_deadline < session_deadline; session deadline equals both
existing provisions, and max_requests equals transport max_requests (1..4096).
Listener epoch is minted inside the existing listener and becomes fixed at the
first valid FD3 notice; it is not another input or part of this inventory cycle.

Before readiness and around each read/publication/control boundary: actual
nonblocking access mode, noninheritability, FIFO fstat identity and exact
`pipe:[inode]` self-FD link must match. Root additionally checks peer FD/fdinfo
joins and pinned reader/bridge/supervisor PIDFD associations/liveness with fresh
stat/status/stat observations, namespaces and boot. Reader checks its own saved
account vectors, all five capability sets zero, NoNewPrivs=1, active namespace,
boot, owned PIDFD associations/liveness and accessible peer process start/account
sources. The launcher clears supplementary groups for both non-root roles before
their exec. The reader verifies its own `getgroups()==[]`; Root verifies empty
`Groups` in its actual reader and bridge status observations. This is an explicit
new local guard, not a change to a frozen helper or evidence schema. No additional
supplementary-group pin set is invented for already privileged Root roles.
Reader is **not** required to bypass access controls to Root's private
FDs or namespaces; those joins are Root acquisition/launch obligations.
Unsupported/denied required observations refuse, never become supplied truth.
Keep the existing FD3 evidence ceiling: the transport supplement contains parsed
reader/writer flags and both pipe-link strings, not raw reader-FD3 fdinfo bytes.
Do not add an undeclared field or claim independent replay can reconstruct that
missing parse. Root's new guards must actually check their additional handles;
the transport supplement is not independent proof of every inventory FD.

Set CLOEXEC only after intentional exec transfer. No process-wide umask/socket
timeout mutation. Pin source directory ancestry using the existing provision;
reader opens only `/`, `/var`, `/var/lib`, and its 0700 source directory. It never
opens the Root archive/store. All actual clock stamps are BOOTTIME in the held
boot/namespace, nondecreasing, within session/request bounds before and after
blocking observations. Root never relabels a later session-entry stamp as the
earlier broker request receipt.

## Startup, cancellation and completion frames

After full loop preflight, emit exactly one FD8 startup frame:

```text
schema session_id epoch_digest loop_provision_digest stream_digest ready_ns
```

Schema: `aragorn/native-phase3-reader-loop-ready/v1`; ready_ns is actual BOOTTIME
after preflight. Require send completion before startup_deadline. Root waits for
this exact frame under that original deadline, independently checks the live
reader/FD joins and only then constructs `ReaderListener`. The reader has no
startup connection; the listener's fixed path need not exist before this frame.
Startup readiness proves only this local initialization, not sensor subscription.
Retain the actual startup frame for the full lifetime. Root also retains the
public `ReaderListener.opening_evidence_raw` after successful construction; if
construction raises, retain only its actual `ReaderTransportError.partial_evidence`.
Never read private listener state or reconstruct a missing opening record.

Every successful immutable publication emits exactly one FD8 frame:

```text
schema session_id epoch_digest phase ordinal request_digest challenge_digest
trigger_digest sequence_after manifest_digest publication_digest batch_digest completed_ns
```

Schema: `aragorn/native-phase3-reader-checkpoint-ready/v1`. Phase is CHALLENGE or
REFRESH; ordinal is that phase's notice/command ordinal, not the checkpoint
sequence. Pins name exact published bytes; completed_ns is observed after file
and parent fsync, exact readback, final custody and successful closure of the
three publication descriptors. No pathname or health Boolean is present.

FD8 and FD5 writes are one nonblocking `os.write` of a whole <=PIPE_BUF frame;
check actual PIPE_BUF. Consume the operation before writing. EAGAIN, EINTR,
short/ambiguous writes or failed final guards poison the session; no retry. Pipe
reads may assemble fragments within a <=2048-byte accumulator, checking identity
and clocks around each read. First-fragment assembly is limited to 100000000 ns
and the existing active/startup/session deadline, whichever is earlier. A parsed
notice/command must additionally meet its original issued/deadline fields; this
assembly bound cannot extend those. Multiple queued frames or any excess byte
refuses rather than draining it into another request.

FD7 has no frame schema: EOF is cancellation. Read readiness followed by EAGAIN
is not cancellation; any data is a protocol error. HUP/ERR/NVAL or supervisor exit
ends eligibility. Cancellation/process-exit flags take priority over a concurrent
completion or telemetry event. Root's frozen `accept_request` does not accept a
cancellation FD; while it runs, the reader observes FD7 and closes/exits, causing
the existing socket/PIDFD path to refuse. Root checks cancellation before and
after that call. No prompt-return guarantee is inferred for a blocked syscall.

## Actual reader loop and byte accounting

One original main loop owns notice, refresh, challenge socket, telemetry, stderr,
completion writer and cancellation. Use finite poll waits under the earliest
active/session deadline; check cancellation/PIDFD/errors, stderr and control work
before each bounded telemetry quantum. No timer thread or independent ACK loop.
Any stderr byte terminates this conservative slice after retaining a bounded
prefix <=65536 bytes; stderr EOF/error also terminates. This selected bridge
profile must be silent on stderr; compatibility remains unmeasured. Never parse
stderr into readiness, ignore warnings or invent zero errors.

All positive FD4 reads use counts <=65536, preserve every returned byte and have
actual BOOTTIME brackets. Accumulate at most 262144 bytes, 256 complete records
and 63 DATA-read entries between checkpoints, reserving one entry for final
EAGAIN. Lifetime limits remain 4194304 bytes/4096 records. Accounting includes
bytes held in an incomplete tail; exhaustion poisons instead of rotating/resetting
or dropping data. Read through actual EAGAIN after a trigger. Earlier zero-byte
EAGAIN observations need not enter the manifest; **every positive DATA read must**.
The manifest is not advertised as a trace of every zero-byte syscall.

Syntax profile: strict UTF-8, one JSON object per LF-inclusive record, no BOM,
CRLF, blank record, duplicate key, nonfinite/overflowed numeric value or trailing
JSON token. Bound LF-inclusive records to 65536 bytes before decoding. Require
integer tokens within signed 64-bit range; finite fractional numbers may remain
opaque parsed numbers. Preserve original whitespace/key order/number spelling
and every raw byte; never canonicalize NDJSON. This is deliberately syntax-only,
not the restricted vendor protobuf/process profile. Unsupported syntax refuses;
unknown valid object keys/event variants are retained. Semantic parsers must
later establish their actual coverage independently. The existing independent
checkpoint consumer verifies raw framing/count/hash and acquisition joins; it
does not validate this writer's JSON syntax or vendor semantics. Do not promote
its result into independent agreement on either of those claims.

An incomplete tail stays in the same bounded buffer until completion within the
active original trigger deadline. EAGAIN with a tail cannot complete a checkpoint;
wait for more input in the same operation without issuing a new challenge or
resetting a budget. EOF, read error, malformed input, custody change or overflow
poisons permanently. A continuous busy stream cannot starve cancellation/control
work or bypass the DATA-read cap. Idle success is an actual post-trigger
`os.read` EAGAIN, not poll readiness, a heartbeat, EOF or an invented event.

At a completed trigger, build the **unchanged** manifest from actual DATA/final
EAGAIN brackets and held counters. Sequence is exactly prior+1; offsets/counts
are contiguous, empty batches keep them unchanged. Set loss_evidence_digest=null
and upstream_loss_state=UNKNOWN. Exclusively publish batch -> manifest -> receipt
using the existing deterministic names, reader-owned regular0400/single-link
files, full write, file/parent fsync and exact named/held readback with guards.
Never overwrite/deduplicate/recover an existing or partial path. Recheck all
three identities/bytes, close each owned file descriptor once, recheck custody
and time, then issue FD8 completion. Preserve files after either success or
failure. This writer does not claim its immutable receipt records its own future
publication; the completion frame reports that later boundary.

The writer advances its committed local checkpoint only after complete
publication; any later completion/ACK uncertainty still poisons and leaves the
artifacts. Root advances only after its separate successful verified acquisition.
Until then no next control operation is accepted. Root can signal that it has
advanced through a subsequent valid notice with the exact local sequence, or a
refresh with both the exact predecessor manifest digest and sequence. The frozen
FD3 notice has no predecessor digest: Root separately binds its last acquired
manifest in the next expectation. Do not add a notice field. A different baseline
terminates the reader rather than repairing state. Sequence counts completed
checkpoints, not vendor events, DATA reads or heartbeats; even idle advances once.
The frozen ACK/transport requires only sequence_after>before; this writer/session
enforces the stronger existing checkpoint rule of exactly before+1. REFRESH
advances checkpoint sequence while the retained original ACK sequence is unchanged.
The next listener request uses the latest acquired checkpoint sequence; the
listener permits that baseline above its last ACK sequence.

## CHALLENGE path, unchanged ACK and Root acquisition

The reader parses the existing FD3 notice exactly, accepts ordinal1 then strictly
next ordinals for one listener epoch, joins its pinned epoch and requires its
sequence_before equal the local committed checkpoint sequence. It retains
admissions up to max_requests and refuses duplicates. It consumes the notice
before making **one** nonblocking AF_UNIX/SOCK_SEQPACKET connection to the fixed
challenge.sock path, within accept_deadline. EINPROGRESS may be polled on that
same attempt and checked via SO_ERROR; no second connect/reconnect or startup
greeting. Check protected pathname ancestry and Root peer SO_PEERCRED, associated
PIDFD, process/boot/namespace-compatible identities; do not equate pathname and
sockfs inode. Reader uses PASSCRED=1/PASSPIDFD=0 and checks per-message native
12-byte little-endian SCM_CREDENTIALS from its pinned Root observer. Close every
unexpected installed ancillary FD and refuse malformed controls/truncation.
The reader's group has search permission only on the root:reader-GID0710 parent:
use nofollow O_PATH directory/path handles for that endpoint's custody checks,
not O_RDONLY opens requiring unavailable directory read permission. Root owns
creation/chown/chmod/listen and its own different handles. Reader checks its own
observed clock domain against protected pins; it must not require opening Root's
protected namespace handle merely to connect. Required peer PIDFD/process
observations must be available to this non-root profile; unsupported kernel
access refuses and is a deployment compatibility blocker.

Receive exactly the unchanged canonical challenge <=4096 bytes, no LF required.
Match epoch/request/sequence and BEFORE_FIRST_EFFECT; validate nonce, actual
same-domain issuance and fixed epoch policy timeout=100000000/max_age=200000000.
Its deadline cannot exceed notice request_deadline. Capture trigger_received_ns
from actual receive and perform the real loop drain/publication above. Completion
ordinal is the notice ordinal and trigger_digest is the actual challenge digest.

Only after successful FD8 completion emission and final guards, stamp original
ack_ns and send exactly the frozen response fields:

```text
schema epoch_digest challenge_digest request_digest sequence_after ack_ns
```

Schema remains `aragorn/native-phase3-run-reader-response/v1`. Require
receipt_prepared <= completed <= ack_ns < challenge deadline. One exact
nonblocking packet send with DONTWAIT|NOSIGNAL; no greeting, replacement ACK or
send retry. After ACK, keep the client socket alive: the frozen Root response
poll refuses HUP even when a valid ACK remains readable. The same reader loop
continues telemetry, stderr and cancellation service while waiting for Root to
close its side. Bound this wait by min(original notice.request_deadline_ns,
ack_ns+200000000, session deadline), refusing uint overflow. Do not use the
earlier challenge deadline: Root retention can finish after it. Expected peer
EOF/HUP after ACK permits one guarded client close; any peer payload, ERR/NVAL,
identity change, deadline or uncertain cleanup poisons. No second ACK or retry.
Resolve an already-closed socket before consuming a queued next notice/refresh;
pipe readiness racing with expected close is not itself a protocol error. Do
not begin the next operation while close is unresolved, and retain that queued
control's original deadline. Peer close proves only local lifecycle completion,
not successful Root retention: the Root failure path closes its connection too.
The Root owning caller still performs its existing credentials/PIDFD/proc/clock,
consume-once claim, protected retention and close path. No extra ACK field carries
a manifest digest; FD8 is separately authenticated by its provisioned custody.

Root `acquire_challenge` requires READY/no outstanding frame. It independently
validates the frozen context against its caller-held digest, its actual observer/
clock and epoch; validates the exact BEFORE_CONNECT packet against that context.
`admission_digest` and request_received_ns are protected Root-service inputs,
not packet fields. The later authenticated broker service must own their actual
acquisition. Require received<=entry; calculate phase_deadline as
min(original wire deadline, received+250000000, session deadline), with uint
overflow refusal. This method cannot replace the service's original receive time
with a fresh entry time to gain another budget.

Choose accept_deadline=phase_deadline-100000000 and refuse if already expired.
Call the actual listener begin_request with the held committed sequence and
phase_deadline as request_deadline; then accept_request exactly once. A TIMEOUT,
owned error or transport failure ends this session. Only a complete successful
owned ACK can proceed; preserve the transport's unchanged error observations.
Use the actual four-key return `owned,transport_raw,transport_digest,
listener_reusable`; require listener_reusable is true. The reader is nested under
owned["reader"]. Verify transport_digest against its bytes and preserve all six
unchanged supplement flags, including request_timing_verified=false. New session
and checkpoint records have five flags; do not narrow the transport's schema.
The existing reader-evidence consumer returns four false flags, without a
phase3_qualified field; preserve that exact return. The owned result has five.

Canonicalize the returned actual reader summary and call the existing
`verify_reader_evidence` using actual successful owned evidence, bindings,
connection epoch, the independently pinned observer and `linux-le-ucred32-v1`.
Never promote ACK-looking partial bytes or synthesize a successful retention
receipt after an exception. The retained receipt fields may be exposed only from
the completed owned source path, whose successful return includes its final
protected store readback.

Receive exactly the matching FD8 completion under phase_deadline, with live pipe/
process/clock guards. Match session, phase/ordinal, request/challenge/trigger,
sequence and actual completed_ns<=original ACK ack_ns. Construct the existing
expectation from that original ACK/challenge and **previous acquired state**;
do not take prior offsets/counts from the candidate. Outer deadline is
min(phase_deadline, original ACK+200000000), with strict uint sum check. The
original challenge deadline remains trigger_deadline, even when Root readback
occurs later. Call `acquire_reader_checkpoint` once, then
`verify_reader_checkpoint` on its exact protected returned bytes and held pins.
Match actual acquired manifest/publication/batch pins to FD8. Final clock,
cancellation and identity checks must still pass before exposing a usable result.
Retain the actual Root completion-receive stamp in bounded observations and require
publication.receipt_prepared_ns<=completion.completed_ns<=actual receipt time<=
checkpoint acquisition.started_ns. Preserve manifest_prepared<=
manifest_publish_started<=manifest_readback_finished<=receipt_prepared<trigger_deadline.
The receipt records earlier manifest publication, not its own future fsync/close.
Completion reports that later writer boundary; acquisition separately records
completed Root retention. None substitutes for another, in either phase.

## REFRESH path and original evidence preservation

Session state is READY -> FIRST_ACQUIRED -> SECOND_ACQUIRED. There is at most
one refresh per admitted request; finish_request may close a FIRST_ACQUIRED
exchange that legitimately ends without payload. Any failed attempted operation
is terminal, not reusable. Complete successful exchanges may return to READY via
finish_request; listener/path are held across them, not recreated. Retain bounded
seen admissions/contexts and command ordinals for this lifetime. close is terminal
and leaves socket/files untouched. No operational recovery is released.

Root `acquire_refresh` requires the same protected context and exact
BEFORE_PAYLOAD_SEND request. Validate the actual first response with the existing
codec and its independently held expected digest, against the stored original
first request. Require EVIDENCE and equality of every available original reader
artifact, binding, connection epoch and retention receipt. The second request's
previous_response_digest must be that exact response pin, and context/epoch/
exchange/request/effect/wire deadline are unchanged. This slice itself supplies
no loss provider and cannot manufacture that EVIDENCE response. A current service
with missing loss must emit REFUSED/LOSS_UNAVAILABLE and cannot reach a legitimate
effect/payload transition; positive wire integration remains a later dependency.

Require the original verified ACK still fresh. Derive phase_deadline as
min(wire deadline, actual second receive+100000000, original ACK+200000000,
session deadline); do not widen any budget. Consume exactly the next refresh
ordinal before one FD5 write of the **unchanged** <=2048 LF-inclusive refresh
schema in reader-checkpoint-contract-v1. `issued_ns` is this write's actual
preceding BOOTTIME; deadline_ns is phase_deadline. previous_checkpoint_digest is
the held first manifest pin, sequence_before is the held first sequence and
second_request_digest pins the exact second packet. No second listener request,
connection, challenge or ACK is issued.

The reader requires its first completed challenge for the same request/challenge,
matching session/epoch, prior manifest and sequence, and exactly the next refresh
ordinal. It checks command issued/deadline against the original ACK age/session
budget. The reader did not receive Root evidence/summary/connection pins in the
frozen challenge: their first refresh appearance is accepted **only as Root's
protected FD5 assertion**, recorded unchanged, never falsely described as
independently reconstructed reader evidence. Root separately compares them to
its original successful owned result. They cannot change within this request.

Perform another actual consuming-loop drain/publication, emit only FD8 completion
with REFRESH/command ordinal and trigger_digest=SHA256(exact command including LF).
Root waits for this matching completion, constructs the existing REFRESH
expectation preserving original ACK/evidence/summary/connection, invokes the
one-shot acquisition and independent verifier, matches all completion pins, and
performs final guards before advancing state. Prior records are immutable. A
late/failed refresh leaves submission ambiguity with the broker's existing
journal; this session never emits NOT_SUBMITTED or repairs an exchange.

## Results, errors, cancellation and integration ceiling

Both acquire methods return exactly:

```text
session_raw startup_ready_raw opening_transport_raw notice_raw command_raw completion_raw transport_raw owned
expectation_raw checkpoint reader_verification_raw checkpoint_verification_raw
```

command_raw is null for CHALLENGE; notice/transport/owned/reader verification are
the unchanged first-phase values for REFRESH. checkpoint is the exact existing
acquisition return dict. Verification records are canonical encodings of the
actual independent consumer return values, not fabricated successes.
startup_ready_raw is the unchanged actual complete <=2048-byte startup frame;
opening_transport_raw is the unchanged public successful <=131072-byte listener
opening evidence. These preserve lifetime raw observations without implying an
independent verifier or authenticity claim for them.
session_raw is canonical ASCII <=8192 bytes, exactly:

```text
schema operation session_id epoch_digest context_digest request_packet_digest
request_received_ns started_ns completion_received_ns finished_ns deadline_ns notice_digest command_digest
completion_digest transport_digest reader_evidence_digest reader_summary_digest
checkpoint_acquisition_digest checkpoint_manifest_digest previous_checkpoint_digest
stream_continuity loss_completeness
acquisition_authenticity_verified sensor_health_verified effect_authorized run_qualified phase3_qualified
```

Schema: `aragorn/native-phase3-reader-checkpoint-session/v1`; operation CHALLENGE
or REFRESH. All pins join the actual returned bytes; command_digest is null only
for CHALLENGE, previous_checkpoint_digest null only at session sequence0. Times
satisfy protected request_received<=started<=completion_received_ns<=finished<deadline;
completion_received_ns is the actual Root frame-receive stamp, not its embedded
completed_ns. Require receipt_prepared_ns<=completed_ns<=completion_received_ns<=
checkpoint acquisition.started_ns. Original ACK
freshness is checked at finished too. Continuity/completeness are UNKNOWN and
all five flags are false. This record names source operations/results, not a
second qualification gate or proof of authenticated broker receipt.

finish_request and close return canonical ASCII <=2048 bytes, exactly
`schema,operation,session_id,context_digest,sequence_after,manifest_digest,finished_ns`
plus the same two UNKNOWN fields/five false flags. Schema is
`aragorn/native-phase3-reader-checkpoint-session-terminal/v1`; operation FINISH or
CLOSE. Context/manifest pins are null only when none was admitted/acquired.
FINISH requires the caller's exact active context, no pending command/frame and
all final guards; it ends that logical exchange without asserting broker effect
or success. CLOSE closes owned endpoints/listener exactly once; notice/refresh
EOF causes reader termination. It is not file/socket cleanup or campaign recovery.

The loop returns only on cancellation/control EOF, with canonical <=2048 terminal
bytes: `schema,session_id,reason,sequence_after,manifest_digest,finished_ns` plus
the same two UNKNOWN fields/five false flags. Schema is
`aragorn/native-phase3-reader-loop-terminal/v1`; reason CANCELLED or OWNER_CLOSED.
All other failures raise ReaderCheckpointLoopError. Root failures raise
ReaderCheckpointSessionError; no failed outer call exposes a usable owned reader
or checkpoint. Both retain original_failure and <=32 cleanup_failures; messages
are fixed and contain no raw records. No retry of an uncertain close/write.
The loop's terminal return is exactly `{"terminal_raw":bytes,"observed":dict}`,
preserving the same bounded observations below, including pending raw bytes. A
terminal summary alone must not discard an incomplete batch. OWNER_CLOSED is
allowed only with no active notice/challenge/refresh; control EOF during an active
operation is an error. The fixed launch caller retains the result/exception and
exits that reader process, never continues another work loop.

Loop error `observed` has exactly
`session_id,startup_ready_raw,notice_raw,challenge_raw,refresh_raw,completion_raw,ack_raw,batch_raw,
stderr_raw,manifest_raw,publication_raw,sequence_before,sequence_after,offset_before,
records_before,publication_attempted,completion_attempted,ack_attempted`.
Raw fields are null or actual bounded partial/complete bytes; batch_raw includes
any tail and is <=262144, stderr<=65536, challenge/ACK<=4096, control frames<=2048,
startup_ready_raw<=2048, manifest<=16384 and receipt<=2048. Attempt fields are strict Booleans set before
the operation. Do not synthesize an absent raw record or claim no write occurred.
Counters are null until initialized. Root error `observed` has exactly
`startup_ready_raw,opening_transport_raw,notice_raw,command_raw,command_attempted,command_bytes_written,completion_raw,
completion_received_ns,transport_raw,owned_observed,expectation_raw,
checkpoint_observed,session_raw`. completion_received_ns is null until actually
observed, then the strict uint actual stamp. command_attempted is a strict
Boolean consumed before FD5 write. command_bytes_written is null if no return
count was observed, otherwise the actual bounded uint returned; null does not
assert no bytes were written. startup_ready_raw is null or an actual <=2048-byte
prefix/complete frame. opening_transport_raw is null, the public successful
opening evidence or actual constructor exception partial_evidence, <=131072;
never an invented successful opening. Nested owned/checkpoint
observations preserve the existing exception formats and actual bounds; usable
candidate records stay unaccepted when a subsequent outer check fails.

FD7 EOF, root/bridge/supervisor exit, unexpected control EOF, malformed framing,
stderr, partial/failed publication, stale deadline and any uncertain identity
poison the loop/session. Preserve bounded actual observations and every existing
artifact. Root closes its notice/refresh endpoints on failure; its actual
supervisor must retain the failure and terminate/reap children through the
separately reviewed launch path. In each process, its local owning service/launch
caller preserves the original exception object and cleanup exceptions, not merely
their strings, and retains strong references to unresolved listener/session/
socket owners after failed detach or uncertain cleanup. No garbage collection,
destructor or discarded exception may later close a potentially reused foreign
descriptor. Mark the owner terminal, never retry its close and keep these local
references until that process exits. Python object references are not transferred
to a different supervisor process. The supervisor retains bounded failure
reports and its PIDFDs and owns separately reviewed termination/reaping, without
receiving those Python objects or borrowed descriptors. No automatic restart,
socket unlink or private
retention campaign is released. Cancellation is observed/terminal; a hung kernel
call is not described as promptly cancellable.

## Concrete caller, closure and focused acceptance

The next production caller is reserved
`native_phase3_broker_reader_service.py`, already Root-owned by the broker
contract. It must authenticate real broker packets, hold protected context and
actual receipt times, construct/own this session and pass its original outputs
to the existing wire codec. It never lets the broker call Root storage or waits
for the broker serialization lock. The existing provider response carries
checkpoint acquisition_raw <=16384; separately retained original batch/manifest/
publication bytes remain available for replay. Missing real loss/sensor/program/
map evidence stays null/UNKNOWN and yields REFUSED, not EVIDENCE/health authority.
This service/client/materializer is not silently assigned by the loop release.

The concrete launcher must create the six pipes, provision directories, acquire
actual process/source/namespace identities, deliver the immutable protected
inputs and independent pins, invoke the fixed loop API, keep only the specified
FDs and own cancellation/termination. The strict post-exec noninheritability
checks also cover bridge stdout FD1 and stderr FD2. Their writer must set CLOEXEC
after intentional exec transfer and before readiness through a reviewed bridge
change; the current unmodified tetra bridge is not established compatible with
this startup contract. Root cannot set another process's descriptor flags. This
is a deployment prerequisite, not an exception to endpoint custody. Successor
bridge/sensor readiness patches, actual installed
hashes and full loss omission scope remain in tetragon-stream-loss-decisions-v1.
No invented PID/hash or historical image pin substitutes for unavailable facts.

Expected project imports: writer standard library plus package init; session
imports the actual ReaderListener, reader-evidence verifier, checkpoint owning
acquisition, checkpoint independent verifier and broker request/response codec.
Root must inspect their complete actual transitive closure, source/fixtures and
generated dependencies at stable hashes. Two internal owners use non-overlapping
paths and submit one coherent connected implementation before stage registration.
Registry ownership remains Root's. No historical suite or unchanged stage rerun.

New focused cases must exercise actual production-call ordering with fabricated
OS primitives and independently authored control/NDJSON fixtures:

- startup barrier and role/FD/boot/namespace/proc custody; surplus/substituted or
  foreign-reused FDs; non-root inability to inspect protected Root handles never
  becomes a false observed join;
- fragmented/duplicate/late notices, prequeued completion, ordinal/admission
  replay, failed one-attempt connect and credential/control/truncation failures;
- idle and nonempty CHALLENGE with same-loop post-receipt EAGAIN, all DATA bytes
  retained, partial tails, UTF-8/duplicate/nonfinite syntax, unknown valid event
  variants, 63-DATA/read/batch/session limits and busy-stream cancellation;
- exact exclusive publication/fsync/readback/close/completion/ACK order; manifest
  appearance without receipt cannot start acquisition; every intermediate
  failure leaves residue and exposes no successful reader/checkpoint;
- queued ACK remains live until Root close; expected post-ACK EOF racing the
  next control, unsolicited peer data, close-wait timeout and failed detach
  preserve bounded ambiguity without a retry or destructor-driven close;
- protected Root flow invokes both independent consumers on actual acquired
  bytes; pins/candidate prior-state substitutions and late final guards refuse;
- REFRESH preserves original ACK/evidence/summary/connection and prior manifest,
  validates first/second packet joins, sends no new challenge/ACK, handles partial
  control writes without retry and retains submitted ambiguity;
- cancellation EOF versus readiness/EAGAIN/data, simultaneous completion/exit,
  stderr/EOF/bridge death, cleanup ambiguity and exact all-false/UNKNOWN outputs.

Source anchors: reader response `:63-99,:343-348`; owned reader acquisition
`acquire_owned_reader_response`; existing reader evidence verifier `:200+`;
checkpoint contract fixed schemas/REFRESH direction and owning acquisition
`acquire_reader_checkpoint`; transport contract notice/lifetime/cancellation
rules; broker contract exact packets, phase caps and protected caller boundary.
runtime_tetragon_process.py `:265` recognizes only process_exec/process_exit and
`:324+` requires a closed capture: neither is an all-event stream proof.

1. Implement the connected loop/session under v8's exact internal-owner release;
   review stable source and schedule only its newly necessary focused checks.
2. Complete real launcher/service/client, retained source identities and typed
   loss/sensor/bridge consumers; wire the existing broker journal and request path.
3. Close the same Phase 3 requirement ledger, both action families/a100, timing,
   cancellation and actual paired tasks before publishing a freeze candidate.
4. Keep final qualification, operational observation, private retention and cleanup
   pending separate release. Local syntax/custody readiness is not Phase 3 exit.
