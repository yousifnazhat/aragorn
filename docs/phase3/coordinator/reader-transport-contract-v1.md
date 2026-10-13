# Guarded reader listener and request lifecycle contract v1

Status: complete bounded contract draft for coordinator review. This file alone
releases no implementation or execution. Release requires its published verified
signed checkpoint, explicit coordinator release and RUN owner agreement. The
publishing checkpoint, not a guessed branch tip, is the lane's required base.

This contract supersedes the transport ownership proposal in
`reader-transport-and-loop-design.md` only. It leaves every existing wire,
acquisition, store and independent reader-evidence schema unchanged.

## Exact delegation and exit

Owner: existing `/Users/yousi/Documents/Commits/aragorn-phase3-run-health`, branch
`codex/phase3-run-health`. Only these three new paths may be written:

- `src/aragorn/native_phase3_run_reader_transport.py`
- `tests/test_native_phase3_run_reader_transport.py`
- `docs/phase3/run-health/READER_TRANSPORT_HANDOFF.md`

The deliverable is an actual Linux AF_UNIX/SOCK_SEQPACKET listener owner, one
protected notice-pipe request lifecycle and the production call into
`acquire_owned_reader_response`. No injected accept, truth, notification,
retention or authentication callback substitutes for those operations. Tests
patch OS primitives. Root retains provisioning, launcher/service integration,
deployed identities, registry, scheduling, shared files and every real telemetry
loop, checkpoint, loss, program/map and broker implementation.

The completed slice may claim a source-implemented guarded accepted transport
and mocked validation. It may not claim deployment, protected acquisition
authenticity, real reader progress, completeness, effect authority or Phase 3
qualification. The independent consumer of the new transport supplement is
specified below but is not implemented or declared passing by this release.

## Public API and ownership

```python
class ReaderListener:
    def __init__(self, *, provision_raw: bytes,
                 expected_provision_digest: str,
                 epoch_raw: bytes, expected_epoch_digest: str,
                 notice_write_fd: int, reader_pidfd: int): ...

    def begin_request(self, *, admission_digest: str, request_digest: str,
                      sequence_before: int, accept_deadline_ns: int,
                      request_deadline_ns: int) -> bytes: ...

    def accept_request(self, notice_raw: bytes) -> dict: ...
    def cancel_request(self, notice_raw: bytes) -> bytes: ...
    def close(self) -> bytes: ...
```

The constructor exclusively receives the two launcher-owned descriptors; it
records ownership before metadata reads and closes them once on construction
failure. They must be distinct strict integers at least 3. Invalid integers
are not descriptors to close. No duplication, descriptor pooling or transfer is
allowed. Listener, pathname-handle and ancestor descriptors are owned internally.
Every operation requires Linux, little-endian native 12-byte `=iII` credentials,
stable real/effective/saved root UID/GID and the original process/main thread.
Use after fork, thread transfer, close, identity change or uncertain custody
refuses. No global socket timeout or process umask changes are allowed.

`begin_request` validates and consumes one new admission identity, emits exactly
one notice through the owned pipe and returns its exact bytes. `accept_request`
accepts only the byte-identical outstanding notice. At most one request is
outstanding; methods cannot overlap or reenter. The constructor exposes its
opening supplement as `opening_evidence_raw`; `begin_request` exposes its
completed supplement as `last_evidence_raw` before returning notice bytes.

A successful `accept_request` returns exactly `owned`, `transport_raw`,
`transport_digest`, `listener_reusable`. `owned` is the unchanged result of
`acquire_owned_reader_response`. A TIMEOUT is a complete acquired TIMEOUT, never
an ACK or accept timeout. It returns only after terminal listener cleanup and
sets `listener_reusable` false. Only ACK can leave the listener reusable.

All errors use `ReaderTransportError` with `original_failure`, `cleanup_failures`,
`partial_evidence` (bounded transport bytes), `owned_observed` (the unchanged
owned-caller error observations, if available) and `unaccepted_reader_raw`.
If a later transport guard fails after the owned caller returned, move the
candidate reader into `unaccepted_reader_raw` and set the exposed
`owned_observed["reader"]` to `None`. No failed outer call exposes a usable
reader. Preserve original, retention and cleanup errors rather than replacing
them with a success record or exception message alone.

## Protected provisioning ABI

Root must acquire `provision_raw` and `epoch_raw` through its separately reviewed
protected launch/credential path and hold their expected digests independently.
The transport takes no credential path, environment override or caller-selected
socket/storage location. Hashing supplied bytes is not independent provisioning.
The lane validates this ABI; it does not manufacture deployment credentials.

Provisioning is canonical ASCII JSON, at most 8192 bytes, with exactly:

```text
schema epoch_digest observer directories notice_pipe
session_deadline_ns max_requests access_inventory_digest
```

- `schema` is `aragorn/native-phase3-run-reader-transport-provision/v1`.
- `epoch_digest` equals the independently held expected epoch pin. The epoch is
  the existing canonical object, at most 32768 bytes. Validate its complete
  frozen structure before opening a socket or writing a notice; do not call
  `_issue` to perform validation or mint an early challenge.
- `observer` has exactly `pid,start_time_ticks,uid,gid,time_namespace`; UID/GID
  are zero. `time_namespace` has exactly `device,inode`. Read back the actual
  observer PID/start/account vectors, boot and active time namespace; retain a
  held namespace FD and compare named/held identities. The reader's active time
  namespace must join the same device/inode and the epoch's time-namespace inode.
- `directories` is exactly three entries, in order `/`, `/run`,
  `/run/aragorn-phase3-reader`. Each has exactly
  `path,device,inode,mode,uid,gid`; mode includes the file type. The first two are
  root:root directories without group/world write permission. The last is
  root UID, exactly the epoch reader GID, and mode directory 0710. Hold nofollow
  descriptors and compare every named/held identity before/after mutations and
  at each request. Ignore unrelated directory timestamp changes.
- `notice_pipe` has exactly `device,inode,mode,uid,gid,reader_fd`. It describes
  one anonymous FIFO, root:root, mode FIFO 0600, with reader FD exactly 3.
  Require actual matching writer `fstat`, nonblocking O_WRONLY access and
  noninheritability. Check `/proc/<reader_pid>/fd/3` and its bounded `fdinfo`
  against the same FIFO and O_RDONLY/nonblocking/close-on-exec state. A pathname
  FIFO, socket, regular file, substituted pipe or different reader FD refuses.
  Retain both fixed proc-FD symlink readbacks and require the exact anonymous
  `pipe:[<inode>]` spelling for the pinned inode; a FIFO mode check alone cannot
  distinguish an anonymous pipe from a named FIFO.
- `session_deadline_ns` is an absolute CLOCK_BOOTTIME deadline. `max_requests`
  is 1 through 4096 and bounds permanent in-memory admission history.
- `access_inventory_digest` pins root's separate installed process/account/
  namespace/FD-transfer/ptrace restrictions. It is supplied authority, not
  independently observed by this module. Do not set an authenticity flag from
  this digest or infer that group membership has been verified.

All digests are strict lowercase `sha256:` values. All integers are strict
non-boolean integers in `[0, 2**63)`; PIDs, start ticks and inodes are positive.
Require reader UID/GID nonzero and reader PID distinct from observer PID. Check
the handed reader PIDFD's actual fdinfo PID and liveness, then fresh stat/status/
stat joins for the epoch reader. Its four UID/GID values must agree, all five
capability sets must be zero and NoNewPrivs must be 1, using the existing leaf's
parsing rules. Recheck before/after each notice and around accept. The passed
PIDFD pins the launch target; it does not replace the accepted connection's
separately acquired socket-derived PIDFD inside the frozen leaf.

Root launch contract: create this anonymous pipe while root, keep only its writer
in the listener owner, transfer only its read end as reader FD 3, and close all
other copies before readiness. The reader sets FD 3 noninheritable immediately
after its authorized exec and before transport readiness. Root must exclude
workload access to either end and unauthorized reader ptrace/FD transfer or
credential-forging capabilities in applicable namespaces. No historical absence
of copied descriptors or hostile-root resistance is claimed by point-in-time
readbacks. A real launcher satisfying this ABI is a root integration dependency.

The existing root-only `/var/lib/aragorn-phase3-reader` root:root 0700 claim and
evidence store must already be provisioned. Its code, permissions and ownership
are unchanged. The reader receives no access to that store.

## Listener creation and pathname custody

The only endpoint is `/run/aragorn-phase3-reader/challenge.sock`. The parent must
already satisfy the provisioning ABI. Require the final name absent; a socket,
symlink or other existing residue refuses. Never unlink, replace, repair or
create the parent. Require actual observer umask 0077 from bounded proc status;
root launch sets it, the lane does not modify it.

Create one nonblocking, noninheritable AF_UNIX/SOCK_SEQPACKET listener. Set and
read back SO_PASSCRED=1 and SO_PASSPIDFD=0 before bind/listen; unsupported options
refuse. Bind the fixed path, then change only the just-created named socket to
root UID / epoch reader GID and 0660 under held parent custody. Verify its type,
single link, owner/mode and stable named/held pathname identity before/after each
change, then listen with backlog 1. Do not use fchmod/fchown on the socket FD as
if that changed the filesystem socket node. Hold a nofollow O_PATH/CLOEXEC handle
to the named socket; the socket FD's sockfs inode and the pathname inode are
different identities and must not be equated. Retain both separately.

Revalidate the full ancestor chain, named socket handle, listener descriptor,
type/options/nonblocking/noninheritable state and fixed getsockname at each
boundary. This is local-root custody, not atomic protection against hostile root.
Do not use an abstract socket, accepted caller socket or supervisor socketpair.

## Fixed notice and at-most-once request admission

`begin_request` first verifies state READY, live held identities, remaining
request capacity and no queued listener connection/error (poll with zero
timeout). It does not accept/drain unsolicited connections. Queue/error presence
ends the listener lifetime. It validates all inputs before admitting the request.

`admission_digest` is a caller-held digest of the separately authorized request
instance in root's protected dispatch record. It is distinct from the frozen
`request_digest`: repeated identical workload contents may have distinct admitted
instances, while a failed instance may not be readmitted. Retain every admitted
digest until terminal close. This API does not generate REQUEST_ACCEPTED evidence
or legitimize a retry merely because a caller chose another digest.

Mint a fresh 32-byte random listener epoch once at construction, not per request.
Assign request ordinals 1 through `max_requests`, without reuse. This listener
epoch is not the per-connection epoch in the frozen acquisition evidence.

The notice is canonical ASCII JSON plus exactly one LF, at most 2048 bytes total.
Its exact object fields are:

```text
schema listener_epoch ordinal admission_digest epoch_digest request_digest
sequence_before issued_ns accept_deadline_ns request_deadline_ns
```

Schema is `aragorn/native-phase3-run-reader-connect-notice/v1`;
`listener_epoch` is 64 lowercase hex characters. Other fields come from the
validated active request; `issued_ns` is an actual monotonic BOOTTIME observation.
The returned `notice_raw` includes the LF. Its digest covers all those bytes.

Observe `PIPE_BUF` on the held writer and require the whole notice to fit.
Reserve the admission and ordinal before one nonblocking `os.write`. Require an
exact full-length return; no repeated write, buffering thread or notification
callback. EAGAIN, short/ambiguous write, interruption, pipe error or a failed
post-write custody guard ends the listener lifetime with retained uncertainty.
Do not retry a notice even when zero delivery appears likely.

The future real reader consumes this fixed pipe in its own loop. It accepts only
the next ordinal for this listener epoch, independently matches its protected
epoch, validates canonical framing and budgets, and creates at most one new
connection for that notice before its accept deadline. No startup connection,
greeting, prequeued data or reconnect after success/failure is permitted. It does
not send notice bytes over the challenge socket. EOF, malformed notice, missed
ordinal, late notice or changed custody terminates that reader's request channel.
Receipt of a notice establishes no telemetry checkpoint and emits no ACK.

This is the exact notification interface for root's later launcher/reader work;
the RUN transport implementation owns actual notice writes now, while no reader
implementation or fake responder is released here.

## Acceptance, deadlines and cancellation

Before notice emission require:

```text
now < accept_deadline_ns
accept_deadline_ns + epoch.policy.timeout_ns <= request_deadline_ns
request_deadline_ns <= session_deadline_ns
```

Reject arithmetic overflow. Require every clock observation nondecreasing and
bound to the held actual boot/time namespace. This reserves the existing
response budget; it is not a new overall return-time guarantee.

`accept_request` validates the exact outstanding notice, then polls only the
held listener and reader PIDFD until the original accept deadline. Use finite
poll waits and recalculate remaining BOOTTIME. EINTR or an accept EAGAIN with no
accepted socket may continue only within this same wait/deadline; this is not
a replacement peer or a restarted request. Reader exit, unexpected poll flags,
custody change, accept timeout or any accepted wrong peer ends the lifetime.
Accept at most one actual connection; never search for another peer.

Track the accepted descriptor immediately. Set/read back nonblocking and
noninheritable state; verify AF_UNIX/SOCK_SEQPACKET and inherited PASSCRED=1 /
PASSPIDFD=0. Read exactly 12 SO_PEERCRED bytes and match epoch reader PID/UID/GID.
SO_PEERCRED is connection-time identity; it is not SCM_CREDENTIALS or proof of
who sent a later packet. The existing leaf must still perform its full per-packet
SCM check, socket-derived PIDFD, restricted-process/boot/namespace joins and
prequeued-data refusal. Never replace those with transport summaries.

Recheck request budget immediately before exclusive transfer. Call exactly:

```python
acquire_owned_reader_response(
    connection, epoch_raw=epoch_raw,
    expected_epoch_digest=expected_epoch_digest,
    request_digest=active_request_digest,
    sequence_before=active_sequence_before,
)
```

After call entry that function alone closes the connection, even on refusal or
interruption. Do not close it again. It internally mints a fresh nonce and
independent connection epoch, creates permanent claims, invokes the unchanged
response leaf and retains/readbacks its evidence. No supplied/recovered challenge
or caller-selected connection epoch is accepted by this transport.

Its `_issue` observes time after input checks and entropy acquisition. On return,
therefore also require the actual issued challenge deadline not exceed the
request deadline. A candidate outside that budget is unaccepted; preserve its
raw evidence and claim. Retention and individual syscalls can run past policy
deadlines. The frozen caller cannot take an outer deadline, cancellation FD or
callback, so do not claim prompt cancellation or end-to-end request timing.

`cancel_request` is allowed only for the byte-identical active notice while no
`accept_request` call is running. It marks cancellation, closes this listener
lifetime and returns the terminal supplement. A trusted interruption raised in
the running owner is preserved through the existing BaseException failure path.
There is no asynchronous cancellation acceptance after connection transfer,
cross-thread socket close or invented cancellation success. Root's later
supervisor must own process termination and retain any resulting ambiguity;
that separate implementation is not supplied by this API.

Only a complete ACK, successful owned cleanup and final transport custody guards
return to READY. Require its sequence strictly above the supplied baseline and
do not allow a later request baseline below the last accepted sequence. Exact
baseline authenticity remains root checkpoint integration work. A complete
TIMEOUT returns its valid TIMEOUT record but terminally closes the listener.
Any notice-issued refusal, cancellation, accept timeout, owned error or cleanup
uncertainty also terminally closes it. This prevents a delayed old connection
from being silently assigned to the next request: the frozen wire has no
pre-challenge request tag to disambiguate such recovery.

Thus one held listener supports many distinct successful requests without path
recreation. Failure recovery is not released. A future recovery protocol would
need its own contract; a new notice or new digest alone cannot recover this one.
The later campaign may require authorized recovery between distinct fault
scenarios. Do not imply that one listener lifetime can complete every gate.

## Closure, residue and bounded evidence

Close owned descriptors once in reverse acquisition order; attempt the remaining
closes even when one fails, preserving all failures. Never retry an ambiguous
close. Terminal closure leaves the socket pathname and every root-store record
untouched. A later constructor at that path refuses. No garbage collection,
stale-socket deletion, claim removal, private evidence retention or operational
restart is authorized. Calls after terminal closure cannot consume another
admission or reuse a connection.

Retain one canonical transport supplement per operation (`OPEN`, `BEGIN`,
`ACCEPT`, `CANCEL`, `CLOSE`). This supplement is separate from, and never appended
to, frozen reader evidence. Its schema is
`aragorn/native-phase3-run-reader-transport-evidence/v1`, maximum 131072 bytes.
The exact common field inventory is:

```text
schema operation status listener_epoch provision_digest epoch_digest
admission_digest request_digest ordinal sequence_before notice_base64
started_ns finished_ns snapshots peer_credentials_base64 accepted_ns
transfer_started_ns transfer_finished_ns owned_evidence_digest challenge_digest
connection_epoch reader_digest descriptor_cleanup failure_type
cleanup_failure_types cleanup_failure_types_complete listener_reusable
acquisition_authenticity_verified sensor_health_verified effect_authorized
run_qualified phase3_qualified request_timing_verified
```

Status is exactly `READY`, `NOTIFIED`, `ACK`, `TIMEOUT`, `CANCELLED`, `CLOSED` or
`REFUSED`, appropriate to the operation. Unavailable values are null, never
invented empty objects or zero observations. No extra fields are permitted. The
six verification/authority flags are literal false in every status.

`snapshots` is an ordered array of at most 32 bounded observation records, each
exactly `name,started_ns,finished_ns,value`. Allowed names are:

```text
observer_before observer_after reader_before reader_after
directories_before directories_after pathname_before pathname_after
listener_before listener_after notice_pipe_before notice_pipe_after
```

The two process values have exactly `stat_before_base64,status_base64,
stat_after_base64,boot_base64,time_namespace` (namespace: `device,inode`). For the
reader, additionally `pidfd_info_base64`. Use the existing 16384-byte proc,
4096-byte fdinfo and 64-byte boot bounds. Directory values use the provisioning
array shape; pathname values have `device,inode,mode,uid,gid,nlink`;
listener values have `device,inode,family,type,nonblocking,noninheritable,
passcred,passpidfd,path`; notice-pipe values have `device,inode,mode,uid,gid,
writer_fd,reader_fd,writer_flags,reader_flags,writer_noninheritable,
writer_link,reader_link` (both links are the exact bounded proc-FD text above).
The total decoded raw snapshot budget is 65536 bytes. Each read bracket uses
actual nondecreasing BOOTTIME. Preserve bounded raw data used for decisions.

`descriptor_cleanup` is an ordered array of at most 16 entries, each exactly
`fd,role,closed`, with a strict descriptor integer, role from `ANCESTOR`,
`PATHNAME`, `LISTENER`, `NOTICE_WRITER`, `READER_PIDFD`, `NAMESPACE`,
`ACCEPTED_BEFORE_TRANSFER`, and literal boolean outcome. It contains only closes
this owner actually attempted; transferred connections remain owned by the
existing caller. `cleanup_failure_types` has at most eight exception class names
of at most 128 characters; the complete flag reports whether any were omitted.
`failure_type` is null or one such class name. Raw exception strings, absolute
private evidence contents and arbitrary object reprs do not enter the supplement.

Budget overflow refuses, preserves the previously bounded observations in a
REFUSED supplement and the original error, and supplies no reader. Reserve 8192
bytes for terminal status and cleanup metadata. Do not silently truncate a
successful evidence record. The outer error can preserve the existing bounded
owned observations separately; do not base64-embed their 131072-byte supplement
inside another 131072-byte envelope.

Independent verification is a later separately assigned consumer: it must take
the expected provisioning/epoch/admission pins, notice bytes and owned evidence
from independent caller state; validate this exact schema and joins without
importing producer/private validators; and call the existing independent reader
evidence verifier separately where applicable. Transport serialization itself
does not prove protected provenance, successful durable retention or meaningful
reader-loop progress. Root must retain this supplemental output through its
reviewed error/evidence path before relying on it. This release adds no new sink
or writes outside the existing store and bound socket node.

## Source basis, closure and focused verification

These source-confirmed facts constrain the release:

- `native_phase3_run_reader_acquisition.py` `_issue` and
  `acquire_owned_reader_response` own entropy, challenge policy timing, durable
  store calls and transferred-connection cleanup. There is no external
  cancellation/deadline parameter. Its reader result appears only after cleanup.
- `native_phase3_run_reader_response.py` `_inputs`, `_peer`, `_readbacks`,
  `_unread` and `acquire_reader_response` define the frozen epoch, exact socket
  credentials, real proc/namespace joins and ACK/TIMEOUT limits. The `sensor`,
  source, stream and program-map fields are supplied, not freshly observed there.
- `native_phase3_run_reader_store.py` owns only its permanent claim and evidence
  namespaces. Do not use its one-shot evidence callback for listener supplements
  or change the fixed root path to store transport records.
- `runtime_process_profile.open_peer_pidfd` derives a PIDFD from SO_PEERPIDFD;
  transport's launcher PIDFD cannot substitute for that socket join.

Before scheduling, submit hashes of the three new files and the complete actual
closure. With only the specified existing source reuse, the source/test closure
is the two new Python paths plus these eleven unchanged paths:

```text
src/aragorn/__init__.py
src/aragorn/native_phase3_run_reader_acquisition.py
src/aragorn/native_phase3_run_reader_store.py
src/aragorn/native_phase3_run_reader_response.py
src/aragorn/native_phase3_run_acquisition.py
src/aragorn/native_phase3_clock_domain.py
src/aragorn/runtime_process_profile.py
src/aragorn/runtime_action_broker.py
src/aragorn/runtime_action_observation_publisher.py
src/aragorn/runtime_action_decision.py
src/aragorn/oci_worker_protocol.py
```

No generated sources, external fixtures or historical test imports are needed.
If actual imports or fixture reads differ, report and review that full closure
before registration; do not keep this list while omitting behavioral inputs.
Use fresh fabricated records in the new test only. Do not import a historical
test fixture, invoke a real socket, open real proc/protected paths, or copy a
cache. Runtime primitives are mocked. No real Tetragon or service is started.

Selected new tests must cover:

1. Exact provisioning/epoch pins and schema; wrong platform/ABI/root/thread/fork;
   capability, account, start, namespace, PIDFD and notice-FD mismatches.
2. Fixed path, absent-name requirement, ancestor/pathname substitution, symlinks,
   wrong mode/owner/link, option setup before listen, and separate named/sockfs
   inode guards. Unsupported syscall/options and constructor partial cleanup.
3. Two or more distinct successful requests on one listener; repeated admission
   rejection, ordinal/capacity/deadline/sequence bounds, notice bytes and one
   atomic write, no unsolicited connection, no reconnect or copied connection.
4. Short/EAGAIN/interrupted notice write, EPIPE/error/custody change, reader
   exit, accept deadline, wrong peer, prequeued payload, accepted option/mode
   failure, and no second-peer search. Every ambiguous attempt ends the lifetime.
5. Exact production owning-caller arguments and single transfer. One wiring case
   invokes the real owning wrapper with patched OS/store/leaf boundaries so its
   issuance and cleanup path is exercised without historical test execution.
   Other cases can fabricate its bounded return/error to isolate new transport.
6. Actual challenge deadline beyond the outer budget, TIMEOUT versus accept
   timeout, post-return guard failure, cancellation before transfer, interruption
   during transfer, and original/retention/cleanup failure preservation.
7. Evidence field/budget/null/false-flag rules, candidate-reader quarantine,
   descriptor closure exactly once, socket/claim residue preservation, refusal
   after terminal state and no callback/store/schema changes.

Root alone reviews stable closure, registers proposed stage
`native-run-reader-transport` and schedules its one new focused execution in the
owning worktree with `/opt/homebrew/bin/python3.12`. No execution is authorized
by this draft. Preserve the actual result/fingerprint and diagnose failures
before any changed-input retry. After reviewed PASS, stage exact assigned paths,
make one signed commit, verify it and hand root the original hash, changed paths,
result/fingerprint, closed requirement, evidence limits and remaining blockers.
Root integrates original ancestry and pushes; feature pushes are unnecessary.

## Root integration blockers and remaining Phase 3 steps

No additional API choice is delegated implicitly. Root must approve this
contract's terminal-on-failure policy and fixed FD 3/0710/0660 provisioning ABI
when signing the release. These are concrete decisions, not claims that a
matching launcher or deployed account exists.

The following remain required outside this lane's bounded implementation:

1. Publish this contract and release the transport slice; root implements the
   exact protected launcher/credentials/pipe inventory, real admitted-request
   source, cancellation supervision and retention of transport supplements.
2. Define and wire the real three-role reader/`tetra`/Tetragon stream custody,
   checkpoint and independent consumer. `normalize_process_capture` requires
   closed/quiescent capture conditions and cannot become a continuous idle-loop
   verifier by fabricating EOF or zero loss. Its private `_event` parser is only
   a reuse candidate; root must freeze the exact parser API before assigning it.
3. Complete actual loss/program/map, serialized broker state, admission/workload
   paths, timing/cancellation and source/identity custody; validate only changed
   composition and integrate verified original signed lane commits.
4. Publish a reviewable implementation freeze only after the existing coverage
   ledger closes its required paths. Final qualification remains the separately
   released campaign; live operations, private retention and cleanup stay held.
