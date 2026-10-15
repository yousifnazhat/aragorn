# Root broker/reader service contract v1

SOURCE CONTRACT: effective only with signed published provider-release-v13.md.
Review base: verified published f65e8f3b8a79f3ac7251a69f6facc7df89042364.
This is a bounded real provider service, not the still-unreleased full IPC/client/
HTTP renderer draft. That original draft remains unchanged. No execution or live
operation is scheduled. The profile is exactly HTTP_REFUSAL_ONLY; all five
health/effect/qualification flags remain false and missing loss stays UNKNOWN.

## Exact ownership and dependencies

Root delegates only these three paths to its internal provider implementer in
the coordinator worktree:

- src/aragorn/native_phase3_broker_reader_service.py
- tests/test_native_phase3_broker_reader_service.py
- docs/phase3/coordinator/broker-reader-service-handoff.md

No bootstrap, context, session, codec/journal, units, launcher, client, renderer,
registry, inventories or other lane files may be edited. RUN retains v12's
bootstrap; Admission retains v9's context leaf; Workloads retains v11. Reuse
existing public protocol validators and actual ReaderCheckpointSession plus the
actual public context acquirer. Never import their private parsers/cleanup/state.
No factory, callback, injected production responder or packet-selected module.
Root reviews stable actual full closure before scheduling. Admission's original
reviewed signed delivery must be integrated before service execution; its frozen
API allows offline service implementation concurrently. Do not copy its draft.

## Public owning API

```python
class BrokerReaderService:
    def __init__(self, *, provision_raw: bytes, expected_provision_digest: str,
                 source_inventory_raw: bytes, expected_source_inventory_digest: str,
                 measurement_binding_raw: bytes, expected_measurement_binding_digest: str,
                 fixture_binding_raw: bytes, expected_fixture_binding_digest: str,
                 epoch_raw: bytes, expected_epoch_digest: str,
                 checkpoint_provision_raw: bytes, expected_checkpoint_provision_digest: str,
                 transport_provision_raw: bytes, expected_transport_provision_digest: str,
                 stream_inventory_raw: bytes, expected_stream_digest: str,
                 loop_provision_raw: bytes, expected_loop_provision_digest: str,
                 notice_write_fd: int, reader_pidfd: int, refresh_write_fd: int,
                 completion_read_fd: int, session_cancel_read_fd: int,
                 ipc_cancel_read_fd: int, supervisor_pidfd: int,
                 readiness_expectation_raw: bytes,
                 expected_readiness_expectation_digest: str,
                 provider_ready_write_fd: int): ...
    @property
    def opening_result(self) -> dict: ...
    def serve_one(self) -> dict: ...
    def close(self) -> dict: ...

class BrokerReaderIpcError(ValueError):
    original_failure: BaseException
    cleanup_failures: tuple[BaseException, ...]
    observed: dict
    unresolved_owner: object
```

Pin original imported process/main native thread before metadata. Reject fork,
reentry, concurrency or second construction in that lifetime before taking
another owner's handles. After that check, take each distinct valid descriptor
before any fallible metadata read; require all eight arguments distinct uint>=3.
Unknown metadata/association never authorizes close. Own the actual listener,
accepted connection, namespace/proc/ancestry and own peer PIDFD resources too.

Transfer notice_write_fd, reader_pidfd, refresh_write_fd, completion_read_fd and
session_cancel_read_fd exactly once into the real ReaderCheckpointSession,
using its public constructor with cancel_read_fd=session_cancel_read_fd. Remove
these five from service close ownership before entering that constructor; it owns
them even if it raises. Preserve its original exception/partial observations/
strong unresolved owner. Service retains IPC cancellation, supervisor PIDFD and
readiness writer. No duplicated or borrowed reader-session private descriptor.

## Canonical provisions and expected-source ceiling

Use canonical ASCII JSON, sorted keys, separators comma/colon, ensure_ascii=True,
allow_nan=False, no LF except the published readiness frame. Reject duplicate,
nonfinite, extra/missing fields, Boolean-as-int and overflow before parsing/hashing
unbounded data. Reuse the exact published v12 provision/source inventory/readiness
expectation schemas, types, bounds and process/clock/pipe/directory semantics.
Validate actual pins and every cross-input equality. Five reader/session pins
must equal the exact supplied original raws and the reader_session provision.
Session deadlines equal the real loop/checkpoint/transport deadlines. Provider
is this actual Root observer; supervisor is a distinct live Root PID and broker
is the protected distinct non-root PID/account from the original Root caller.

Measurement and fixture use the published v9 schemas and 8192/16384 bounds.
Bind their actual bytes/pins to provision, grant/deployment/clock and actual
provider/broker expectations. Do not reopen inaccessible secret paths.

For this bounded service, source_inventory is a canonical independently pinned
Root-supplied finite installed allowlist. Validate shape/predecessor pin and
cross-input joins; do not open arbitrary inventory paths or claim file acquisition
or loaded-code provenance from supplied hashes. Root's actual protected launcher
must acquire the complete installed inventory, credentials, unit/executable and
dynamic process/FD origins before native use. This explicit ceiling replaces the
unreleased draft's broader source-acquisition premise without weakening a deployed
protection. All flags remain false. Actual broker context acquisition below still
performs its own declared protected proc/control-file observations.

## Real opening, guard listener and readiness writer

Fixed guard endpoint: /run/aragorn-phase3-broker-reader/guard.sock, AF_UNIX/
SOCK_SEQPACKET. Hold nofollow ancestry /, /run, endpoint parent; Root nonwritable
ancestors, parent Root:broker-GID0710, socket Root:broker-GID0660. Bind once, refuse
any existing path, verify named/held identities, listen and retain listener.
Never unlink, replace, select an abstract path, widen accounts or modify a
preexisting endpoint. Pathname inode and sockfs inode are distinct observations.
Creating the new endpoint may set its declared mode/group; no ambient umask change.

Use actual nonblocking/CLOEXEC, PASSCRED=1/PASSPIDFD=0 and Linux little-endian
64-bit pointer/4-byte int/native12-byte '=iII' credential profile. Request ordinary
SO_RCVBUF/SO_SNDBUF=524320, require actual getters>=262176 for this bounded
transport, and before each send require SO_SNDBUF>=2*actual_packet_bytes+32.
These are local preflights, not remote-option observations or guaranteed send.
A maximum-size response may refuse if actual ordinary capacity is insufficient;
never truncate artifacts, force buffers, change sysctls or retry an uncertain send.
This avoids rejecting every smaller compatible response solely because a clamped
buffer cannot hold the theoretical maximum. Wire response bound stays262144.

Construct the real session, separately bind/listen on guard.sock and complete
opening process/namespace/FD/clock/cancellation guards before readiness. Reader
session construction alone establishes only its separate reader listener.
Validate actual provider readiness writer O_WRONLY/O_NONBLOCK/CLOEXEC, Root:Root
FIFO0600 identity/link and dynamic FD/process joins to the v12 expectation. Root
launcher owns the actual sole-writer/reader-copy topology; no Boolean can attest it.

Under the original loop startup deadline, emit exactly the v12 provider-ready/v1
canonical JSON plus LF, <=4096 and actual PIPE_BUF, in one os.write. Its provision/
source/reader/session pins are the exact validated supplied bytes; guard metadata
is actual named socket metadata and ready_ns actual BOOTTIME. Mark attempted
before syscall. Short/EAGAIN/interrupted/unknown write is terminal, never retried.
Retain exact frame and actual write count. The writer remains live after normal
refusal through Root-supervised lifetime; service.close is an explicit terminal
operation. Supervisor, not serve_one's normal return, chooses lifetime end.
Sample actual BOOTTIME after potentially blocking guards/readiness write and
before successful opening return; late completion refuses. No hard syscall
return-time guarantee is claimed.

## Actual first request, protected context and connected reader acquisition

serve_one accepts only one connection by provision.accept_deadline_ns, authenticates
actual kernel peer credentials/socket-derived live PIDFD and protected broker
PID/account, and retains actual bounded process/namespace observations. Poll with
IPC cancellation, supervisor PIDFD and peer PIDFD; cancellation/exit/custody loss
wins simultaneous packet readiness. EOF cancels; any cancellation-pipe data is
an error; EAGAIN after readiness preserves the same original deadline.

Receive one actual datagram <=4096 with DONTWAIT|CMSG_CLOEXEC, retaining controls/
flags and actual immediate receive BOOTTIME (not a later disk-validation stamp).
Exactly one native12-byte SCM_CREDENTIALS joins the authenticated peer. Reject
rights/SCM_PIDFD/extra controls/truncation, but track all actually installed FDs
before metadata and close only known-safe owned handles once. Validate the real
public request; only BEFORE_CONNECT with null predecessor is accepted. First-packet
wait is min(actual accept+250000000, unchanged session deadline); all later work
uses min(original wire deadline, actual receive+250000000, session deadline).
No reset or replacement original acceptance/receipt timestamp.

Derive exact v9 context expectation from protected constructor inputs only:
provision broker/provider/clock/grant/deployment/epoch, measurement/fixture pins,
immutable measurement.source_pins, the five control-ancestry entries (/, /var,
/var/lib, runtime-action parent, control) and unchanged session deadline. Pin its
canonical bytes; never derive expected identity from the packet or candidate file.
Directly call the actual public acquire_broker_reader_context with the unchanged
borrowed connection, exact expectation, measurement/fixture raw pins, original
request and actual request_received_ns. Preserve all eight returned raw/pin fields,
including custody_raw and submission_verification_raw. Do not duplicate its parser,
acquire the broker lock or inspect private state. Its original acquisition deadline
reserves100ms from the phase deadline for the later actual reader challenge.

On a successful public context result, call real session.acquire_challenge with
context_raw/context_digest, exact request, admission_digest=context.grant_digest
and unchanged actual receive timestamp. Preserve the complete actual result and
partial/error observations on every later failure. This executes the actual
listener, protected retention and both independent consumers. No fake response.
Check the service-owned IPC cancellation pipe and supervisor liveness immediately
before and after both public context/session calls, and before send/return.
Inside a frozen session operation its original FD7 governs cancellation; Root
owns closing both the session and IPC cancellation writers. No private state read.

Build the frozen public response from the original returned owned evidence,
connection epoch/bindings, canonical owned.reader, successful owning retention
and checkpoint.acquisition_raw. Status is exactly REFUSED, error_codes exactly
[LOSS_UNAVAILABLE], loss_record null, five flags false. Public protocol validator
checks it against the original request. Do not hash exception bytes into a
successful retention record or truncate an artifact to fit262144. On acquisition
failure preserve original public error and partials; do not publish a successful
ACK/checkpoint. INPUT/PROTOCOL/IDENTITY failures before authentication may close
without response; this bounded profile may otherwise fail terminally without
fabricating a negative health response.

Send once DONTWAIT|NOSIGNAL after guards and capacity check; attempted is consumed
before call, actual count retained only after return. No retry on EAGAIN, short or
unknown send. Keep the socket alive until expected broker EOF under the unchanged
wire/session deadline; queued response+HUP must not discard a complete response.
No extra packet/phase is permitted. EOF after the actual successful acquisition
and complete response permits real session.finish_request(expected_context_digest)
once; retain its terminal bytes. Never call finish to repair a poisoned session.
serve_one normal return does not close the readiness writer, listener, session or
supervisor lifetime. serve_one cannot be called twice.

## Retained outputs, failure and terminal custody

opening_result, serve_one and close return detached exactly {ipc_raw,observed}.
ipc_raw is canonical<=16384, schema aragorn/native-phase3-broker-reader-ipc-observation/v1:
exactly schema,role,operation,provision_digest,context_digest,exchange_id,
request_packet_digest,response_packet_digest,started_ns,received_ns,finished_ns,
deadline_ns,peer,context_file_digest,bound_event_digest,measurement_pending_digest,
status,stream_continuity,loss_completeness,acquisition_authenticity_verified,
sensor_health_verified,effect_authorized,run_qualified,phase3_qualified.
Role SERVICE; operation OPEN/BEFORE_CONNECT/CLOSE. Status OPENED for completed
opening only, REFUSED for a completed refusal exchange, CLOSED for terminal close.
Unobserved pins/marks/peer/context are null; actual marks strict uint. Both
continuity fields UNKNOWN; flags false. Lifecycle status is not action/health proof.

observed has exactly provision_raw,source_inventory_raw,readiness_expectation_raw,
provider_ready_raw,ready_write_attempted,ready_bytes_written,context_expectation_raw,
context_result,context_error,request_raw,response_raw,ipc_raw,session_result,
session_error,session_finish_raw,session_close_raw,handle_observations,transport_observations,
send_attempted,bytes_sent. Unavailable values null, attempted fields initially false.
Preserve actual public context/session returns and exceptions, not recreated success.
Their original raw bounds apply; ready<=4096, context expectation<=16384. At most16
actual ordered snapshots, retaining initial/latest per edge rather than claiming
an entire syscall trace. Each exactly edge,started_ns,finished_ns,
peer_credentials_raw,pidfd_info_raw,proc_raw,boot_raw,namespaces,controls,
receive_flags,socket_options,directories. Edges OPEN/ACCEPT/CONTEXT/RECEIVE/SESSION/
SEND/EOF/CLOSE. Proc map exactly broker_stat_before,broker_status,broker_stat_after,
provider_stat_before,provider_status,provider_stat_after; each null or actual<=16384.
Credentials12, fdinfo<=4096, boot<=64, controls<=8/4096total with level,type,raw.
Namespaces map broker/provider, each time/mount views held,named,link (device,inode;
actual ASCII link<=128). Socket options exactly fd,device,inode,mode,uid,gid,
nonblocking,noninheritable,passcred,passpidfd,sndbuf,rcvbuf,so_type, actual getters.
Directories are actual observed prefixes of fixed provision entries augmented
with held,named five-field metadata. No supplied expectation becomes a raw read.
These Python snapshots preserve actual raw bytes; successful and failed outputs
retain the same full bounded inventory. ipc_raw names only its enumerated
context/request/response/provision digest fields; no implicit snapshot digest
binding or independent authenticity verification is claimed.

handle_observations retains first/latest for IPC_CANCEL, SUPERVISOR_PIDFD and
PROVIDER_READY, at most six rows. Each is exactly role,descriptor,observed_ns,
metadata,flags,descriptor_flags,link,pidfd_info_raw,closed. Metadata is actual
device,inode,mode,uid,gid; flags/descriptor flags are actual strict integers,
link actual ASCII<=128, PIDFD fdinfo null or actual bounded<=4096 bytes.
Unavailable observations are null, never copied expectations. Descriptor>=3,
observed_ns actual uint, closed true only after a confirmed owned close. All
these descriptors are in this process; no remote numeric descriptor is closed.
Retain original exception/owner object identities in detached returned data;
never deepcopy a live socket, unresolved owner or exception carrying ownership.

Errors preserve the first original BaseException, at most32 actual cleanup errors,
observed and a strong local unresolved_owner. Record resource ownership before
fallible metadata. Guard current original process/thread, held identity, flags,
borrowed aliases, namespace links and PIDFD association after external reads and
immediately before each sensitive read/close. Consume close/detach once; never
close a foreign number, retry an ambiguous close or rely on GC cleanup. Keep
unresolved local owners strongly quarantined until owning process exit, even when
caller discards an exception. Do not transfer Python owners across processes.
close attempts independent known-safe resources once, preserves original failures
and actual session.close result/errors, never unlinks sockets or signals/reaps
processes. Root supervisor owns cancellation writers and process lifetime.
Final actual BOOTTIME follows terminal guards/cleanup; late completion cannot
return usable acquisition, readiness or refusal evidence.

## Focused validation and remaining obligations

Prepare newly authored fabricated-native cases using real public codec plus
actual public context/session integration where relevant. No production injection
API; unit boundary mocks must be explicit evidence limits. Cover construction/
transfer even on failure, actual readiness ordering/writer ambiguity, endpoint
custody, original peer/clock/receipt joins, cancellation vs readiness/EAGAIN,
malformed ancillary installed handles, actual context/session call order/raw
retention, LOSS_UNAVAILABLE with no effect path, send/EOF/finish, descriptor
substitution and primary/cleanup interruption/strong quarantine. No historical
TestCases/imports/reruns or live effects. Submit stable hashes and full actual
source/generated/fixture closure before Root schedules one necessary stage.

Root still owes fixed protected launcher/input acquisition, sole writer/FD
inventory, actual bootstrap/configure/client/HTTP renderer, complete installed/
loaded source/deployment evidence, authenticated stream and full loss/program/map,
policy/lifecycle, destructive observer and actual paired contexts. These are
native-use/full-path obligations, not preconditions to writing this service.
The actual original signed context delivery is a concrete execution dependency.
No final qualification, positive two-phase effect path or operational release.
