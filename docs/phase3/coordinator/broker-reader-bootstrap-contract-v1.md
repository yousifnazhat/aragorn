# Fixed broker reader bootstrap contract v1

**SOURCE CONTRACT — released only by signed published provider-release-v12.md.**
Review base: `cfef272262e79a917f11e35889c1c46651c62460`. Root supplies the exact
containing checkpoint after normal push and remote-tip verification. Only RUN's
three explicit paths are released. No registry, execution, staging or operation
is scheduled. Existing operational, private retention and cleanup holds remain.
No bridge, sensor, launcher, service/client or HTTP renderer is assigned here.

The selected implementation is a real, finite descriptor bootstrap. It joins
the existing systemd broker to the Root supervisor and waits on an actual
provider readiness pipe before releasing the HTTP_REFUSAL_ONLY configuration.
It never accepts a readiness/identity/health callback. Missing installed evidence
does not prevent offline implementation and mocked validation of this ABI; it
does prevent claiming that an actual deployment is ready.

## Exact RUN ownership

- `src/aragorn/native_phase3_broker_reader_bootstrap.py`
- `tests/test_native_phase3_broker_reader_bootstrap.py`
- `docs/phase3/run-health/BROKER_READER_BOOTSTRAP_HANDOFF.md`

No shared source, codec, journal, context acquirer, reader session, generated
module, unit, activator or registry edits. The bootstrap module is standard
library only and independently implements this finite transport/custody schema.
It does not import frozen private socket/proc cleanup helpers. Root retains the
reserved IPC service/client/materializer and all actual launch/acquisition work.

## Existing decisions retained

The sole endpoint is `/run/aragorn-phase3-broker-reader/bootstrap.sock`, an
AF_UNIX/SOCK_SEQPACKET pathname socket. Hold `/`, `/run` and the endpoint parent
through nofollow ancestry traversal. Ancestors are Root-owned and not
group/world writable; parent is Root:broker-GID0710 and socket
Root:broker-GID0660. Root binds once, refuses any existing path, verifies named
and held identities, and never unlinks/replaces it. Broker uses O_PATH ancestry
where 0710 prevents directory reads. Pathname and sockfs identities are separate.
No chmod/chown of a pre-existing endpoint is allowed. No abstract/alternate path.

Broker remains `aragorn-broker`, primary `aragorn-runtime`, supplementary
`aragorn-sensor`, with the current credential mounts, empty capabilities and
three-argument HTTP94 generated ExecStart. Shared runtime GID is supported;
broker/runtime UIDs remain distinct in the owning service policy. No non-root
Root-proc bypass, secret-path reopening, privilege widening or helper process.
The broker calls the new client in the same MainPID after protected credential
reads/measurement configuration and before existing startup readiness/serve.

Root supervisor Type=notify/NotifyAccess=main READY means only that the bootstrap
listener constructor returned with its protected endpoint held. It precedes
broker startup and does not wait for the reader session. RELEASE is the later
provider/session barrier. Preserve Restart=no, broker After/BindsTo supervisor,
supervisor PartOf broker, and no supervisor After=broker cycle. Units/entrypoints
and sd_notify implementation remain Root-owned future work.

## Public APIs and single-use state

```python
class BrokerReaderBootstrapServer:
    def __init__(self, *, broker_uid: int, broker_gid: int,
                 startup_deadline_ns: int, session_deadline_ns: int): ...
    @property
    def opening_raw(self) -> bytes: ...
    def accept_hello(self) -> dict: ...
    def offer_handles(self, *, broker_expectation_raw: bytes,
                      expected_broker_expectation_digest: str,
                      ipc_cancel_read_fd: int,
                      supervisor_pidfd: int) -> dict: ...
    def release(self, *, provision_raw: bytes, expected_provision_digest: str,
                source_inventory_raw: bytes, expected_source_inventory_digest: str,
                readiness_expectation_raw: bytes,
                expected_readiness_expectation_digest: str,
                provider_ready_read_fd: int, provider_pidfd: int) -> dict: ...
    def close(self) -> dict: ...

def receive_broker_reader_bootstrap(
    *, capability_grant_raw: bytes, expected_capability_grant_digest: str,
    measurement_binding_raw: bytes, expected_measurement_binding_digest: str,
    fixture_binding_raw: bytes, expected_fixture_binding_digest: str,
    startup_deadline_ns: int,
) -> BrokerReaderBootstrapTransfer: ...

class BrokerReaderBootstrapTransfer:
    def take_configuration(self) -> dict: ...
    def close(self) -> dict: ...
```

Server states are OPEN -> HELLO -> RECEIVED -> RELEASED -> CLOSED. Each method
is callable once in order; failure is terminal, not retryable. `accept_hello`
accepts one actual peer, acquires its socket-derived PIDFD, authenticates its
kernel UID/GID and returns exactly `hello_raw,peer_raw,observation_raw`. Its
returned peer identity is an observation, not the protected expected MainPID.
Root then performs its real fixed-unit/source acquisition and supplies the
expectation to `offer_handles`. No handles leave before that independent join.
The accepted socket and peer PIDFD stay exclusively owned by this server.
`peer_raw` is canonical bytes <=16384, schema
`aragorn/native-phase3-broker-reader-bootstrap-peer/v1`, exactly
`schema,process,clock,mount_namespace,credentials_hex,pidfd_info_hex,observed_ns`.
Process/clock/namespace use the types below; credentials_hex is the actual 12
credential bytes encoded lowercase hex, pidfd_info_hex is actual <=4096-byte
fdinfo encoded lowercase hex, and observed_ns is the actual closing BOOTTIME.

`offer_handles` receives its two distinct FD arguments before fallible metadata,
sends HANDLES once and receives RECEIVED once. Return exactly
`hello_raw,handles_raw,received_raw,observation_raw`. After validating RECEIVED,
close these two sender copies once, with custody guards, before returning.
They are separate transfer copies: Root must not pass its retained supervisory
PIDFD or the provider's cancellation read handle. A failed send may already
have installed receiver FDs; it never permits resending the offer.

`release` takes the readiness read FD and provider PIDFD before metadata reads,
checks their identities/liveness against the supplied final provision, consumes
the actual ready frame defined below, sends RELEASE once and waits for the
broker's expected EOF. It returns exactly `hello_raw,handles_raw,received_raw,
release_raw,provider_ready_raw,observation_raw`. It closes only its own ready
read/PIDFD/accepted-socket copies once; Root retains a distinct provider PIDFD
for later supervision. `close` terminates the remaining listener/ancestry and
other owned handles, leaving the endpoint path. It never sends cancellation,
signals/reaps a child or claims that broker/provider lifetime has ended.

The broker call makes one socket and one connect attempt, receives the two
handles, validates RELEASE, then closes the bootstrap connection once before
returning the transfer owner. It accepts no arbitrary endpoint. The transfer's
`take_configuration` runs once in the original process/thread, rechecks local
handle custody/liveness/cancellation and removes ownership before returning
exactly `provision_raw,expected_provision_digest,source_inventory_raw,
expected_source_inventory_digest,measurement_binding_raw,
expected_measurement_binding_digest,fixture_binding_raw,
expected_fixture_binding_digest,ipc_cancel_read_fd,supervisor_pidfd,
bootstrap_raw`. Root's generated entrypoint immediately passes the first ten
fields to the actual `configure_broker_reader_guard`; it retains bootstrap_raw.
Configuration receives ownership even if it raises. No callback/factory or
implicit private-state access substitutes for this owning call. `close` releases
untransferred handles only; no double close after take_configuration.

All owners pin actual entry PID/native thread/account vectors before fallible
resource metadata, reject reentry/concurrency/fork and retain unresolved local
objects after failure. A single process-lifetime server/client attempt latch
prevents another bootstrap after a consumed attempt; no reset/recovery API.

## Canonical types and bounded packets

Use canonical ASCII JSON, sorted keys, `separators=(",", ":")`, no LF,
duplicate/nonfinite/extra-field rejection. UInt is a non-Boolean integer in
[0,2**63); arithmetic overflow refuses. Pin is `sha256:` plus 64 lowercase hex;
nonce is 64 lowercase hex. Process is exactly `pid,start_time_ticks,uid,gid`,
with PID 1..2147483647, positive start and uint32 accounts. Clock is exactly
`boot_id,clock_id,time_namespace`; canonical lowercase UUID, CLOCK_BOOTTIME and
namespace `device,inode`. Metadata is exactly `device,inode,mode,uid,gid`, inode
positive, mode includes type. Directory identity excludes mutable mtime/nlink.

Packets have these exact fields and no additional generic payload:

| Packet / schema suffix | Exact fields after schema | Bound |
| --- | --- | --- |
| `hello/v1` | `broker_nonce,grant_digest,measurement_binding_digest,fixture_binding_digest,deadline_ns` | 4096 |
| `handles/v1` | `hello_digest,broker_nonce,deadline_ns,supervisor,clock,cancellation_pipe,supervisor_pidfd` | 4096 |
| `received/v1` | `hello_digest,handles_digest,broker_nonce,deadline_ns,cancellation_fd,supervisor_pidfd` | 4096 |
| `release/v1` | `hello_digest,handles_digest,received_digest,broker_nonce,deadline_ns,provider_ready_digest,provision,provision_digest,source_inventory,source_inventory_digest` | 131072 |

All schemas use prefix `aragorn/native-phase3-broker-reader-bootstrap-`.
The broker mints its nonce internally once. HELLO contains hashes of its actual
protected input bytes, not an asserted PID. `handles.supervisor` is the actual
Root server process. `cancellation_pipe` is five-field metadata for Root:Root
FIFO0600. `handles.supervisor_pidfd` is exactly `metadata,pid`, where metadata
is the five-field actual sender observation and pid equals supervisor.pid.
The receiver compares the received PIDFD's identity and actual local fdinfo
association; a sender FD number is neither present nor meaningful remotely.
Client requires HANDLES supervisor PID/UID/GID to equal its actual authenticated
SO_PEERCRED and the socket-derived PIDFD association. Root start ticks and peer
namespace/source facts remain protected received bindings where local access is
unavailable; this does not turn those supplied values into local observations.
RECEIVED's two descriptor fields are distinct actual receiver FD integers >=3.
Root independently observes those broker fd/fdinfo links before release.

The three broker credential arguments are immutable canonical byte inputs with
independent digest arguments: grant<=65536, measurement<=8192, fixture<=16384.
This bootstrap validates their canonical encoding/bounds/pins; existing service
configuration and the later actual guard configure own semantic credential
validation. It never reopens their inaccessible source paths.

HELLO carries the broker's original caller-held startup deadline. The server's
original startup deadline and HELLO deadline are immutable; the effective wire
deadline is their minimum, echoed in all later packets. Neither preliminary
wait renews a budget. Fixed maximum local startup budget is 4 seconds,
strictly below session_deadline; each entry rejects a caller deadline beyond
actual entry BOOTTIME+4s. Root selected this cap during source review. The broker
does not know session_deadline until RELEASE; it joins the received value there.

RELEASE embeds the provision and installed-source inventory objects specified
below, not base64 copies. Canonicalizing each embedded object must reproduce its
supplied original bytes/pin. The bootstrap checks these exact structural schemas
and enumerated joins; it does not acquire inventory file bytes or establish
loaded-source identity. Root launch owns that acquisition, and actual guard
configure owns full semantic validation of its reader and credential inputs.
Client receives authenticated Root bindings, not local Root-proc observations.

Provision is <=16384 bytes, schema
`aragorn/native-phase3-broker-reader-ipc-provision/v1`, exactly:

```text
schema profile broker provider supervisor clock epoch_digest deployment_digest
grant_digest measurement_binding_digest fixture_binding_digest source_inventory_digest
access_inventory_digest reader_session directories cancellation_pipe
session_deadline_ns accept_deadline_ns
```

Profile is HTTP_REFUSAL_ONLY, with no positive switch. The three distinct process
records have non-root broker UID/GID and root provider/supervisor UID/GID. Clock
uses the full shape above. Every *_digest is a pin. `reader_session` is exactly
`epoch_digest,checkpoint_provision_digest,transport_provision_digest,stream_digest,
loop_provision_digest`, all pins; its epoch equals the outer epoch. Deadlines are
positive uint with accept_deadline_ns<session_deadline_ns. Accept must remain
future when RELEASE is validated; bootstrap may not spend the entire guard budget.
`directories` is exactly seven ordered `path,device,inode,mode,uid,gid` records:
`/`, `/run`, `/run/aragorn-phase3-broker-reader`, `/var`, `/var/lib`,
`/var/lib/aragorn-runtime-action`, `/var/lib/aragorn-runtime-action/control`.
All are directories. Ancestors are root-owned and not group/world writable;
endpoint parent is Root:broker-GID0710 and control broker-UID:broker-GID0700.
The bootstrap actually observes its first three ancestry entries; remaining
entries stay Root-supplied expectations for the later guard/context acquisition.
`cancellation_pipe` is exactly `device,inode,mode,uid,gid,writer,readers`, the
Root:Root FIFO0600 from HANDLES. Writer is `{process:"SUPERVISOR",fd:uint}`;
readers is exactly `[{process:"PROVIDER",fd:uint},{process:"BROKER",fd:uint}]`.
All FD values are >=3; compare same-process descriptors only. Equal numbers in
different processes do not imply aliasing. Root joins actual peer FD inventories;
client observes only its own received end and the authenticated Root bindings.

Source inventory is <=65536 bytes, schema
`aragorn/native-phase3-broker-reader-installed-sources/v1`, exactly
`schema,predecessor_report_digest,entries`. Predecessor is the fixed HTTP94 report
pin below. Entries are 1..128 unique ascending paths, each exactly
`path,role,bytes,digest,device,inode,mode,uid,gid`. Role is BROKER/PROVIDER/SHARED;
path is an absolute ASCII normalized path <=4096 bytes, with no empty, dot, dotdot
or NUL components. Byte count is positive uint<=16777216 and aggregate<=67108864;
digest is a pin; metadata is regular root-owned and not group/world writable.
This leaf does not open a path obtained from this inventory. The actual finite
installed allowlist, single-link checks, exact bytes and loaded-process mapping
are Root acquisition/configuration obligations, not inferred from this shape.

Final provision broker equals the authenticated socket peer and protected unit
expectation; supervisor equals actual server; provider equals the ready PIDFD;
the three credential pins equal HELLO; reader/session/source pins equal the ready
frame. Its broker cancellation FD equals RECEIVED, and its actual pipe metadata
equals HANDLES. Its clock shares actual self BOOTTIME/boot/time-namespace; join
the reader epoch's separate inode spelling explicitly, not whole-object equality.
Session deadline remains the original supplied deadline; all bootstrap timestamps
must precede it. No broker-supplied value may create its own expected identity.

## Protected MainPID expectation and Root-owned acquisition

`broker_expectation_raw` is <=16384 bytes, schema
`aragorn/native-phase3-broker-reader-bootstrap-peer-expectation/v1`, exactly:

```text
schema broker clock mount_namespace unit invocation_id control_group
command_digest executable_digest source_inventory_digest grant_digest
measurement_binding_digest fixture_binding_digest observed_before_ns observed_after_ns
```

The unit is literal `aragorn-runtime-lineage-capability-action-broker.service`;
InvocationID is 32 lowercase hex, control_group is one bounded canonical absolute
cgroup path <=4096 bytes, mount_namespace is `device,inode`. Command/executable/
source and credential fields are pins. Observation times are actual uint with
before<=after<=current startup deadline. Root's protected acquisition supplies
the raw systemd before/after result, actual MainPID/InvocationID/cgroup, exact
cmdline/executable and final generated-source inventory. These external raw
records remain Root-owned evidence; this leaf does not call systemctl or accept
caller booleans as their substitute.

The server independently checks the accepted kernel peer/PIDFD, actual bounded
stat/status/stat, cmdline, executable bytes/digest, cgroup, held/named mount/time
namespaces and boot against the expectation. It retains actual reads. Root must
reacquire/compare the fixed unit and all launch/source bindings after RECEIVED
and before `release`; the final provision's broker and source pins must still
match. This is an explicit trusted-caller obligation, not a claim that the
bootstrap independently queried systemd or proves uninterrupted ownership.

Broker checks actual self account vectors, own stat/start, mount/time namespace,
protected `/run/aragorn-broker-boot-id`, socket credentials and local PIDFD
association/liveness. Its initial Root authentication is the fixed protected
endpoint plus actual root UID and socket-derived live PIDFD. Received Root
start/namespace/source facts are authenticated Root acquisitions; inaccessible
Root proc/named namespaces remain null in client observations. Do not alter
ProtectProc, ProcSubset, credentials or unit accounts to obtain those reads.

## Separate concrete provider readiness channel

Root creates one fresh anonymous Root:Root FIFO0600, unrelated to reader FD8,
reader FD7 and IPC cancellation. Provider owns the sole nonblocking/CLOEXEC write
end; Root transfers its sole nonblocking/CLOEXEC read end to `release`. No other
writer/reader copy remains. Numbers are dynamic, acquired by the launcher and
joined through actual provider fd/fdinfo observations; no inherited FD is
pretended to exist in the current systemd units. The reader session exclusively
owns its original completion channel and this module never reads it.

`readiness_expectation_raw` is <=4096 canonical bytes, schema
`aragorn/native-phase3-broker-reader-bootstrap-readiness-expectation/v1`, exactly
`schema,provider,supervisor,pipe,provider_write_fd,supervisor_read_fd,
provision_digest,source_inventory_digest`. Processes/pins use the shapes above;
pipe is five-field FIFO0600 Root:Root metadata, and FDs are uint>=3. This protected
Root launcher input binds both dynamic endpoints. The server matches the actual
supplied read FD and local identity, and independently reads the actual named
provider FD/link/fdinfo to join the sole writer and its O_WRONLY/O_NONBLOCK/
CLOEXEC properties. It retains those actual observations. Caller-supplied
"sole writer" is not a discovered kernel history: the fixed Root launch source
must close all unlisted copies and retain its exact process/FD inventory.

Provider writes exactly one canonical ASCII JSON frame plus LF, <=4096 bytes and
<=actual PIPE_BUF, in one os.write, then keeps that writer alive until bootstrap
release/lifetime completion. Frame schema
`aragorn/native-phase3-broker-reader-provider-ready/v1`, exact keys:

```text
schema provider supervisor clock provision_digest source_inventory_digest
epoch_digest checkpoint_provision_digest transport_provision_digest stream_digest
loop_provision_digest guard_socket ready_ns
```

`guard_socket` is exactly `path,metadata`; path is the fixed
`/run/aragorn-phase3-broker-reader/guard.sock`, metadata is actual named socket
metadata. Root holds and compares that protected named socket and provider
process/PIDFD/pipe associations. A file inode does not itself attest listening.
The loaded owning provider writes only after constructing the real
ReaderCheckpointSession, binding/listening on its real guard socket and completing
all its opening guards. The session constructor already consumes/validates the
actual reader FD8 startup frame, constructs ReaderListener and checks completion
quiescence before returning; no private `_state` inspection or separate Boolean
readiness callback is allowed. The new provider writer/caller is Root's concrete
remaining source obligation.
ReaderListener owns the separate reader challenge endpoint; constructing it is
not guard.sock readiness. The provider must separately bind/listen on guard.sock
before writing this frame. Successful session construction alone is insufficient.

Root receives the entire frame with bounded partial retention, validates every
pin/identity, checks ready_ns<=actual_received_ns<effective startup deadline,
checks no prequeued surplus frame and rechecks provider liveness and all held
custody. EOF before a complete frame, data after its LF, pipe substitution,
unknown writer custody or provider exit refuses. EAGAIN after readiness resumes
the same bounded read; it is neither EOF nor readiness proof. The frame proves
this loaded provider's bounded startup assertion and the actual read; it carries
no health, acquisition-authenticity, loss completeness or effect authority.

## Socket, transferred handles, cancellation and terminal behavior

Use Linux little-endian 64-bit pointer/native 4-byte int ABI, native 12-byte
`=iII` credentials, PASSCRED=1,
PASSPIDFD=0, actual O_NONBLOCK/FD_CLOEXEC and noninheritability. SO_PEERCRED and
SO_PEERPIDFD must join the same peer; bounded local fdinfo (<=4096 bytes) has one
positive matching Pid field and polling shows no exit. Root additionally checks
actual named process/source/namespace bindings. No numeric-PID fallback.

Exactly HANDLES carries one SCM_RIGHTS item containing exactly two native int
FDs in order: IPC cancellation read end, supervisor PIDFD. Every packet carries
exactly one SCM_CREDENTIALS matching the authenticated sender. No packet uses
SCM_PIDFD. Receive with DONTWAIT|CMSG_CLOEXEC; send with DONTWAIT|NOSIGNAL. Bound
ancillary bytes at CMSG_SPACE(12)+CMSG_SPACE(8); reject truncation, duplicates,
unexpected controls and flags outside MSG_EOR/MSG_CMSG_CLOEXEC. Track all actually
installed descriptors before metadata reads, including malformed ancillary.
Close known-safe unexpected installed handles once before refusal; unknown or
foreign custody remains retained/unclosed. No FD number derived from payload
bytes is ever closed. Received descriptor numbers must be distinct from socket,
peer PIDFD and all already owned resources.

Each endpoint requests ordinary SO_RCVBUF=262176 and SO_SNDBUF=262176 and requires
both actual getters>=262176. Before each send also require actual
SO_SNDBUF>=2*packet_bytes+32. These are local capacity preflights, not claims of
remotely observed options or guaranteed send success; each receiving owner checks
its own actual buffers. No force-buffer option/sysctl change. One send call per
packet; EAGAIN, short/unknown result or interruption after attempt is terminal,
not permission for another send. A connect in progress may be polled to completion
on the same socket and SO_ERROR; no second connect. Final source review must
verify all actual constants/flags and capacity checks against the selected mock
ABI before scheduling; deployment must separately observe native support.

Root retains the sole cancellation writer; server only transfers a distinct
read copy. Provider and broker hold their two declared read references. All
unlisted copies close before RELEASE; Root actually checks receiver FD numbers
from RECEIVED. Root writes no data; EOF cancels. A byte is a protocol error;
readiness followed by EAGAIN is not cancellation. The client polls this pipe after
HANDLES with its peer/supervisor PIDFD. Before HANDLES, root-peer death/connection
failure/deadline refuses. During release, Root polls provider PIDFD/ready pipe and
broker PIDFD; its supervisor cancellation policy owns closing writers on signal
or failure. This bootstrap does not borrow session FD7 or read private state.

Cancellation, peer/provider exit and custody failure take precedence over packet
readiness. Apply current owner/flags/link/final-fstat guards at I/O and cleanup
boundaries. Deadline samples follow potentially blocking guards. No hard return
time is promised for proc, file reads, fsync or kernel calls. No helper thread.

After sending RELEASE, Root keeps the connection alive until broker validates
and closes it. Broker accepts the complete packet, performs final guards and
closes once; it sends no extra ACK. Root resolves expected EOF under the same
startup deadline; additional payload or incomplete packet is terminal. Closure
is lifecycle completion, not proof that configure or the future HTTP call passed.
Any send uncertainty is preserved; missing response is not proof of no transfer.

After successful bootstrap, Root provider/supervisor remain alive through the
fixed session lifetime, including after one normal REFUSED guard exchange, so
BindsTo cannot truncate the broker's outer result. Root retains distinct PIDFDs
and its cancellation writers until fixed deadline or explicit cancellation.
Unexpected child exit/bootstrap/custody failure poisons the whole launch and
Root closes all declared cancellation writers; termination/reaping is a separately
reviewed Root launcher responsibility. No second attempt/restart/socket cleanup.

## Bounded outputs, errors and focused checks

`observation_raw`/`opening_raw`/`bootstrap_raw` are <=3145728 canonical bytes,
schema `aragorn/native-phase3-broker-reader-bootstrap-observation/v1`, exactly
`schema,role,phase,started_ns,finished_ns,deadline_ns,packet_digests,peer,
provider_ready_digest,status,limitations,packet_artifacts,provider_ready,
handle_observations,transport_observations`. Role SERVER/CLIENT; phase
OPEN/HELLO/HANDLES/RELEASE/CLOSE; unavailable actual marks/pins/peer are null.
peer is null or the complete actual process record. If any process field is
locally unavailable (notably CLIENT's Root start ticks), the entire peer field
is null; actual credentials/PIDFD bytes remain retained in transport observations.
Unavailable fields are never filled from a protected expectation. The separate peer_raw retains the actual kernel
credential/PIDFD joins above.
packet_digests is exactly hello,handles,received,release with null-or-pin values.
packet_artifacts has those same four keys, null or the corresponding actual
packet artifact, and its digests agree with packet_digests. provider_ready is
null or the actual received readiness-frame artifact, matching its digest.
Every raw bytes field in serialized handle/transport observations uses the
artifact shape `{base64,bytes,digest}`: canonical base64, exact non-Boolean byte
count, SHA-256 of the bounded original bytes. Empty actually observed bytes are
permitted; unobserved bytes are null. Bound raw bytes before encoding/hashing.
This is evidence packaging, not authenticity or semantic verification.
Status OPENED/RECEIVED/RELEASED/CLOSED/REFUSED is transport lifecycle only.
Limitations are the fixed list: NO_HEALTH_OR_EFFECT_AUTHORITY,
NO_LOSS_COMPLETENESS,NO_LOADED_SOURCE_ATTESTATION,
ROOT_CALLER_OWNS_UNIT_SOURCE_AND_LAUNCH_ACQUISITION,
CLIENT_ROOT_PROC_OBSERVATIONS_UNAVAILABLE,NO_PHASE3_QUALIFICATION.

Errors are `BrokerReaderBootstrapError(original_failure, cleanup_failures,
observed, unresolved_owner)`. Preserve original interruption/resource-exhaustion
instances and attach the same bounded observed/cleanup fields. `observed` is
exactly `hello_raw,handles_raw,received_raw,release_raw,provider_ready_raw,
observation_raw,send_attempted,bytes_sent,handle_observations,transport_observations`.
Unavailable fields are null; packets/ready prefixes keep their stated bounds.
send_attempted is consumed before the current send, bytes_sent is null until
actual return. Maximum 32 cleanup failures. At most 32 handle observations
record actual `fd,role,process_role,metadata,flags,descriptor_flags,link,pidfd_info_raw,closed`,
unavailable fields null and fdinfo<=4096/link<=128. Role is LISTENER, CONNECTION,
PEER_PIDFD, CANCEL_TRANSFER, SUPERVISOR_TRANSFER, READY_READ, PROVIDER_PIDFD,
ANCESTOR, NAMESPACE, TRANSIENT or UNEXPECTED_ANCILLARY. fd is an actual uint;
Two observation-only roles are READY_WRITER and CANCEL_RECEIVED; process_role
is SELF, PEER or PROVIDER and disambiguates every numeric FD. These remote
observations confer no ownership: their closed field is false, and their numeric
FD is never passed to local close. All owned-resource rows have process_role SELF.
flags/descriptor_flags are actual uint, metadata the five-field shape above,
closed a literal Boolean set only after successful owned close. Each encoded
handle observation is <=8192 bytes. At most 16 transport snapshots
record `edge,process_role,started_ns,finished_ns,peer_credentials_raw,pidfd_info_raw,
stat_before_raw,status_raw,stat_after_raw,cgroup_raw,cmdline_raw,boot_raw,
executable_digest,namespaces,socket_options,directories`; proc/cmdline/cgroup each<=16384, boot<=64,
credentials12, fdinfo4096. Freeze nested snapshot key shapes by reusing the IPC
protocol's metadata semantics with these self-contained exact shapes:

- edge is OPEN, ACCEPT, CONNECT, RECEIVE, TRANSFER, READY, SEND, EOF or CLOSE;
  process_role is SELF, PEER or PROVIDER and names the process for stat/status/
  cgroup/cmdline/executable observations. Socket peer credentials and local peer
  PIDFD info remain explicitly those of the authenticated connection peer.
  all timestamps are actual uint or null until observed. executable_digest is
  null or the digest of actually read bounded executable bytes, never an expected
  pin relabeled as observed. No executable/source raw bytes are returned here.
- namespaces is exactly `self,peer,provider`. Each is null or exactly `time,mount`;
  each of those is null or exactly `held,named,link`, with held/named null or
  `device,inode` and link null or actual ASCII namespace spelling <=128 bytes.
- socket_options is null or exactly `fd,device,inode,mode,uid,gid,nonblocking,
  noninheritable,passcred,passpidfd,sndbuf,rcvbuf,so_type`. Only nonblocking and
  noninheritable are literal Booleans; other values are actual uint.
- directories is an observed prefix of the three ordered bootstrap ancestors;
  each is exactly `path,held,named`, with held/named null or five-field metadata.

SERVER may retain actual peer proc reads; CLIENT leaves inaccessible Root views
null. Each encoded transport snapshot is <=131072 bytes. The error's Python
handle_observations/transport_observations retain bytes directly; the successful
public observation_raw/bootstrap_raw embeds the same actual observations with
the artifact encoding above. This supplies successful actual raw custody to
the owning caller without private-state access. No raw field is invented from
a supplied expected identity. Keep initial/latest snapshot per executed edge
within the 16-record cap, with actual timestamps; it is not a complete syscall
trace. Never discard actually installed ancillary-FD ownership to fit a cap.
An observation cap poisons the attempt and preserves available partials.

Calculated non-wire bound: 16*131072 snapshot bytes + 32*8192 handle bytes +
<=212992 bytes for four bounded packet/readiness artifacts + <=16384 structural
overhead is <=2588672, below the selected 3145728-byte limit. Enforce those
component caps as well as the total. The largest raw snapshot contribution is
five 16384-byte proc/cgroup/cmdline fields plus 4096 fdinfo, 64 boot and 12
credential bytes; canonical artifact expansion fits its stated 131072 cap.
No packet/wire bound or existing reader response schema is enlarged.

Cleanup consumes each owned close/detach once, rechecks original owner plus
metadata/flags/link and PIDFD association after external reads and immediately
before numeric close, and skips foreign or unknown handles. Failed detach keeps
the actual local object/exception strongly held until process exit; no GC cleanup,
cross-process object transfer or retry. One bounded unresolved owner poisons
subsequent acquisition. Borrowed Root supervision/cancellation-writer descriptors
are never closed by this leaf. Root preserves every returned partial/error.

Focused mocked cases must cover all four actual messages and fixed order, dynamic
receiver FD inventory, wrong/missing peer credentials and PIDFD association,
every malformed ancillary/installed-FD path, live/unknown owner cleanup and late
flags/link/PIDFD substitution, partial/oversize send and packet bounds, stale
nonce/pins/role/account/clock/source expectations, independent unit-expectation
join, provider-ready partial/extra/EOF/EAGAIN/exit/deadline, cancellation priority,
queued RELEASE versus HUP, one-time transfer into the future configure call,
strong quarantine after discarded errors, and lifetime/close refusal. All native
boundaries fabricated; fixtures authored locally. No historical suite imports.
Submit stable hashes and actual full closure before Root registry/scheduling.

## Root review decisions and remaining integration obligations

Root selected the 4-second original startup cap and ordinary local buffer profile
during review; exact nested snapshot, readiness-expectation and embedded
provision/inventory schemas are fixed above. No inaccessible untracked draft is
a schema dependency. Root and an independent reviewer found no remaining
concrete offline source blocker after correcting successful raw retention.
The exact interfaces/paths take effect at the signed published v12 checkpoint.
No live/installed observation is required before this bounded implementation;
those remain mandatory before later native-use or deployment claims.

Root must then supply the actual fixed-unit/source/credential acquisition caller,
dynamic final provision/FD inventory, separate provider-ready pipe/writer, actual
service/session construction and guard listener, supervisor cancellation/lifetime,
broker configure integration, generated HTTP94 renderer/source inventories and
units/activators. A ready transport slice does not complete these obligations.
The frozen context leaf remains Admission-owned. Bridge post-exec CLOEXEC,
one-use sensor subscription and complete loss remain explicit successor work.

Source anchors: `broker-reader-bootstrap-review-v1.md` selected two-FD/order/units;
`http94-caller-successor-review-v1.md:65–95`;
`native_phase3_run_reader_checkpoint_session.py:164–258,991–1015`;
`native_phase3_broker_reader_protocol.py:152–224`; systemd broker unit:17–29,41–74.
Preserve HTTP94 report sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9;
do not repeat unchanged predecessor staging.

Completed: bounded bootstrap/readiness source contract and independent review.
RUN's three-path source-only assignment takes effect at the signed published v12
checkpoint. Actual launch/caller integration remains Root implementation work.
Remaining Phase 3 steps:

1. Publish exact assignments; review stable closure and schedule only new checks.
2. Wire protected HTTP/DNS/destructive/a100, admission/RUN and actual paired tasks.
3. Close the existing ledger's real paths/consumers/custody and freeze implementation.
4. Separately release qualification, independent replay, gate evaluation and cleanup.
