# Protected broker context acquisition contract v1

Status: reviewed by Root and released with provider-release-v9.md in its
containing signed published checkpoint. Only the three assigned Admission paths
are released; no test execution is scheduled. Live operations, private retention
and cleanup remain held. Root retains registry and scheduling ownership.

This is the bounded context-acquisition prerequisite for the reserved Root
`native_phase3_broker_reader_service.py` caller. It acquires the actual broker's
retained context, BOUND event and measurement pending record, joins independently
held expectations to a kernel-observed peer and filesystem, and invokes the
existing independent submission-prefix consumer. It does not implement IPC
bootstrap, receive a request, acquire a broker lock or authorize an HTTP effect.
The unreleased full IPC draft remains unreleased except for this separately
assigned leaf after Root publishes its release.

## Ownership and public API

Assigned owner: existing Admission worktree, with only these new paths:

- `src/aragorn/native_phase3_broker_reader_context.py`
- `tests/test_native_phase3_broker_reader_context.py`
- `docs/phase3/admission/BROKER_READER_CONTEXT_HANDOFF.md`

No edits to the journal, codec, independent verifier, HTTP helpers, reader
session, generated modules, service units, registry or another lane's files.

```python
def acquire_broker_reader_context(
    connection, *,
    expectation_raw: bytes, expected_expectation_digest: str,
    measurement_binding_raw: bytes, expected_measurement_binding_digest: str,
    fixture_binding_raw: bytes, expected_fixture_binding_digest: str,
    request_raw: bytes, request_received_ns: int,
) -> dict: ...

class BrokerReaderContextError(ValueError):
    original_failure: BaseException
    cleanup_failures: tuple[BaseException, ...]
    observed: dict
    unresolved_owner: object
```

`connection` is the actual, exclusively borrowed accepted AF_UNIX/SOCK_SEQPACKET
socket owned by the Root service. Never close, detach, duplicate, send, receive,
shutdown, reconnect, reconfigure or transfer it. The implementation acquires and
owns its own peer PIDFD, namespace, ancestry, record and transient proc FDs.
Track every acquired FD before any fallible metadata operation. FD numbers are
not proof of continued ownership. The caller must keep its borrowed socket
alive and exclusively owned until return or exception.
An acquired FD must not alias that borrowed descriptor or another held owned FD;
an invalid/aliased descriptor is refused without closing the borrowed handle.

This public operation is one attempt in the original Linux Root main process
and thread. Reject reentry, concurrent use and post-import fork before receiving
ownership or touching the original owner's resources. Consume a process-local
one-attempt latch only after that original-owner check; a failed authorized
attempt cannot be retried or recovered. No factory or callback argument can
replace the actual acquisition or independent consumer. The sole production
caller remains the reserved Root service; connecting that caller is Root-owned
follow-up work, not completion claimed by this leaf.

## Canonical inputs and exact expectation

All JSON here is canonical ASCII: sorted keys, separators `,` and `:`,
`ensure_ascii=True`, `allow_nan=False`, no LF. Reject duplicate keys, nonfinite
values, noncanonical encodings and any extra field. `uint` means a non-Boolean
integer in `[0,2**63)`. A pin is `sha256:` followed by 64 lowercase hex digits;
a nonce is 64 lowercase hex digits. Check byte bounds before parsing or hashing.
Arithmetic must remain in the uint domain; overflow refuses.

Process is exactly `pid,start_time_ticks,uid,gid`: PID 1..2147483647, positive
start ticks, UID/GID 0..4294967295. Clock is exactly
`boot_id,clock_id,time_namespace`; boot is lowercase canonical UUID,
clock_id is `CLOCK_BOOTTIME`, and namespace is exactly `device,inode`, with
uint device and positive uint inode.

`expectation_raw` is 1..16384 bytes, exactly:

```text
schema broker provider clock grant_digest deployment_digest epoch_digest
measurement_binding_digest fixture_binding_digest broker_source_pins
directories session_deadline_ns
```

Schema is `aragorn/native-phase3-broker-reader-context-expectation/v1`.
Broker and provider are distinct process records; broker UID/GID are positive,
provider UID/GID are zero. Provider must be this actual original Root process.
The actual broker may share the runtime GID, as the current service uses
Group=aragorn-runtime. Do not demand GID separation or invent an expected runtime
identity in this leaf. Runtime UID separation remains the owning launch policy;
this contract acquires the actual broker identity only. All proc/root/namespace
reads here run as Root; no non-root broker access to Root proc state is assumed.
All five named digest fields are pins. Session deadline is positive uint.
`broker_source_pins` is a map of 1..128 exact Python basenames to pins; basename
syntax is `[A-Za-z_][A-Za-z0-9_]{0,127}\.py`, with no separators or dot components.
The map is an independently held expected inventory, not an observed installed
or loaded-source inventory. Its entire canonical encoding must fit the enclosing
expectation and measurement binding bounds.

`directories` has exactly these five ordered entries:

```text
/
/var
/var/lib
/var/lib/aragorn-runtime-action
/var/lib/aragorn-runtime-action/control
```

Each entry is exactly `path,device,inode,mode,uid,gid`. Mode includes file type;
all are directories, device is uint and inode positive. The first four are
Root-owned, with their exact independently pinned GIDs and no group/world write.
The control directory is exactly broker-UID:broker-GID0700. Directory comparisons
use device/inode/mode/uid/gid, not size, link count or modification times, because
the broker may legitimately create later journal files.

All three expected input digests are independently supplied by the protected
Root caller and match the exact raw bytes. Measurement/fixture digest arguments
also match the corresponding expectation fields; the expectation has no
self-referential digest field. Do not derive an expected identity from a candidate request/context.
This leaf does not acquire those caller expectations from a launch credential.
Root must do so in the later protected service bootstrap.

### Measurement and fixture inputs

`measurement_binding_raw` is 1..8192 bytes. The HTTP successor bound is 8192,
not the predecessor module's 4096. It is exactly:

```text
schema boot_id attempt_id deployment_identity_digest measurement_schedule_digest
collection_commitment_digest scheduled_measurement_request_digest grant_digest
runtime_profile_digest sensor_digest source_pins runtime_digest policy_digest
active_skill_digest operation_digest path_digest payload_digest
```

Schema is `aragorn/runtime-broker-decision-measurement-binding/v1`. Its boot ID
matches the actual/expected clock; source_pins exactly equals broker_source_pins.
Every `*_digest` is a pin. Attempt ID must pass the existing public HTTP effect
helper; this immediate HTTP profile supports its actual `p3-lab-a001`..`a025`
canary range. It does not invent a representation for a100 or another family.
Grant and deployment identity pins equal the expectation. Schedule, collection,
sensor, runtime and policy pins remain protected supplied bindings here; this
leaf does not resolve their CAS, establish admission or qualify a measurement.

`fixture_binding_raw` is 1..16384 bytes, exactly
`schema,fixture,expected_broker_uid,expected_broker_gid`. Schema is
`aragorn/runtime-http-fixture-binding/v1`; broker accounts match the expectation.
Fixture is exactly `container_id,boot_id,netns_device,netns_inode`: container ID
is a nonce, boot is the common boot ID, netns device uint and inode positive.
Validate through public `runtime_http_action.validate_fixture_binding` as well.
These are protected expected HTTP fixture bindings, not an observation of an
actual net namespace or endpoint by this leaf.

`request_raw` is 1..4096 bytes validated by PUBLIC `validate_guard_request`.
Require BEFORE_CONNECT and null previous_response_digest. Retain its original
bytes. The request and request_received_ns come from the protected service's
actual receive path in the later integration. This leaf cannot prove their
SCM_CREDENTIALS or receive timestamp by accepting them as arguments; it reports
that ceiling explicitly and never manufactures a receive event.

## Actual descriptor, peer and filesystem acquisition

Require Linux, little endian and the native 12-byte `=iII` credential ABI.
Read the borrowed socket's actual family, SO_TYPE, timeout, FD flags, inheritance
and fstat identity. Require AF_UNIX/SOCK_SEQPACKET, timeout zero, O_NONBLOCK,
CLOEXEC/noninheritability, and a socket file type. Require existing
SO_PASSCRED=1 and SO_PASSPIDFD=0; do not change either. The supplied object must
keep the same fileno and full fstat identity around acquisition. SO_PEERCRED
(Linux option 17) must be exactly the protected broker PID/UID/GID.

Acquire SO_PEERPIDFD (Linux option 77), mark it owned immediately, require
noninheritability, a unique positive `Pid:` association equal to that peer from
bounded actual `/proc/self/fdinfo/<fd>` bytes, and no PIDFD poll event. No
numeric-PID-only fallback is allowed. Peer credentials and PIDFD are kernel
observations of this connection; they do not authenticate caller-supplied
request bytes or prove a received per-message credential.

Hold self and broker `/proc/<pid>/ns/time` handles and the broker's
`/proc/<pid>/ns/mnt` handle. These are specifically allowed proc namespace magic
links; arbitrary links are forbidden. Require regular nsfs handles, held/named
device/inode equality, and exact `time:[inode]` / `mnt:[inode]` links. Both actual
time namespaces must equal the expected device/inode. Broker mount namespace
need not equal Root's; its actual string/device/inode are retained separately.

Bracket the acquisition with actual Root/broker stat/status/stat reads, peer
PIDFD association/liveness, `/proc/sys/kernel/random/boot_id`, owned socket/FD
identities, namespaces and monotonic CLOCK_BOOTTIME samples. Proc stat start
ticks match expected identities. Each status has exactly one Uid/Gid vector,
four equal uint values matching expected accounts. Root's actual getresuid and
getresgid are `(0,0,0)`; PID and native main-thread ID remain the original PID.
Do not invent an empty broker supplementary-group policy: the existing broker
unit has a separately controlled supplementary group. This leaf does not claim
complete systemd/capability-policy acquisition.

Open and hold the five fixed Root-view directories using nofollow directory
opens. Additionally hold the one intentional `/proc/<broker PID>/root` magic-link
directory, then walk only the same fixed var/lib/runtime-action/control components
relative to it with nofollow directory opens. Both views must match the five
expected ancestry identities. Guard the named broker-root magic link against its
held identity, with the broker PIDFD/start and held mount namespace throughout.
This is a concrete shared-filesystem join across PrivateMounts. Denied proc/root
access, a different control directory or source view refuses; never enter the
namespace, substitute Root's own view or weaken permissions to make it pass.

Only after validating the strict request pin derive these three names under the
held control directory:

- `run-reader-<request hex>-context.json`, 1..8192 bytes;
- `run-reader-<request hex>-event-0.json`, 1..8192 bytes;
- `decision-measurement-pending.json`, 1..131072 bytes.

Open each once O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC. Each must be regular,
single-link, broker-UID:broker-GID0400 and within its bound; all three device/inode
pairs are distinct. Full identity is exactly
`device,inode,mode,uid,gid,nlink,bytes,mtime_ns,ctime_ns`; metadata times are signed
64-bit integers, all other numeric metadata uint with positive inode/nlink.
Compare held metadata and both Root/broker-view named metadata before and after
bounded reads. Retain the original bytes, then reread all three exactly under
the held descriptors and names before final success. Guard the full peer,
namespace and ancestry identities around those reads. Do not accept changed,
partial, missing, malformed, linked or differently owned records. No polling
retry, broker-lock acquisition, file creation, retention publication or cleanup
occurs in this leaf.

## Semantic joins and independent replay

The pending record is canonical and exactly these ten fields:

```text
schema binding process clock_id acceptance_boundary accepted_boottime_ns
action_request_digest submission_digest lease_digest runtime_attribution_digest
```

Schema is `aragorn/runtime-broker-decision-measurement-pending/v1`; clock_id is
CLOCK_BOOTTIME, and acceptance_boundary is exactly
`V4_ISSUED_SUBMISSION_VALIDATED_BEFORE_GRANT_CLAIM`. Canonical binding bytes equal
the protected measurement_binding_raw. Process is exactly
`boot_id,pid,uid,gid,start_time_ticks,mount_namespace`; all match actual broker
observations, including its separately acquired `mnt:[inode]` string. The four
digest fields are pins. The original accepted timestamp is uint and equals the
context's accepted_boottime_ns; action_request_digest equals the actual acquired
context and candidate request's request_digest. Do not substitute scheduled
measurement request digest for action_request_digest.

Use only PUBLIC `effect_for_attempt(plan['attempt_id'])` and
`action_digests(plan['attempt_id'], fixture_binding)` to derive the selected
canary effect and its operation/path/payload pins. Context effect_digest is the
canonical digest of that effect. All three action pins equal the protected plan.
This reuses existing HTTP byte semantics without invoking an HTTP effect or
reading the broker's inaccessible source credential paths. Actual fixture/netns
and source/deployment observations remain the later service's responsibility.

Parse the acquired context with exact frozen fields and canonical bytes, and
require grant/deployment/epoch equal protected expectation; provider, broker and
clock equal the independently joined actual records. Every echoed request field
matches acquired context and its digest. Do not use the request's context_digest
as the sole expected authority: acquire and join the protected bytes first.
Context is exactly `schema,request_digest,effect_digest,grant_digest,
deployment_digest,epoch_digest,broker,provider,clock,exchange_id,
accepted_boottime_ns,deadline_boottime_ns,clock_bracket`, with schema
`aragorn/native-phase3-broker-reader-context/v1`. The exchange ID is a nonce;
named digests are pins and timestamps uint. Clock/process/bracket shapes are
specified in this contract.

BOUND is exactly `schema,context_digest,sequence,previous_digest,phase,checked_ns,
request_packet_digest,response_packet_digest,transport_digest,failure_code,
intent,effect_possible`. Schema is
`aragorn/native-phase3-broker-submission-event/v1`. Phase is BOUND, sequence is
integer zero, checked_ns uint, previous/request/response/transport/failure fields
are null, and both Boolean fields false. Context digest hashes the acquired
context bytes.

Invoke PUBLIC `verify_submission_transcript` with those actual context bytes,
exactly `[bound_raw]`, `{}` packets, the actual acquired context digest, joined
request digest, independently joined broker/provider/clock, and
expected_terminal_digest=None. No journal private parser or producer import.
Require exactly the consumer's CONSISTENT_OPEN_PREFIX, UNKNOWN submission state,
matching context/BOUND digests and all five false flags. Thus BOUND must be
sequence0/previous null with no packet/transport/failure pins, false intent and
false effect_possible. A copied prefix, another phase or a changed field refuses.
This is independent semantic replay over acquired bytes, not a second acquisition
authenticator. It cannot prove NOT_SUBMITTED or an uninterrupted broker lock.

## Clock and finite budget

Acquire actual BOOTTIME `started_ns` at entry after the original-owner check and
before slow observations. Check nondecreasing actual samples throughout; every
guard and closing sample must precede the acquisition deadline. Require:

```text
context.accepted_boottime_ns
  <= context.clock_bracket.boottime_before_ns
  <= context.clock_bracket.boottime_after_ns
  <= BOUND.checked_ns
  <= caller request_received_ns <= actual started_ns <= actual finished_ns
```

The frozen bracket has exactly boottime_before_ns, monotonic_ns,
boottime_after_ns, original_monotonic_deadline_ns. Its positive remaining
monotonic budget is <=500000000 and context deadline equals lower BOOTTIME sample
plus that budget without overflow. Context/request wire deadlines agree.

Set `phase_deadline_ns = min(request.deadline_boottime_ns,
request_received_ns + 250000000, expectation.session_deadline_ns)`, rejecting
overflow. Require phase_deadline_ns >=100000000 and set
`deadline_ns = phase_deadline_ns - 100000000`. Require actual started and finished
strictly before deadline_ns. This leaves the frozen reader's 100ms challenge
budget available to the later session call; it does not reserve actual CPU or
guarantee that a subsequent operation will finish. Never renew the original
receipt, HTTP deadline or accepted timestamp. Proc/file reads and cleanup have
no hard syscall return-time guarantee; late completion refuses.

Retain a final time sample after all owned read-only handles have closed once,
with local original-Root context checks and unchanged borrowed socket identity.
No successful result survives cleanup ambiguity or a deadline crossed in cleanup.

## Exact results and bounded error observations

Successful return has exactly:

```text
context_raw context_digest bound_raw pending_raw submission_verification_raw
acquisition_raw acquisition_digest custody_raw
```

The first three raw records keep their actual bytes and bounds above. Replay is
the canonical public consumer result, <=4096 bytes. All returned digests are
actual SHA256 byte digests. `custody_raw` is canonical <=524288 bytes, exactly
`schema,before,after`; schema
`aragorn/native-phase3-broker-reader-context-custody/v1`. Each edge is exactly:

```text
started_ns finished_ns peer_credentials_base64 peer_pidfd_info_base64 boot_base64
processes socket time_namespaces broker_mount_namespace
root_directories broker_directories files
```

Process observations are a map with exactly broker/provider, each exactly
`stat_before_base64,status_base64,stat_after_base64`; each decoded proc byte
value <=16384. Peer credentials decode to exactly12 bytes, PIDFD fdinfo <=4096,
boot <=64. Base64 is strict standard ASCII with canonical padding. These are
actual first/final observations, not copies filled from expectations.

The replay result has exactly `status,context_digest,last_event_digest,
submission_state,acquisition_authenticity_verified,sensor_health_verified,
effect_authorized,run_qualified,phase3_qualified`; status is
CONSISTENT_OPEN_PREFIX, submission_state UNKNOWN, the five Booleans false and
both digest fields hash the actual context/BOUND bytes.

Socket is exactly `descriptor,identity,peer_pidfd_descriptor,nonblocking,
noninheritable,passcred,passpidfd`; descriptors uint>=3, identity full metadata
as above, booleans true/true, options integers1/0. Namespace maps are exactly
broker/provider for time, each `device,inode,link`; the mount namespace has that
same shape with an mnt link. Each directory-view list contains the exact five
`path,device,inode,mode,uid,gid` records in fixed order. Files is exactly three
ordered records with role CONTEXT,BOUND,PENDING, each `role,name,identity,digest`.
Record all of these from actual observations. Edge times are actual bracket
samples, nondecreasing and within the leaf's original acquisition budget.

`acquisition_raw` is canonical <=16384 bytes, exactly:

```text
schema status expectation_digest measurement_binding_digest fixture_binding_digest
request_packet_digest context_digest bound_digest pending_digest
submission_verification_digest custody_digest caller_request_received_ns
started_ns finished_ns deadline_ns broker provider clock broker_mount_namespace
source_files submission_state acquisition_authenticity_verified
sensor_health_verified effect_authorized run_qualified phase3_qualified
request_receipt_authenticity_verified installed_sources_verified
```

Schema is `aragorn/native-phase3-broker-reader-context-acquisition/v1`; status is
ACQUIRED_BROKER_CONTEXT_PREFIX. Source files are the final custody edge's three
records. Broker mount namespace is the final edge's actual namespace record.
Submission_state is UNKNOWN. **All seven Boolean fields are exactly false.**
The expectation/measurement/fixture pins are the caller-held, checked values;
all other digest fields hash the exact corresponding returned/input bytes.
The two custody edges have equal peer/process/namespace/ancestry/file bindings;
their actual raw proc byte encodings need not be byte-identical when unrelated
proc status/stat fields legitimately change. Validate the required identity
fields independently at both edges. The after edge finishes before final close;
the acquisition finished_ns additionally includes terminal cleanup.

Exceptions never return a usable acquisition. `observed` is exactly:

```text
request_raw caller_request_received_ns started_ns deadline_ns context_raw bound_raw
pending_raw submission_verification_raw custody_before custody_after
```

Every unavailable value is null. Raw values are actual bounded prefixes, not
reconstructed success bytes; the request bound is4096, context/BOUND8192 each,
pending131072 and replay4096. Custody edge dictionaries have exactly the declared
edge keys; unavailable members are null, completed values have the same bounds,
and proc members may retain actual prefixes. No acquisition_raw is exposed on
failure. Preserve the original exception, up to32 actual cleanup exceptions,
and a strong local owner reference for unresolved owned descriptors/errors until
process exit. Own at most32 simultaneous FDs; take no new ownership beyond that
bound. Close once after verifying held identity and, for PIDFDs, association;
check identity again after the association's proc read. Never close a foreign or
uncertain reused descriptor or retry an ambiguous close. The borrowed socket is
never included in owned cleanup. On lost borrowed-socket custody this leaf
refuses and preserves the actual observed identity/error; it neither closes nor
claims to recover the caller's socket. The Root service keeps its own socket
object/failed-detach ownership references until separately reviewed terminal
cleanup; this function cannot transfer Python objects or FDs to a supervisor.
No path, file, credential or partial journal is
removed or repaired. Retention here means bounded returned/in-memory evidence,
not a new private archive or campaign retention permission.

## Dependencies, review and focused cases

Permitted direct project imports are only public functions from:

- `native_phase3_broker_reader_protocol`: validate_guard_request;
- `native_phase3_run_submission_verify`: verify_submission_transcript;
- `runtime_http_action`: validate_fixture_binding, effect_for_attempt,
  action_digests.

Implement this leaf's canonical parsing, OS custody and metadata bookkeeping
locally with stdlib. Do not import private parsers, journal/measurement producer
state, test fixtures, callbacks, service launchers or a dynamic module named by
input. Never invoke effect execution, credential loading, CAS/staging, service,
container or network operation helpers while deriving the pure HTTP values.

Current static project import closure is the new module and test, package init,
those three public dependency modules, native_phase3_http_canary_contract,
runtime_process_profile, runtime_action_broker, runtime_action_observation_publisher,
runtime_action_decision and oci_worker_protocol. This is twelve paths including
the two new paths; confirm actual closure and exact stable hashes before Root
registers a stage. A generated HTTP successor has a different closure and must
be independently inventoried at service integration. No source pin from the
old report is substituted for a successor, and no unchanged staging is repeated.

Author independent canonical fixtures locally. Focused public-API tests use a
complete in-memory syscall/socket model while calling the real public codec,
HTTP derivation and independent submission verifier. Cover valid actual prefix;
same file in distinct broker mount view; different broker-root/control view;
wrong peer/credential ABI/PIDFD reuse/liveness; process/boot/time/mount changes;
Root/foreign thread/fork/reentry; missing/partial/linked/malformed files; permission,
size, full named/held file substitution and legitimate directory-time changes;
partial observations preserved on read/close failure; no close of borrowed or
foreign FD; exact canonical schemas and expected pins; wrong pending acceptance,
request, plan, grant, source-map or effect bindings; BOUND after caller receipt;
copied/non-BOUND/extra-field prefix; independent replay actually invoked on
acquired bytes; original deadline/overflow and cleanup deadline refusal; and
all-false UNKNOWN outputs with no disk writes, lock acquisition or socket IO.

Owner submits stable hashes, complete actual import/fixture/generated closure
and focused proposed stage; Root alone reviews/registers/schedules it. No tests,
imports, compile or live execution before that scheduling. Handoff after reviewed
PASS follows existing exact-path signed-commit rules; no feature-branch push.

Source anchors: runtime_http_run_submission.py:203,253,392 (fixed context/BOUND
publication); runtime_broker_decision_measurement.py:128,284 (mount identity and
actual pending fields); runtime_http_action.py:81,104,140 (pure public fixture/
effect/action derivation); native_phase3_run_submission_verify.py:265 (independent
open-prefix consumer); materialize_runtime_http_collection.py:84,106 (8192-byte
HTTP binding); native_phase3_run_reader_checkpoint_session.py:847 (reserved real
caller handoff and 250ms phase/100ms challenge budget). Parent IPC draft and
reader-session contract continue to own bootstrap, SCM receive custody and
actual reader/loss/service integration. No phase completion or qualification is
established by this acquisition leaf.
