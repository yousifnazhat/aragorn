# Destructive peer lineage: bounded singleton lookup contract v1

**SOURCE CONTRACT — released only by signed published provider-release-v11.md.**
Review base: `6af32a0f127999ef44dfddf37763789ba3fef52c`. The containing checkpoint
must be signed, published and supplied by Root before implementation begins.
This contract creates no stage, execution permission, deployed compatibility
claim or qualification.

## Purpose, ownership and usable claim

Implement the missing lookup prerequisite for the genuine a100 control: acquire
the actual runtime-to-sensor peer, compare it with the one actually loaded allowed
runtime profile, and independently replay that comparison. Preserve the existing
runtime -> non-root sensor -> broker topology. The broker's immediate peer is the
sensor; it must never be substituted for the runtime peer.

Workloads ownership under that release is exactly:

1. `src/aragorn/native_phase3_workload_destructive_lineage.py`
2. `src/aragorn/native_phase3_workload_destructive_lineage_verify.py`
3. `tests/test_native_phase3_workload_destructive_lineage.py`
4. `docs/phase3/workload-verifiers/DESTRUCTIVE_LINEAGE_HANDOFF.md`

Root retains the v4 service/publisher and loader changes, service rendering,
authenticated transport, source/deployment/generation custody, actual registered
worker lifecycle, destructive request parsing and ingress, broker decision and
intent, effect implementation, continuous destructive observation, scheduling
and collector integration. No shared or frozen source is assigned to Workloads.

This leaf yields a bounded **configured-scope comparison**, not a globally
complete registry search, semantic causation proof, authorization or proof that
a100 was blocked. `NO_MATCH` means only that a live authenticated runtime peer is
outside the one pinned configured profile while that profile's real registered
worker remains present. Acquisition failures are `UNKNOWN`, never absence.

There is no new generic registry, fallback profile, capability issuance or
callback-returned truth. A signed source implementation can be completed offline;
native use remains gated by the concrete Root obligations below.

## Source-backed decisions and concrete Root prerequisite

The following existing mechanisms determine this contract:

| Source anchor | Reuse or limit |
| --- | --- |
| `runtime_observation_service_v2.py:_BINDING_FIELDS`, `_read_binding` | The complete binding is exactly schema/sensor_digest/runtime_profile, parsed into one `RuntimeProcessProfile`. There is no existing profile list or fallback lookup. |
| `runtime_observation_service_v4.py:_run` | One loaded observation binding and one grant construct one frozen publisher config. It currently discards the original observation-binding bytes; Root must retain the exact bytes used by this parser. Reopening the path later is not an equivalent snapshot. |
| `runtime_action_observation_publisher_v4.py:_handle_connection` | Actual accepted AF_UNIX/SOCK_STREAM frontend, runtime UID/GID, peer PIDFD, process measurement and active lineage precede sensor-to-broker submission. The existing route refuses an unprofiled peer before reading its envelope; it cannot itself implement a100. |
| `runtime_process_profile.py:runtime_process_profile`, `measure_runtime_process_profile` | The positive profile binds runtime/executable digests, exact unified cgroup and skill path. Positive measurement requires the registered cgroup to contain exactly the worker and no delegated descendants. |
| `runtime_active_skill_lineage.py:hold_runtime_active_skill_lineage` | The actual shared install lock and protected active transaction/tree acquisition are reusable in the Root-owned caller. Its yielded lineage is a summary, not returned raw acquisition evidence or a transferable FD owner. |
| `runtime_action_observation_publisher_v2.py:_adopt_runtime_fs_identity` | Sensor real/effective/saved IDs remain observer IDs; FSUID/FSGID become runtime IDs and capability sets become zero. Do not require four equal observer UID/GID fields or silently run this leaf as Root. |
| `packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service` | Source config conflicts with predecessor publishers, uses `Restart=no`, `Delegate=no`, `ProcSubset=pid` and the existing capability-drop startup. These file contents are not deployed singleton/loader evidence. |
| `scripts/materialize_runtime_http_credentials.py`, `scripts/materialize_runtime_broker_decision_measurement.py` | Existing source uses a read-only boot-ID bind at `/run/aragorn-broker-boot-id`. Root must explicitly provide that binding to the sensor successor; `/proc/sys/kernel/random/boot_id` is not an assumed sensor fallback under `ProcSubset=pid`. |

**Concrete Root prerequisite:** a source-owned sensor caller must possess the
original parsed binding bytes, immutable config object and generation, the real
registered worker's independently acquired PIDFD, and a live positive lineage
hold obtained with the public existing API. It must keep that hold across this
leaf and the later broker exchange, remeasure the registered worker afterwards,
and retain the result and any failure. The leaf cannot inspect a caller's Python
context-manager lifetime or authenticate its config object from a digest.

Root's caller sequence is fixed as follows; this is an implementation obligation,
not a claim that these connections already exist:

1. At the original service load, retain the exact canonical bytes consumed by
   `_read_binding`, their digest, the resulting sole profile and original parsed
   grant bytes. Pin actual loader/source/config/deployment identity and a fresh
   generation to that service process/start/boot epoch. Publish no `complete=true`
   substitute. Prevent configuration replacement/reload and parallel alternative
   admission routes during the attempt using the reviewed service architecture.
2. Retain an actual independently launched registered worker and its PIDFD. It
   must remain in the loaded profile even while the separate a100 process runs.
   Use `measure_runtime_process_profile` with that PIDFD and the loaded profile.
   With the actual parsed grant, enter public
   `hold_runtime_active_skill_lineage(registered_pid, attribution, grant, ...)`.
   Keep the real yielded lineage and lock; never call the positive API on a100
   with copied attributed data. A failed/missing positive hold blocks lookup.
3. Derive the immutable scope below from those exact loaded and measured values.
   Freeze attribution and lineage bytes before passing them; no user labels or
   exception text enters the scope. Resolve the actual peer launch binding from
   protected scheduling custody, not fields in a worker request. Configure the
   accepted frontend as nonblocking/CLOEXEC before borrowing it to this leaf.
4. Call this leaf inside the hold using the same actual frontend connection and
   worker PIDFD. The caller has already received the actual bounded request on
   its authenticated ingress; this leaf performs no socket receive/send.
5. After return, rerun the real registered profile measurement and require exact
   equality with the held attribution; retain that independent closing result.
   Keep the active-install hold through the broker's decision/response. Any
   changed config/generation, worker/profile/hold/transport/cleanup or deadline
   condition invalidates the provisional lookup for policy use as `UNKNOWN`.

The existing positive helpers' raw reads and cleanup have their existing trust
ceiling. This new leaf must not import their private parsers or imply it repairs
their ownership behavior. A later Root acquisition contract is required before
claiming independently replayable full active-install/source custody. The
contract deliberately exposes that remaining dependency instead of
manufacturing raw inventory from the positive summary.

## Exact public APIs

Producer:

```python
def acquire_destructive_peer_lineage(
    connection, *, registered_worker_pidfd: int, cancellation_fd: int,
    scope_raw: bytes, expected_scope_digest: str,
    loaded_binding_raw: bytes, registered_attribution_raw: bytes,
    registered_lineage_raw: bytes, request_raw: bytes,
) -> dict: ...

class DestructiveLineageError(ValueError):
    lookup: str                    # exactly UNKNOWN
    code: str                      # finite enum below
    original_failure: BaseException
    cleanup_failures: tuple[BaseException, ...]  # at most 32
    observed: dict                 # exact partial schema below
    unresolved_owner: object       # strong local ownership reference
```

Consumer, in the separate verifier module:

```python
def verify_destructive_peer_lineage(
    evidence_raw: bytes, *, expected_evidence_digest: str,
    scope_raw: bytes, expected_scope_digest: str, request_raw: bytes,
) -> dict: ...

class DestructiveLineageVerificationError(ValueError):
    lookup: str                    # exactly UNKNOWN
    code: str                      # exactly EVIDENCE_REFUSED
```

The independent verifier uses stdlib only and imports neither the
producer nor any existing private parser, OS acquisition helper, test or fixture.
The producer uses stdlib plus this public independent verifier on its final exact bytes;
that direct project dependency must then be included in the actual closure. No
other project import is released for these two files. No arbitrary callable,
factory, mode/attempt label or injected successful observation is a public input.

Producer successful return has exactly `evidence_raw,evidence_digest,result_raw`.
`result_raw` is the canonical independent consumer result over those actual bytes.
The caller must retain all three; it must not replace raw kernel observations
with the producer's derived comparison.

## Encoding, types and original immutable scope

Every document is canonical ASCII JSON: sorted keys, separators `,` and `:`,
`ensure_ascii=True`, `allow_nan=False`, no trailing LF, no duplicate keys,
nonfinite numbers, unknown keys or noncanonical representation. Enforce byte
bounds before parsing/hashing. `uint` means strict Python int, not bool,
0..2**63-1; positive values are >=1. PID is 1..2147483647; UID/GID are
0..4294967295. A `pin` is `sha256:` plus 64 lowercase hex characters. A nonce is
64 lowercase hex characters. UUID is the canonical lowercase 8-4-4-4-12 form.
No locale-dependent decoding or unbounded exception text enters evidence.

`Process` is exactly `pid,start_time_ticks,uid,gid` with positive ticks.
`Namespace` is exactly `device,inode`, with positive inode. `Clock` is exactly
`boot_id,clock_id,time_namespace`, using UUID, literal `CLOCK_BOOTTIME`, Namespace.
`Identity` is exactly `device,inode,mode,uid,gid,nlink,bytes,mtime_ns,ctime_ns`;
times are signed 64-bit, other values uint, inode/nlink positive, mode includes
file type. `ObjectIdentity` is its first five fields only. Descriptor integers
are >=3. No descriptor number is transferable authority in retained evidence.

`Artifact` is exactly `base64,bytes,digest`: strict standard padded base64,
canonical round trip, positive decoded length within its role's bound, actual
length/digest equality. Bound the encoded text before decoding. Input scope is
1..16384 bytes; request is 1..8192 and a canonical object. This leaf pins request
bytes but does **not** declare them structurally valid destructive ingress.

Scope is exactly:

```text
schema generation deployment_digest loader_origin_digest source_inventory_digest
loaded_binding_digest registered_attribution_digest registered_lineage_digest
capability_grant_digest install_context_digest source_manifest_digest
active_skill_digest peer_launch_binding_digest request_digest observer
registered_worker expected_peer runtime_uid runtime_gid clock cgroup_namespace
cancellation_identity positive_observation_finished_ns deadline_ns
```

Schema is `aragorn/native-phase3-destructive-lineage-scope/v1`. Generation is a
nonce. All `*_digest` values are pins; `request_digest` hashes `request_raw` and
`expected_scope_digest` hashes scope bytes. The three input artifacts hash to
their corresponding scope pins. Observer, registered_worker and expected_peer
are Processes. Observer PID is this process; observer UID/GID are positive and
distinct from the positive runtime UID/GID. Both runtime processes use exactly
runtime_uid/runtime_gid. Their PIDs differ from observer; peer may equal worker.
If those PIDs are equal, the entire expected Process is identical. No attempt ID,
expected decision, `attributed=false` or inventory-complete flag exists here.

`cgroup_namespace` is a Namespace. Require observer/worker/peer actually share
this namespace; a namespace-relative cgroup-path ambiguity must refuse, not
produce NO_MATCH. `cancellation_identity` is an ObjectIdentity with FIFO type.
`positive_observation_finished_ns` and `deadline_ns` are uint, deadline positive.
At actual entry require positive_observation_finished_ns <= started_ns and age
<200000000; require 0 < deadline_ns - started_ns <=250000000. Retain this original
deadline unchanged. The positive timestamp is caller-held input, not a new native
measurement by this leaf, and cannot prove the install lock is still held.

The source/deployment/loader/generation/grant/launch pins are **explicit Root-held
bindings**. This leaf neither loads installed Python nor authenticates those
inventories. Root must bind them to the actual parsed config, live generation,
grant and process launch before using this conditional comparison.

### Loaded binding and real positive inputs

`loaded_binding_raw` is 1..4096 bytes, exactly the canonical bytes accepted by
the current loader, with `schema,sensor_digest,runtime_profile`; schema is
`aragorn/runtime-observation-binding/v2`, sensor_digest a pin. Runtime profile
has exactly `schema,authority,runtime_digest,executable_digest,cgroup,skill_path`.
Schema/authority are respectively
`aragorn/runtime-single-skill-process-profile/v1` and
`ROOT_PROFILE_PIN_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY`. Both digests are pins.
For this bounded profile, cgroup and skill_path are ASCII absolute paths <=4096
bytes, with nonempty components, no `.`/`..`, NUL, backslash or trailing slash;
cgroup is not `/`, skill_path ends in `/SKILL.md`. This is an explicitly narrower
supported profile than arbitrary filesystem names. A different profile refuses.
The profile digest is SHA256 of its canonical object, not the enclosing binding.

`registered_attribution_raw` is 1..8192 bytes, exactly:

```text
schema authority profile_digest runtime_digest executable_digest active_skill_digest
skill_path cgroup pid uid gid start_time_ticks mount_namespace
```

Schema/authority are the existing
`aragorn/runtime-process-profile-attribution/v1` /
`KERNEL_PROCESS_PROFILE_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY`.
Profile/runtime/executable/path/cgroup fields equal the loaded profile; Process
fields equal scope.registered_worker; mount_namespace is Namespace.
active_skill_digest equals scope.active_skill_digest. It must be the actual
registered worker's public positive measurement, never a synthesized control
attribution. This leaf also acquires and compares the corresponding live process,
cgroup and mount namespace below, but does not rehash the executable or skill.

`registered_lineage_raw` is 1..8192 bytes, exactly the public yielded fields:

```text
schema authority active_record_digest context_digest manifest_digest tree_digest
version_path target_name root_device root_inode active_link_device active_link_inode
version_device version_inode skill_device skill_inode runtime_skill_path
active_skill_digest
```

Schema is `aragorn/verified-runtime-active-skill-lineage/v1`; authority is
`SENSOR_LIVE_PROTECTED_TRANSACTION_BINDING_ONLY_NOT_INSTALLER_OR_SEMANTIC_CAUSATION_AUTHORITY`.
All digest fields are pins; devices uint and inodes positive. target_name matches
`[a-z0-9][a-z0-9._-]{0,127}`. version_path is an ASCII relative path <=4096 bytes,
exactly `.aragorn-versions/<target_name>/<64 lowercase hex>-<manifest digest hex>`.
The second hex component equals lineage.manifest_digest without `sha256:`.
Source confirmation: `runtime_active_skill_lineage.py:_version_names` builds the
first component from transaction.context_id, not context_digest. The public
yielded lineage omits context_id, so this consumer checks its exact shape but
does not independently join it to context_digest. Its actual context-ID binding
remains the Root caller's positive hold/active-record obligation; do not invent
an omitted transaction field or copy another digest into that component.
runtime_skill_path equals the loaded skill path. context_digest equals scope
install_context_digest, manifest_digest equals source_manifest_digest and the
active_skill_digest joins attribution/scope. active_record/tree pins bind the
actual yielded summary; they do not replace the raw protected record/tree.

## Native acquisition and descriptor ownership

Supported offline ABI profile is Linux, little endian, Python3.12, native
`struct '=iII'` 12-byte SO_PEERCRED, unified cgroup v2 proc syntax and usable
SO_PEERPIDFD option77. Native availability/permissions and actual kernel identity
must be retained by Root's later deployment evidence. A repository constant or
mocked PASS is not that evidence. No numeric pidfd_open fallback for the runtime
peer, no setns, privilege/FSID change, capability acquisition or socket mutation.

Each operation runs in the original imported sensor process/main native thread.
Reject fork, foreign thread, reentry and concurrent invocation before borrowing
or acquiring resources. Use a nonblocking entry lock and a fresh per-call owner.
A fully resolved success or refusal releases the entry lock and permits a later
independent request in the same service generation, matching the existing v4
repeated accept loop. This does not permit automatic retry of a failed request.
Retain a module-strong poisoned owner only when acquired ownership is unresolved,
a close is ambiguous or cleanup cannot establish resolution. Subsequent calls
then refuse before touching caller resources; no reset/recovery API exists.
Reentry/fork/foreign-thread refusal neither poisons nor cleans the outer owner.
Invalid input, timeout or cancellation with fully resolved cleanup alone does
not poison the process. Root owns disposition of uncertain borrowed connections.

Borrow connection, registered_worker_pidfd and cancellation_fd exclusively until
return/error. Never close, duplicate, detach, reconfigure, read/write, poll away
data, send/receive, shutdown or transfer the socket. Never close/duplicate or
consume data from either borrowed FD. Compare all three numeric descriptors to
prevent aliases. Own only new peer PIDFD, namespace, boot/path and transient proc
FDs; at most16 simultaneous owned FDs, tracked immediately before fallible
metadata. A returned numeric FD alias is refused without closing a borrowed FD.

Require the actual socket family AF_UNIX, SO_TYPE SOCK_STREAM, timeout0,
O_NONBLOCK, FD_CLOEXEC/noninheritable, socket metadata, stable descriptor and full
Identity. Read SO_PEERCRED once per edge and retain all12 bytes; exact pid/uid/gid
must join expected_peer and runtime identities. SO_PEERCRED is the connection's
credential snapshot; current status is checked independently. Do not require or
change SO_PASSCRED/SO_PASSPIDFD: this leaf does not receive ancillary messages.
Get SO_PEERPIDFD77 once and immediately track the acquired FD. Both PIDFDs need
noninheritability, stable first-five identity, exact unique positive `Pid:` in
bounded fdinfo (<=4096), and no poll(0) event. Retain actual fdinfo bytes. Do not
mistake equal anonymous-inode metadata for equal PID association.

Cancellation uses the actual borrowed FIFO read end. Check its held first-five
identity against scope, O_RDONLY/O_NONBLOCK/CLOEXEC/noninheritable and
`/proc/self/fd/<fd>` link `pipe:[inode]`. `select.poll().poll(0)` with
POLLIN/HUP/ERR/NVAL: any event refuses CANCELLED, including writer closure; no
read drains the event. Recheck after potentially slow acquisitions and before
final success. Root owns the writer and process supervision; no callback Boolean
can stand in for this channel.

For observer, worker and peer, acquire bounded actual proc stat/status/cgroup
bytes with stat-before/status/cgroup/stat-after ordering, then repeat at the
closing edge. stat PID/start ticks match scope; require exactly one Uid/Gid,
NoNewPrivs and each CapInh/CapPrm/CapEff/CapBnd/CapAmb field. Worker/peer have four
equal runtime account fields, NoNewPrivs1 and all five capability sets zero.
Observer getresuid/getresgid are three equal observer IDs; its proc Uid/Gid are
observer/observer/observer/runtime, NoNewPrivs1 and all capability sets zero.
Do not impose an invented empty supplementary-group policy. The leaf must not
call setfsuid/setfsgid to make observations succeed.

Each cgroup raw record is <=16384 ASCII bytes and exactly one LF-terminated
`0::<absolute-cgroup-path>` record in the path grammar above. Retain actual raw
bytes; do not normalize a mismatching path into the loaded profile. Observer
cgroup is retained but need not equal the runtime cgroup. Worker cgroup equals
the configured profile at both edges. Require equal peer cgroup at both edges.
Opening/closing process identities and required security fields must agree;
unrelated stat/status fields may legitimately differ.

Hold actual `/proc/<pid>/ns/time`, `/proc/<pid>/ns/mnt`, and
`/proc/<pid>/ns/cgroup` for the distinct observer/worker/peer PIDs (reuse one held
set if peer==worker). Only these exact magic links may be followed. Require
regular nsfs type, held/named device/inode agreement and exact
`time:[inode]`, `mnt:[inode]`, `cgroup:[inode]` links. All time namespaces join
scope.clock.time_namespace; all cgroup namespaces join scope.cgroup_namespace.
Worker mount namespace joins the positive attribution. Peer mount namespace need
not equal worker's and cannot select MATCH/NO_MATCH; it must remain stable.

Root provides the fixed read-only boot bind at `/run/aragorn-broker-boot-id` in
the sensor's view. Hold `/` and `run` using nofollow directory opens, require
root ownership/no group/world write, pin their first-five identities. Open the
fixed leaf O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC; require root-owned regular
non-writable single-link metadata and held/named identity stability. Read <=64
bytes, exactly scope.clock.boot_id plus LF, at both edges; retain actual bytes
and path/FD metadata. No proc/sys, environment, supplied-string or host-Root view
fallback. Root must establish that the bind originates from actual kernel boot
ID; the byte comparison alone does not authenticate bind origin.

Proc files open O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC. Retain bounded prefixes
on error, never reopen/retry an unchanged failed observation. Check owner,
deadline, held identity, flags and borrowed aliases at finite local boundaries
immediately before each read, after any seek/other external observation, and
after read. Full process/PIDFD/namespace/socket/cancellation/boot guards bracket
the edge. Clock samples use actual CLOCK_BOOTTIME, never a MONOTONIC substitution;
all are nondecreasing and strictly below the original deadline.

Before closing an owned FD, verify identity, association if PIDFD, original
owner and no current borrowed alias; finish with a held-identity/owner/alias
check after all fallible flag/proc observations. Consume close ownership before
one close attempt. Never close a foreign/uncertain descriptor, retry an ambiguous
close or release unresolved ownership via GC. Preserve the original exception,
all bounded cleanup failures and a strong local owner. Final local owner,
borrowed socket/PIDFD/cancel checks and actual clock sample follow owned cleanup;
late time/cancellation/cleanup ambiguity cannot return success. These are finite
observation boundaries, not an atomic-race or hard syscall return-time guarantee.

## Evidence, deterministic classification and independent result

Evidence is canonical 1..524288 bytes, exactly:

```text
schema scope_digest request_digest loaded_binding registered_attribution
registered_lineage started_ns finished_ns before after lookup
```

Schema is `aragorn/native-phase3-destructive-peer-lineage-evidence/v1`.
The three artifact fields contain exact original supplied bytes and declared
role bounds. They join independently pinned scope. Scope and request digests
hash the separately supplied bytes. `started_ns` is acquired after owner check
and before slow acquisition; `finished_ns` includes owned cleanup and final
borrowed/clock/cancel guards. Each edge is exactly:

```text
started_ns finished_ns peer_credentials_base64 socket peer_pidfd registered_pidfd
cancellation processes time_namespaces mount_namespaces cgroup_namespaces boot
```

Edge times are actual nondecreasing samples, with acquisition.started <=
before.started <= before.finished <= after.started <= after.finished <=
acquisition.finished < scope.deadline. A final clock check does not extend a
process, lineage, request or deployment lifetime.

Socket is exactly `descriptor,identity,nonblocking,noninheritable,type`; Identity
is full, booleans true, type literal `SOCK_STREAM`. Each PIDFD is exactly
`descriptor,identity,fdinfo_base64,live`; identity is ObjectIdentity, fdinfo bound
4096, live true only after actual no-event poll. Cancellation is exactly
`descriptor,identity,link,read_only,nonblocking,noninheritable,poll_events`;
identity ObjectIdentity, link exact pipe form, three booleans true and events
the actually observed empty list. Successful evidence cannot hide a nonempty
poll result. Peer credentials are exact12 bytes in strict canonical base64.

Processes is exactly a map observer/worker/peer, each exactly
`stat_before_base64,status_base64,cgroup_base64,stat_after_base64`, each decoded
bound16384. Namespace maps have exactly observer/worker/peer, each exactly
`device,inode,link` from actual held/named observations. When peer==worker, actual
acquired bytes may be shared for those aliases, explicitly validated by equal
Process identity; do not copy expected values into observations.

Boot is exactly `raw_base64,identity,root_directory,run_directory`:
raw bound64, full boot Identity, directory ObjectIdentities. Before/after
bindings must be equal except unrelated proc bytes and edge timestamps.

The producer and independent consumer derive the same classification:

| Acquired condition after every required join | lookup |
| --- | --- |
| Peer Process equals the registered worker Process, peer cgroup equals the sole profile, peer mount joins positive attribution; other required observations valid | MATCH |
| Peer PID differs from registered worker, stable peer cgroup differs from the sole profile, actual worker remains joined to positive scope and all other required observations valid | NO_MATCH |
| Same cgroup with another peer PID, changed/missing/malformed/inaccessible observation, lost positive prerequisite, unsupported ABI/profile, stale scope, alias, cancellation, deadline or cleanup ambiguity | UNKNOWN; refuse usable evidence |

Different executable/skill bytes are never used as a negative shortcut. This
slice does not acquire them for the control. MATCH means the exact positively
bound registered worker, not any process with a similar label. No `a100` string
or caller expected-result flag participates in classification.

Consumer independently parses all canonical input/artifact/raw proc forms,
reconstructs both credential triples, all namespace/process/cgroup joins and
time ordering, checks actual digests and recomputes lookup. It checks the loaded
binding has exactly one profile and that positive artifacts match it. It does
not authenticate loader origin, deployment exclusivity or the external hold.
Reject unknown/missing edge keys, decoded-prefix truncation in success evidence,
changed bits/identities, booleans used as integers and evidence with `UNKNOWN`
presented as a complete acquisition. It performs no file/proc/socket reads.

Result is canonical <=8192 bytes, exactly:

```text
schema status lookup evidence_digest scope_digest request_digest generation peer
registered_worker submission_state acquisition_authenticity_verified
scope_completeness_verified positive_lineage_custody_verified
request_structural_validity_verified effect_authorized run_qualified phase3_qualified
```

Schema is `aragorn/native-phase3-destructive-peer-lineage-result/v1`, status
`CONSISTENT_CONFIGURED_SCOPE_COMPARISON`; lookup MATCH or NO_MATCH. Peer and
registered_worker are the independently reconstructed Processes. Generation is
the scope nonce. submission_state is always UNKNOWN. All seven Boolean fields
are exactly false. This deliberately leaves native enforcement and complete
positive/source custody to the actual Root-owned caller/evidence path.

## Failure schema, finite errors and cancellation limits

Producer error `lookup` is UNKNOWN; code is one of
`INPUT_REFUSED,OWNER_REFUSED,SOCKET_REFUSED,PEER_UNAVAILABLE,PIDFD_REFUSED,PROC_REFUSED,NAMESPACE_REFUSED,BOOT_REFUSED,SCOPE_JOIN_REFUSED,UNSUPPORTED_PEER,IDENTITY_CHANGED,CANCELLED,DEADLINE_EXPIRED,READ_FAILED,CLEANUP_FAILED,INTERNAL_REFUSAL`.
Do not convert generic exceptions to NO_MATCH. An ordinary read failure remains
READ_FAILED/UNKNOWN; an unexpected BaseException remains INTERNAL_REFUSAL/UNKNOWN
while preserving the original object. Cleanup-only failure is CLEANUP_FAILED;
cleanup never erases an earlier failure. The verifier uses EVIDENCE_REFUSED and
UNKNOWN on any invalid input, without producer/private-parser imports.

Error `observed` is exactly `scope_raw,request_raw,loaded_binding_raw,
registered_attribution_raw,registered_lineage_raw,started_ns,deadline_ns,before,
after`; unavailable values null, raw values actual bounded prefixes at their
declared limits. Edge keys are the exact success edge inventory; unavailable
members null and partially read proc/base64 values retain actual prefixes.
No usable evidence/result digest or success record is exposed on error. Keep
unresolved owned descriptors and failed-close references local until the owning
process exits under Root's separately reviewed supervision. No cleanup of files,
processes, target bytes, journals or private retained evidence is released here.

The leaf has no effect authority, so cancellation always prevents a usable new
lookup. It cannot promise there was no previous broker submission/effect. Root
retains explicit submitted ambiguity and the original REQUEST_ACCEPTED ->
DECISION_FINALIZED timing domain through the later destructive route.

## Root integration and a100 completion requirements

The source-ready slice is the actual borrowed-peer acquisition plus independent
configured-scope consumer. Its output can join a concrete complete path only
after Root implements these remaining prerequisites:

1. Preserve original parsed binding bytes/generation and exact loaded source
   inventory in the v4 successor; retain actual deployment exclusivity and
   supported kernel/namespace/boot-bind evidence. Keep original privileges and
   capability-drop protections. No historical deployment report proves a newly
   rendered sensor successor.
2. Keep the actual registered worker alive and hold its real positive lineage
   as specified above, including independent closing measurement and errors.
   Preserve the current repeated sensor caller: independent resolved calls may
   proceed; unresolved ownership poisons further acquisition until process exit.
   Do not introduce a new worker/daemon lifetime solely for this leaf.
3. Read and validate one real destructive envelope on the existing frontend
   route before interpreting lookup. Root must publish its exact new request
   and sensor-to-broker schema: existing v4/v5 create-only attributed issuance
   cannot encode this valid unattributed request. Bind actual request, scope,
   lookup, peer and deployment in authenticated sensor-to-broker transport.
4. Root launches a separate owned control process under the authorized runtime
   transport account but outside the registered profile cgroup, with independent
   PIDFD/start/executable/source/namespace launch custody. It submits the same
   valid unlink request as other unlink trials. Protected scheduling joins it
   to a100 exactly once; the label cannot select lookup or policy denial. A
   socket permission failure, parser rejection, missing target, absent positive
   worker or fabricated attribution is not the control.
5. Broker independently consumes the exact scope/evidence result and complete
   authenticated prerequisites, records missing lineage before any destructive
   intent, and joins the same continuous object/name observation as other unlink
   attempts. UNKNOWN must fail closed without becoming proof of pre-effect
   blocking. Existing full measurement timing and actual collector replay remain
   required; the leaf never emits attributed/blocked/residue metric Booleans.

There is no operational observation prerequisite to implementing the bounded
source slice. These are concrete caller/deployment obligations before native
policy use or a complete a100 claim. The version-path and repeated-caller
decisions above are fixed by existing source; no new transaction representation
or service lifecycle is required for the bounded offline implementation.

## Focused review and newly necessary checks

Submit stable source hashes, actual transitive imports, inline/file fixture and
generated-source dependencies, and exact test method inventory before execution.
Root owns registration and scheduling. Use only mocked native effects at this
stage; no historical-suite imports/reruns, protected path reads, live sockets,
native process launches, cache copying or unchanged retries.

Meaningful new cases must use the public producer and real independent consumer
on independently encoded fixtures, with every effectful native boundary mocked:

1. Exact registered peer MATCH and separate different-cgroup peer NO_MATCH; both
   retain real modeled raw proc/PIDFD bytes and false claim flags. Changing an
   irrelevant request label cannot change lookup; request-byte pins still join.
2. Another PID in the same profile cgroup refuses UNKNOWN. Missing positive
   binding, changed loaded singleton, changed active/grant/source pins, stale
   generation/positive sample, missing registered worker or malformed cgroup is
   never NO_MATCH. Match parsing remains independent of producer helpers.
3. Frontend versus backend peer mismatch, wrong UID/GID, short credentials,
   SO_PEERPIDFD unavailable/wrong association/liveness, post-import fork/thread/
   reentry and borrowed aliases refuse before unsafe use.
4. Correct sensor FSUID/FSGID profile works; four-equal-observer-account shortcut,
   regained capability, changed status/start, namespace mismatch and root/relative
   cgroup ambiguity refuse. Root boot bind missing/changed cannot use a fallback.
5. Changed held/named/borrowed descriptor, partial reads, oversize/noncanonical
   records, namespace/link mutation and inode substitution during the last flag
   or proc read preserve raw prefixes and never read/close a known foreign FD.
6. Cancellation readability/HUP/error and deadline crossing during acquisition
   or cleanup refuse. Show original owner/borrowed checks immediately precede
   sensitive reads/closes after intervening fallible observations.
7. Close/cleanup interruptions preserve the original failure and strong owner,
   close known-safe owned handles once, never close borrowed handles and never
   retry an ambiguous close. No success after cleanup error.
8. Independent consumer rejects forged NO_MATCH, switched raw process/cgroup
   records, changed scope/request/artifact pins and any promoted authority flag;
   no OS or producer call is made by replay.
9. Two sequential resolved successes, a fully resolved refusal followed by a
   different independent request, isolated reentry refusal and unresolved-owner
   poisoning match the existing repeated caller. No reset or automatic retry.

## Checkpoint status and remaining Phase 3 steps

Completed here: source-backed bounded contract and explicit non-root/caller/
absence claim boundaries, including original version-path representation and
compatible sequential caller lifecycle. The four-path source-only assignment
takes effect at the signed published v11 checkpoint. Native integration still
requires the original-config/positive-hold/destructive-ingress obligations above.

1. Release and implement reviewed bounded providers, validate only their new
   selected dependency closures, and integrate original verified signed commits.
2. Wire real HTTP/DNS/destructive paths, including this lookup plus actual a100,
   cancellation, full timing, protected observations and four actual paired tasks.
3. Close the existing 48-entry implementation/evidence inventory and publish a
   reviewable freeze candidate; no new gate framework or placeholder PASS.
4. After separate operational release, perform and independently replay the
   campaign and existing exit gate, including approved cleanup. Final
   qualification remains false.
