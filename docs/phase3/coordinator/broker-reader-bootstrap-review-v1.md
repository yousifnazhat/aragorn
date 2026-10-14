# Broker reader bootstrap and cancellation: coordinator source review v1

Status: read-only source findings and concrete decisions for the next signed
contract. This document does not release source, checks, staging, activation,
live observation, private retention or cleanup. The preserved
`broker-reader-ipc-next-contract-draft-v1.md` remains unchanged. Root must publish
the amendments and exact ownership before implementation.

## Decision: preserve the existing broker service boundary

Use a separate, fixed AF_UNIX/SOCK_SEQPACKET bootstrap rendezvous at
`/run/aragorn-phase3-broker-reader/bootstrap.sock`. It is not `guard.sock` and
does not change the frozen guard request/response or ancillary protocol.
The existing broker starts through systemd as `aragorn-broker`, primary group
`aragorn-runtime`, supplementary group `aragorn-sensor`, with empty capabilities,
NoNewPrivileges, its private credential mount and its existing three-argument
ExecStart. LoadCredential does not transfer a descriptor.

The generated `runtime_action_service_v5._run` calls the fixed bootstrap after
reading its protected credentials and configuring measurement, before startup
readiness and `serve_runtime_action_broker_v5`. It stays the same MainPID and
uses no helper child, shell, ExecStartPre FD trick, alternate user or credential
path. Preserve the repaired `/run/aragorn-broker-boot-id` binding. Do not reopen
inaccessible `/etc` inputs or `/proc/sys` from the broker.

The endpoint parent is Root:broker-GID 0710, socket Root:broker-GID 0660, beneath
held Root-owned non-writable ancestors. Root binds once and refuses an existing
path. Close never unlinks this socket. Broker opens searchable ancestry with
O_PATH where directory read permission is unavailable. Its runtime group can
search the endpoint; authorization therefore requires actual peer identity,
not group membership or pathname access alone. This does not promise resistance
to denial of service by another process able to connect.

Actual source anchors: `packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service:17-22,26-29,41-74`;
`src/aragorn/runtime_action_service.py:95-130`;
`scripts/materialize_runtime_broker_decision_measurement.py:161-197`;
`scripts/materialize_runtime_http_readiness.py:46-53`;
`scripts/materialize_runtime_http_credentials.py:60-91,267-285`.
The HTTP successor already permits AF_UNIX while retaining its loopback-only
HTTP network policy (`scripts/stage_runtime_phase3_http_profile.py:216-237`).

## Decision: exact two-descriptor transfer and MainPID freeze

Root creates a separate anonymous Root:Root FIFO0600 for broker/provider IPC
cancellation. It owns the sole writer; provider and broker receive separate
read-end references. This pipe is distinct from reader FD7 and every reader
session pipe. No process ever writes cancellation data.

Exactly one SCM_RIGHTS item in the HANDLES packet carries exactly two FDs in
this order:

1. IPC cancellation read end: O_RDONLY, O_NONBLOCK, FD_CLOEXEC, exact FIFO
   identity and own `pipe:[inode]` link.
2. Supervisor PIDFD: FD_CLOEXEC, exact live supervisor association obtained from
   the receiver's own bounded fdinfo, independently matching the authenticated
   bootstrap peer PID and its socket-derived PIDFD.

Use PASSCRED=1, PASSPIDFD=0, exactly one native 12-byte SCM_CREDENTIALS item, and
MSG_CMSG_CLOEXEC on receive. Every other packet carries credentials only.
Truncation, unexpected controls, duplicate handles or a handle outside the
declared inventory refuses. Record all actually installed handles before
metadata reads. Consume ownership once; cleanup refuses foreign reused handles
and preserves partial results, close/detach failures and unresolved local owners.
No namespace, credential file, arbitrary pathname or executable FD is transferred.

Freeze the one-connection order HELLO -> HANDLES -> RECEIVED -> RELEASE:

- HELLO contains a fresh broker nonce and the actual protected grant,
  measurement-binding and fixture-binding pins. It transfers no handles and
  does not authenticate its own claimed PID.
- Root authenticates the socket peer using credentials and socket-derived
  PIDFD, then independently joins that PID to the fixed broker unit's MainPID,
  InvocationID, cgroup, saved/effective/real account vectors, exact command,
  executable/source inventory and held namespaces. A PID/name supplied by the
  broker is not a replacement. Preserve stat/status/stat and before/after
  unit/PIDFD observations; this is a bounded observation, not atomic immutability.
- HANDLES binds the offer to HELLO and the actual supervisor/pipe observations.
  The broker validates the received handles and reports their actual numeric
  values in RECEIVED, bound to the exact offer digest. FD numbers are assigned
  by recvmsg, so the final broker FD inventory cannot precede this receipt.
- Root reads the actual broker FD/fdinfo links, checks the receipt against the
  transferred objects and account/process pins, closes every unlisted sender
  copy, then freezes the final dynamic provision. RELEASE contains that
  provision and the installed source inventory, their exact pins and the three
  prior packet digests. The client transfers the two owned handles directly to
  `configure_broker_reader_guard` only after the complete release validates.

Use canonical bounded JSON; HELLO/HANDLES/RECEIVED are each <=4096 bytes and
RELEASE <=131072 bytes. RELEASE embeds the existing canonical provision and
source-inventory objects, not base64 copies or arbitrary additional artifacts.
The static schema strings and exact keys must be included in the signed contract.
All packet sizes and actual socket-buffer sufficiency are checked before send;
no privileged buffer-force option or sysctl change is permitted. One connect
attempt and one send per packet, one original startup deadline, no retry or
deadline reset. Required kernel/socket/proc support unavailable means refusal.

## Decision: observation ceiling is role-specific

The broker checks its own process, saved accounts, current held/named time and
mount namespaces, protected boot binding, transferred pipe and supervisor PIDFD,
and actual socket peer credentials/PIDFD. Root owns fresh named/held observations
of both sides and the pipe endpoints. Non-root code must not bypass Root's proc
access controls, fabricate provider stat/status bytes or relabel supplied
namespace pins as locally observed.

Provider/supervisor start and namespace records received over the authenticated
Root bootstrap are protected Root acquisitions, not independent broker proc
readbacks. CLIENT observations leave inaccessible Root proc and named namespace
views null. Root SERVICE observations retain the actual observations. The
bootstrap's protected expected pins are separate from later candidate guard
packets. Self-hashing RELEASE is not its authentication; the fixed Root endpoint,
actual credentials/PIDFD and protected launch/source custody establish its origin.
This explicit ceiling is compatible with HTTP_REFUSAL_ONLY and all-false claims.

Transferring namespace handles would only prove held namespace objects, not
their continuing association with an inaccessible Root process. It is therefore
not selected. Amend the draft's process/namespace requirements and CLIENT null
rules at lines 261-279 and 404-426 before source release. Do not weaken units to
make Root `/proc` inspection available.

## Decision: bootstrap availability precedes session readiness

Use a separate Root supervisor unit with Restart=no and a fixed entrypoint.
Its Type=notify READY signal means only that the bootstrap endpoint is bound
and ready to accept the broker. It must not wait for broker identity or complete
reader-session construction before that signal: broker After=supervisor would
otherwise deadlock startup. Set NotifyAccess=main; no health meaning is attached
to this notification.

The broker has After= and BindsTo= the supervisor. The supervisor has
PartOf=broker for coordinated stop, without an After=broker or dependency that
waits for broker startup. Preserve broker KillMode=control-group and Restart=no.
The supervisor's own cgroup contains its provider/reader/bridge children, not
the existing broker. The fixed activator starts the supervisor before the broker;
no automatic restart, boot enablement or replacement of retained endpoints is
introduced.

RELEASE is a later barrier: actual MainPID/descriptor observations, immutable
provisions and owning provider/session startup must be complete. The reader's
actual FD8 startup frame and Root session/listener readiness are distinct from
the earlier systemd bootstrap notification. The launcher/source contract must
name their concrete bounded internal transport; a Boolean callback is insufficient.

After a normal one-attempt REFUSED exchange, provider and supervisor stay alive
in a bounded cancellation/PIDFD wait until the fixed session deadline or explicit
cancellation. They do not serve a second attempt. Immediate exit after serve_one
could cause BindsTo to stop the broker before it returns its outer result.
Unexpected child/peer exit, malformed bootstrap, cancellation or custody failure
closes the supervisor's cancellation writers and permanently poisons the launch.
Readiness followed by EAGAIN is not cancellation; any cancellation-pipe data is
an error. Cancellation/process exit wins simultaneous response readiness.

The existing broker has a blocking idle accept loop
(`src/aragorn/runtime_action_broker.py:280-292`), so service dependency shutdown
is required for idle termination; merely handing it an FD does not add polling
there. Its existing finally unlinks its old broker.sock (`:299-319`). New
bootstrap/guard paths remain retained, but do not claim existing broker shutdown
is cleanup-free. Operational stop/activation remains under the current hold.

## Decision: bridge CLOEXEC needs an executable change

The final bridge process must set FD_CLOEXEC on stdout FD1, stderr FD2 and its
intentionally transferred sensor FD after exec, before readiness, and check
their actual flags/identity. A wrapper setting CLOEXEC before exec would close
those FDs; clearing it for exec leaves them inheritable afterward. Root cannot
set another process's descriptor flags. No wrapper alone closes this prerequisite.

The already selected same-source bridge successor must include this change with
its fixed one-use connected sensor socket, explicit Go descriptor-conversion
ownership, checked output and sensor subscription-readiness work. Full build and
installed identities are required. The unmodified tetra bridge is not compatible
by assumption. See `reader-session-contract-v1.md:620-630` and
`tetragon-stream-loss-decisions-v1.md:130-196`. No bridge/sensor patch is released
by this review; complete upstream health and loss remain UNKNOWN.

## Finite output ownership and compatibility closure

Reserve these additional paths for Root's signed assignment:

- `src/aragorn/native_phase3_broker_reader_bootstrap.py`: fixed broker rendezvous
  and Root owning handshake, no arbitrary endpoint/command/callback inputs.
- `tests/test_native_phase3_broker_reader_bootstrap.py`: fabricated low-level OS,
  systemd-readback and ancillary boundaries; no historical test imports.
- `packaging/libexec/aragorn-phase3-reader-supervisor.py` and
  `packaging/systemd/aragorn-phase3-reader-supervisor.service`: fixed Root launch
  entry and lifetime. Their actual module/child entrypoints, credential arguments
  and complete launch closure are assigned by the separate Root launch review.

Extend the existing proposed renderer's exact allowlist with the generated
broker unit and both `packaging/activate-runtime-capability-host.sh` and
`packaging/activate-runtime-action-worker-host.sh`. Their exact command/account,
dependency, installed-file and source pins must advance together; keep the old
broker shim/ExecStart unchanged. Existing activation anchors are capability
`:174-238,265-300` and worker `:553-615,740-758`. Root owns inventory and registry.

Use the actual preserved HTTP94 report, 68263 bytes,
sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9.
Its generated broker unit is 3353 bytes,
sha256:88fe42b9257aa8aaefbc527bc12e3c1b3273fcd10c6bbdf09037701990c6dfa0;
generated service source is 4790 bytes,
sha256:b802d6b797aae8f209bafdbea483384d49128b4d35cbc0de4769ab0955126dbc.
These are generated-input pins, not the repository predecessor file hashes.
No repeated predecessor staging is needed for this design review.

The real broker intentionally shares runtime GID. Current journal
`runtime_http_run_submission.py:217-220` rejects that value, whereas v5 config
passes expected_runtime_gid=runtime_gid and `_service_identities` requires it.
Resolve this through a separately pinned source amendment: configured runtime
UID remains distinct from broker UID; validate configured numeric UID/GID and
their completeness; sharing runtime GID is allowed. Preserve the independently
pinned actual broker GID, 0700 control, 0600 lock, 0400 records, exclusive create,
named/held custody and Root non-writable ancestry. Do not change the service
account or construct a fake config GID to hide the incompatibility.

## Exact remaining release conditions

1. Root signs the selected bootstrap packet keys, owning APIs, startup deadline,
   Linux ancillary/buffer profile, CLIENT observation ceiling and finite path
   assignment. The two-FD topology and four-message order are decided above.
2. Root's launch review supplies actual protected input origins and the fixed
   provider/session readiness barrier and lifetime, including post-exec bridge
   compatibility. No fabricated PID, installed hash or readiness is accepted.
3. Root signs the narrow shared-GID journal correction and its newly necessary
   focused cases. Existing historical journal results remain retained.
4. Stable implementation and full generated/import/fixture closure are reviewed
   before a selected new offline stage. All health/qualification/effect flags
   remain false; live operations, private retention and cleanup stay on hold.
