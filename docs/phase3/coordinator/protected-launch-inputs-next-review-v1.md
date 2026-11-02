# Protected broker launch inputs: bounded next-release review v1

PROPOSAL ONLY. No source ownership, execution, registry entry, native acquisition,
launch, retention operation or qualification is released by this document.
Root must publish the decisions below and an exact signed containing checkpoint
before assigning implementation. Existing v12 bootstrap, v13 service, v14 client
and v15 HTTP successor ownership remains unchanged. All operational holds apply.

## Smallest missing complete path

The v12 server authenticates an actual accepted peer, but its protected expected
MainPID, invocation, command, executable, credentials and installed-source pins
still need an independent Root acquisition. Implement this bounded broker input
leaf first. It must not become a second launcher, deployment gate or all-service
identity framework. Root continues to own actual launch, shared dispatch,
provider provisioning, inventories and the sensor/bridge decisions.

Proposed exclusive implementation paths, not yet released:

1. `src/aragorn/native_phase3_broker_reader_launch_inputs.py`
2. `src/aragorn/native_phase3_broker_reader_launch_inputs_verify.py`
3. `tests/test_native_phase3_broker_reader_launch_inputs.py`
4. `docs/phase3/coordinator/broker-reader-launch-inputs-handoff.md`

The first module acquires only the fixed broker path below. The second independently
replays its bounded retained observations without systemctl, proc, clocks, imports
selected by evidence or source acquisition. Tests author local fixtures; no old
TestCase import or historical suite rerun. No changes to existing identity readers,
bootstrap/context/client/service, units, renderers, inventories or registry belong
to this split. Root owns their actual callers and composition.

## Source-backed reuse and explicit ceilings

Existing public `native_phase3_live_identity.read_native_live_identity` and
`native_phase3_common_identity.read_native_common_identity` are useful prior
patterns, but neither returns the required raw unit/proc observations. Both
measure four running services; the common reader fixes an older seven-module
measurement inventory and a 4096-byte binding. Their `_show`, `_process`, `_read_at`
and alias helpers are private; do not import them into a new public leaf or call
the aggregate reader to fabricate the missing raw evidence. The old `_show`
starts a new three-second deadline, which cannot replace the original v12 budget.

Reuse public `runtime_process_profile.require_live_pidfd` where its actual contract
fits, `runtime_capability_grant.parse_runtime_capability_grant`, public HTTP fixture
validation and existing canonical JSON utilities. Independently implement only the
fixed raw acquisition that those public interfaces do not expose. No callback,
injected production observer, parsed-dict-only systemctl result or expected-process
record is an actual observation.

Relevant source anchors:

- `native_phase3_live_identity.py:312,377,437,571,666,726`: bounded unit reads,
  fixed Python/merged-usr aliases, account/proc/PIDFD and protected loaded views.
- `native_phase3_common_identity.py:91,103,201,286,306`: three-credential command,
  grant/measurement joins and the public reader's explicit provenance limits.
- `packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service:18`:
  broker account, primary runtime GID, supplementary sensor GID and protections.
- `scripts/materialize_runtime_broker_decision_measurement.py:162,178,185`:
  actual generated three-argument service and measurement credential loading.
- `scripts/materialize_runtime_http_credentials.py:50,131,178,248,269`: repaired
  service-only credential reading, fixed fixture/readiness sources and PID1 views.
- `scripts/stage_runtime_phase3_http_profile.py:316`: actual HTTP94 label-scoped
  measurement credential loader8192 successor; original helper4096 is not the
  generated predecessor that must be inventoried.
- v12 `broker-reader-bootstrap-contract-v1.md`: exact existing peer expectation,
  two-phase caller obligation, original budget and source inventory schema.
- v13/v14 contracts: Root-supplied inventory is an expectation, not acquisition.

## Proposed exact public boundary

Use one acquisition API twice, with no refresh/reset/retry API or persistent
ownership object. Each call owns and closes only its own newly acquired handles;
the bootstrap server keeps its actual accepted socket/PIDFD for the whole interval.

```python
def acquire_broker_bootstrap_expectation(
    *, accepted_peer_raw: bytes, expected_accepted_peer_digest: str,
    protected_launch_binding_raw: bytes, expected_launch_binding_digest: str,
    source_inventory_raw: bytes, expected_source_inventory_digest: str,
    startup_deadline_ns: int, cancel_read_fd: int,
) -> dict: ...

def verify_broker_bootstrap_expectation(
    *, accepted_peer_raw: bytes, expected_accepted_peer_digest: str,
    protected_launch_binding_raw: bytes, expected_launch_binding_digest: str,
    source_inventory_raw: bytes, expected_source_inventory_digest: str,
    expectation_raw: bytes, expected_expectation_digest: str,
    observation_raw: bytes, expected_observation_digest: str,
) -> dict: ...
```

Acquisition returns exactly `expectation_raw,expectation_digest,observation_raw,
observation_digest,verification_raw,verification_digest`. The first bytes match
the existing v12 `bootstrap-peer-expectation/v1`, with no new wire fields. The
pure verifier independently constructs that same expectation from actual raw
observations and checks exact equality; it never accepts a recorded PASS alone.
Its result has exact `schema,status,expectation_digest,observation_digest,
authority,limitations,phase3_eligible,route_qualified,application_acknowledged`;
the three flags are false. Successful status means only the bounded joins match.

Proposed error `BrokerLaunchInputsError` retains original exception, actual
partial observation dictionary, bounded cleanup failures and strong unresolved
owners. Early invalid entry must not take or close a caller's cancel FD. Accepted
entry borrows it throughout and never duplicates, closes or transfers it. Mark
newly acquired handles before fallible metadata, guard PIDFD associations and
descriptor generations, consume each close once, and retain ambiguous owners
until process exit. Preserve interruption and MemoryError identities. A failed
acquisition is terminal for that bootstrap attempt, not an automatic retry.

Caller sequence is fixed:

1. Root supervisor calls actual `accept_hello`, retaining returned raw peer/HELLO.
2. Root independently supplies protected launch binding and final installed-source
   inventory. Acquire first expectation under the original startup deadline;
   independently replay it, retain both actual results, then call `offer_handles`.
3. After actual RECEIVED, Root calls the same acquisition again under the same
   deadline, not a renewed budget. Replay and compare stable expectation fields
   byte-for-byte, excluding only actual before/after times. Require identical
   unit invocation, peer/process/domain, source and credential pins. Join HELLO's
   grant/measurement/fixture digests to the acquired expectation explicitly.
4. Root constructs/joins its actual provision and provider readiness inputs, then
   calls `release`. The second acquisition is not proof of unchanged custody in
   the intervening interval. Retain the original bootstrap PIDFD, supervise it
   and preserve both observations. RELEASE retains its own final guards.

Root is the only acquirer, in its original main process/thread, with actual saved
UID/GID vectors all zero. The non-root broker supplies only its actual credential
digests in HELLO and locally observed kernel identity; it cannot mint its own
expected MainPID or read Root proc/source secrets. Do not widen ProtectProc,
ProcSubset, credentials, account groups, capabilities or secret-path visibility.

## Protected binding and finite file selection decisions

Proposed canonical ASCII binding schema
`aragorn/native-phase3-broker-reader-launch-binding/v1`, exactly:

```text
schema profile fixture clock broker_uid broker_gid broker_supplementary_gids
unit_fragment_digest interpreter_digest source_inventory_digest
runtime_binding_digest grant_digest measurement_binding_digest fixture_binding_digest
readiness_binding_digest startup_deadline_ns
```

Profile is literal HTTP_REFUSAL_ONLY; fixture is exactly the existing HTTP
`container_id,boot_id,netns_device,netns_inode`; clock uses the existing v12 shape.
Integers exclude bool, fit the existing uint domain; account IDs are uint32,
broker IDs positive, supplementary GIDs a sorted unique list. All named digests
are pins. Bind startup deadline to the caller's original value. Bound binding to
8192 bytes, no LF/extra/duplicate/nonfinite fields. It contains no arbitrary path,
command, unit name, socket endpoint, callback or account alias. This is an
independently pinned Root provisioning input, not an assertion that provisioning
or an actual fixture exists. Root must fix its actual protected acquisition origin
and custody before native use; a digest supplied with untrusted bytes is no origin.

Use literal unit `aragorn-runtime-lineage-capability-action-broker.service` and
the generated HTTP94 three-argument argv, in this order:

```text
/usr/bin/python3.12 -I -S -B
/usr/libexec/aragorn/aragorn-runtime-action-service-v5.py
/run/credentials/aragorn-runtime-lineage-capability-action-broker.service/runtime-binding
/run/credentials/aragorn-runtime-lineage-capability-action-broker.service/capability-grant
/run/credentials/aragorn-runtime-lineage-capability-action-broker.service/decision-measurement-binding
```

The argv line breaks above are presentation only: actual proc cmdline is exact
NUL-separated arguments with one terminal NUL. Expected command_digest is SHA256
of those actual bytes, not systemctl's textual rendering or a shell command.

Acquire five fixed credential source/view pairs; sources are Root:Root0400,
single-link regular files under protected nofollow ancestry. Read actual loaded
views through the held PIDFD-pinned broker `/proc/PID/root`, never a local host
`/run/credentials` pathname mistaken for the broker's view:

| Credential name | Fixed Root source | Proposed bound |
| --- | --- | --- |
| runtime-binding | /etc/aragorn/runtime-action-runtime.json | 4096 |
| capability-grant | /etc/aragorn/runtime-capability-grant.json | 4096 |
| decision-measurement-binding | /etc/aragorn/runtime-broker-decision-measurement.json | 8192, existing HTTP94 generated loader |
| http-fixture | /etc/aragorn/runtime-http-fixture.json | 4096 |
| http-readiness | /etc/aragorn/runtime-http-readiness.json | 4096 |

Loaded credential ownership/modes and read-only mount observations must preserve
the repaired service reader's actual policy: owner broker or Root, exact allowed
Root/broker GIDs and0400/0440 combinations, not a blanket root-owned rule. Require
actual source bytes equal actual loaded bytes both before and after, with full
nine-field held/named file identities and single-link checks. Secret bytes stay
inside the privileged acquisition, never in observation_raw, logs or exception
text. Emit metadata/digests and explicit equality observations, not secret content.
Independent replay can verify these reported equality joins but cannot re-prove
the acquisition's hidden credential reads; state this ceiling. Original raw
credentials already held by protected Root provisioning remain separate inputs.

Require measurement/grant/runtime/fixture joins from the existing schemas:
grant_digest equals actual canonical grant bytes; measurement boot and fixture
boot match actual observed clock; fixture accounts match actual broker; measurement
runtime/profile/sensor/policy/active-skill/operation joins match the parsed grant;
runtime binding agrees on runtime/profile; measurement source_pins equals the
exact final generated broker closure. Compare fixture's expected netns with an
actual held broker net namespace and source fixture identity; an equal supplied
nonce is not a measured container image or HTTP endpoint. Readiness source/view
digest equality is not a successful readiness probe or its application use.
Deployment/schedule/collection pins remain expected until their owning consumer
resolves actual retained inputs. Do not call a CAS/stager or execute a probe here.

The final literal installed module allowlist must be published with this release.
It must be derived from the actual HTTP94 predecessor report
`benchmark/evidence/phase3-http-credential-staged-profile-v1.json`, pin
`sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9`,
plus reviewed successors and complete actual imports/generated dependencies.
The report describes94 staged files, not a deployment or sufficient final closure.
Never execute its historical stager, copy its cache or substitute original source
for a generated file. Do not allow a packet/inventory to choose paths: finite
source-coded allowlist first, supplied inventory must match exactly. Broker-role
files are acquired in Root source and broker process-root views; provider/SHARED
inventory acquisition remains Root-owned caller work where outside this leaf.
Process-root Python bytes prove a file view, not which modules Python loaded.
In particular, its actual generated `runtime_action_service.py` is8315 bytes,
pin `sha256:0aef94234717e3821b606fd0ada2cb16631d8b5d7556f8265aa4254082241bee`.
That predecessor already permits8192 only for the decision-measurement label;
the generated service passes `max_bytes=8192`. Preserve this existing repair and
all other credential limits. Original source's4096 is not a new loader blocker.

## Actual raw observations and original budget

Acquire bounded systemctl output BEFORE and AFTER using literal
`/usr/bin/systemctl --system --no-pager show --property=... UNIT`, fixed
PATH=/usr/bin:/bin and LC_ALL=C. Exact properties are existing
`Id,MainPID,ControlPID,ControlGroup,InvocationID,ActiveState,SubState,User,Group,
ExecStart,FragmentPath,DropInPaths`. Preserve stdout<=16384, stderr<=4096 and actual
return code; no parsed-only substitute. Require nonzero MainPID, active/running,
ControlPID0, nonzero32-lowercase-hex InvocationID, no drop-ins, fixed account names
and exact generated ExecStart structure. Take actual ControlGroup, validate the
fixed owned fixture prefix and literal unit, then join actual proc cgroup and
cgroup membership. Never construct a cgroup string and label it observed.

Open a separate actual PIDFD for the systemctl MainPID; read actual fdinfo Pid
association, require liveness and match accepted peer PID/account/start/domain.
Keep it across process/source/loaded-view reads and both unit snapshots. Preserve
actual stat/status/stat, cmdline, cgroup, cgroup.procs, executable link and digest,
process root identity, held/named mount/time/net namespaces, boot and account
observations. UID/GID vectors must match actual broker policy; primary runtime GID
sharing is permitted, distinct broker/runtime UIDs remain required. Unit bytes
and loaded unit properties are two observations, not interchangeable identities.

Per proc text/cgroup member read<=16384, cmdline<=8192, PIDFD fdinfo<=4096,
boot<=64; each fixed namespace/link string<=4096. Source modules<=16MiB each and
64MiB aggregate per v12 inventory. Interpreter bytes need the existing separate
256MiB bound, never silently squeeze into the source inventory's16MiB limit.
Use streaming digest with exact held/named metadata and retain digest/length
observations, not256MiB in observation_raw. A release must choose a finite raw
record bound from the actual final allowlist before execution; do not truncate
needed joins or add an unbounded evidence envelope.

Each syscall/child wait uses the immutable original v12 startup deadline, minimum
of caller/server deadlines as already bound, within the4-second local cap and
strictly before session deadline. BOOTTIME/time-namespace identity and rollback
guards bracket slow unit/source observations. No fresh3-second `_show` deadline,
clock substitution or budget renewal. Wait for systemctl pipes with original
remaining budget and borrowed cancellation; cancellation/EOF/data/custody loss
wins simultaneous completion. Cancellation during regular/proc reads is checked
before and after; no hard syscall-return-time bound is asserted. A timed-out
owned systemctl child must be terminated/reaped, never a service process. Root
must define bounded termination/reap and unresolved child retention on failure.

Sample final enforcing BOOTTIME after all slow rereads/cleanup, then finite local
FD/PIDFD/account custody checks before returning usable expectation. A late result
remains failure evidence. Retained before/after equality never proves continuous
ownership or absent transient rewrites. Raw observation fields are actual/null,
never expected values copied into a raw record; every partial read keeps its
actual prefix and complete/partial state. All health/authorization/effect/
qualification flags remain false; loss is UNKNOWN.

## Decisions Root must close before a source release

1. Publish exact final generated broker module list and pins, installed unit/shim
   pins, interpreter pin and source-to-process-view rows. Client/bootstrap/renderer
   successors must be stable; no guessed final closure. Keep provider full inventory
   composition separate from this finite broker slice.
2. Freeze exact binding origin/acquisition and raw observation schema, size bound,
   independent-consumer equality ceiling and permitted retained nonsecret data.
   Existing private retention hold is not resolved by writing this module.
3. Choose supported actual launcher aliases: existing fixture explicitly allows
   `/usr/bin/python3.12 -> /usr/local/bin/python3.12` and `/lib -> usr/lib` only
   with held before/after alias provenance. Do not follow arbitrary symlinks,
   require a fictitious regular launcher or claim those aliases are currently
   deployed. Retain `/proc/PID/exe` actual executable identity independently.
4. Bind the existing generated HTTP94 loader8192 and caller pins through the final
   closure, together with final measurement configure/plan/verifier bounds. Do not
   replace the actual generated helper with original source4096 or duplicate its
   already implemented label-scoped repair. Require actual final binding<=8192.
5. Fix actual supervisor cancellation input/topology before assigning its borrow.
   No such Root-local read handle is proven by current units. Do not borrow a
   transferred provider/reader endpoint, retain an extra copy that defeats EOF,
   or infer cancellation from a caller Boolean. Root owns signal/stop handling,
   cancel writer closure, child PIDFD supervision and reap, not this leaf.
6. Fix precise ExecStart accepted rendering and effective unit security-property
   validation. The13 existing identity properties alone do not measure all unit
   protections or application configuration use; bind complete generated unit
   bytes and let Root's actual launch verifier own effective protection checks.
7. Publish complete caller integration paths and candidate stage closure/cases.
   This proposal alone grants no edits or execution. A ready internal owner can
   take these four paths once decisions1-6 are concrete; no additional worktree
   currently needed. No bridge/sensor endpoint, account or identity is released.

Focused eventual cases: actual peer/MainPID mismatch and PID reuse; changed
InvocationID/cgroup/argv/accounts; source/load mismatch and partial reads;
credential ownership/read-only failure; unknown PIDFD association; final FD/clock
substitution; missing/extra generated module; actual binding loader overflow;
late systemctl/source completion and cancellation priority; failed child reap;
second snapshot changed stable bindings; independent replay rejects forged or
incomplete joins. Submit stable hashes and actual full imports/fixtures/generated
dependencies to Root before one newly selected owning stage. No execution now.

1. Integrate ready providers with necessary new focused checks only.
2. Wire full HTTP then DNS/destructive, admission/RUN, genuine a100, cancellation,
   full timing and four actual paired tasks; finish real stream/loss/program/map,
   policy/lifecycle and paired-context providers. Missing loss refuses.
3. Close the same48-entry path/consumer/source-custody inventory and freeze.
4. Separately release31 cases,100 actions and100 pairs on one deployment;
   independently replay, evaluate existing gate and verify approved cleanup.
