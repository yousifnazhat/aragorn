# Aragorn

**Agent Runtime Admission, Governance, Observation, Response, and Neutralization**

Aragorn is a planned open-source admission-control foundation for agent capabilities. It binds evidence to exact artifact digests and fails closed when acquisition or required analysis is incomplete.

Current status: **private qualified Phase 0 validation milestone complete; the bounded Phase 1 acquisition lock is complete for the public-GitHub exact-commit profile; the bounded exercised-profile Phase 2 exit is complete; Phase 3 runtime-prevention engineering is active**. The machine-derived [Phase 1 completion receipt](./benchmark/receipts/phase1-acquisition-lock-completion-v3-2026-07-29.json) derives its numerical gate from the signed `c87b82b9` production ingress and cross-binds request-v4 release-pin custody; the earlier v2 numerical receipt remains historical evidence only. It does not make a runtime admission-conformant, grant installer authority, or authorize public release. Retained evidence includes one fresh hidden efficacy pass, final-candidate maintenance replay, paired acquisition/reference evaluation, and the standards gate. OpenClaw `2026.7.1` passed the explicit install-block probe but failed the mandatory direct-write path, which eliminates it as a standalone admission reference monitor. A separate OS-mediated contained profile passed install, direct-write, rename, symlink, auto-discovery, runtime restart, policy-failure, unprivileged policy-tampering, exact conformance-fixture activation, three of nine inventoried update routes, six of twelve reload routes, and the retained activation and recovery slices. One additional update route failed, so the formal profile is `FAIL` and installer-ineligible; its cumulative ledger still leaves `reload/workshop-invalidation` `NOT_TESTED`. A separately pinned dedicated current-V3 capture now qualifies workshop invalidation only at route level and does not rewrite that formal profile. Formal `ADM-01` passes for the contained conformance fixture. A separate DET-only receipt passes four fixed decision exits across three clean processes each, but is not composed with the runtime receipt. Host/root tampering and Pi also remain dynamically untested. No runtime is admission-conformant yet. This is not EDR, a supported release, an installer-authority claim, a general OpenClaw security finding, or a claim that a skill is safe. Aragorn remains private until every roadmap phase is completed and evaluated and every applicable exit gate has passed.

Separate signed current-V3 subfixtures now qualify
[DET-01](./benchmark/receipts/phase3-openclaw-final-v3-det01-dedicated-qualification-v1-2026-09-06.json)
at decision-case level and
[core-updater replacement](./benchmark/receipts/phase3-openclaw-final-v3-core-updater-route-qualification-v1-2026-09-06.json)
at route level. These join the existing workshop-invalidation qualification as
standalone regression evidence, not final campaign evidence, and do not rewrite
the historical formal `FAIL` profile or grant aggregate authority.

Phase 2 P2.1 now has a deterministic category-only declared-versus-observed
behavior diff contract. It verifies set arithmetic only; it is not detonation
evidence, isolation, admission, installer, runtime, or public-release authority.

Phase 2 P2.2 now provides one strict source-event grammar and derives its
normalized category during both CAS retention and replay, bound to exact subject,
input, run-request, and normalizer identities. No execution is claimed.

Phase 2 P2.3 [retains and replays](./benchmark/receipts/phase2-gvisor-runtime-smoke-b86096ddeed564a5938ae9dc1819c7a8-2026-08-02.json)
one pinned inert Linux/arm64 container launch through `runsc-systrap`; its
[complete CAS transport](./benchmark/evidence/phase2-gvisor-runtime-smoke-b86096ddeed564a5938ae9dc1819c7a8-2026-08-02.tar.gz)
retains the collector source closure and binary identities, not the gVisor
binary bytes. It is self-reported integration evidence only, not collector or
runtime attestation, isolation, detonation, egress mediation, backend
qualification, or Phase 2 exit authority.

Phase 2 P2.4 now retains and independently replays one caller-selected
observation-to-source set through the P2.2 normalizer and exact P2.1 capability
diff. This detects omission or substitution relative to that caller-held set;
it does not prove live capture or event completeness. The retained fixed
[canary receipt](./benchmark/receipts/phase2-gvisor-detonation-canary-7838a22fbd2de49b6f833443ca60f45e-2026-08-02.json)
binds one new container lifecycle, cleanup result, and bounded gVisor JSON
`openat`/`execve` trace to that diff under one run identifier; its exact
[40-blob CAS transport](./benchmark/evidence/phase2-gvisor-detonation-canary-7838a22fbd2de49b6f833443ca60f45e-2026-08-02.tar.gz)
replays offline. `RECORDED` is not capture completeness, backend qualification,
isolation, arbitrary-artifact detonation, admission authority, or a Phase 2 exit.

The next bounded P2.4 operation acquired the exact public
[`agent-skill-inert-fixture` commit](https://github.com/yousifnazhat/agent-skill-inert-fixture/commit/26c6e69ee1c597be3c5b096af0e77df93e71489c)
through the ordinary credentialless Phase 1 gateway, copied its verified source
closure from protected quarantine, and mounted only its fixed 79-byte `run.sh`
read-only into gVisor. The retained
[artifact receipt](./benchmark/receipts/phase2-gvisor-acquired-artifact-4147e7ee2b15c6ada9832112122225f4-2026-08-02.json)
and [53-blob transport](./benchmark/evidence/phase2-gvisor-acquired-artifact-4147e7ee2b15c6ada9832112122225f4-2026-08-02.tar.gz)
replay the acquisition, implementation, runtime, selected `openat`/`execve`
observations, capability diff, and cleanup evidence from a fresh local CAS.
This proves one digest-bound inert fixture path only; it is not arbitrary-artifact
support, capture completeness, backend qualification, admission, or Phase 2 exit.

A follow-on run of that same fixed fixture added a fail-closed host trace-store
boundary: a root-owned `0700` tmpfs capped at 8 MiB and 32 inodes, required before
Docker and containerd start. Collection also requires the collector and PID 1
mount namespaces to match, then checks the live container shim against that host
namespace and removes the run's exact trace files after container cleanup. Its
[receipt](./benchmark/receipts/phase2-gvisor-acquired-artifact-a34474048ae9cdd792c2d2c37c9cb4c0-2026-08-02.json)
and [53-blob transport](./benchmark/evidence/phase2-gvisor-acquired-artifact-a34474048ae9cdd792c2d2c37c9cb4c0-2026-08-02.tar.gz)
replay offline. They do not retain mount-table evidence, attest every short-lived
writer, support other daemon layouts, authorize arbitrary artifacts, or exit Phase 2.

The next same-fixture rerun binds the receipt and run request to normalization
profile `successful-openat-execve-set/v1`. Its
[v2 receipt](./benchmark/receipts/phase2-gvisor-acquired-artifact-v2-e55ef93d8538c50c94dee1c25899faf0-2026-08-02.json)
and [63-blob transport](./benchmark/evidence/phase2-gvisor-acquired-artifact-v2-e55ef93d8538c50c94dee1c25899faf0-2026-08-02.tar.gz)
replay seven sorted, unique successful boot-trace events: four read opens, one
write open, and two executions. Nine failed calls remain only in the retained
raw JSONL. The profile still observes only `openat` and `execve`; an open with
write access does not prove bytes were written, deduplication does not preserve
process or temporal multiplicity, and the result is not capture completeness,
causal attribution, arbitrary-artifact support, backend qualification,
admission authority, or Phase 2 exit.

The v3 `bounded-single-script/v1` path caller-pins public commit
[`13a8aff0`](https://github.com/yousifnazhat/agent-skill-inert-fixture/commit/13a8aff0cfa045df508149e0a99b4373740816db),
its source tree, `scripts/check.sh` digest, normalization profile, execution
profile, and declared `file-read` and `process-exec` capabilities. Its retained
[receipt](./benchmark/receipts/phase2-gvisor-acquired-artifact-v3-0b6ec3ea4b469e9f0ad26728a8711ecf-2026-08-02.json)
and [69-blob transport](./benchmark/evidence/phase2-gvisor-acquired-artifact-v3-0b6ec3ea4b469e9f0ad26728a8711ecf-2026-08-02.tar.gz)
replay from a fresh CAS. The run matched both declared categories and also
recorded undeclared `file-write` to `/dev/null` in the bounded execution path.
`RECORDED` is not a clean capability verdict, script safety,
capture completeness, runtime attestation, isolation, backend qualification,
admission authority, or Phase 2 exit.

The v4 profile adds an ordered
entrypoint-epoch attribution manifest. Successful pre-entrypoint events remain
`harness`, the wrapper's launch is `entrypoint`, same-thread events after that
launch completes become `subject`, and unrelated post-entrypoint events remain
`unknown`; only `subject` events feed the capability diff. Replay re-derives the
manifest and checks its CAS digest. The retained v3 matrix exercises this path
in all 100 cells and fails closed on `unknown`; this still does not establish
process ancestry or universal capture completeness.

The lockless compatibility command is:

```console
python -m aragorn.benchmark SUITE OUTCOMES --state EVIDENCE_CAS --phase2-metrics-checkpoint
```

It applies the four Phase 2 numerical thresholds with exact fractions to a
caller-declared, unfrozen five-run `held_out` matrix. Its report always sets
`phase2_exit_eligible` to `false` by design: it is metrics-only. A separate
Phase 2 exit gate must re-evaluate the locked report and compose it with
exact-profile backend qualification and configured-point remote-capture
completeness. Only a tracked, validated exit-gate report can establish bounded
Phase 2 completion. That completion is not EDR or public-release readiness;
Phase 3 is runtime-prevention engineering.

The tracked [Phase 2 exit report](./benchmark/receipts/phase2-exit-gate-1c47d2fc62332152dfad337a4288e53c-2026-08-03.json)
replayed the locked 100-cell matrix, exact configured-point protobuf profile,
and three-run exact-profile gVisor backend qualification. Its
[portable evidence archive](./benchmark/evidence/phase2-exit-gate-1c47d2fc62332152dfad337a4288e53c-2026-08-03.tar.gz)
reproduces the same report from retained bytes. The pass is limited to the
exercised arm64 profile and does not attest gVisor, the host, universal event
completeness, independent efficacy, Phase 3 response, or public release.

The first retained Phase 3 engineering slice now binds one exact fixture-skill
read to one model-transport and runtime `write` call against an explicitly
read-only mount. The live probe recorded `EACCES`, the same run/session/tool
identifiers, and an empty protected directory before and after the attempt in
[its canonical evidence](./benchmark/evidence/openclaw-v2026.7.1-pre-effect-write-2026-08-03.json).
This is a bounded P3.0 harness observation only: it establishes neither general
causal attribution nor an Aragorn policy decision, revocation, sensor health,
`RUN-01`, `RUN-02`, Phase 3 exit, EDR, or public-release authority.

The private P3.1 decision core now returns `ALLOW` only when an exact runtime,
session, run, tool-call, active-skill, measured-action, short-lived request,
runtime-scoped allow rule, revocation snapshot, and fresh policy-bound sensor
identity all agree. Trusted monotonic floors reject revocation-generation and
health-epoch rollback. Structurally invalid decoded requests return `BLOCK`,
while malformed trusted state aborts evaluation so a caller cannot proceed.
P3.2a composes that core with a create-only broker primitive: canonical
length-prefixed Unix-stream requests, Linux peer-credential checks, a distinct
runtime UID, descriptor-relative protected control state, independent durable
revocation and health floors, bounded replay consumption, a final fresh
pre-effect evaluation, and atomic no-replace publication into a host-only
mode-`0400` sink. Trusted control publishers share a private mode-`0600` lock;
revocation/health counters and sequenced observations cannot roll back or
equivocate, while policy is immutable for the broker lifetime. A separate
mode-`0600` instance lock permits identity-checked stale-socket recovery;
post-link uncertainty is reported as indeterminate rather than blocked. This is
not yet the live P3.2 OpenClaw composition. P3.2b adds one private native
optional tool and a dedicated Linux broker service definition. The pinned
OpenClaw tool preparation step supplies host run, session, and tool-call
identifiers after model arguments pass their schema; opaque session keys are
represented only by a bounded SHA-256 binding, as are provider-opaque tool-call
IDs. Its finalize step preserves that correlation across other pre-tool
parameter rewrites while retaining their public-effect changes. Execution
independently revalidates the public effect and sends one exact framed request
with no fallback. Static sysusers/tmpfiles contracts provision distinct
broker/runtime identities and
durable broker roots. The active-skill digest remains a fixed deployment
binding, not general causal attribution. P3.2c adds one durable single-effect
`PENDING`/`APPLIED` journal to the broker state. Startup and every mediation
reconcile it under the existing global action lock without reauthorizing or
reexecuting an effect; exact inode, link-count, metadata, payload, protected-root,
and replay bindings must agree before cleanup or success. Forked `os._exit`
tests cover each durable process-crash boundary and prove replay preservation,
nondecreasing floors, no replacement, and at most one effect. This is
process-crash recovery, not power-loss qualification. That checkpoint alone
grants no `RUN-01`, `RUN-02`, Phase 3, EDR, or release authority.

The private broker upgrades a valid v1 state under the action lock by preserving
its replay entries and monotonic floors, selecting schema v2, and initializing
the journal to `null`; it never infers a prior effect from legacy state.

P3.3a now routes the private OpenClaw create tool through a mandatory
out-of-process `aragorn-sensor` gateway. The gateway authenticates the runtime
with Linux peer credentials, independently recomputes the operation,
protected-root path, and payload digests, and forwards one measured wrapper to
a backend socket that rejects the runtime principal. The broker rechecks the
wrapper and raw effect under its existing action lock, stamps and publishes the
next sensor-health epoch and observation sequence without promoting an
independently unhealthy status, and only then enters replay claim and durable
effect mediation. The sensor has no control/protected write
path and no staging access. This slice is unit/static exercised only. It does
not turn opaque run/session/tool identifiers into causal evidence, and the
active-skill digest remains a fixed deployment binding. At that checkpoint,
installed live composition evidence and semantic verification remained
incomplete.

P3.3b adds [retained live Linux systemd composition evidence](./benchmark/evidence/runtime-action-systemd-composition-p3-3b-2026-08-04.json)
for that same synthetic create route. The production installer, sysusers,
and tmpfiles provision separate broker, sensor, and runtime identities; the
probe uses a distinct fourth attacker UID. The installed units and
`LoadCredential` paths run under systemd as PID 1. The capture records
collector-observed source/installed digest and
size equality, loaded unit commands, mount and network namespaces,
capabilities, socket DAC, and paired successful `SO_PEERCRED` traces. It
records a successful mediated create plus fail-closed direct-backend,
wrong-principal, unhealthy-mediator, and stopped-sensor cases; the pinned
semantic verifier replays the decision and rejects boundary mutations. The
[capture recipe](./scripts/capture_runtime_action_systemd.sh) retains normalized
image and HostConfig identity and runs the container without networking. The
privileged Docker control plane is not attested, the client is synthetic, and
OpenClaw is not composed. Direct-write and broader event coverage, forced-reset
qualification, `RUN-01`, `RUN-02`, Phase 3, EDR, and release authority remain
incomplete.

P3.3c adds [retained bounded OpenClaw/systemd composition evidence](./benchmark/evidence/runtime-action-openclaw-systemd-composition-p3-3c-2026-08-04.json)
for one exact route: pinned OpenClaw 2026.7.1 optional native create tool
-> mandatory sensor -> broker -> one create. The same capture records
`ALLOW`/`CREATED`, unhealthy `BLOCK`/`NOT_PERFORMED`, sensor-unavailable
`CLIENT_ERROR`/`NOT_SUBMITTED`, and peer, DAC, and direct-write denials.
Because OpenClaw does not retain plugin `details` in tool history, the plugin
retains the result as canonical structured text; its `isError` presentation
flag is not policy, decision, or effect authority. The semantic verifier is
implemented in
[`aragorn.runtime_action_openclaw_evidence`](./src/aragorn/runtime_action_openclaw_evidence.py),
and independently replays the retained artifact and rejects repinned boundary
mutations. This bounded milestone does not establish causal skill attribution
or broader action coverage; `RUN-01`, `RUN-02`, Phase 3 exit, EDR, and release
remain false or incomplete.

P3.3d adds [retained live-revocation evidence](./benchmark/evidence/runtime-action-openclaw-live-revocation-p3-3d-2026-08-05.json)
for that exact create route. One healthy allowed request establishes an
actionable baseline; one later publication adds the pinned active skill digest,
and a distinct native OpenClaw request returns exactly
`ACTIVE_SKILL_REVOKED` / `BLOCK` / `NOT_PERFORMED`. The capture binds the
publication digest and generation to the decision and broker floor, retains
unchanged protected-target and staging snapshots, and records stable service,
socket, and peer identities. The semantic verifier is
[`aragorn.runtime_action_openclaw_revocation_evidence`](./src/aragorn/runtime_action_openclaw_revocation_evidence.py).
Publication is evaluator-operated rather than authenticated production ingress,
so `RUN-02`, Phase 3 exit, EDR, and release eligibility remain false.

P3.4a adds [retained synthetic Linux process-profile evidence](./benchmark/evidence/runtime-process-profile-systemd-composition-p3-4a-2026-08-05.json)
for the create route. The sensor authenticates the runtime socket peer, pins its
PID, and measures an exact single-process cgroup, capability-free identity,
mount namespace, root-owned executable digest, and one root-owned immutable
`SKILL.md`. Its transient filesystem-identity capabilities are absent from all
capability sets before the first request is accepted. The broker durably binds
that attribution to its result and fails closed on an unresolved pending
record. The retained receipt is latest-only for this single-action slice, and
the before/after snapshots are not continuous exec or per-message writer
attestation. The retained allow case is `ALLOW` / `CREATED`; a wrong-cgroup peer is
closed before broker state or protected files change. Source-to-installed
artifact equality, the exact P3.3b base image, loaded units, service commands,
and collector inputs are retained and checked by
[`aragorn.runtime_process_profile_systemd_evidence`](./src/aragorn/runtime_process_profile_systemd_evidence.py).
This is a synthetic root-provisioned one-skill profile, not proof that OpenClaw
consumed the skill or that the skill caused the action. `RUN-01`, `RUN-02`,
Phase 3 exit, EDR, and release eligibility remain false.

P3.4b adds [retained pinned OpenClaw/systemd process-profile evidence](./benchmark/evidence/runtime-process-profile-openclaw-systemd-composition-p3-4b-2026-08-05.json)
with canonical evidence digest
`sha256:2cf59377917cea1461179c3a364cdfe07cdc69181eb1538abebea908954dda9c`.
It observes one synthetic protected create through the gateway `MainPID`,
`SO_PEERCRED`, profile sensor, and broker, ending in `ALLOW` / `CREATED`. The
exact root-owned skill is projected into the pinned runtime prompt, but this is
prompt-projection evidence only, not semantic causation. It grants no
`RUN-01`, `RUN-02`, Phase 3 exit, EDR, or release evidence.

P3.5a now has an additive, unit-qualified dynamic one-shot capability path. A
canonical root-provisioned grant binds caller-supplied source-manifest and
install-context digests plus the process profile, runtime, active skill, sensor,
policy, and operation, with `max_actions` fixed to one. After authenticating the
runtime, measuring its process profile before and after the request,
constructing the exact profiled submission, authenticating the broker, and
measuring the unchanged profile once more, the v3 sensor issues a short-lived
random-nonce lease over that complete submission. The lease exists only on the
sensor-to-broker channel. The v4 broker independently
validates the identical grant credential, lease, submission, dynamic timing,
and sensor peer, then keys durable `AVAILABLE` / `CLAIMED` / `CONSUMED`,
`ABANDONED`, or `EXPIRED` state by the stable grant digest before calling the unchanged v2
effect route. The exact lease is retained inside the claim, a fresh nonce cannot
reopen the grant, and exact-receipt recovery never retries the effect. A known
pre-effect broker failure becomes non-reopenable `ABANDONED`; an indeterminate
attempt without an exact receipt remains `CLAIMED`, fail-stop, and requires
operator remediation. Replacing a terminal grant first archives its exact state
and, for `CONSUMED`, its bound profile receipt as immutable evidence; that state
archive is also a permanent replay tombstone for the grant digest.
The installer stages only the dynamic capability units; activation masks every
legacy v1/v2 route.
[Retained pinned OpenClaw/systemd evidence](./benchmark/evidence/runtime-capability-openclaw-systemd-composition-p3-5a-2026-08-06.json),
with canonical evidence digest
`sha256:7fee778bbf16dd80c726c5007e290f948c1f3ae8212fe462e1a5c2345a32ab45`,
now observes the same root grant remain `AVAILABLE` while an unavailable issuer
returns `CLIENT_ERROR` / `NOT_SUBMITTED` without an effect, then become
`CONSUMED` for one `ALLOW` / `CREATED` action after bounded gateway restart and
dynamic-route activation. The capture binds the exact lease, profile receipt,
target, gateway `MainPID`, `SO_PEERCRED` chain, systemd credentials, and effective
unit state; every legacy v1/v2 route is masked. The semantic verifier is
[`aragorn.runtime_capability_openclaw_systemd_evidence`](./src/aragorn/runtime_capability_openclaw_systemd_evidence.py).
The gateway restart is fixture sequencing, not continuous same-process
evidence. Root-provisioned provenance digests remain bindings, not independently
promoted installer authority. This grants no semantic-causation, aggregate
`RUN-01`, `RUN-02`, Phase 3 exit, EDR, installer, or release evidence.

P3.5b adds a minimal local root-controlled revocation-publication ingress. A
manual hardened systemd oneshot snapshots an optional root:root, mode `0400`,
single-link canonical document with `LoadCredential`, runs as the existing
broker principal, validates the exact runtime binding and credential bytes, and
calls the existing locked publisher. The activator verifies the effective unit
and credentials but never enables or starts it; missing credentials and an
interrupted publication fail nonzero. The shared publisher rejects
invalid, stale, rollback, and same-generation equivocation attempts without
changing the retained control or floor state. This is a bounded 4 KiB local
credential path, not cryptographic authorship or a durable credential-receipt
protocol.
[Retained pinned OpenClaw/systemd revocation evidence](./benchmark/evidence/runtime-revocation-openclaw-systemd-composition-p3-5b-2026-08-06.json),
with canonical evidence digest
`sha256:3751a1650b0f5caa49fa56ef412047f7965ecd06c659e46ca223715de5868e94`,
now binds one root source, one successful invocation-scoped publisher journal
result, and the exact generation `1` to `2` control-floor transition. Only the
revocation document and floor change before the same OpenClaw gateway PID,
start time, and cgroup returns `BLOCK` / `NOT_PERFORMED` solely for
`ACTIVE_SKILL_REVOKED`; the grant becomes `CONSUMED`, its exact no-effect
profile receipt is retained, and the target remains absent. The journal result
is local process evidence, not durable provenance. The semantic verifier is
[`aragorn.runtime_revocation_openclaw_systemd_evidence`](./src/aragorn/runtime_revocation_openclaw_systemd_evidence.py).
This closes only the bounded P3.5b composition slice and does not establish
aggregate `RUN-02`, Phase 3 exit, EDR, installer, or release authority.

The additive [runtime stop response](./src/aragorn/runtime_response_service.py)
provides a manual root-only command for an exact revoked active-skill digest and
accepted revocation-snapshot digest. It binds the provisioned and running worker
credentials, checks the fresh broker snapshot and persisted generation floor under
the existing locks, then stops only the fixed gateway and worker units. Success
requires inactive units and empty process subtrees; partial stops fail explicitly.
[Installation](./packaging/install-runtime-response-host.sh) adds the command
and a root-only evidence directory without activating it or changing the historical
worker, broker, or unit files.
After installation, a root operator supplies both exact `sha256:` digests:

```sh
/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-response-service.py EXPECTED_SKILL_DIGEST EXPECTED_REVOCATION_SNAPSHOT_DIGEST
```

The optional `--prevent-starts` flag also creates and verifies persistent systemd
masks for those two fixed units under the same locks. It refuses existing unit
overrides and never automatically unmasks; a partial response remains indeterminate.
This is a whole-profile start barrier, not installed-digest quarantine or an
automatic detector. The [bounded Linux check](./scripts/capture_runtime_response_systemd_check.py)
exercises wrong-digest refusal, unit-wide stop, an extra gateway-cgroup process,
and refused restart in a disposable fixture. Live RUN qualification and final
common-deployment qualification remain required.
Add `--retain-evidence` to retain the canonical response in the fixed root-owned
`/var/lib/aragorn-runtime-response` CAS. This opt-in mode returns a separate response
and digest-receipt envelope after exact readback and file/directory syncing;
the default output is unchanged. Retention failure after a stop returns
`INDETERMINATE` (125), never a claim that no stop occurred. The store is local,
not independently attested or protected from root; retention/rotation and external
alert delivery are not implemented.
The [retention development observation](./benchmark/evidence/phase3-runtime-response-retention-development-v1-2026-09-09.json)
records successful separate-process CAS readback and deduplication alongside the
stop/mask checks. This verifies the local integration, not power-loss recovery
or independent evidence attestation.
The [September 9 live observation](./benchmark/evidence/phase3-runtime-response-systemd-development-v1-2026-09-09.json)
confirms those bounded checks, persistent masks, absent cgroups, and owned-container
cleanup. It is local integration evidence, not automatic response or digest quarantine.

The opt-in `--dispatch` mode selects only the current fixed profile and accepted
broker snapshot under the same locks; it always stops and masks a revoked active
profile and retains the result. A valid nonrevoking snapshot is an explicit
no-op. Both units already inactive with empty/absent cgroups yield
`NO_ACTIVE_RUNTIME_PROFILE`, which makes no snapshot-acceptance or restart-barrier
claim. Partial, stale, malformed or changing state fails nonzero.

The explicit root-only `--health` mode instead checks the current profile's
broker-accepted health snapshot, bound policy/runtime/sensor, and persisted epoch
under those locks. A fresh accepted `unhealthy` report stops and masks the fixed
gateway and worker; a valid `healthy` report is a no-op. Both completed outcomes
are retained in CAS. Invalid, stale, future, rollback, or changing snapshots are
refused before effects; partial effects remain indeterminate. This mode is an
operator command, not an automatic health trigger, stale/hung-sensor detector,
or installed-digest revocation. Its regression tests are not a live qualification.

The additive [health publisher](./src/aragorn/runtime_health_service.py) reads only
the fixed root-provisioned runtime-binding and health credentials, then uses the
broker's existing publication lock and acceptance rules. The response installer
stages its hardened oneshot, a separate root response using `--health-dispatch`,
and the inert hook `/usr/share/aragorn/systemd/50-runtime-health-response.conf`.
A root operator may opt in by installing that hook under
`/etc/systemd/system/aragorn-runtime-health-publisher.service.d/` and reloading
systemd. Installation alone neither starts nor enables them. The hook responds
to a successful publication of the current accepted health snapshot; it is not
a sensor detector, an expiry timer, or a durable queue. Concurrent revocation and
health responses share a nonblocking activation lock; contention fails nonzero
and requires root retry. `--health` remains the manual retry outside the service
namespace. Publisher success does not establish response completion; cleanup
failure may occur after publication without emitting success. This development
integration still needs live testing and a new common-deployment freeze.

The installer also stages an inert root oneshot and the publisher hook
`/usr/share/aragorn/systemd/50-runtime-response.conf`. To opt in, a root operator
installs that hook as
`/etc/systemd/system/aragorn-runtime-revocation-publisher.service.d/50-runtime-response.conf`
**after** the fixed stack's activation, then reloads systemd. The existing frozen
activator rejects publisher drop-ins: remove this opt-in hook before reactivation;
do not alter that check. This is a development deployment change requiring a new
common-deployment freeze, not authority granted by historical captures.

The hook starts the separate response after a successful publisher invocation.
The response is ordered before subsequent publisher starts to avoid overlapping
oneshot jobs coalescing. Publisher success is **not** response completion: inspect
the response unit's result and its invocation-scoped retained-response envelope.
Failed dispatch requires root attention/retry; no retry daemon, external alert
delivery, durable event queue or general installed-digest quarantine is provided.
See [systemd trigger and ordering semantics](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.unit.xml).
Dispatch is intended for this oneshot's namespace: its fixed `BindPaths` alias
exposes only the loaded worker credential directory while preserving the source
mount's read-only status for the custody check. It does not copy or force that
credential read-only. Use the manual exact-digest command for an operator retry
outside the service namespace.
The [dispatch development observation](./benchmark/evidence/phase3-runtime-response-dispatch-development-v1-2026-09-09.json)
records two distinct publisher/response invocations: generation 2 is a retained
nonrevoking no-op; generation 3 terminates and masks the fixed profile. A bounded
fixture-only two-second delay proves the second publisher waits behind the first
response. Both CAS results pass separate-process readback and deduplication;
the owned container is removed and frozen-parent bytes remain unchanged. This
is a local dispatch integration observation, not a latency benchmark, unattended
delivery guarantee, independent qualification or Phase 3 completion.

The additive [digest denial state](./src/aragorn/protected_skill_quarantine.py)
is a quarantine prerequisite, not a complete response. Its private primitive
retains the first immutable per-digest record under the install-root lock; there
is no unquarantine operation or publishing CLI. The
[successor installer](./src/aragorn/protected_install_v2.py) and
[live lineage wrapper](./src/aragorn/runtime_active_skill_lineage_v2.py) enforce it
under the existing exclusive/shared locks while
preserving frozen modules and their pins. They deny the same `SKILL.md` bytes
even under a new manifest/context and preserve predecessor evidence for a clean
different-digest update. The
[producer source overlay](./scripts/materialize_protected_install_quarantine_producers.py)
renders both frozen producers with exact input/output pins and uses a
[strict namespace adapter](./src/aragorn/protected_install_namespace_v2.py) to
validate every denial record under a shared lock. Unknown entries remain subject
to the original namespace rules. Both rendered producers exercise the inert
install/update/rollback fixture and reject matching denied skill bytes before
transaction state is created. The overlay is not standalone: it excludes the full
source package, dependency lock, and deployment identity bindings. The separate
[runtime source overlay](./scripts/materialize_runtime_quarantine_services.py)
pins three import-only overrides so the sensor, capability issuer, and action
broker use the digest-denial lineage wrappers while preserving their existing
lock scopes and result authority. It also requires a complete, separately bound
package; it does not install services or enforce startup. The private
[startup byte verifier](./src/aragorn/runtime_skill_startup.py) checks the actual
installed tree, fixed external source, worker binding, and V3 gateway selection
under the shared install lock and rejects a matching denial record. Its bounded
nonblocking reads and point-in-time snapshot do not prove process consumption.
The zero-argument [startup service](./src/aragorn/runtime_skill_startup_service.py)
holds exactly two fixed, read-only systemd credentials through the byte check,
rechecks their custody, and fails closed on cleanup errors. The pinned
[activation source generator](./scripts/materialize_runtime_quarantine_activation.py)
adds the mandatory pre-start command and second credential to a successor worker
unit, raises its bounded descriptor limit to 128, and verifies both effective
credentials and the single non-ignored command before starting services.
It preserves the frozen packaging and generates a new profile, not the distinct
retained V3 deployment. The generator does not run an installer. A separate
[staging script](./scripts/stage_runtime_quarantine_profile.py) verifies 47 pinned
inputs, runs the frozen installers from a private immutable snapshot into a fresh
caller-owned `DESTDIR`, applies the source overrides, and audits all 54 final
files. It returns a deterministic inventory without activating services or
deploying to the host. The full producer package, actual runtime credentials,
and root deployment remain separate. A private
[quarantine response composition](./src/aragorn/runtime_quarantine_response.py)
now joins a current accepted revocation to the measured installed digest and
running worker binding, publishes the permanent denial first, then stops and masks
the fixed profile and retains its result. Activation, install, and broker locks
are held in that order; any failure after publication begins is indeterminate,
never evidence of rollback. Its uninstalled
[quarantine entrypoint](./src/aragorn/runtime_quarantine_service.py) accepts only
the two exact expected digests and preserves indeterminate status if result or
diagnostic delivery fails after the response. The staged profile includes its
four-file response closure with exact activation pins. Tests use real denial
records and mocked systemd/CAS effects; there
is no deployment hook, process byte-consumption proof, or live quarantine
qualification. The frozen historical producers are unchanged and
must not be deployed with denial records. No installed-digest quarantine or
future-start qualification is claimed by these offline tests alone.
The [fresh quarantine/systemd development observation](./benchmark/evidence/phase3-runtime-quarantine-systemd-development-v1-2026-09-13.json)
from signed `c9a5d4e` exercises the 54-file successor profile in one disposable
Linux fixture. It records clean pre-start exit 0, wrong-digest refusal without
changes, permanent denial publication, stop-and-mask response, and separate-process
CAS readback. After removing only that fixture's response-created masks, a new
worker pre-start exits 126 with denial and startup inputs unchanged. The expected
failed flag is reset only during fixture cleanup; all four services are stopped
and the container removed. Parent snapshots and staged source pins were rechecked.
This is `OBSERVED`, not production deployment, automatic detection dispatch,
successor producer reinstallation coverage, or RUN/Phase 3 qualification.

The additive [endpoint journal overlay](./scripts/materialize_runtime_endpoint_journal.py)
instruments the worker, sensor, and broker at their existing peer, validation,
submission, result, and delivery boundaries. It emits bounded, best-effort records
without raw requests, credentials, paths, or exception text; transport submission
and a verified broker result remain distinct. Its
[55-file profile stager](./scripts/stage_runtime_endpoint_journal_profile.py)
preserves the quarantine issuer, startup gate, response closure, and unit while
updating the three module pins and adding the journal helper to the activator.
Staging does not activate services. Linux helper checks cover nonblocking output
and descriptor preservation, not live journald retention or complete event capture.
Mandatory loss enforcement, durable retention, native events, and RUN qualification
remain separate requirements.
The existing [owned-fixture capture](./scripts/capture_runtime_quarantine_systemd_check.py)
accepts `--endpoint-journal` for this profile. Its separate
[integration checker](./scripts/runtime_endpoint_journal_systemd_check.py)
requires exact service/process/source custody, an unchanged-state unauthorized
peer refusal, one native benign create, and eight journal records joined to the
actual consumed grant and retained result. The default quarantine capture remains
unchanged; offline capture tests do not establish live delivery.
This capture now selects the [bounded broker response profile](./scripts/stage_runtime_broker_response_drain_profile.py).
After successful response delivery and clean connection closure, the broker
checks its consumed grant and receipt under a read-only lock and uses the
original grant lifetime for its accept wait. In-flight work and cleanup can
outlast that window; it is not a hard process-exit deadline. One-shot effect
checks and every fail-stop service dependency remain unchanged. Startup with a consumed grant
still refuses; this response window is not a native terminal ACK or completion
guarantee.
The [retained journal development observation](./benchmark/evidence/phase3-runtime-endpoint-journal-systemd-development-v1-2026-09-13.json)
from signed `91c1deb` captures all eight selected records in the disposable
55-file fixture, including the unchanged-state peer refusal and a native create
joined to its consumed grant and retained result. The first matching record is
preserved even when the global baseline cursor is outside the unit filter;
baseline, process, boot, invocation, time-window, and pair checks still apply.
All four services were stopped, the owned container removed, and the frozen
parent rechecked unchanged. This is `OBSERVED`, not durable or complete event
coverage, native terminal retention, production activation, or RUN/Phase 3 qualification.

The [restricted Tetragon process adapter](./src/aragorn/runtime_tetragon_process.py)
validates bounded offline records against an
[exact source lock](./benchmark/tetragon-candidate-source-v1.lock.json).
Nineteen selected upstream source files are byte-bound; no release image or live
sensor is qualified. Host PIDs, container-ID prefixes, namespace inodes, and debug
flags are not promoted to stronger identities or execution proof. A clean
caller-reported capture window does not prove authenticity or completeness, and
returned vendor records still contain their original arguments and paths.
Independent kernel-to-wall-clock conversions do not establish cross-field timestamp
ordering; the adapter preserves those values without rounding or a guessed tolerance.
The [isolated OS smoke](./benchmark/evidence/tetragon-isolated-exec-exit-smoke-v1-2026-09-13.json)
retains six original exec/exit records for three inert markers from a dedicated,
now-deleted VM with no host-folder mounts. Its
[fixed-artifact replay](./tests/test_tetragon_isolated_smoke.py) checks byte pins,
marker/process joins, and collector snapshots without executing the
[inert helper reference](./benchmark/evidence/reference/tetragon-isolated-exec-exit-smoke-v1-2026-09-13.py.txt).
The missing BPF loss metric remains unknown; reader shutdown returned exit 1/EOF.
Helper execution, executed binary bytes, complete coverage, release authenticity,
and RUN/Phase 3 eligibility are not established by these retained artifacts.
The separate [release-signature check](./benchmark/evidence/tetragon-release-signature-crypto-check-v1-2026-09-13.json)
retains successful offline signature, certificate-chain, SCT, and Rekor checks
for the signed image index containing that exact ARM64 child. Trust uses an
explicit pinned official HTTPS snapshot, not verified TUF updates. Its
[fixed replay](./tests/test_tetragon_release_signature_retention.py) checks retained
pins and joins without rerunning cryptography. The older smoke stays unchanged;
executed-binary binding, build reproduction, and RUN/Phase 3 qualification remain open.

The [native tool receipt core](./src/aragorn/runtime_native_tool_receipts.py) retains
bounded attempt/terminal chains using the existing CAS and atomic publisher. It
requires externally bound, preprovisioned worker-owned state, acknowledges only
after synchronized readback, and refuses uncertain retention or unresolved startup.
The fixed ceiling is 512 serial calls; duplicate attempts never authorize another
execution. This core alone supplies no transport, mandatory native hook, effect
authority, hostile-owner anti-rollback, or RUN qualification.
The additive [receipt transport renderer](./scripts/materialize_runtime_native_tool_receipts.py)
produces four pinned sources: worker dispatch, receipt-aware journal v2, a
three-credential startup guard, and the worker unit. It reuses authenticated
framing, requires externally provisioned genesis/state before listening, and
exits on uncertain retention. Receipt requests never enter the effect relay;
ordinary creates are not yet gated to an open attempt. Native hooks, provisioning,
successor activation, and performance qualification remain required.
The [native client source successor](./scripts/materialize_runtime_native_tool_client.py)
reuses the pinned gateway transport. It binds attempt ACKs to external genesis
and detached final parameters, invokes one selected read/create callback once,
and awaits its terminal ACK. Duplicate or uncertain retention prevents further
execution by that client. Frozen-parameter compatibility, native hook reachability,
gateway credential loading, and worker-side create-to-attempt enforcement are not
established by its inert client tests.
The [worker create gate successor](./scripts/materialize_runtime_native_create_gate.py)
requires a matching open retained create attempt, holds its existing store lock
through relay, and consumes one worker-lifetime admission before any sensor
connection. Duplicate requests cannot retry; an unresolved attempt prevents
restart-based reset. This is a tested source overlay, not deployed enforcement
or proof that an authenticated gateway report came from a native tool hook.
The [absent-only receipt provisioner](./src/aragorn/runtime_native_tool_provisioning.py)
prepares the fixed empty store under the existing activation and broker locks,
hands its ownership to the worker, and publishes the common root genesis source
last without replacement. Existing or partial history is never reset or repaired;
publication, custody, synchronization, or cleanup uncertainty refuses success.
Its tests use caller-owned files and mocked root/systemd boundaries, including
acceptance by the unprivileged receipt core. No host provisioning or activation
has been performed; gateway projection and native hooks remain separate work.
The [gateway credential renderer](./scripts/materialize_runtime_native_gateway_credentials.py)
adds the same root genesis source to the gateway's read-only systemd credentials.
Its fixed helper reuses the existing held-descriptor custody checks and emits only
bounded canonical worker configuration plus the externally supplied genesis digest.
It validates actual service account identities and never opens the receipt store
or derives trust from an ACK. Inert tests cover identity, namespace, read-only
mount, input, and cleanup refusals; native bootstrap, hooks, complete deployment
pins, and live projection validation are still required.
The [native hook source overlay](./scripts/materialize_runtime_native_tool_hooks.py)
now joins both exact OpenClaw caller paths to one fixed-path client, bootstrapped
by that credential helper. It passes detached final parameters to the selected
read/create callback, awaits terminal retention, and refuses other tool names.
Inert tests execute extracted source functions with mocked transport and helper
launch; they preserve callback arguments, cancellation, and native return/throw.
Progress, transcripts, and later diagnostics are outside this receipt boundary.
The [isolated Linux build observation](./benchmark/evidence/phase3-native-tool-runtime-build-development-v1-2026-09-13.json)
now retains passing core TypeScript, full build, workspace-aware package/import
checks, and a fresh offline install. The new runtime tree is unchanged before
and after CLI and inert read checks. The compiled public read factory accepts
frozen parameters and preserves its actual result through a recording bridge
test double; this does not exercise credentials or durable receipt transport.
Complete dynamic import closure, common deployment, mandatory native capture,
build reproduction, and RUN/Phase 3 qualification remain unverified.
The [common native-receipt stager](./scripts/stage_runtime_native_receipt_profile.py)
now assembles the exact 60-file successor around that new runtime identity.
Its activator checks matching root genesis/binding inputs, exact worker/gateway
credential sets, and preprovisioned receipt-store ownership before startup.
Staging never installs the runtime, provisions state, or activates services;
the absent-only provisioner must run separately before activation.
The [native cache compatibility overlay](./scripts/materialize_runtime_native_tool_cache.py)
addresses a subsequently reproduced integration failure: after a read warms the
descriptor cache, the cached create descriptor lacks its private preparation and
finalization callbacks. Native validation correctly refuses the unattributed
parameters before retaining a create attempt. The fixed worker plugin now uses
the existing current-context factory path; other plugins keep their cache path.
Inert regressions reproduce the original failure and verify that selection fix.
The [successor build observation](./benchmark/evidence/phase3-native-tool-runtime-build-development-v2-2026-09-13.json)
retains passing TypeScript, full build, workspace-aware package/import checks,
fresh offline install, and unchanged read-only runtime measurements. Build
dependencies remained read-only; packaging used a private temporary namespace.
The stager and owned capture now bind this successor without changing the earlier
build record or runtime.
The [owned native read/create capture](./benchmark/evidence/phase3-native-receipt-systemd-development-v1-2026-09-13.json)
now observes real gateway credentials, native hooks and durable worker transport
on that 60-file profile: the receipt store advances from zero to two to four
records, one permitted nonexecuting create has matching broker evidence, and
four ACK digests join fourteen endpoint journal rows. The frozen parent and
successor runtime remain unchanged; all owned fixture containers were removed.
Its source checkpoint passes 2,106 regression tests (one skip) and 169 schema
checks. This bounded integration is not complete event capture, hostile-process
causation, health-loss response, performance, RUN or Phase 3 qualification.
The [accepted-health successor](./scripts/stage_runtime_native_health_profile.py)
adds six existing publisher/response files and their activator pins, preserving
the 60-file predecessor. Its 66-file stage leaves the health hook inert. The
owned capture's explicit `--health` mode runs the native read/create checks first,
then tests fresh healthy and unhealthy publications on that same runtime.
The [composed native/health observation](./benchmark/evidence/phase3-native-health-systemd-development-v1-2026-09-13.json)
from signed `94d788a` retains a healthy no-op followed by unhealthy gateway/worker
suspension, persistent unit masks, and a refused direct restart. Both responses
have separate-process evidence readback; the four native receipts and protected
create remain unchanged, and all six fixture services are stopped before owned
container removal. The check retains typed empty systemd command arrays and
allows only the observed worker command-history reset during hook reload while
preserving exact kernel process identities. This is accepted-health response
composition, not sensor-loss detection, a stale-health watchdog, a durable dispatch
queue, complete RUN coverage, production activation or Phase 3 qualification.
The same owned capture now accepts `--config-denial` (optionally with `--health`)
to submit one fixed native `skills.update` request with `enabled=false`. It
requires the exact read-only configuration denial and unchanged configuration
identity, installed skill, gateway processes, broker result bytes, full controls,
and four native receipts. Native CLI discovery remains eligible before and after;
this is not observation of the gateway's live skill cache or a successful reload.
This bounded successor check does not wire another frozen V3 admission case or
change the 14/31 campaign count.
The [retained configuration-denial composition](./benchmark/evidence/phase3-native-config-denial-systemd-development-v1-2026-09-22.json)
from signed `7dad4d4` observes that denial followed by the existing healthy no-op,
unhealthy suspension, and persistent restart refusal on the same native runtime.
All six services were stopped and the owned container removed; source, runtime,
and parent checks passed. Two earlier attempts were not retained as successes:
one exposed a late-import source-inventory bug (now regression-tested), and one
failed credential setup with a worker-cgroup process-limit refusal. The worker's
inherited `TasksMax=2` remains unchanged in that retained profile. A successful
fresh-VM run does not repair that intermittent startup issue.
The [startup/watchdog successor](./scripts/stage_runtime_native_startup_profile.py)
preserves that frozen predecessor and stages a finite `TasksMax=8` worker, with
activation checks for both configured and effective limits. Its owned capture
also reads the worker and ancestor cgroup task counters. The same stage packages
an opt-in one-second [accepted-health expiry watchdog](./src/aragorn/runtime_health_watchdog.py).
Fresh accepted health is a no-op; expired or unhealthy accepted health triggers
fixed gateway/worker suspension and persistent restart masks. Exact accepted
epoch, runtime, policy, sensor, process and custody checks remain mandatory.
Partial response or retention failure stays indeterminate until root repair;
healthy timer ticks do not accumulate CAS records. This is wall-clock expiry
handling, not sensor-heartbeat or hung-sensor detection. The timer is not enabled
by staging. The owned capture selects this path explicitly with
`--health --startup-reserve --watchdog`; no historical fixture is upgraded.
This successor does not add admission cases or establish RUN/Phase 3 completion.
The [retained watchdog acceptance](./benchmark/evidence/phase3-native-watchdog-systemd-development-v1-2026-10-01.json)
from signed `800ad8a` observes kernel `pids.max=8`, one worker task and no PID-limit
rejections before/after native read/create; the four receipts remain unchanged
through timer-driven expiry suspension. A healthy timer invocation precedes
expiry; the subsequent retained response stops both services, drains their
cgroups, persists restart masks and clears the pending marker only after evidence
retention. Direct restart is refused. All eight fixture units are inactive and
the owned container is removed; the 78 pre-existing containers remain stopped.
Only focused changed-behavior checks were run, not the broad regression suite.
Earlier attempts were refused rather than retained as successes: systemd 252
lacks the newer `EffectiveTasksMax` property (the successor now checks kernel
limits directly), and timer timestamps required typed D-Bus reads. Another run
refused a missing worker `pids.max`; a clean-VM attempt passed without changing
source. That intermittent controller-availability issue remains open: this
single successful capture is not startup-reliability or Phase 3 qualification.

P3.6a adds a live protected-install lineage gate to the one-shot capability
route. The protected-install primitive now publishes a canonical active
transaction record under its exclusive root lock after verifying the active
link and immutable version. The additive v4 sensor and v5 broker independently
remeasure that record, its root and active-link identities, the exact version,
and one root-owned `SKILL.md`; they bind the reconstructed tree, context,
manifest, and skill digests to the grant and hold a shared installer lock
through capability issuance and effect mediation. The production ingress
requires PASS evidence to match the exact returned transaction bytes, and the
activator masks the prior capability units before enabling only the lineage
route.
[Retained pinned OpenClaw/systemd lineage evidence](./benchmark/evidence/runtime-active-lineage-openclaw-systemd-composition-p3-6a-2026-08-07.json),
with canonical evidence digest
`sha256:5c48201f3273dc4597e0e387f2873d6cf93940a645d6a528344c4aa9e2f7e1bd`,
observes a stale record fail before broker submission: OpenClaw conservatively
returns `CLIENT_ERROR` / `INDETERMINATE` because bytes reached the sensor
frontend, while the empty broker peer trace, unchanged control state,
`AVAILABLE` grant, and absent target, pending record, and receipt prove no
broker submission or effect in this fixture. After restoring a coherent record
and restarting only the pinned gateway for fixture sequencing, the same bound
grant produces one `ALLOW` / `CREATED` action and becomes `CONSUMED`. The
semantic verifier is
[`aragorn.runtime_active_lineage_openclaw_systemd_evidence`](./src/aragorn/runtime_active_lineage_openclaw_systemd_evidence.py).
The protected tree in this capture is root-assembled rather than produced by
the full protected-install service. It proves neither semantic causation nor
multi-file or broader-action coverage, hostile-root resistance, aggregate
`RUN-01` or `RUN-02`, Phase 3 exit, EDR status, installer authority, or release
authority.

P3.6b removes only P3.6a's root-assembled-tree limitation for one retained-CAS
fixture. The exact protected-install unit and launcher run under systemd with a
pinned Python 3.12 drop-in and measured current-module adaptation. After
verifying the transported Phase 1 closure, the evaluator issues a receipt for
the copied CAS's live custody; the service then emits one PASS receipt whose
transaction exactly matches the immutable version, claim, active link, and
canonical active record. An evaluator-injected stale record still stops before
broker submission, and restoring the exact producer record permits one
`ALLOW` / `CREATED` action.
[Retained P3.6b producer-to-runtime evidence](./benchmark/evidence/runtime-producer-lineage-openclaw-systemd-composition-p3-6b-2026-08-07.json),
with canonical evidence digest
`sha256:485232aa3565f056fff3a2f1e1b14e81e6dfadc175099e315eef8e9f5cabca20`,
is checked by
[`aragorn.runtime_producer_lineage_openclaw_systemd_evidence`](./src/aragorn/runtime_producer_lineage_openclaw_systemd_evidence.py).
This is not live acquisition or coordinator composition, retained Phase 1
release identity, prompt consumption or semantic causation evidence, or
multi-file, broader-action, hostile-root, or power-loss qualification.
`RUN-01`, `RUN-02`, Phase 3 exit, EDR status, installer authority, and public
release authority remain false.

P3.7a begins the trust-plane repair required by the protected session-snapshot
failure. An additive OpenClaw plugin now sends only bounded effect bytes and
opaque run, session, and tool-call correlation to a distinct
`aragorn-runtime` worker; it no longer gives the gateway runtime, skill,
policy, protected-root, sensor, or broker pins. The worker authenticates the
gateway with Linux peer credentials, derives the existing broker request from
one exact five-field operator binding, authenticates the existing sensor, and
makes exactly one relay attempt. Its result distinguishes `NOT_SUBMITTED`,
`INDETERMINATE`, and `COMPLETED`; `COMPLETED` means only that a strictly
validated broker result returned, not that the effect was allowed or that run
conformance was established. The reduced plugin authenticates the worker
UID-owned Unix endpoint by exact parent and socket metadata because Node does
not expose peer credentials on every supported runtime; the downstream sensor
must still measure the worker process before any effect. Additive sysusers and
a hardened systemd unit keep the worker away from gateway state, provider
credentials, broker control/staging state, observation credentials, and the
capability grant. The digest-bound v4 sensor and v5 broker sources remain
unchanged, but their earlier OpenClaw evidence does not transfer: a
worker-specific process profile, capability grant, Linux activation, and live
exact-profile qualification are still required. This source/static checkpoint
includes an optional `DESTDIR`-aware host-staging installer that copies the
existing capability route plus the worker, service, identity declaration, and
reduced plugin bytes. It also stages a static gateway unit whose root-owned
configuration is projected as a service credential and whose default network
policy permits only localhost. The installer writes no configuration or
credentials and invokes no identity or service manager, so staging does not
activate the route or grant `RUN-01`, `RUN-02`, Phase 3 exit, EDR, installer,
or release authority. Activation must first validate the root-owned environment
file and reject assignments that override `HOME`, `OPENCLAW_CONFIG_PATH`,
`OPENCLAW_STATE_DIR`, `PATH`, or `NO_PROXY`; it must also verify the effective
gateway UID, GID, and complete group set because the static unit cannot erase
NSS-derived supplementary memberships.

P3.7b retains one bounded live qualification of that split for the exact
OpenClaw 2026.7.1 tree in a local privileged Docker/systemd fixture. The same
single-file retained-CAS skill and optional create action exercise five
fail-closed cases: the legacy OpenClaw profile, a mismatched worker binding, an
unavailable worker endpoint, an unauthorized root peer, and a stale active
record. A sixth coherent case binds the worker-specific profile and one-action
grant to the measured worker, preserves the gateway -> worker -> sensor ->
broker peer chain, and returns one `COMPLETED` / `ALLOW` / `CREATED` result.
The evaluator-controlled loopback provider determines that tool call; this
does not establish autonomous model tool selection or production-provider
behavior.
The trace proves one routed connection without a reconnect attempt; it does not
count application send syscalls.
The negative outcomes and unchanged effects are retained, but their cause
labels rely on the pinned capture setup rather than retained runtime reason
evidence.
`COMPLETED` still means only that the worker received a strictly validated
broker result. The
[retained observation](./benchmark/evidence/runtime-action-worker-openclaw-systemd-composition-p3-7b-2026-08-09.json)
has canonical digest
`sha256:4b668b1eae1875c6e129afd8fd0a56c4dc2e912179644bba22cc3e5a285b969e`;
the separate
[qualification receipt](./benchmark/receipts/phase3-runtime-action-worker-openclaw-systemd-qualification-v1-2026-08-09.json)
records semantic replay without rewriting the observation's capture-time
`NOT_TESTED` fields. Its closure retains both the base capability installer and
the worker host installer. The verifier binds the canonical installed-target
inventory and separately proves each retained source/installed byte pair. The
capture wrapper publishes only a complete,
fsynced canonical file through a no-replace hard link. The qualification is
limited to this pinned fixture and exact pair. It establishes no raw
provider/session replay, independent host or container attestation, continuous
measurement, semantic skill causation, multi-file or broader-action coverage,
hostile-root, same-UID output-directory, or power-loss resistance, aggregate
`RUN-01` or `RUN-02`, Phase 3 exit, EDR status, installer authority, or
public-release authority. The verifier source is digest-bound, but its Python
standard-library and dynamic dependency closure is not pinned.

An unused `AVAILABLE` grant now becomes an authenticated, durable `EXPIRED`
tombstone at its deadline, including while either broker generation is waiting
for a request. Only exact terminal state may be archived before a fresh grant
becomes `AVAILABLE`; `CLAIMED` is never expired or reopened. Once `EXPIRED` has
been written, rollback to older code is deliberately fail-stop because older
readers reject that state. Operators must not delete or rewrite it. These
expiry and host-activation bytes are newer than the retained P3.7b pair and
inherit none of its qualification authority.
The host activator accepts only the worker plugin and an exact OpenClaw policy:
the `minimal` profile, `aragorn_runtime_create` as its sole addition, and denial
of the profile's sole built-in `session_status`. Any failed transaction stops
all four services, disables the sensor and broker, and masks the gateway and
worker. An operator must inspect the failure and explicitly unmask those two
units before retrying.

The [retained P3.7c observation](./benchmark/evidence/runtime-action-worker-activation-expiry-systemd-composition-p3-7c-2026-08-09.json),
canonical digest
`sha256:a0607801571db26cf8d2f2c07ebc6ca7675da8dbc2f385e0e64f5ab5e3187322`,
and its separate
[qualification receipt](./benchmark/receipts/phase3-runtime-action-worker-activation-expiry-systemd-qualification-v1-2026-08-09.json)
semantically replay one unused grant becoming `EXPIRED`, fail-stop activation,
exact terminal archive rotation to a distinct fresh `AVAILABLE` grant, four-unit
activation without boot authority, and one `COMPLETED` / `ALLOW` / `CREATED`
action ending `CONSUMED`. P3.7c inherits P3.7b only through its exact immutable
parent binding. It remains one privileged local Docker/systemd fixture, not
native-host production evidence, automatic or concurrent renewal, reboot,
crash or power-loss coverage, aggregate `RUN-01`/`RUN-02`, Phase 3 exit, EDR,
installer authority, or public-release authority.

The bounded [sensor-process-loss observation](./benchmark/evidence/runtime-action-worker-sensor-loss-systemd-composition-2026-08-28.json)
and [qualification receipt](./benchmark/receipts/phase3-runtime-action-worker-sensor-loss-systemd-qualification-v2-2026-08-28.json)
bind one root-issued `SIGKILL` of the exact active sensor PID to a durable
fail-stop. The sensor remains `failed` with signal 9 and no restart; the
gateway and worker remain inactive with empty cgroups; the sensor and worker
sockets remain absent; the broker PID, invocation, cgroup, and socket remain
unchanged. A successful
two-second stability window separates two terminal snapshots with identical
non-command service and socket state, while the protected target and projected
skill remain unchanged. This is one
privileged private-cgroup systemd fixture and one process-loss case, not full
sensor-health, in-flight response, worker/broker-loss, hostile-root,
power-loss, `RUN-01`, `RUN-02`, Phase 3 exit, EDR, installer, or release
authority.

P3.8a adds only a receipt-level cross-capture composition; it adds no new live
runtime capture. Its
[qualification receipt](./benchmark/receipts/phase3-runtime-acquisition-action-binding-v1-2026-08-11.json)
and
[`aragorn.runtime_acquisition_action_binding`](./src/aragorn/runtime_acquisition_action_binding.py)
replay the retained Phase 1 supported-ingress archive and exact P3.7c parent
chain, then join the same 140-byte protected `SKILL.md`, source request,
manifest, and tree digests to P3.7c's producer, grant, runtime attribution, and
one `COMPLETED` / `ALLOW` / `CREATED` action ending `CONSUMED`. The Phase 1
install case retains a live summary and protected installed bytes, not its live
quarantine CAS. This proves exact content identity across separate captures,
not continuous custody, one transaction or release identity, semantic skill
causation, aggregate `RUN-01`/`RUN-02`, Phase 3 exit, EDR, installer authority,
or public-release authority.

P3.8b adds one bounded live capture of public GitHub commit
`2235be7c60b551f5de82ade908fd3816455afcda`. Its
[observation](./benchmark/evidence/runtime-acquisition-action-systemd-composition-p3-8b-2026-08-11.json),
[verifier](./src/aragorn/runtime_acquisition_action_systemd_evidence.py),
[schema](./schema/runtime-acquisition-action-systemd-qualification-v1.schema.json),
and [qualification receipt](./benchmark/receipts/phase3-runtime-acquisition-action-systemd-qualification-v1-2026-08-11.json)
bind same-container custody from the quarantine CAS through protected install
into one `ALLOW` / `CREATED` action ending `CONSUMED`; network access is
disconnected and reverified before runtime. The capture uses adapted Python
3.12 and fixture-only systemd 252, cgroup, and Docker-DNS adapters. It does not
establish the Phase 1 release identity, semantic skill causation, aggregate
`RUN-01`/`RUN-02`, Phase 3 exit, EDR, installer authority, or release authority.

P3.8c extends that exact live route with one bounded capture of public GitHub
commit `f57638a74759376871509ccf080e606f62052f1b` from `obra/superpowers`. Its
[observation](./benchmark/evidence/runtime-acquisition-action-multifile-systemd-composition-p3-8c-2026-08-11.json),
[verifier](./src/aragorn/runtime_acquisition_action_multifile_systemd_evidence.py),
[schema](./schema/runtime-acquisition-action-multifile-systemd-qualification-v1.schema.json),
and [qualification receipt](./benchmark/receipts/phase3-runtime-acquisition-action-multifile-systemd-qualification-v1-2026-08-11.json)
bind the exact flat `SKILL.md` and `code-reviewer.md` tree from the live
quarantine CAS through one protected transaction and projection into one
`ALLOW` / `CREATED` action ending `CONSUMED`; network access is disconnected
and reverified before runtime. It remains one privileged local Docker/systemd
fixture using adapted Python 3.12, with no nested-skill assets, broader source
layouts or action families, provider/session raw bytes, full non-skill blob
replay, or continuous measurement qualified. It does not establish the Phase 1
release identity, semantic skill causation, aggregate gate or `RUN-01`/`RUN-02`,
Phase 3 exit, EDR, installer authority, or public-release authority.

P3.8d adds one exact third-party public two-file depth-one Markdown source:
commit `9b081280bc52ee6f22a2e0463761b318936dd980` from `affaan-m/ecc`, rooted at
`skills/brand-voice`. Its
[observation](./benchmark/evidence/runtime-acquisition-action-nested-systemd-composition-p3-8d-2026-08-11.json),
[verifier](./src/aragorn/runtime_acquisition_action_nested_systemd_evidence.py),
[schema](./schema/runtime-acquisition-action-nested-systemd-qualification-v1.schema.json),
and [qualification receipt](./benchmark/receipts/phase3-runtime-acquisition-action-nested-systemd-qualification-v1-2026-08-11.json)
bind `SKILL.md`, the direct `references` directory, and
`references/voice-profile-schema.md` from the live quarantine CAS through the
protected and projected trees into the same bounded coherent action. This is
one nonempty direct directory at depth one, not general nested or deeper
recursive coverage, and remains one privileged local Docker/systemd fixture
using adapted Python 3.12. It does not establish remote signer or signature
trust, the Phase 1 release identity, semantic skill causation, aggregate gate
or `RUN-01`/`RUN-02`, Phase 3 exit, EDR, installer authority, or public-release
authority.

The final common-runtime
[fresh-session qualification](./benchmark/receipts/phase3-openclaw-protected-final-fresh-session-reset-route-coverage-v1-2026-08-13.json)
records 6 `PASS` and 15 `NOT_TESTED`. Five passes are exact static gate-or-deny
routes whose transitions were not dynamically exercised; only
`ADM-02/reload/fresh-session-reset` is dynamic. It binds accepted `/new`,
session-ID rotation, a cleared snapshot, and exact protected prompt and catalog
rebuild before the terminal network error. All nine broad eligibility decisions
remain false; this is one private local fixture with no provider, reply, or
model-success claim.

The locked v2 checkpoint additionally requires a caller-held digest for a
canonical pre-outcome coverage lock:

```console
python -m aragorn.benchmark SUITE OUTCOMES --state EVIDENCE_CAS --phase2-metrics-checkpoint --phase2-coverage-lock LOCK --expected-phase2-coverage-lock-digest sha256:...
```

That lock binds the exact Aragorn candidate, every held-out suite case, separate
suite and acquired-source manifests, bounded entrypoints, declared capability
categories, and gVisor v4 replay pins. It requires at least 20 cases (4 benign
and 16 adversarial), the seven required adversarial families with two lineages
each, and five unique runtime evidence records per candidate case. Unknown
attribution scopes fail closed, and the outcome verdict is re-derived from the
verified capability diff. The v2 report still sets `phase2_exit_eligible` to
`false`: capture completeness, a qualified isolated backend, and varied live
scenarios remain unproven.

The checked-in v3 Phase 2 matrix catalog pins public fixture commit
[`fdf91113`](https://github.com/yousifnazhat/agent-skill-inert-fixture/commit/fdf9111395179343a742d9dd6649e6d5f9da737b)
and exactly 20 cases across a fixed five-run primary/alternate scenario
schedule. The four benign scripts use same-thread reads; the 16 adversarial
scripts add inert `/tmp` writes through shell builtins, so the bounded v4
classifier does not silently turn forked child activity into subject evidence.
This is operator-authored contract plumbing, not independent efficacy evidence.

On the qualified Linux/root capture host, one prepare call performs all 20
protected acquisitions and prints the caller-held coverage-lock digest. One run
call then performs the complete serial 20-by-5 matrix:

```console
PYTHONPATH=src python3.12 -m aragorn.phase2_matrix_prepare benchmark/phase2-matrix-catalog-v3.json WORK_ROOT --worker-uid WORKER_UID --worker-gid WORKER_GID --gateway-root GATEWAY_TMPFS
PYTHONPATH=src python3.12 -m aragorn.phase2_matrix_run WORK_ROOT --expected-coverage-lock-digest sha256:...
```

Keep the printed digest outside `WORK_ROOT`. Preparation and the final
`results/` directory publish atomically; an interrupted attempt cannot leave a
partial final suite or a report without its 100 canonical outcomes. The runner
also stops on the first verified `unknown` attribution scope instead of burning
the rest of the matrix.

The fixed OpenClaw restart evidence pair is now rechecked by an exact
`ADM-02/restart` verifier. Carried scenario claims remain retention-only. The
verifier rejects promotion and aggregate `PASS`; it grants no installer
authority and does not replace the future general verifier.

The update-slice verifier proves that one user-writable managed target was not
replaced after an exact `skill-install/update` policy denial. That slice did not
establish aggregate update conformance; cumulative formal `ADM-02/update` is now
`FAIL` because of the independently retained workshop route.

A separate shared-filesystem slice proves that the root-owned broker atomically
changed exact skill bytes beneath a read-only OpenClaw bind mount and that the
same running PID resolved the new immutable path without restart. It is
composition evidence only, not `ADM-02` route conformance or installer
authority.

The live-reload verifiers bind one admitted forced replacement to a new watcher
snapshot consumed by the same chat session and to two forced isolated cron runs
that built fresh prompt snapshots on opposite sides of that replacement,
without a gateway restart. The cron runs used distinct isolated sessions and
lifecycle revisions but stopped at model resolution before provider execution;
this proves prompt-snapshot construction, not successful provider completion.
Formal `ADM-02/update` is now `FAIL`; formal `ADM-02/reload` remains
`NOT_TESTED`. These route-level observations grant no installer authority.

The config-activation-slice verifier proves `skills.update` disabled and
re-enabled a previously verified skill digest mounted read-only, while the same
chat session dropped and restored that skill without a gateway restart. It also
proves one missing prompt blob was rebuilt to the same prompt digest while the
bound read-only bytes stayed unchanged, without changing the session or
snapshot version. These are reactivation and cache-recovery routes, not
acquisition or authentication; they do not promote formal `ADM-02/update` or
`ADM-02/reload`.

The model-activation verifier binds the same 104-byte conformance fixture to
OpenClaw's real gateway, model transport, and `read` tool path. An
evaluator-controlled loopback provider requested that exact `SKILL.md`; the
second provider request carried the complete bytes, and the turn completed
without target mutation or gateway restart. This promotes only formal
`ADM-01`. It is not production `ALLOW` lineage, external-model efficacy,
deterministic replay, or installer authority.

The deterministic-authority verifier binds canonical manifest, analyzer
evidence, policy, and target-runtime inputs to exact canonical decisions for
`ALLOW`, `REVIEW`, `DENY`, and `ERROR`. Each vector produced byte-identical
output across three fresh CPython processes with distinct hash seeds. This
promotes only `DET-01` in a separate receipt; it does not attest the fixed
analyzer evidence, compose `ADM-01`, or grant installer authority.

The cumulative update/reload coverage verifier derives one canonical 21-route
ledger from exact source receipts and their transitive evidence. It records
3/9 update routes as `PASS`, 1/9 as `FAIL`, and 6/12 reload routes as `PASS`.
`ADM-02/update/workshop-proposal-apply` failed because the configured install
policy blocked the positive-control installer but was not invoked when workshop
apply created the workspace skill. This result is limited to the pinned runtime,
configuration, route, and retained evidence; `reload/workshop-invalidation`
remains `NOT_TESTED`. External workspace mediation is implemented below; the
current gate is exact protected-consumer admission-profile closure.

A separate
[protected-route raw-action receipt](./benchmark/receipts/phase1-openclaw-protected-route-actions-v5-2026-07-29.json)
binds one hardened read-only-root profile to five `OBSERVED` actions and seven
`NOT_TESTED` routes. It records no `PASS` or `FAIL`, grants no installer
authority, and does not alter the cumulative conformance ledger.

The additive
[protected-workshop qualification](./benchmark/receipts/phase1-openclaw-protected-workshop-route-v1-2026-08-04.json)
semantically replays that raw capture and promotes only
`ADM-02/update/workshop-proposal-apply` to route-level `PASS` for the exact
protected-consumer profile: the native apply reached the root-owned read-only
workspace mount, failed with `EROFS`, and left the target absent and
undiscovered. The earlier writable-profile `FAIL` remains historical truth;
the new route result does not promote aggregate admission, installer, Phase 3,
EDR, or release authority.

A second additive
[protected-archive route qualification](./benchmark/receipts/phase3-openclaw-protected-archive-route-qualification-v1-2026-08-04.json)
promotes only `ADM-02/update/archive-source-force-replacement` to route-level
`PASS` for existing-target pre-effect denial in that exact profile. It binds
the full pinned runtime tree before and after, a successful writable-target
positive control for the valid inert directory source, the protected attempt's
`EROFS` staging denial, and the unchanged existing target and discovery state.
Both upload calls were disabled before ingest, so no archive bytes were
ingested; this qualification covers the forced directory-source replacement
denial, not archive parsing. Aggregate admission, installer, `RUN-01`,
`RUN-02`, Phase 3, EDR, and release authority all remain false.

A third additive
[protected-config route qualification](./benchmark/receipts/phase3-openclaw-protected-config-route-qualification-v1-2026-08-07.json)
promotes only `ADM-02/update/config-entry-activation` to route-level `PASS` for
that exact profile. A native `skills.update` activation request (`enabled:true`)
for the discovered protected skill reached the read-only configuration lock
path and failed with `EROFS`.
The verifier binds unchanged configuration, active-skill, discovery, runtime
tree, and gateway process identity before and after. It grants no aggregate
admission, installer, Phase 3, EDR, or release authority.

A fourth additive
[protected prompt-rebuild qualification](./benchmark/receipts/phase3-openclaw-protected-prompt-rebuild-route-qualification-v1-2026-08-09.json)
promotes only `ADM-02/reload/missing-prompt-blob-rebuild` to route-level `PASS`
for that exact profile. After a baseline prompt snapshot, the probe preserved
the session record, writable by the same profile UID, but removed its referenced
prompt blob. The next same-session attempt reconstructed the exact 728-byte
protected prompt blob before provider execution. Both agent attempts then failed because the
contained profile intentionally had no provider credentials; the result does
not claim a successful model turn. The verifier binds the reconstruction to
the second attempt's time window and proves unchanged session-store bytes,
protected roots, configuration, runtime tree, target, and gateway process
identity. It grants no aggregate admission, installer, Phase 3, EDR, or release
authority.

The exact protected-consumer
[session-snapshot qualification](./benchmark/receipts/phase3-openclaw-protected-session-snapshot-route-qualification-v1-2026-08-09.json)
records `ADM-02/reload/session-snapshot-consumer` as route-level `FAIL`.
After a native baseline turn, a self-consistent prompt reference and blob were
substituted through state writable by the same profile UID, without changing
protected skill bytes.
The exact retained compiled consumer chain loaded that prompt and placed its
inert marker once in both the skills prompt and configured system prompt.
This is a deterministic pinned-function replay, not native agent-command or
provider execution; no provider request or native system-prompt report was
observed. The result disproves protected-bytes-only consumption for this exact
profile and grants no broader authority.

A separate private patched-runtime
[session-snapshot qualification](./benchmark/receipts/phase3-openclaw-protected-session-snapshot-fixed-route-qualification-v1-2026-08-12.json)
promotes only `ADM-02/reload/session-snapshot-consumer` to route-level `PASS`
for `openclaw-2026.7.1-session-snapshot-fixed`. The pinned resolver returned
the same trusted protected prompt and skill catalog for the clean baseline
(`shouldRefresh:false`) and attacker-supplied prompt reference
(`shouldRefresh:true`); the bounded native turn then persisted that protected
snapshot. This fresh profile records 1 `PASS` and 20 `NOT_TESTED` and does not
revise the official-runtime failure above. The private build is not an official
or independently reproducible release, and aggregate admission, installer,
`RUN-01`, `RUN-02`, Phase 3, EDR, and release authority remain false.

The additive private fixed-runtime
[route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-session-snapshot-fixed-route-coverage-v1-2026-08-13.json)
records 6 `PASS` and 15 `NOT_TESTED`. The core-updater route is retained as an
observation but is not qualified because no plugin replacement outcome occurred.
Aggregate admission, installer, `RUN-01`, `RUN-02`, Phase 3, EDR, and release
authority all remain false.

A subsequent private fixed-runtime
[fresh-session route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-session-snapshot-fixed-fresh-session-route-coverage-v1-2026-08-13.json)
records 7 `PASS` and 14 `NOT_TESTED`, adding only
`ADM-02/reload/fresh-session-reset`. It binds accepted `/new` dispatch,
session-ID rotation, a cleared snapshot, and reconstruction of the exact
protected prompt reference. Reset reply dispatch and both model turns failed;
no full-runtime-tree, aggregate, installer, Phase 3, EDR, or release authority
is claimed.

The same private fixed-runtime capture also supports a narrowly scoped
[native chat route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-session-snapshot-fixed-chat-route-coverage-v1-2026-08-13.json),
bringing the profile to 8 `PASS` and 13 `NOT_TESTED`. It adds only
`ADM-02/reload/chat-session-snapshot-consumer`: the second same-session native
chat turn discarded an injected prompt reference and persisted the exact
protected prompt and catalog. This reuses a shared capture and is black-box
behavioral evidence, not a direct `session-updates.ts` trace; model delivery and
all broader authority remain unclaimed.

A newer private restore-authority runtime
[curator route qualification](./benchmark/receipts/phase3-openclaw-protected-curator-restore-denial-route-qualification-v1-2026-08-13.json)
records 1 `PASS` and 20 `NOT_TESTED` on its own fresh profile. Both the native
gateway restore and the CLI local fallback were denied by the shared external-
authority guard while the exact archived lifecycle row and protected skill
remained unchanged. The archived row is an explicit ephemeral fixture, the
build is private, and no prior-profile, aggregate, installer, `RUN-01`,
`RUN-02`, Phase 3, EDR, or release authority is composed or claimed.

An additive
[restore-authority config route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-restore-authority-config-route-coverage-v1-2026-08-13.json)
records 2 `PASS` and 19 `NOT_TESTED`. A separate exact capture adds only
`ADM-02/update/config-entry-activation`: native `skills.update` reached the
read-only configuration lock and failed with `EROFS` while configuration and
the protected skill remained unchanged. The captures are composed only at the
qualification layer; no aggregate, installer, `RUN-01`, `RUN-02`, Phase 3,
EDR, or release authority is claimed.

The next additive
[restore-authority archive route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-restore-authority-archive-route-coverage-v1-2026-08-13.json)
records 3 `PASS` and 18 `NOT_TESTED`, adding only
`ADM-02/update/archive-source-force-replacement`. The exact source install
reached the protected target and failed with `EROFS`; uploaded archive routes
were disabled and no archive bytes were ingested, while source, target, and
runtime state remained unchanged. This is separate-capture composition only;
all aggregate, installer, `RUN-01`, `RUN-02`, Phase 3, EDR, and release
authority remains false.

The following additive
[restore-authority prompt route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-restore-authority-prompt-route-coverage-v1-2026-08-13.json)
records 4 `PASS` and 17 `NOT_TESTED`, adding only
`ADM-02/reload/missing-prompt-blob-rebuild`. After the exact 728-byte protected
prompt blob was removed and the byte-identical session store was mtime-touched,
a second native turn rebuilt the identical `promptRef`, prompt, and session
identity. Both turns ended at the expected model-not-found boundary, so no
provider execution is claimed. This is separate-capture composition on a
private build; all aggregate, installer, `RUN-01`, `RUN-02`, Phase 3, EDR, and
release authority remains false.

The additive
[restore-authority fresh-session route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-restore-authority-fresh-session-route-coverage-v1-2026-08-13.json)
records 5 `PASS` and 16 `NOT_TESTED`, adding only
`ADM-02/reload/fresh-session-reset`. A separate exact capture binds the accepted
`/new` reset, session-ID rotation, cleared snapshot, and reconstruction of the
same protected prompt and skill catalog. The failed model row's non-monotonic
`ended_at`/`started_at` values are excluded from the route claim, and no reset
reply completion, model success, or reply delivery is claimed. This remains
separate-capture composition on a private build, with every broad eligibility
decision false.

The additive
[restore-authority workshop route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-restore-authority-workshop-route-coverage-v1-2026-08-13.json)
records 6 `PASS` and 15 `NOT_TESTED`, adding only
`ADM-02/update/workshop-proposal-apply`. A separate exact capture binds proposal
creation in ephemeral state and the native apply's `EROFS` denial before the
protected target was created; the target remained absent. The legacy proposal
volume has only its phase label, and this capture has no writable-workspace
positive control. Composition remains separate-capture and private-build only,
with every broad eligibility decision false.

The additive
[restore-authority session-consumer route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-restore-authority-session-consumer-route-coverage-v1-2026-08-13.json)
records 7 `PASS` and 14 `NOT_TESTED`, adding only
`ADM-02/reload/session-snapshot-consumer`. A separate exact native turn began
with no session store and populated the exact protected prompt snapshot. This
is an absent-before population result only: it does not establish reuse,
tamper repair, invalidation, direct module execution tracing, provider or model
success, reply delivery, or a fresh full-runtime-tree hash. Composition remains
separate-capture and private-build only, with every broad eligibility decision
false.

The additive
[restore-authority chat route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-restore-authority-chat-route-coverage-v1-2026-08-13.json)
records 8 `PASS` and 13 `NOT_TESTED`, adding only
`ADM-02/reload/chat-session-snapshot-consumer`. It reuses the exact shared
prompt-rebuild capture rather than an independent execution and binds only the
black-box native same-session chat persistence visible there, without a direct
session-update or module-execution trace. Both model turns failed, so no
provider body, model success, or reply delivery is claimed. The result remains
private-build composition with every broad eligibility decision false.

The additive
[restore-authority cron route coverage qualification](./benchmark/receipts/phase3-openclaw-protected-restore-authority-cron-route-coverage-v1-2026-08-13.json)
records 9 `PASS` and 12 `NOT_TESTED`, adding only
`ADM-02/reload/cron-rescan`. This separate-capture composition uses one fresh,
exact private patched-runtime capture: one isolated job was created, forced,
and removed, without a repeatability claim. The absent base session establishes
neither snapshot reuse nor tamper repair; the exact `promptRef` persisted before
the expected model-not-found result, distinct run-ID and `runAtMs` clock reads
are only causally bounded, and mutations stayed in ephemeral state. It is
black-box native cron evidence without a direct module trace, provider network
or request, successful model, reply, or delivery. It also inherits the chat
ceilings: the shared prompt-rebuild capture is not an independent chat run,
there is no direct session-update trace, and one missing-blob trigger is not
general chat coverage. The private build is not an official release and its
source-to-binary reproduction is not independently attested; 12 routes remain
untested and every admission-profile, aggregate-admission, installer, `RUN-01`,
`RUN-02`, Phase 3, EDR, and release decision remains false. This is a
checkpoint only and is non-composable with P3.7c before the final runtime
freeze because the captures bind different runtime identities. A common final
runtime freeze, fresh reruns, and an explicit cross-capture qualifier are
required before any shared Phase 3 claim.

The exact protected-consumer
[cron-rescan qualification](./benchmark/receipts/phase3-openclaw-protected-cron-rescan-route-qualification-v1-2026-08-09.json)
promotes only `ADM-02/reload/cron-rescan` to route-level `PASS`. One forced
isolated cron run created the exact protected 728-byte prompt snapshot before
the expected model-resolution failure; the verifier binds the random job ID,
pre-run key absence, one terminal run, persisted snapshot, unchanged protected
state, and successful job cleanup. It does not claim provider execution.

The current
[route-coverage ledger](./benchmark/receipts/phase3-openclaw-protected-profile-route-coverage-v3-2026-08-09.json)
composes all six pinned qualifications in the authoritative 21-route inventory
order: 5 `PASS`, 1 `FAIL`, and 15 `NOT_TESTED`. The known session-snapshot
consumer failure makes the exact profile result `FAIL`. Missing, duplicate,
modified, cross-profile, or PASS/FAIL-substituted qualifications are rejected;
aggregate admission, installer, Phase 3, EDR, and release authority remain
false.

The [Phase 3 V1 exit-gate manifest](./benchmark/phase3-exit-gate-manifest-v1.json)
now freezes the admission, runtime-prevention, response, and quantitative
requirements without evaluating them. The matching non-executing V3 campaign
contract and dispatcher enumerate 31 fresh isolated subfixtures against one
exact parent: fourteen have retained current V3 implementations, and seventeen
still require a V3 port or route adapter. A separate set of fourteen retained receipt
paths remains regression-oracle-only and cannot promote campaign eligibility.
The dedicated workshop-invalidation capture now has one fail-closed route-level
qualification and replaces the shared-capture child as that route's regression
oracle. DET-01 and core-updater replacement now have standalone qualifications;
their exact, read-only materialized bundle descriptors remain available. These
receipts do not replace the 31 fresh, isolated final campaign subfixtures.
The first small campaign wave now provides a shared exact-request builder and
a [DET-01 request-to-byte binder](./src/aragorn/admission_openclaw_final_v3_det01_binding.py).
It joins a caller-held campaign contract to the pinned materializer, source
files, and read-only local bundle. This is a point-in-time byte check, not
execution, live runtime custody, or qualification; all eligibility stays false.
An opt-in [one-case DET-01 backend](./scripts/capture_openclaw_final_v3_det01_campaign.py)
now wraps the unchanged native capture recipe, checks actual source/bundle/argv
bindings, snapshots the complete frozen parent before and after execution, and
publishes CAS evidence only after local cleanup checks. Its campaign nonce is
associated by the host wrapper, not echoed by the native collector. The third
small wave adds an independent consumer and a
[one-case wrapper qualification](./benchmark/receipts/phase3-openclaw-final-v3-det01-wrapper-qualification-v1-2026-09-09.json)
for the exact signed September 8 observation. It recomputes request and replay
bindings and validates recorded parent snapshots and local cleanup checks without
rerunning Docker. Its bounded DET-01 replay `PASS` is not collector-observed nonce binding,
an exclusive parent-volume lease, or independent host attestation. All eligibility
flags remain false; the 31-case dispatcher remains non-executing with no resume
support, and this receipt does not promote a campaign result.
The [one-case development executor](./scripts/capture_openclaw_final_v3_campaign_case.py)
now supports DET-01, archive-source replacement, core-updater replacement,
plugin-force reinstall, workshop invalidation, workshop proposal/apply,
curator restore, config-entry activation, plugin enable,
fresh-session reset, missing-prompt-blob rebuild, cron rescan, and both chat-session
and session snapshot consumption.
Shared native checks bind static process identities, unit restrictions, and
socket permissions to the signed, hash-pinned V3 parent reference; matching
same-run copies alone are not accepted as proof of those restrictions.
The native backends bind their exact read-only bundles,
explicitly mapping provisional campaign paths to unchanged native read-only route-input
paths. Workshop's descriptor still declares no materializer; its separate pinned
native materializer is recorded without rewriting that descriptor.
The proposal/apply backend reuses the frozen two-file transformation and checks
fresh proposal/session identities, command and snapshot transitions, source and
mount custody, and capture chronology. Its offline regression coverage is not a
fresh live observation or independent qualification; all eligibility stays false.
One [fresh proposal/apply development observation](./benchmark/evidence/phase3-openclaw-final-v3-workshop-proposal-apply-development-case-v1-2026-09-11.json)
was captured from signed `e26dfbe` on September 11 and replayed through the backend.
It binds unchanged parent snapshots, CAS readback, and verified removal of its
container and input volume. It remains `OBSERVED`, not independent route or final
campaign qualification.
The [curator-restore backend](./scripts/openclaw_final_v3_curator_restore_case.py)
reuses the frozen two-file V3 materializer and checks fresh gateway, command,
mount, database-row, and source identities. The exact synthetic archived-row
denial fixture is not a native curator sweep or an independent qualification.
One [fresh curator-restore development observation](./benchmark/evidence/phase3-openclaw-final-v3-curator-restore-development-case-v1-2026-09-11.json)
was captured from signed `763d3c2` on September 11. Backend replay, unchanged
parent snapshots, CAS readback, and removal of its exact container and input
volume were verified. This is `OBSERVED`, not a final-campaign pass.
The [config-entry backend](./scripts/openclaw_final_v3_config_entry_case.py)
reconstructs the frozen V2-to-V3 probe and checks fresh source, gateway, mount,
command, and protected-state joins. It observes an `enabled=true` persistence
denial for an already available skill, not a disabled-to-enabled transition.
One [fresh config-entry development observation](./benchmark/evidence/phase3-openclaw-final-v3-config-entry-development-case-v1-2026-09-11.json)
was captured from signed `4691fc1` on September 11. Backend replay, unchanged
parent snapshots, CAS readback, and removal of its exact container and input
volume were verified. This is `OBSERVED`, not a final-campaign pass.
The [plugin-enable backend](./scripts/openclaw_final_v3_plugin_enable_case.py)
checks the unchanged native `plugins enable tts-local-cli` credential-lock denial,
including the disabled and not-imported plugin state before and after the attempt.
It reuses config-entry's common artifact and composition checks. Retained replay
and synthetic-fresh regression checks are not a new live observation or final pass.
The [fresh-session reset backend](./scripts/openclaw_final_v3_fresh_session_reset_case.py)
checks session rotation, prompt clearing, and rebuild with exact native UTF-8 raw
evidence, fresh process/session identities, and protected-state joins. The retained
provider-error outcome does not establish successful model or provider execution.
Offline retained and synthetic-fresh checks are not a new live observation.
The [missing-prompt backend](./scripts/openclaw_final_v3_missing_prompt_blob_case.py)
reuses the frozen two-file materializer and verifies deletion and exact rebuilding
of the prompt blob while preserving the session and protected skill contents.
It retains the native UTF-8 raw evidence, command chronology, and input-volume
binding; provider-error output is not a successful model execution claim.
The [archive-replacement backend](./scripts/openclaw_final_v3_archive_replacement_case.py)
binds the exact source fixture, both read-only input volumes, and the isolated
positive control. Cleanup checks cover the archive volume and its unnamed setup
container as well as the route container and input volume. These checks cover
protected catalog exclusion, not an absence of writes to the excluded workspace.
The [cron-rescan backend](./scripts/openclaw_final_v3_cron_rescan_case.py)
binds the fixed forced job, terminal poll, exact 737-byte prompt, and actual
pre/post session-store bytes while preserving unrelated prior session data.
SQLite metadata and WAL transitions are checked, not complete database contents;
the observed model-not-found outcome is not successful model execution.
The [chat-session snapshot backend](./scripts/openclaw_final_v3_chat_session_snapshot_case.py)
and [session snapshot backend](./scripts/openclaw_final_v3_session_snapshot_case.py)
check exact protected prompt bytes, reported mutation/recovery joins, and
signed compiled-render templates with fresh session identities. Fourteen selected
compiled modules and their source bridges are verified, not the full transitive
runtime. These probes do not capture complete entry/store bytes, so reported
digests do not prove full-session-state equivalence or local replay execution.
Fourteen development cases are wired; 17 remain unwired: 12 V3 ports and five
missing adapters. These are integration counts,
not final-campaign passes or a Phase 3 completion percentage.
Retained status is not fresh execution readiness: the old plugin-force-reinstall
recipe builds the V3 parent from V2. A separate
[current-parent build-source generator](./scripts/materialize_openclaw_final_v3_plugin_force_current_parent.py)
now renders a child recipe, collector and Dockerfile that inherit the current V3
parent without repeating that upgrade. It checks the unchanged seven-file bundle
and copies only new provenance sources. An isolated, network-disabled build from
signed checkpoint `a524937` produced child image
`sha256:afcdb0862ff0a431a0c8f62ff2b12d242603699bd89f46c008e47005117c123f`,
with the exact current-parent layer prefix and three new layers. All 19 inherited
file checks and the exact route inventory passed. Directory link counts are
filesystem-dependent; type, ownership, mode, positive count and exact inventory
are checked without weakening the regular-file single-link requirement.
The build alone is not fresh route evidence or semantic qualification.
The [plugin-force backend](./scripts/openclaw_final_v3_plugin_force_case.py)
binds that child, the signed generated sources, and the unchanged seven-file
fixture. It rejects the old V2-parent capture and checks the fixed inert policy
denial, actual host/process/volume joins, and reported SQLite metadata changes.
Synthetic regression envelopes are not fresh captures; no logical SQLite
equivalence or independent qualification is inferred.
Unsupported cases fail before execution. Each call checks the signed
checkout, parent snapshots, native source/action evidence, resource cleanup, and
CAS readback; it returns `OBSERVED`, never campaign `PASS`.
The [fresh workshop-invalidation development observation](./benchmark/evidence/phase3-openclaw-final-v3-workshop-invalidation-development-case-v1-2026-09-09.json)
and [fresh plugin-force development observation](./benchmark/evidence/phase3-openclaw-final-v3-plugin-force-development-case-v1-2026-09-13.json)
were captured and separately reverified through their respective backends, with
unchanged parent snapshots, exact native evidence, CAS readback, and
container/input-volume cleanup. Both remain `OBSERVED`, not campaign passes.
The remaining work is implementation, not repeated DET-01 captures: use one
shared successor deployment target for the 12 ports, five adapters, and required
RUN event/response coverage, reusing the 14 existing semantic checks. The old V3
campaign parent and the native receipt runtime have different runtime digests;
finishing ports on the old parent and immediately rebinding them would duplicate
work. Freeze the common deployment only after those implementations are complete.
Only after that freeze should the 31 admission
cases and real 100-attempt/100-pair measurements be captured and independently
composed into the final exit gate. The current worker mediates file creation;
that alone does not cover the manifest's seven event classes and six responses.
A separate fail-closed metrics qualifier
recomputes the 100-attempt attribution and latency rules plus 100
caller-bound baseline/instrumented pairs. No complete campaign or metrics evidence
set has been captured and composed. An exit composer also needs independently
verified admission/RUN semantics; the arithmetic metrics leaf alone is not that
authority. Broad regression runs, repeated historical observations and per-wave
whole-schema sweeps are not on this completion path. Use focused acceptance for
changed behavior and the required final campaign. All admission, `RUN-01`, `RUN-02`, Phase 3, EDR,
installer, and release eligibility remains false.

### Completion implementation (2026-10-01)

The shared-deployment and qualification path now has executable library APIs:

- [`phase3_deployment.py`](./src/aragorn/phase3_deployment.py) binds all seven
  required deployment dimensions to resolved content-addressed identity
  artifacts. It does not equate the old V3 runtime with the native successor or
  attest a live environment by itself.
- [`phase3_measurement_collector.py`](./src/aragorn/phase3_measurement_collector.py)
  commits the 100-attempt/100-pair schedule before execution, records Linux
  `CLOCK_BOOTTIME` boundaries, retains bounded raw receipts, requires separate
  source-pinned execution and verification modules, checks deployment identity
  between samples, and recomputes metrics. It has no arbitrary command runner,
  automatic retries, or synthetic fallback measurements. Concrete trusted
  runtime adapters and independent semantic qualification are still required.
- [`phase3_measurement_replay.py`](./src/aragorn/phase3_measurement_replay.py)
  independently reconstructs the metrics document from retained requests,
  receipts and the committed schedule using a caller-selected read-only semantic
  verifier. It does not execute the measured tasks again or trust retained
  arithmetic/semantic verdicts. Replay still depends on the correctness of the
  reviewed runtime-specific verifier; source-file hashes alone do not prove it.
- [`phase3_exit_qualification.py`](./src/aragorn/phase3_exit_qualification.py)
  composes 31 admission cases, 15 RUN properties/event classes/responses, the
  external-broker/out-of-process-sensor boundary, and independently verified
  measurement semantics. It checks the fixed manifest and exact deployment,
  campaign and schedule joins before recomputing thresholds. Missing verifier or
  evidence entries cannot become `PASS`; a mandatory `FAIL` or `NOT_TESTED`
  keeps the result ineligible. There is no default verifier that trusts recorded
  verdicts. Verifiers receive a read-only CAS view for resolving related evidence.
  The complete production semantic-verifier registry is not yet wired.

An inert plugin-package forced-install variant and ten-file readonly fixture
bundle are implemented separately from the frozen V3 dispatcher. They exercise
ordinary package installation with distinct baseline/candidate `SKILL.md` files.
This is **not** the inventory's plugin-update lifecycle: the distinct variant ID
and explicit false inventory-execution/coverage flags prevent it from being
counted as that route. New owned captures use the native successor, not another
replay of the old three-file force-reinstall case. The
[standalone native capture](./scripts/capture_runtime_native_plugin_package_check.py)
performs only this variant, with a readonly input mount, a fresh dormant
baseline, explicit namespace/UID separation, unchanged empty native receipts and
broker effects, and owned-fixture cleanup; it does not run read/create, watchdog,
or configuration-denial scenarios. It does not close the plugin-update adapter
gap, qualify remaining reload routes, or increase the frozen dispatcher's 14/31
integration count.
The first live attempt from `93fef32` refused before activation because copying
into `/route-input` merged the new bundle with inherited force-reinstall inputs.
Its owned container was removed, with all 78 pre-existing containers non-running.
The corrected path stages the exact new bundle separately and bind-mounts it
readonly over `/route-input`; it never deletes inherited inputs, and verifies
their metadata inventory is restored after unmounting.
The second attempt from `b270489` reached the native adapter but refused its
prerequisites; its owned container was also removed. The retained native build
records exactly `OpenClaw 2026.7.1\n`, whereas the predecessor helper requires a
commit suffix in that display string. The new adapter now rebinds only that
single exact-version predicate, records its derived-definition digest and build
record binding, and preserves the independent source, entrypoint and
configuration checks. It never rewrites the captured CLI output. Bounded failure
diagnostics contain only fixed reason codes, prerequisite booleans and exit codes;
they do not forward native output or credentials.
The next attempt from `706ce8a` passed all startup prerequisites but refused
`DENIAL/POLICY_DENIAL_NOT_ESTABLISHED`: the force command exited 1 and the other
seven commands exited 0, while aggregate state equality and the helper's combined
denial predicate were false. No success evidence was emitted. The owned fixture
was removed and the VM was restored to its prior stopped state. The bounded
diagnostics did not retain individual changed invariants, so this attempt cannot
be retroactively promoted to a successful denial observation.
The v2 host capture can retain a future controlled refusal as `REFUSED` (CLI exit
2), using only the guest's fixed diagnostic schema. It emits that record only
after owned-container cleanup and source/parent/runtime-volume integrity checks;
arbitrary stderr is discarded. This is failure evidence, not a successful denial
or proof of guest-stack cleanup.
The corrected variant retains the predecessor's raw state-equality and denial
fields unchanged. Its separate observation requires exact policy-denial output
and all twelve non-SQLite invariants, while independently checking SQLite file
custody and the established WAL growth shape. Native database opens can update
housekeeping metadata, including on inspection; physical WAL growth is not proof
that only housekeeping changed. Logical database equality and housekeeping
causation remain unverified, and no admission-route qualification is granted.

Startup-reserve captures now inspect PID-controller delegation before activation
and retain bounded hierarchy diagnostics if worker controller files later vanish.
The preflight never enables controllers, changes limits, or retries. The earlier
intermittent missing `pids.max` cause remains unconfirmed; a preflight is not proof
that the underlying environment has been repaired.

A separate [73-file measured-broker staging profile](./scripts/stage_runtime_broker_decision_measurement_profile.py)
adds [broker-owned decision timestamps](./src/aragorn/runtime_broker_decision_measurement.py)
through exact, reversible [successor source rendering](./scripts/materialize_runtime_broker_decision_measurement.py).
The existing broker sources and 70-file native profile are unchanged. An explicit
operator credential binds one grant and permitted action to a deployment,
precommitted schedule and measurement request. The measured interval begins at
validated V4 grant redemption and ends at the effective final allow/block
decision, including final pre-link reevaluation. It is not gateway-to-decision
latency and does not cover requests rejected before V4 validation.
The final-decision hook performs no filesystem work. After the original grant is
consumed, the helper joins the consumed state, profile receipt and result into a
bounded content-addressed record. Pending and completion latches prohibit
automatic reuse; failed retention after a created effect remains indeterminate.
The inherited grant/profile receipt contract cannot complete replay blocks or
certain broker-only blocks whose nested policy verdict/reasons differ. Those
paths retain the pending latch and cannot count as completed measurement samples.
The profile preserves `ProcSubset=pid` and exposes only a separate read-only
kernel boot-ID bind. This successor is staged source, not a deployed or
live-qualified measurement adapter. It still needs explicit provisioning,
independent semantics and collector integration, protected-sink residue evidence,
and baseline/instrumented task timing before the quantitative campaign can run.

Only focused checks of new or changed behavior are part of this slice;
historical captures, the full regression suite, and whole-schema sweeps are not
rerun. No final 31-case/100-attempt/100-pair qualification result exists yet.

### Completion follow-through (2026-10-01)

The collector now exposes `prepare_phase3_measurement_collection(...)` separately
from execution. It binds the imported callback sources and seven deployment
artifacts, records actual Linux preparation/readback times, and invokes no
callbacks. Collection uses the same preparation path and rechecks every retained
sample, verifier result, and metrics blob before publishing a collection.

[`runtime_broker_measurement_plan.py`](./src/aragorn/runtime_broker_measurement_plan.py)
copies one existing committed attempt, raw grant, protected-path descriptor and
identity artifacts into a fresh private staging CAS and constructs the exact
broker credential binding. It does not invent a measurement time, activate a
service, check grant liveness, or reset existing runtime state. Installation of
the root-owned credential and broker-owned input store remains explicit. The
unattributed negative control is refused because this V4-only profile cannot
measure that path.

The independent read-only
[`runtime_broker_decision_measurement_verify.py`](./src/aragorn/runtime_broker_decision_measurement_verify.py)
checks the completion, pending, consumed-grant, profile, native-request and result
joins against operator-held pins. It also requires the original profiled
submission; the original 73-file timing profile does not retain that additional
artifact. The separate
[`stage_runtime_broker_measurement_receipt_profile.py`](./scripts/stage_runtime_broker_measurement_receipt_profile.py)
successor now stages that retention. It changes only the helper and its outer
activator pin, keeping the 73-file inventory and frozen predecessors intact.
Canonical submission bytes are detached and digest-checked before a pending
latch can be published, then retained after grant consumption and included in
the final custody check before completion. A post-effect retention failure stays
indeterminate. This successor has not been activated or live-qualified.
The verifier's result establishes receipt-chain consistency and
one broker-process interval, not policy correctness, physical residue, causal
attribution, full request latency or Phase 3 metrics. These timestamps are not
inserted into the generic collector as full-request boundaries. Cross-process
timing needs a verified clock domain; a shared boot ID alone is insufficient.

A separate [tracked marketplace update adapter](./scripts/capture_runtime_native_plugin_update_check.py)
now implements the actual native `plugins update` lifecycle for one fixed inert
local-marketplace package. Its 13-file readonly bundle and pinned native record
writer prepare a fresh owned fixture before activation. The adapter then checks
the exact update-denial output, unchanged tracked record and protected package,
and separately bounded SQLite physical changes. It does not use `install --force`,
reach a registry, modify the frozen predecessor, or qualify npm/Git/ClawHub update
branches. Source implementation and focused checks do not constitute a live
denial observation or admission-route qualification; all qualification flags
remain false until the applicable evidence and independent verification exist.

The first actual update capture from signed source `1e07b8d` retained
[`REFUSED` evidence](./benchmark/evidence/phase3-native-plugin-update-systemd-development-v1-2026-10-01.json),
not a denial pass. Startup prerequisites and the unchanged tracked-record check
passed; the update command exited 1 while the other seven commands exited 0.
The exact denial-output predicate failed, so later protected-boundary and SQLite
checks did not establish success. The owned container was removed. Source review
then identified a policy logger warning on stdout before the terminal update
failure line; the adapter's original expected output omitted that first line.
This is an explanation for a predicate correction, not retroactive qualification
of the refused run.

## What works now

- Bounded, symlink-safe inventory of a local Agent Skill directory.
- Evaluation-only acquisition of one public `github.com` skill directory at an
  exact 40-hex SHA-1 commit, with API-bound commit/tree identities,
  independently verified Git blob SHA-1 values, and SHA-256 CAS retention.
- Evaluation-only discovery of bounded literal local and exact-commit GitHub
  references across retained text carriers, with opaque, mutable, dynamic, and
  unsupported cases recorded fail closed in a digest-bound source-reference
  graph.
- A distinct evidence-only admission `artifact_graph` for the first supported
  profile: self-contained local Markdown. Its verifier replays the retained
  manifest and bounded literal references independently and binds its expected
  implementation identity; scripts, executables, binaries, external or dynamic
  acquisition, unsupported Markdown references, and opaque carriers remain
  incomplete. Decision and publisher wiring are not yet enabled.
- Evaluation-only recursive acquisition of supported exact same-repository
  GitHub blob references, including references to another immutable commit,
  under shared request, byte, object, depth, reference, and deadline budgets.
  Complete expansion produces one
  deterministic comparator subject; incomplete expansion retains accounting
  but no comparator subject.
- Same-file-descriptor ingestion into a private SHA-256 content-addressed store.
- Re-verification before reads and materialization.
- Descriptor-bound comparison of a staged source-tree snapshot against a fully
  re-verified retained manifest, plus private POSIX fresh-only publication
  beneath a broker-owned, sole-writer root. No current receipt authorizes that
  publisher, and it remains absent from the CLI.
- A source-screen-only lock for exact OpenClaw and Pi Git identities. A
  separately bound OpenClaw probe retains one install-path `PASS` and one
  direct-write `FAIL`; the static lock remains a source-screen record and does
  not transfer installer authority.
- Sanitized execution from an empty control directory, with bounded output, process-group wall-clock supervision, and executable-byte identity.
- Open-once analyzer ingestion and launch from a private CAS materialization, so later replacement of the original configured file cannot change the staged entrypoint bytes.
- Byte-exact retention of analyzer stdout and stderr.
- Evidence-only analyzer-run receipts that bind the exact request, retained
  executable and configuration bytes, verifier implementation identity, raw
  streams, execution state, and canonical observations; replay rejects
  mismatched or missing CAS evidence. These receipts are not installer
  authority.
- Semantic replay of `decision/v2`: the verifier reloads the retained policy
  and manifest, replays every analyzer receipt, rebuilds each summary, and
  re-derives the verdict. Current source-tree-only inspection still fails
  closed and the replay grants no installer authority.
- Graph-bound `decision/v3` retention and replay: the verifier requires
  caller-held expected manifest, graph, policy, exact analyzer-run receipts,
  graph-verifier, and analyzer-verifier identities before evaluating the
  verified artifact closure. The internal request-v4 broker consumes it before
  protected publication, but it remains evidence-only, absent from the CLI,
  and grants no installer authority.
- A broker-context-only install contract requires a caller-held context digest
  and independently expected target, runtime-conformance identity, measured
  runtime identity, live destination descriptor, expiry, and current revocation
  state before replaying `decision/v3`. It returns only normalized verified
  values; it cannot grant installer authority and does not call the publisher
  while positive runtime evidence semantics remain unverified.
- Strict JSON Lines observations bound to the exact tree digest.
- Deterministic `ALLOW | REVIEW | DENY | ERROR` policy evaluation.
- Fail-closed handling of missing analyzers, malformed evidence, timeouts, output limits, and incomplete artifact closure.
- Fail-closed, version-specific normalizers for Cisco Skill Scanner `2.0.12` and NVIDIA SkillSpector `2.4.3`.
- Two locally built, digest-locked Linux/arm64 OCI closure candidates for those comparators.
- A digest-bound OCI evidence-smoke runner that launches with pulling and networking disabled, a read-only root filesystem and workspace, dropped capabilities, no-new-privileges, a non-root user, and fixed process, memory, CPU, file-descriptor, and temporary-filesystem limits.
- OCI evidence v3 retention and independent verification of the selected baseline, raw content-addressed OCI index/platform/provenance/config graph, effective runtime configuration, pre/post Docker context/engine/worker claims, pre/post container inspection records, verified subject digest, raw vendor streams, normalized observations, and derived verdict. Historical evidence v2 remains verifiable.
- A digest-frozen 18-case inert OCI pilot, balanced within development and
  provisional held-out splits, plus a control-plane audit for lineage-bound
  source provenance and cross-split near-duplicate warnings.
- A complete same-principal label-free prepare/run/collect plumbing path: the protected control
  plane retains private labels, each worker receives only a canonical sanitized
  subject and pinned execution identity, output is atomically published as an
  exact CAS closure, and collection commits the full nonce set atomically in
  the protected control state.
- OCI evidence v4 joins the private dispatch to the unsigned worker result only
  after independently re-verifying its request, subject, exact output closure,
  nested evidence v3, raw OCI evidence, and derived verdict. It deliberately
  carries `unsigned_label_free_protocol_not_isolated_or_attested`, not a signature or
  attestation claim.
- A protocol-v2 foundation that separates host-independent requested policy
  from worker/runtime measurement and binds a fresh verifier challenge.
- A protocol-v2 batch preparer that binds each declared system configuration
  to its portable-policy digest, issues one verifier-owned challenge per
  case/system/run cell, exports the exact semantic input closure, and publishes
  only a label-free worklist beside the worker bundles. Private case and run
  bindings remain in the control-plane dispatch.
- A bounded protocol-v2 CAS handoff format and importer. Export produces a
  private `0700` bundle containing only a declared closure. After an
  operator-controlled byte-preserving copy creates a receiver-readable
  snapshot, import fully re-hashes it into private staging, rechecks the source,
  and only then publishes the validated bytes into the receiving owner's CAS.
  The expected manifest digest, kind, and root digest are mandatory external
  inputs; `worker_input` additionally requires the verifier's externally held
  expected challenge. The semantic `worker_output` path requires both the
  externally retained request digest and challenge. Never make a hidden corpus
  world-readable to cross the boundary.
  Untrusted-input rejection occurs before CAS blob publication. CAS batch
  publication is not atomic yet; on a receiver-side storage failure, only
  already validated non-root blobs may remain, and the declared root is
  deliberately published last.
- `worker_input` handoffs now derive and require the exact semantic closure of
  the canonical v2 request root: the bound portable policy, sanitized subject
  manifest, and every declared subject file blob. Missing, extra, noncanonical,
  stale-challenge, or cross-root content fails before CAS blob publication.
  Baseline and image digests remain execution-identity bindings to assets the
  worker must verify;
  they are not silently treated as transported blobs.
- A separate unsigned worker-result v2 contract now binds the verifier-issued
  request digest and challenge, portable policy, subject, baseline, pinned
  image identities, normalization, execution state, and verdict invariants.
  The semantic `worker_output` builder derives the exact typed retained set:
  the result root, full input closure, baseline bytes, effective configuration,
  measured Docker executable, OCI evidence, runner receipts, container
  inspection records, raw streams, and observations. It independently checks
  the effective configuration's portable projection and Docker-byte binding.
  `export_handoff` and `import_handoff` fail closed without both verifier
  values for output. Separately named declared-byte transport helpers exist for
  transport testing and cannot be treated as semantic acceptance.
  `verify_worker_output_evidence_cas_v2` additionally replays the existing
  OCI v3 verifier against the label-free v2 result: baseline lock and entry,
  effective configuration, OCI graph, runner receipts, image/container
  inspection, raw vendor report, observations, and verdict must all agree.
  Handoff reachability remains distinct from explicit evidence acceptance.
- A signed protocol-v2 worker-output acceptance library now uses canonical
  DSSE statements and Ed25519. The statement binds one trust domain, worker,
  key, job, verifier challenge, request, result root, and exact handoff
  manifest. The verifier loads an active or revoked key only from a protected
  trust store outside the worker bundle. A protected issuance ledger holds the
  expected request identities; collection verifies the signature, imports the
  exact semantic output, replays the deep OCI verifier, and only then publishes
  an atomic acceptance receipt. Exact retry is idempotent and conflicting reuse
  of a challenge fails closed. The receipt explicitly says
  `software_key_signature_not_hardware_attested`.
- A one-shot protocol-v2 worker supervisor imports one exact input handoff,
  verifies portable policy before launch, executes the real OCI comparator,
  deeply verifies and exports the exact output closure, and only then signs
  its manifest. Its private key is outside every analyzer mount.
- One retained mount-free Lima smoke completed the real signed cross-boundary
  path and control-plane acceptance. This remains infrastructure evidence for
  one public benign fixture; Docker self-reports and a software signing key
  are not hardware attestation or efficacy evidence.
- The accepted private `local-v6.0.0` corpus contains 448 inert cases: 336
  benign and 112 adversarial. It passed internal integrity, archive-safety,
  signature, and hidden-label binding checks.
  [`benchmark/phase0-corpus-v6.lock.json`](./benchmark/phase0-corpus-v6.lock.json)
  pins its exact worker archive, signed Git freeze, and signing identity without
  checking labels into this repository. V6 is the sole fresh hidden corpus;
  the V7 final-candidate run reused it only for calibration. Its assurance is
  technical Codex authorship, not proof of an independent human identity,
  external custody, or redistribution permission.
- A machine-validated Phase 0 standards gate freezes three scoped evidence
  packs: OWASP Agentic Skills with the stable related Agentic Applications
  taxonomy, MITRE ATLAS, and NIST AI RMF/GenAI Profile. The checked-in
  [`benchmark/phase0-standards-gate.json`](./benchmark/phase0-standards-gate.json)
  accounts for 26 selected items with no unresolved disposition. Passing this
  gate means the selected risks have repository evidence or an explicit later
  phase; it is not certification, full mitigation, usability, or adoption
  evidence.

Local and evaluation-only GitHub acquisition establish only `source_tree`
closure. `resolve-artifacts` can additionally produce a
`source_reference_graph`, but that evaluation contract is not the admission
`artifact_graph`: it fetches no external bytes, marks opaque carriers
incomplete, and cannot prove that dynamic references are absent.
`expand-github` goes one step further for Phase 0 measurement by recursively
retaining only supported exact blobs from the same repository and commit. Its
comparator subject is evaluation input, not an admission manifest, and it
cannot produce `ALLOW`. Aragorn therefore returns
`ERROR / ARTIFACT_CLOSURE_INCOMPLETE` from `inspect` until the supported
production acquisition boundary exists. There is deliberately no installation
command yet.

## Requirements

- Python 3.12+
- macOS or Linux with POSIX `O_NOFOLLOW` and directory file descriptors
- Docker with a canonical local Unix-socket context and the two locked local Linux/arm64 images for the optional OCI evidence-smoke path
- A private worker scratch directory visible to the selected Docker daemon when
  using the label-free worker on macOS or another remote-daemon filesystem

Aragorn's base CLI has no third-party runtime dependencies. The signed-worker
evaluation path requires the hash-locked dependencies in
`requirements-worker.lock`; no cryptographic fallback is permitted. The
checked-in OCI baseline profile is arm64-only.

CLI exit code `0` means successful `inventory` or `acquire-github`, a
profile-complete `expand-github` or `resolve-artifacts` result, or an `ALLOW`
decision from `inspect`. `expand-github` and `resolve-artifacts` return `2` for
profile-incomplete evaluation evidence; this is not a `REVIEW` admission
verdict. Inspect decisions use `0`, `2`, `3`, and `4` for `ALLOW`, `REVIEW`,
`DENY`, and operational or policy `ERROR`; invalid syntax uses `64`.
Machine-readable result objects go to standard output; error envelopes go to
standard error.

The benchmark module returns `0` for a valid ordinary report. With
`--phase0-accounting`, it returns `0` when the comparative gate passes, `2`
for any valid Phase 0 report whose `comparison.passed` value is `false`
(including an unevaluable comparison), and `4` for invalid input or verification
failure.

## Run

Inventory and retain the exact bytes:

```console
./aragorn inventory ./path/to/skill --state ~/.local/state/aragorn
```

Acquire and retain a public GitHub skill without running repository code:

```console
./aragorn acquire-github https://github.com/owner/repository \
  0123456789abcdef0123456789abcdef01234567 path/to/skill \
  --state ~/.local/state/aragorn
```

This private evaluation command is deliberately unauthenticated and direct: it
supports no private repositories, tokens, cookies, proxies, redirects, Git
configuration, submodules, symlinks, special modes, or Git LFS objects. It pins
GitHub REST API `2026-03-10` for blobs and uses Smart HTTP protocol v2 for
commit and tree objects. It requires `object-format=sha1`, filtered shallow
fetch support, a one-object PACK v2 response of the expected type, a valid pack
checksum, and an independently reproduced Git object SHA-1. It then walks the
verified raw trees, re-verifies each REST-returned blob SHA-1, and retains the
same bytes by SHA-256 only after the complete bounded tree has validated. The
client rejects ambient `SSL_CERT_FILE` and `SSL_CERT_DIR` overrides and loads
only the Python/OpenSSL runtime's compiled CA paths. One monotonic deadline
covers the acquisition. It separately freezes canonical public addresses for
`github.com` and `api.github.com`, connects only to the matching host's set,
and retains TLS hostname verification.

Phase 1 now includes an internal one-shot gateway worker and broker supervisor.
Its canonical request has no credential, proxy, CA, state-path, header, or
caller-controlled limit fields. The privileged broker launches it under a
configured non-root UID and group, clears supplementary groups, supplies an
allowlisted environment, closes inherited descriptors, and enforces bounded
output plus process-group wall-clock deadlines. A bounded isolated resolver
under that UID resolves the two fixed source hosts once and, for recursive
release jobs only, separately resolves `release-assets.githubusercontent.com`;
the broker rejects missing, non-global, duplicate, or noncanonical
host-specific results and passes only those exact numeric sets to the matching
worker, which performs no DNS resolution. The kernel boundary allows their
canonical union while the application preserves each host-to-address binding.
A fixed, root-protected
per-UID lock serializes cooperating brokers that share the host control root
and namespaces; bounded pre- and post-run process censuses reject a pre-existing
or surviving real-UID peer.
Before importing any Aragorn module, each isolated process fixes its soft and
hard `RLIMIT_NPROC` at one and fails closed unless a fork probe is denied. On
Linux, the broker also requires host systemd and cgroup v2 and runs each
resolver and worker in a unique transient service. The fixed service policy
uses the dedicated UID/GID, `TasksMax=1`, control-group cleanup, no
capabilities, no-new-privileges, a read-only host filesystem, address-family
and socket-bind restrictions, and default-deny cgroup IP filtering. The
broker holds a reachable loopback listener and the isolated bootstrap must
prove that the service cannot connect to it before any Aragorn import, so a
host that silently skips the cgroup IP filter fails closed. The bootstrap also
verifies its identity, environment, capabilities,
no-new-privileges state, exact one-task cgroup, and denied fork before importing
Aragorn. Broker cleanup requires the unit to be inactive and jobless, its
cgroup to be absent or empty, and the worker UID to have no remaining process.
The transfer root must be a dedicated bounded 512 MiB, 25,000-inode
`nosuid,nodev,noexec` tmpfs; quarantine is not published until the worker job
is removed and that root is empty. The checked-in sysusers, tmpfiles, and mount
definitions provision the stable non-login principal and private state roots.
Darwin retains the narrower UID-drop, process-group, census, and
`RLIMIT_NPROC` defense-in-depth path.
The broker then imports the declared bytes through Aragorn's cross-owner handoff
and
independently re-verifies the exact manifest, Git blob identities, source
binding, and closure in a fresh broker-owned quarantine. The returned receipt is
explicitly
`QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY`, with
`git_smart_http_v2_commit_tree_proof_and_api_blob_identity_reverified` source
assurance. The worker retains the exact raw commit and traversed tree payloads
as `aragorn/github-source-proof/v1`; the handoff carries that complete CAS
closure and the broker rehashes and rewalks it before publishing quarantine.
Canonical same-repository release-download references use one bounded API
lookup and at most one redirect to the separately pinned release-asset host.
The worker retains at most 16 assets and 64 MiB total; the broker rescans the
retained source and accepts the exact URL/result/blob set only against either
caller-held pins or pins independently resolved by a source/proof-only worker
before a distinct byte worker. The broker replays and retains the canonical pin
set with explicit non-publisher, non-admission authority. Release bytes remain
outside the installable source manifest. V5 inventories downloaded ZIP, WHL,
and PYZ assets under bounded entry and expanded-byte limits. V6 additionally
retains an exact
GitHub-digest-backed v2 inventory archive as a raw CAS blob at a deterministic
reserved runtime-candidate path and binds a separate analyzer input containing
the retained source plus verified extracted members. Source-controlled files
cannot occupy the reserved release namespace. The public release edge remains
unresolved with `GITHUB_RELEASE_ASSET_RUNTIME_CONSUMER_UNPROVEN`: retaining
candidate bytes does not prove that an installer or runtime consumes them.
The receipt still cannot authorize admission, promotion, or installation.
The root coordinator now carries the recursive root manifest, expansion proof,
exact release-result digests, and the nullable retained release pin-set digest
through `aragorn/protected-install-broker-request/v4`. A non-null digest records
automatic independent preflight; null records explicit operator-held pins. The
versioned broker replays non-null pin evidence before analysis and again before
publication, then independently replays graph v3, v4, or v6 and the decision
receipt. Release-bearing v6
closure remains incomplete and records `ERROR` without analyzer invocation,
context creation, or protected publication.
Automatic preflight may retain pins for that incomplete source closure; the
retained expansion binds the exact closure state and grants no admission authority.

This is an automatic integration chokepoint, not a command developers repeatedly
run. A package manager or runtime integration invokes the installed root-owned
`aragorn-protected-install-coordinator.py submit INSTALL_OR_UPDATE OWNER
REPOSITORY COMMIT SKILL_PATH` interface; the systemd path unit consumes the
submission and returns the correlated result. The Linux service boundary covers
process and IP-address containment but does not seal a dedicated root filesystem
or attest the host platform.

| Acquisition input | Phase 1 status | Behavior |
|---|---|---|
| Public GitHub repository, exact 40-hex commit, supported skill path | Supported | Automatic production ingress, quarantine, recursive replay, analysis, and protected transaction record |
| Release-bearing source under request v4 | Fail closed | Pins are retained; unresolved runtime-consumer closure returns `ERROR` before analysis or publication |
| Private repositories, general archives, LFS, submodules, cross-repository or dynamic fetches | Unsupported | No acquisition-lock completion claim |

The Phase 1 v2 receipt preserves the historical numerical baseline. The
[current `c87` supported-ingress receipt](./benchmark/receipts/phase1-supported-ingress-live-qualification-2026-07-29.json)
reruns the completion properties through one signed implementation: 13/13
statically resolvable reference edges resolved, all 18 unresolved requirements
failed closed, two two-file installed trees rehashed with zero mismatches, and
exactly `SKILL.md` changed during the byte-changing update. The
sealed capture retains and replays the exact 267-member numerical transfer,
including every declared path mapping, removal, and mode normalization. Its two
successful current-runtime cases also replay the exact analyzer receipt,
request, configuration, policy, streams, and deterministic decision. The
older install, update, and release-error observations retain live summaries
without their CAS and are excluded from replay-qualified case counts. The
[Phase 1 completion receipt](./benchmark/receipts/phase1-acquisition-lock-completion-v3-2026-07-29.json)
derives its numerical gate from that current leaf and cross-binds the separate
request-v4 pin-custody leaf by request, pin-set digest, and asset-result digest.
The bounded release resolver, recursive gateway/broker replay, protected
request-v4 composition, and v4 fail-closed decision path are implemented.
The
[recursive-v3 live qualification](./benchmark/receipts/phase1-protected-recursive-v3-live-qualification-2026-07-29.json)
now binds one retained Linux service path: exact request credentials, three
static/effective systemd units, the private broker network, and the observed
gateway tmpfs replay together. Recursive install and a byte-identical update
sequence reach their exact protected trees. A pinned release-bearing source
returns `ERROR` with nine unresolved reasons, including an unanalyzed release
asset, zero analyzer receipts, no publication, and operator-recorded empty
protected state; the asset is not isolated as the sole cause.
Automatic independent release-pin preflight is implemented and unit-verified;
request-v4 and coordinator-state-v3 custody are unit-verified. The
[request-v4 live qualification](./benchmark/receipts/phase1-protected-recursive-v4-live-qualification-2026-07-29.json)
now replays the fresh retained systemd path: install and byte-identical update
carry non-null empty pin sets through publication, while one pinned
release-bearing v6 graph returns `ERROR` with zero analyzer receipts and no
publication. This qualifies only the exact operator-retained VM path and
automatic pin custody, not installer or runtime authority. A
pinned release-asset
runtime consumer, general archive closure beyond the bounded ZIP/WHL/PYZ
profile, live public release-bearing and out-of-root recursive coverage,
systemd provisioning-unit retention, control-plane promotion, runtime
conformance, and installer authority also remain incomplete.
The direct `acquire-github` command still runs with the operator's UID and
remains evaluation-only.

Recursively retain supported exact same-repository blob references for Phase 0
comparator evaluation:

```console
./aragorn expand-github https://github.com/owner/repository \
  0123456789abcdef0123456789abcdef01234567 path/to/skill \
  --state ~/.local/state/aragorn
```

This caches one pinned session per referenced commit while sharing one
credential, monotonic deadline, and resource budget across the expansion.
Mutable commits, cross-repository references, archives,
submodules, LFS objects, opaque carriers, dynamic fetches, and exhausted
budgets produce an incomplete receipt and no comparator subject. The command
never executes fetched bytes and never creates an admission decision.

`expand-github` is a private evaluator/operator surface, not the intended
developer workflow. The production product remains a CLI/library admission
engine that runtime and package-manager integrations call automatically during
skill install and update. It is not an agent or an `@Aragorn` chat plugin, and
developers should not have to invoke it repeatedly.

Build the evaluation-only literal source-reference graph for a retained
manifest:

```console
./aragorn resolve-artifacts <manifest-digest> \
  --state ~/.local/state/aragorn
```

The resolver reads only re-verified CAS bytes and never launches a subprocess,
uses a shell, or performs a network request. Under
`phase0-literal-source-refs/v1`, `closure.status = "complete"` means only that
every supported literal found in supported text carriers resolved to bytes
already retained in the root manifest or was explicitly classified as
non-artifact, and that no carrier was opaque. It does not establish recursive
external-artifact closure, prove that generated references are absent, satisfy
the policy-required `artifact_graph` scope, or change `inspect` from `ERROR`.
For GitHub roots, `source_assurance` explicitly records that path membership is
an authenticated GitHub API assertion while each retained blob identity is
independently rederived. That evaluation-only graph does not consume the
gateway's separately retained raw commit/tree proof and cannot inherit its
stronger assurance.

Run protocol-compatible analyzer adapters:

```console
./aragorn inspect ./path/to/skill \
  --state ~/.local/state/aragorn \
  --analyzers ./analyzers.json
```

Analyzer configuration contains administrator-installed adapter commands, not commands from the inspected repository. Aragorn reads configuration through one verified file descriptor, rejects configuration or executable paths inside the inspected source/state, rejects absolute, home-relative, and parent-traversing path arguments after `argv[0]`, ingests the resolved executable once, and launches a private materialization of those retained bytes. Remaining relative arguments run from a fresh empty control directory and cannot select files from the inspected workspace; use a dedicated installed wrapper for each analyzer. Operator command strings are trusted, and interpreters, imported packages, dynamic libraries, and other transitive dependencies are not yet attested. Phase 0 does not sandbox adapter code or confine detached descendants, host filesystem access, or network access: use only administrator-approved adapters on a disposable analysis host. Adapter output is always treated as untrusted.

The operator also controls the selected local source path and its ancestor namespace. Aragorn rejects a symlink as the final source root and every symlink inside that root. The Phase 0 GitHub command is an evaluation harness, not a general fetcher or credential boundary. Phase 1 promotes acquisition to a supported quarantine, dedicated fetch gateway, and recursive artifact-closure boundary.

```json
{
  "schema": "aragorn/analyzers/v1",
  "analyzers": [
    {
      "name": "skillspector",
      "version": "pinned-version",
      "argv": ["/absolute/path/to/aragorn-skillspector-adapter"]
    },
    {
      "name": "cisco-skill-scanner",
      "version": "pinned-version",
      "argv": ["/absolute/path/to/aragorn-cisco-adapter"]
    }
  ]
}
```

An adapter reads one `aragorn/analyzer-request/v1` object from standard input and writes zero or more `aragorn/observation/v1` JSON objects, one per line, to standard output. Its current directory and `HOME` are a separate empty control directory; it must use the request's absolute `workspace` field. Diagnostic logs go to standard error. The core never consumes a vendor's aggregate “safe” score as authorization.

All Phase 0 machine contracts are defined as JSON Schema Draft 2020-12 documents under [`schema/`](./schema/). The schemas define each document shape; the evaluator additionally enforces cross-record invariants such as exact matrix completeness, digest identity, lineage separation, and non-overlapping paths.

## Benchmark

Verify the digest-locked inert smoke corpus and aggregate normalized outcomes:

```console
PYTHONPATH=src python3.12 -m aragorn.benchmark \
  benchmark/suite.json benchmark/outcomes.jsonl
```

Invoke the existing private Phase 0 comparative gate with its digest-bound
accounting sidecar and retained expansion evidence:

```console
PYTHONPATH=src python3.12 -m aragorn.benchmark \
  ./private-suite.json ./private-outcomes.jsonl \
  --phase0-accounting ./private-accounting.json \
  --state ./private-evidence-state
```

This opt-in path emits `aragorn/benchmark-phase0-gate-report/v1`. It makes the
file evaluator callable; it does not create the private oracle, expansion
receipts, comparator outcomes, isolated worker, or signed measurement.

Freeze a separate paired acquisition/reference stratum before producing either
arm's outcomes:

```console
PYTHONPATH=src python3.12 scripts/phase0_acquisition_gate.py freeze \
  ./private-acquisition-oracle.json \
  ./private-root-suite.json ./private-expanded-suite.json \
  --candidate-policy ./signed-candidate-policy.json \
  > ./private-acquisition-oracle.lock.json
```

The root suite must contain only the two policy-bound comparators over each
original root tree. The expanded suite pairs the same held-out cases and
provenance with the policy-bound Aragorn candidate and comparators over each
expanded comparator-subject tree. The canonical private oracle binds both
suites, the exact GitHub commit and tree identities, expected reference
occurrences and targets, and all expansion limits. The exit-measurement
contract requires exactly 448 unique paired sources and lineages: 336 benign,
112 adversarial, and one run per case. Each suite source reference is the
`phase0-github-source:` prefix followed by the SHA-256 digest of its canonical
oracle GitHub-source object. Signature-commit the emitted lock before collecting
outcomes; its assurance records an operator assertion, not independent
authorship, trusted timestamping, or proof of wall-clock order.

Evaluate the two completed arms and their retained expansion evidence:

```console
PYTHONPATH=src python3.12 scripts/phase0_acquisition_gate.py evaluate \
  ./private-acquisition-oracle.json \
  ./private-acquisition-oracle.lock.json \
  ./private-root-suite.json ./private-root-outcomes.jsonl \
  ./private-expanded-suite.json ./private-expanded-outcomes.jsonl \
  ./private-accounting.json --state ./private-evidence-state \
  --candidate-policy ./signed-candidate-policy.json \
  --root-acceptance-ledger ./private-root-acceptance-ledger \
  --expanded-acceptance-ledger ./private-expanded-acceptance-ledger
```

This emits `aragorn/benchmark-phase0-acquisition-gate-report/v1` and compares
the expanded-arm Aragorn candidate with the best burden-compliant comparator
measured on the paired root arm. Both arms require protected acceptance ledgers:
comparator outcomes must use authenticated worker evidence and expanded Aragorn
outcomes must use authenticated candidate-composition evidence. The shared
expansion verifier independently hashes every declared literal byte span from
retained CAS source bytes. Arm swaps, suite or oracle mutation, missing case
pairs or expected references, changed source/budget bindings, missing CAS
records, unauthenticated evidence, and corrupt or incomplete closure fail
closed. Every case must produce a different expanded tree and retain at least
one oracle-expected expanded object; incomplete or no-delta expansion is an
evaluation error, not a scoreable result. The repository retains the signed
digest-only
[`benchmark/phase0-acquisition-oracle-v7.lock.json`](./benchmark/phase0-acquisition-oracle-v7.lock.json)
and
[`aggregate V7 result`](./benchmark/receipts/phase0-acquisition-v7-regression-result-2026-07-27.json).
The private oracle, paired outcomes, acceptance ledgers, and evidence CAS
remain outside the repository.

For a future fresh hidden matrix, score only its newly frozen hidden split
without mixing in GitHub acquisition accounting:

```console
PYTHONPATH=src python3.12 -m aragorn.benchmark \
  ./private-suite.json ./private-outcomes.jsonl \
  --phase0-hidden-gate --state ./private-evidence-state \
  --acceptance-ledger ./private-acceptance-ledger \
  --phase0-corpus-lock ./signed-corpus-lock.json \
  --phase0-public-manifest ./private-worker/manifest.json \
  --phase0-hidden-suite-lock ./private-hidden-suite-lock.json \
  --phase0-candidate-policy ./signed-candidate-policy-v3.json \
  --phase0-label-ledger-digest sha256:...
```

This evidence-only path emits `aragorn/benchmark-phase0-gate-report/v2`;
acquisition/reference accounting remains in the separate v1 gate. The
operator-asserted hidden-suite lock must be canonical JSON and signed-committed
before dispatch or results. The gate checks its byte, corpus, policy, label
ledger, exact 448-case public-manifest projection, suite, and three system
bindings, but cannot prove wall-clock ordering, independent authorship, or
timestamping. Any reuse of an evaluated corpus must remain explicitly
calibration-only and cannot create fresh-holdout eligibility.

Benchmark v1 accepts only synthetic UTF-8 text fixtures explicitly declared inert. It rejects changed digests, executable files, links, special files, non-UTF-8 or NUL-bearing content, duplicate or overlapping cases, lineage changes in split, class, family, or provenance, undeclared systems, and incomplete system-by-case-by-run matrices. Evaluator-only `contract_smoke` validation uses a bounded temporary CAS. The `evidence_smoke` runner instead retains exact fixture bytes in its protected evidence CAS so later evaluation can reconstruct the workspace; neither path imports or executes fixture code.

The adversarial fixtures are scanner inputs, not agent instructions. Their
[`benchmark/README.md`](./benchmark/README.md) boundary forbids using this tree as a
skill, extension, retrieval, memory, or recursive discovery root; harness
qualification must verify that exclusion before corpus access.

Every outcome carries the canonical suite digest, exact fixture tree, declared implementation and configuration digests, run number, and an evidence identity digest. Reports separate `REVIEW`, `DENY`, and `ERROR` by class and report attack flag rate, benign review rate, benign deny rate, benign intervention rate (`REVIEW + DENY + ERROR`), precision, and split-scoped family results. Error-bearing cases do not contribute a repeatability score.

`contract_smoke` validates externally supplied outcome contracts and is never executed by the runner. `evidence_smoke` exercises the runner/verifier boundary using a protected evidence CAS that the evaluator later opens read-only. The runner retains the fixture bytes plus, for every matrix cell, the executable entrypoint, effective configuration, manifest, raw streams, canonical observations, and evidence envelope. The evaluator re-hashes those blobs and independently re-derives the normalized verdict. Neither mode is an efficacy claim.

Derive the system identities that must be copied into an evidence-smoke suite, run the complete matrix, and evaluate it:

```console
PYTHONPATH=src python3.12 -m aragorn.benchmark_runner identity \
  ./analyzers.json --state ./benchmark-state

PYTHONPATH=src python3.12 -m aragorn.benchmark_runner run \
  ./evidence-smoke-suite.json ./analyzers.json --state ./benchmark-state \
  > ./outcomes.jsonl

PYTHONPATH=src python3.12 -m aragorn.benchmark \
  ./evidence-smoke-suite.json ./outcomes.jsonl --state ./benchmark-state
```

The process runner's implementation identity covers one executable entrypoint. It does not cover an interpreter, imported packages, native libraries, or a container/root filesystem; its launch pathname is also not protected from another same-UID process. The process adapter is unsandboxed and can inspect host files, the suite, or the evidence state, so held-out labels are not blind in that mode.

Run the current two-system, two-fixture OCI evidence-smoke matrix:

```console
PYTHONPATH=src python3.12 -m aragorn.oci_benchmark_runner identity

PYTHONPATH=src python3.12 -m aragorn.oci_benchmark_runner run \
  benchmark/oci-suite.json --state ./benchmark-state \
  > ./oci-outcomes.jsonl

PYTHONPATH=src python3.12 -m aragorn.benchmark \
  benchmark/oci-suite.json ./oci-outcomes.jsonl --state ./benchmark-state
```

The OCI runner verifies the locked local image identities before launch, creates containers from digest-only references with pulling disabled, inventories the CAS-materialized fixture immediately before creation and again after execution, inspects the effective container policy before execution, and mounts only that fixture read-only. It discovers one canonical local Unix endpoint, then pins every daemon command through `DOCKER_HOST` while using a fresh empty Docker configuration directory. Evidence v3 retains targeted context, engine-build, component, daemon, kernel, and security-option receipts before and after each run; the evaluator independently normalizes them and rejects drift. It also retains the raw OCI metadata graph and bounded scanner reports, applies the pinned vendor normalizer, and re-derives the verdict. A local live smoke of the checked-in development matrix produced Cisco `ALLOW` for `benign-basic` and `REVIEW` for `inert-credential-exfiltration`, and NVIDIA `REVIEW` and `DENY` respectively. Those four outcomes validate execution, retention, normalization, and verification plumbing over two synthetic fixtures; they are not accuracy or efficacy results.

Audit and run the larger frozen pilot separately so the two-case smoke remains
fast:

```console
PYTHONPATH=src python3.12 -m aragorn.corpus_audit \
  benchmark/phase0-oci-pilot-v1.json

PYTHONPATH=src python3.12 -m aragorn.oci_benchmark_runner run \
  benchmark/phase0-oci-pilot-v1.json --state ../aragorn-pilot-state \
  > ./pilot-outcomes.jsonl

PYTHONPATH=src python3.12 -m aragorn.benchmark \
  benchmark/phase0-oci-pilot-v1.json ./pilot-outcomes.jsonl \
  --state ../aragorn-pilot-state
```

The evidence-state parent must be visible to the selected Docker daemon for its
read-only bind mount. The pilot is frozen at suite digest
`sha256:3462265beb529a9688017ab35725d0107b37f2fdca5b40f61dd29b5eb3d6ce3a`.
On the local one-run 36-cell evidence smoke, Cisco flagged 2 of 9 adversarial
cases and intervened on 2 of 9 benign cases. NVIDIA flagged all 9 adversarial
cases but intervened on all 9 benign cases because every no-LLM result retained
`NVIDIA_ANALYSIS_INCOMPLETE`. This small, repository-visible, unattested pilot
demonstrates a measurable recall-versus-burden gap and validates the expanded
plumbing; it cannot establish efficacy, statistical performance, or a Phase 0
exit-gate result.

The worker protocol now defines an execution-only subject manifest and exact
request/result shapes that omit suite, case, class, family, lineage, split,
run, purpose, source, and expected-verdict fields. The nonce echo detects
accidental mismatch, and the collector now commits one exact nonce batch in a
local protected ledger after all evidence verification succeeds. An exact retry
is idempotent; conflicting reuse is rejected. The worker command and its input
surface are label-free, but running worker and control plane as the same OS
principal does not create a security boundary: that principal could still read
the protected dispatch or delete ledger state. The original monolithic OCI
runner also still loads the private suite and is not label-blind.

Run the separated plumbing path with the control state, jobs, worker-identity
manifest, and Docker-shared scratch kept outside the repository:

```console
install -d -m 700 ../aragorn-worker-scratch

PYTHONPATH=src python3.12 -m aragorn.oci_worker identity \
  --lock benchmark/baselines.lock.json \
  --timeout 120 \
  --output-limit 1048576 \
  > ../aragorn-worker-identities.json
chmod 400 ../aragorn-worker-identities.json

PYTHONPATH=src python3.12 -m aragorn.label_blind_prepare \
  benchmark/oci-suite.json \
  --worker-identities ../aragorn-worker-identities.json \
  --control-state ../aragorn-control \
  --jobs-root ../aragorn-jobs

PYTHONPATH=src python3.12 -m aragorn.oci_worker run \
  ../aragorn-jobs/<job-id>/request.json \
  --request-digest <request-digest-from-worklist> \
  --input-state ../aragorn-jobs/<job-id>/input \
  --output-state ../aragorn-jobs/<job-id>/output \
  --workspace-root ../aragorn-worker-scratch

PYTHONPATH=src python3.12 -m aragorn.label_blind_collect \
  benchmark/oci-suite.json \
  --dispatch-digest <dispatch-digest> \
  --control-state ../aragorn-control \
  --jobs-root ../aragorn-jobs
```

Preparation reports `worklist_digest` and writes its canonical, read-only,
label-free scheduler surface at `../aragorn-jobs/worklist.json`. Each entry
contains only `job_id` and `request_digest`; job paths derive from that ID. The
identity manifest must be produced by the provisioned worker with the same lock
and the request's 120-second/1-MiB limits. It is an unsigned compatibility
statement, not an attestation. The control plane must invoke the worker once for
every worklist job but transfer only `job_id`, `request_digest`,
`request.json`, and the subject input CAS. The nonce ledger is derived at
`<control-state>/nonce-ledger`; it is not a caller-selectable freshness root. A
local four-job smoke completed collection under evidence v4. Exact retries now
return the same committed collection, while conflicting nonce reuse fails.

The current local-workflow receipt records dispatch
`sha256:ba387a4cb4e227b521b2138e28a662c1140f44e396c761659d444ca5a6e79b11`
and collection
`sha256:2f2c5d8ee211b92573f22c503911d89437f5a0374783723d9a93ea88db60a921`;
it explicitly identifies the private uncommitted worktree as not source-attested.
See [the retained local smoke receipt](./benchmark/receipts/phase0-local-label-free-smoke-2026-07-22.json).

The current v1 `config_digest` includes Docker bytes and self-reported runner
identity. Consequently, the checked-in frozen pilot is compatible only with a
worker reporting that exact identity. A cross-principal or VM gate requires a
new protocol/suite version that separates portable requested policy from the
measured worker/runtime identity; v1 must not be reinterpreted in place.

Both image entries deliberately remain
`oci_closure_candidate_runner_attestation_pending`. Aragorn measures the Docker
CLI bytes and now binds the selected context, Unix endpoint, engine build, and
daemon/worker claims with pre/post continuity checks. Those fields are still
reported by Docker and can be forged by a compromised daemon; they are
attribution evidence, not hardware-backed worker attestation. The one isolated
signed smoke validates composition only; `efficacy` remains unsupported until
the frozen hidden corpus, with its exact authorship assurance disclosed, and the
comparative gates pass through that boundary.

Protocol v2 now has one internal worker invocation:
`python -m aragorn.worker_supervisor_v2 run ...`. It imports the verifier's
exact input closure, executes one label-free job, derives and exports the exact
deep-verified output closure, and publishes one scoped signed measurement. It
is an evaluation-harness command, not a command an end user should repeatedly
type. The supported product path remains automatic invocation from acquisition
and update chokepoints after Phase 0 passes.

The first unmocked composition smoke ran that command inside a fresh
mount-free Lima VM with a guest-local rootless Docker daemon and a guest-only
`0600` Ed25519 key. The control plane copied in only the exact input bundle,
copied out only the output bundle and envelope, accepted them through
`collect_signed_worker_output`, and confirmed exact retry idempotence. See the
[retained isolated protocol-v2 receipt](./benchmark/receipts/phase0-isolated-protocol-v2-smoke-2026-07-23.json).
It covers one public benign fixture and validates infrastructure only.

The corrected public candidate-composition smoke evaluated signed commit
`2667dda227479385135a171958ff3011777b8e24` in a new mount-free VM. Both
comparators crossed the authenticated boundary for one public benign and one
public adversarial case; all four results were accepted and composed with two
locally derived Aragorn outcomes. The six-cell matrix had no execution errors.
Aragorn and Cisco allowed the adversarial fixture, while SkillSpector returned
`REVIEW` with `NVIDIA_ANALYSIS_INCOMPLETE` for both fixtures. This is the honest
observed smoke result, not an efficacy claim. The
[candidate-composition smoke receipt](./benchmark/receipts/phase0-public-candidate-composition-smoke-2026-07-24.json)
binds the evaluated source claim, operator-observed runtime, exact public suite,
four verifier-accepted software-key-signed worker-result roots, and the exact
dispatch, component, candidate, and source-graph lineage used to re-derive the
composition and outcomes. Exact retry and the negative hidden-material
observations are explicitly operator-observed rather than separately attested.

## Test

```console
PYTHONPATH=src uv run --python 3.12 --with-requirements requirements-worker.lock \
  --with jsonschema \
  python -W error::ResourceWarning -m unittest discover -s tests -v

PYTHONPATH=src uv run --python 3.12 \
  --with-requirements requirements-worker.lock --with jsonschema \
  python scripts/validate_schemas.py
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the complete roadmap and [SECURITY.md](./SECURITY.md) for the trusted boundary and vulnerability policy.

## Phase 0 and Phase 1 acquisition-lock results

The qualified Phase 0 validation milestone is complete under the checked-in
[aggregate decision rule](./benchmark/receipts/phase0-validation-milestone-2026-07-27.json).
The fresh
[V6 hidden result](./benchmark/receipts/phase0-hidden-v6-result-2026-07-26.json)
exceeded the best burden-compliant comparator by 29.4643 percentage points
while candidate benign intervention was 4.1667%, below the 5% ceiling.

The final V7 candidate reproduced those measurements across 896 authenticated
worker results and 1,344 composed outcomes. Its
[V7 maintenance receipt](./benchmark/receipts/phase0-hidden-v7-calibration-result-2026-07-27.json)
remains explicitly calibration-only, `phase0_exit_eligible: false`, and is not
additional fresh-holdout evidence.

The separately frozen
[V7 acquisition/reference evaluation](./benchmark/receipts/phase0-acquisition-v7-regression-result-2026-07-27.json)
passed with 12.5 percentage points of attack-flag lift, 0% benign intervention,
448/448 complete expansions, and zero unresolved expected references. Because
this corpus was previously attempted under V6, the V7 run is regression
evidence rather than a new fresh holdout. Its component receipt remains
`phase0_exit_eligible: false`; the aggregate rule uses it only to satisfy the
bounded terminal-depth-1 acquisition-integration criterion.

The OWASP, MITRE, and NIST standards gate remains passing with 26 selected
items, 22 evidence-mapped items, four roadmap-mapped items, and zero unresolved
dispositions. Together these records authorize Phase 1 engineering under the
qualified aggregate rule; they do not establish an unqualified fresh V7 exit,
supported acquisition, complete artifact closure, installation binding,
runtime containment, or EDR status.

Authorship remains technical Codex authorship rather than independent human
identity. Software signatures trust the operator UID and prove neither
same-UID, VM, hardware, nor platform attestation. The acquisition lock's
pre-outcome ordering remains operator-asserted without trusted timestamping.
Independent review remains a Phase 5 release requirement.

The historical
[Phase 1 v2 numerical receipt](./benchmark/receipts/phase1-acquisition-lock-milestone-v2-2026-07-29.json)
records `PASS` and `acquisition_lock_exit_eligible: true` for its frozen
workload: zero installed digest mismatches across two install/update trees and
four file instances; 13/13 statically resolvable references covered (100%,
above the 95% threshold); and 18/18 unresolved requirements covered by the
fail-closed `ERROR` outcome.

The
[Phase 1 v3 completion receipt](./benchmark/receipts/phase1-acquisition-lock-completion-v3-2026-07-29.json)
re-verifies the historical v2 baseline without using it to authorize the
current result. Its numerical gate comes from three fully replayed cases in the
signed `c87b82b9` production-ingress capture: two successful install/update
cases plus one recursive fail-closed case, including 13/13 statically
resolvable reference edges, 18/18 unresolved requirements failed closed, and a
byte-changing two-tree update. Three older live cases are summary-only and do
not count toward that gate. The aggregate also cross-binds the separate
request-v4 release-pin-custody
capture to the current release-error case. It records
`bounded_acquisition_lock_complete: true` for the public-GitHub exact-commit
profile and makes Phase 2 engineering eligible. It does not make the current
runtime profile admission-conformant or installer-eligible, authorize the
publisher, or establish general recursive acquisition. The bounded release
gateway and v4 fail-closed graph are implemented. Automatic independent
release-pin preflight is implemented and unit-verified; request v4 carries and
replays the retained pin-set digest. V5 additionally
provides bounded ZIP/WHL/PYZ inventory and a
separate analyzer input. V6 retains exact
GitHub-digest-backed inventory archives in a deterministic runtime-candidate
manifest but leaves each public release edge unresolved until a pinned consumer
is implemented. General archive closure and live public
release-bearing/out-of-root recursive evidence remain incomplete. Production
installation and public release remain blocked by the runtime, coverage, and
later-phase gates.
