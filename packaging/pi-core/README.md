# Pi-core request-only adapter and compiled bootstrap

`worker.ts` runs one fresh Pi 1.4.0 Agent with one prompt and one bounded
`aragorn_runtime_create` request tool. The caller must explicitly supply a model,
provider `StreamFn`, relay, correlation IDs and limits. No discovery, restored
conversation, credential lookup, default provider, general shell or service
entrypoint is supplied by the loop. The separate bootstrap below remains
provider-unavailable. A fresh JavaScript Agent is **not** a fresh OS process.

The adapter reuses `../openclaw/aragorn-runtime-action-worker/index.js`'s existing
codec/result parser/transport exports without registering its plugin or changing
the predecessor. Retain that exact relative file and its package metadata in a
later adapter build closure. `__testing` is its existing export namespace, not a
security boundary. There is no copied second protocol implementation.

`createLegacyRelay(config)` performs the caller UID/GID checks omitted by the
low-level helper, then calls that helper once. It opens no socket at construction.
The old relay's UID/GID and endpoint checks do **not** authenticate an isolated
Pi bundle/process activation. Do not deploy it as that missing authority join.

The native profile adds `createNativeRelay(endpoint, options)`, which reuses that
same frozen transport and codec but fixes the root-owned endpoint to
`/run/aragorn-pi-bootstrap/requests/request.sock`. Its exact v1 endpoint object
binds the nonroot worker UID/GID, supervisor UID 0 and one request. The factory
checks the actual caller, binds session/run to the activation, spends its slot
even on failure and preserves one original deadline. The inherited helper's
shorter 750 ms transport limit remains; no timeout is refreshed or retried.
Cancellation is cooperative: synchronous metadata work in the frozen helper
cannot be preempted by the client timer. Late completion is indeterminate, not
success or proof that nothing was sent. The protected root/broker deadline is
the authoritative effect-time boundary; the future pilot must measure whether
the existing transport cap fits its real workload.
Protected root-owned ancestors and endpoint identity are checked. Where Node
lacks a peer-credentials API, this is endpoint-ownership evidence, not a claim
that the client obtained kernel peer credentials. Root independently authenticates
the actual accepted Pi process at the security boundary.

Protected launch configuration opts in with `native_request=True`; v2 START
contains a derived `native_request` object instead of a legacy `relay`. The
protected configuration still pins and masks the legacy endpoint; it cannot
overlap the bootstrap or native request endpoint. Native mode requires one tool
call and matching protected request channels. Default v1 START and configuration
digest remain distinct; v1 never accepts root as its legacy relay worker.

`runPreparedNativePiEntry` connects v2 START to the actual Pi loop and fixed
native client. It accepts a reviewed in-process provider function, never a
substitute relay. The legacy injectable composition rejects v2 START. This is
prepared provider integration, not an enabled provider: native bootstrap still
returns `PROVIDER_UNAVAILABLE`, issues no request and waits for RELEASE.

`provider.ts` adds a separate fixed client for
`/run/aragorn-pi-bootstrap/provider/provider.sock`. It projects exactly the
initial system/user messages, full fixed tool declaration and model. Local display
timestamps are validated then normalized to zero; all semantic data stays in the
canonical approval payload. It never forwards credentials, Pi options/callbacks,
assistant continuation or tool results. Its one request slot and original
deadline cannot be renewed. Root-owned endpoint checks are not portable kernel
peer-credential proof; the external gate authenticates the accepted Pi process.

`runProtectedNativePiEntry` composes that provider client with the existing fixed
native action client, without injectable callbacks or transport overrides. It
caps the initial turn at one. Bounded buffered provider output becomes Pi's real
terminal events; this is not incremental streaming. Reported token usage is
untrusted provider data; required zero cost fields mean unpriced, not cost proof.
The native bootstrap does not call this composition and stays unavailable.

`src/aragorn/pi_core_provider_mediation.py` requires root-held approval for the
exact payload/model/route and public or fabricated owned-lab data, then reuses
the existing policy, independent observation, health, revocation and replay
decision. It retains worker PIDFD/lineage custody, permanently spends an
activation budget before an authenticated service handoff, and closes its owned
handles before worker completion. Caller-owned channels must still be closed by
their owner. This gate reads no credentials and opens no provider connection:
actual TLS/DNS/proxy/redirect controls and network-send-time policy enforcement
were outside batch 9's handoff. See the
[batch-9 checkpoint](../../docs/phase3/coordinator/pi-core-provider-mediation-batch-9.md).

Batch 10 adds `pi_core_openai_responses.py`, `pi_core_openai_transport.py` and
`pi_core_provider_service.py`. The root gate opts into service-v2 explicitly;
legacy v1 stays handoff-only. The new service independently binds the exact
approved request and profile, obtains fresh one-use CONNECT/SEND permissions,
and attempts one numeric-address TLS connection and one buffered Responses API
request. Dedicated CA trust, fixed hostname verification, original deadlines,
bounded HTTP parsing, no DNS/proxy/redirect/retry and owned-handle cleanup are
implemented. The maximum 100 ms permit is not atomic revocation. Keys are user
supplied and read only by the separate service, never by Pi; provisioning and
user key setup are not implemented or performed by this batch. Its handler owns
transport/peer handles, not the caller's channel or service process lifetime.
See the [batch-10 checkpoint](../../docs/phase3/coordinator/pi-core-openai-service-batch-10.md).

Batch 11 adds `pi_core_provider_provision.py`: an absent-only protected bundle
containing exactly the public profile and dedicated CA at their fixed relative
paths under `<deployment>/root`. It reuses the existing installer, requires
reviewed exact bytes and preserves partial output on failure. Its receipt is
explicitly `PROVISIONED_PUBLIC_INPUTS_ONLY_NOT_SERVICE_READY`; it does not supply
Python/OpenSSL, service code, a unit or credentials. No real CA trust is validated
by this copy operation.

`pi_core_request_recovery.py` reuses the durable grant core while understanding
Pi effective-BLOCK receipts. Explicit lifecycle preparation archives exact
terminal receipts/state before a distinct authorized grant can be published.
The request-service caller recovers retained state and requires AVAILABLE before
accepting request custody. It never initializes fresh authority or retries
effects on an incoming request; unresolved journals, missing receipts and
uncertain cleanup remain holds. Fresh grant preparation is not fresh admission
or worker activation. See the
[batch-11 checkpoint](../../docs/phase3/coordinator/pi-core-provision-recovery-batch-11.md).

Batch 12 adds `pi_core_service_provision.py`. It accepts an independently reviewed
complete service-root manifest and binding, copies the exact files to a new
protected destination and retains all partial output on failure. The fixed
layout has a regular `usr/bin/python3`, Python3.12 stdlib/native extensions,
arm64 loader/shared libraries and `opt/aragorn/src/aragorn` source. Fixed roles
point to the existing provider, request-broker and sensor handlers. Essential
file checks do not discover all dynamic imports or prove runtime compatibility;
the caller must supply the complete reviewed closure. No host Python fallback,
package installation, service wrapper, credential or real image is supplied.

`hold_pi_service_runtime` retains and rechecks installed bytes and named-file
custody against independent pins. Inside it, `hold_pi_service_channels` accepts
already-connected post-exec action/sensor/provider packet sockets. It opens only
new peer PIDFDs, verifies exact kernel peers, process start/cgroup/interpreter
identity and returns native request channels carrying the same sealed lease.
The caller retains ownership of sockets and service processes. Native guards
and opt-in provider-v2 mediation recheck the lease; no plain receipt or arbitrary
callback is accepted. Provider completion irreversibly retires its live checks
only after the authenticated terminal, while action/sensor checks remain active.
Retirement is not unit-exit proof and permits no later provider request.

These APIs do not prove which Python modules a service actually loaded or which
systemd invocation owns its lifetime. Service wrappers, concrete reviewed image
assembly, loaded-code joins and native start/stop integration remain before the
pilot. Complete-tree/interpreter rechecks may exceed the existing short action
and provider permit budgets; this batch keeps failure closed and does not widen
limits or claim measured feasibility. See the
[batch-12 checkpoint](../../docs/phase3/coordinator/pi-core-service-runtime-batch-12.md).

Batch 13 adds a concrete staged service image and fixed wrappers. The assembler
reuses the retained Python3.12.13-slim-bookworm arm64 archive, existing ELF and
license inspection, and independently pinned source/wrapper inventories in
`service-assembly-inputs-v1.json`. No target interpreter, container or service
executes. The additive v2 binding pins libpython and exactly these commands:

```
/usr/bin/python3 -I -S -B /opt/aragorn/bin/action.py SUPERVISOR_PID DEADLINE_NS
/usr/bin/python3 -I -S -B /opt/aragorn/bin/sensor.py SUPERVISOR_PID DEADLINE_NS
/usr/bin/python3 -I -S -B /opt/aragorn/bin/provider.py SUPERVISOR_PID DEADLINE_NS
```

The wrappers check fixed root-owned configuration, exact role identities and
post-exec authenticated channels before invoking existing handlers once. The
future lifecycle owner must create supervisor listeners, wait for the action
listener before starting the sensor, and separately verify wrapper/unit exit
and cleanup. Handler completion is not service-lifetime proof. No stale socket
is removed and no connection or effect is retried.

Early environment refusal precedes service imports, but cannot undo native
loader activity before Python starts. Future protected units must supply a
clean environment and isolate OpenSSL configuration/providers. The image's
static closure supports the three fixed handlers; four function-local optional
benchmark DSSE imports are explicitly unsupported. No site-packages or host
Python fallback is allowed. This is not proof that every API in every copied
module is supported. See the
[batch-13 checkpoint](../../docs/phase3/coordinator/pi-core-service-image-batch-13.md).

The additive Python supervisor boundary now lives in
`src/aragorn/pi_core_bundle_launch.py` and `pi_core_worker_identity.py`: exact
admitted-bundle preparation, one-shot protected activation publication and a
PIDFD-bound accepted-peer handler around the existing relay. These APIs are
checked offline but are not installed by this package. A future confined
launcher must consume the prepared prompt/supporting bytes, bind its actual
child PID and route accepted connections through the new guard; using the old
UID-only handler does not gain these protections. See the
[D2 batch checkpoint](../../docs/phase3/coordinator/pi-core-launch-identity-batch-2.md).

The [compiled/bootstrap checkpoint](../../docs/phase3/coordinator/pi-core-compiled-launch-batch-3.md)
adds `entrypoint.ts` and `pi_core_confined_launch.py`. The root-side plan reuses
admission and activation binding, verifies exact installed runtime/OS receipts
and prepares fixed confinement arguments. It does not execute systemd or own
native lifecycle/cleanup. The native entrypoint connects after exec to the
fixed protected bootstrap socket and exchanges only provider-unavailable status.
The legacy action endpoint is inaccessible in the plan until protected identity
handoff is integrated; no provider fallback or credentials are enabled.

Results distinguish completed protocol exchanges from `NOT_SUBMITTED` and
`INDETERMINATE`. A completed exchange may report BLOCK; it is not automatically a
successful effect. Failure/uncertainty stops later dispatch. Adapter return or
abort does not establish remote cancellation or process-tree cleanup. An
uncooperative callback may remain running after the bounded return; only the
future external launcher can establish containment.

## Dependencies and offline checking

`package-lock.json` translates the approved source-lock inventory to published
packages with the same 89 runtime occurrences and 215 effective dependency
edges. Five absent optional peers remain absent. No compiler is installed here;
the selected compiler is separately supplied by exact reviewed archives. The
Linux build emits the adapter, preserves the dependency/legacy layout and copies
the pinned Node24 executable without executing it. `compiled-artifact-v1.json`
preserves the earlier bootstrap output; the compiled native-client successor is
recorded in `compiled-artifact-v2.json`; `compiled-artifact-v3.json` adds the
provider client and protected composition without altering either predecessor.
The unchanged Node/static OS closure is reused without another OS assembly.
The static OS source assembly is
recorded in the [OS/supervisor checkpoint](../../docs/phase3/coordinator/pi-core-os-supervisor-batch-4.md);
it is not an installed or runtime-qualified OS.
Dependency preparation uses `npm ci --ignore-scripts --no-audit --no-fund` with
isolated empty npm configuration. Do not run install scripts or silently change
pins to make a resolver succeed.

The first focused stage is `pi-core-worker-offline`, registered in the root
pipeline. Its reviewed closure includes the exact package lock and
`offline-toolchain-v1.json`. The latter binds the developer Node26.3.1 binary and
every prepared dependency file/link before any test child executes. The Python
test checks these identities again afterward and fails rather than skips when
they differ. Host type stripping is **not** TypeScript type checking, a compiled
Linux build, installed-source custody or deployment qualification. The standard
pipeline fingerprint remains an explicit-input developer cache; this record is
not a general toolchain attestation. Re-preparation changes require real review,
not rewriting a pin to bypass a failed test fingerprint.

New stages are `pi-core-linux-build-offline` (inert assembler checks),
`pi-core-linux-compile` (one isolated compiler execution),
`pi-core-entrypoint-offline` and `pi-core-confined-launch-offline` (inert
composition). `linux-build-toolchain-v1.json` pins local archives and Docker
metadata for the compiler-only stage. Exact unchanged passes must be reused;
no old stage is scheduled merely because these files were added.

Batch 9 adds `pi-core-provider-mediation-offline`,
`pi-core-provider-client-offline` and `pi-core-provider-build-offline`. These
select only the new data/client behavior and affected assembler checks. Importing
older fixture helpers does not schedule their historical test classes.

Batch 10 adds four new Python-only stages: `pi-core-openai-responses-offline`,
`pi-core-openai-transport-offline`, `pi-core-provider-service-offline` and
`pi-core-provider-egress-offline`, plus the affected registry-capacity slice.
No TypeScript artifact changed; compiled-artifact-v3 and OS-v1 are reused,
without another compiler or assembler run. Native/file/network edges are inert.

Batch 11 selects `pi-core-provider-provision-offline`,
`pi-core-request-recovery-offline` and `pi-core-service-recovery-offline`, plus
four affected registry-capacity checks. Provider installation checks write only
exclusively owned temporary public-input fixtures with mocked Linux/root ancestry;
recovery uses an inert in-memory file table. Four selected affected caller
methods are included, not the whole historical request-service suite. No target
deployment, service or credential is used.

Batch 12 selects `pi-core-service-runtime-offline`,
`pi-core-service-channels-offline` and `pi-core-service-integration-offline` plus
the affected capacity checks. Installed-tree fixtures are owned temporary files;
all service/process/socket edges are inert. Four selected affected caller methods
run with the new integration checks; historical suites are not rescheduled.

Batch 13 selects `pi-core-service-image-offline`, `pi-core-service-entry-offline`,
`pi-core-service-image-contract-offline` and `pi-core-service-image-assemble`,
plus affected capacity checks. The assembly stage only reads the retained archive
and writes a fresh local artifact; it never executes its target bytes. Successful
unchanged dependencies are reused. `service-artifact-v1.json` records the exact
retained artifact and its limits, not an installed or qualified deployment.

The initial worker checks run the actual pinned Pi loop against a scripted provider and in-memory
relay, with cross-language verification by Aragorn's existing Python parser.
They do not start listeners, call model providers, execute protected effects or
measure Phase 3 performance. No source/test helper is production authority.

## Still required for D2

The static OS assembler, protected absent-only provisioner and native supervisor
now exist. They reuse the compiled artifact and protected plan/bootstrap APIs;
the supervisor remains provider-unavailable. Installation and native lifecycle
must still be exercised in a separately authorized controlled fixture. Protected
identity, native request dispatch and independent sensor/broker wiring now exist;
the fixed client/START binding is implemented without activating that path.
The concrete service image and fixed wrappers are now staged. Connect their
protected configuration/installation to unit startup, authenticated channel
acquisition, unit-generation/lifetime and consumed-code custody; establish native
recovery/timing evidence and installed protected provider service custody
(the public-input provisioner and Pi-aware recovery source now exist;
OpenAI Responses is selected and its source adapter exists,
but no concrete model/key deployment or service is activated), followed by
real positive effect/health/cleanup integration. The HTTP reader service remains
refusal-only. The approved 29-requirement map is not an executable result and no
final acceptance or Phase 4 readiness is claimed here.

The native supervisor requires Linux arm64, root-owned installed inputs, unified
cgroups/PIDFDs and **systemd manager plus client 257+**, including explicit
log-socket isolation. The prepared Debian library closure is not the host's
systemd version. No host upgrade or native activation has been performed.
