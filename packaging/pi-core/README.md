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
the pinned Node24 executable without executing it. See `compiled-artifact-v1.json`
for the local output/receipt pins. The subsequent static OS source assembly is
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

Tests run the actual pinned Pi loop against a scripted provider and in-memory
relay, with cross-language verification by Aragorn's existing Python parser.
They do not start listeners, call model providers, execute protected effects or
measure Phase 3 performance. No source/test helper is production authority.

## Still required for D2

The static OS assembler, protected absent-only provisioner and native supervisor
now exist. They reuse the compiled artifact and protected plan/bootstrap APIs;
the supervisor remains provider-unavailable. Installation and native lifecycle
must still be exercised in a separately authorized controlled fixture. Connect protected identity
handoff to the unprivileged action relay; establish consumed-code custody;
credential-isolated provider mediation with data-scope policy;
real positive effect/health/cleanup integration. The HTTP reader service remains
refusal-only. The approved 29-requirement map is not an executable result and no
final acceptance or Phase 4 readiness is claimed here.

The native supervisor requires Linux arm64, root-owned installed inputs, unified
cgroups/PIDFDs and **systemd manager plus client 257+**, including explicit
log-socket isolation. The prepared Debian library closure is not the host's
systemd version. No host upgrade or native activation has been performed.
