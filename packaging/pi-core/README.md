# Pi-core request-only adapter (first offline slice)

`worker.ts` runs one fresh Pi 1.4.0 Agent with one prompt and one bounded
`aragorn_runtime_create` request tool. The caller must explicitly supply a model,
provider `StreamFn`, relay, correlation IDs and limits. No discovery, restored
conversation, credential lookup, default provider, general shell or service
entrypoint is supplied. A fresh JavaScript Agent is **not** a fresh OS process.

The adapter reuses `../openclaw/aragorn-runtime-action-worker/index.js`'s existing
codec/result parser/transport exports without registering its plugin or changing
the predecessor. Retain that exact relative file and its package metadata in a
later adapter build closure. `__testing` is its existing export namespace, not a
security boundary. There is no copied second protocol implementation.

`createLegacyRelay(config)` performs the caller UID/GID checks omitted by the
low-level helper, then calls that helper once. It opens no socket at construction.
The old relay's UID/GID and endpoint checks do **not** authenticate an isolated
Pi bundle/process activation. Do not deploy it as that missing authority join.

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
the selected Linux TypeScript/compiler and Node24 deployment remain future work.
Dependency preparation uses `npm ci --ignore-scripts --no-audit --no-fund` with
isolated empty npm configuration. Do not run install scripts or silently change
pins to make a resolver succeed.

The only focused stage is `pi-core-worker-offline`, registered in the root
pipeline. Its reviewed closure includes the exact package lock and
`offline-toolchain-v1.json`. The latter binds the developer Node26.3.1 binary and
every prepared dependency file/link before any test child executes. The Python
test checks these identities again afterward and fails rather than skips when
they differ. Host type stripping is **not** TypeScript type checking, a compiled
Linux build, installed-source custody or deployment qualification. The standard
pipeline fingerprint remains an explicit-input developer cache; this record is
not a general toolchain attestation. Re-preparation changes require real review,
not rewriting a pin to bypass a failed test fingerprint.

Tests run the actual pinned Pi loop against a scripted provider and in-memory
relay, with cross-language verification by Aragorn's existing Python parser.
They do not start listeners, call model providers, execute protected effects or
measure Phase 3 performance. No source/test helper is production authority.

## Still required for D2

Protected admitted-bundle loading and consumed-byte custody; fresh isolated
Linux launch and authenticated peer-to-activation joins; target compilation and
image inventory; credential-isolated provider mediation with data-scope policy;
real positive effect/health/cleanup integration. The HTTP reader service remains
refusal-only. The approved 29-requirement map is not an executable result and no
final acceptance or Phase 4 readiness is claimed here.
