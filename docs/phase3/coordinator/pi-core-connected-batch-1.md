# Pi-core connected batch 1: offline implementation release

Date: 2026-11-02. Base: signed `b12a5de522b47bea305c9038ed0cb4c92ebc8783`.

The user explicitly approved the 29-requirement managed-profile mapping and
authorized the first connected implementation batch, new/affected checks only,
a verified signed commit and push. **No live operations are authorized.** The
original manifest, evaluator, evidence and cleanup/private-retention holds stay
unchanged. Approval does not mean any requirement has passed.

## Released interface and ownership

- Root: approval/current-roadmap records, package preparation, pipeline capacity
  and selected stage registration, review, checkpoint, signing and push.
- RUN agent: only `packaging/pi-core/worker.ts` (relay types are inline).
  Export `runManagedPiWorker(options)` and `createLegacyRelay(config)`.
- Workload agent: only `packaging/pi-core/package.json` and `package-lock.json`,
  translating the approved exact runtime graph into an installation lock.
- Admission agent: only `tests/test_pi_core_worker.py` and
  `tests/fixtures/pi_core_worker_offline.mjs` for this connected caller.

The adapter owns one fresh Pi Agent and one prompt, with one bounded file-create
request tool, explicit provider-stream and relay functions, sequential actions,
bounded model/tool calls, no session restore/discovery, and no implicit provider
or credential fallback. Correlation identifiers are not protected activation
authority. Reuse the frozen Node worker module's existing exported codec and
transport functions; do not register its OpenClaw plugin or mutate its bytes.
The new wrapper supplies the native caller identity/config checks that its
low-level transport does not itself perform. Validate returned bytes using the
existing exact canonical result parser. Stop on uncertain outcomes; no automatic
effect retry or claim that aborting the loop cancelled a remote effect.

The offline fixture uses the actual pinned Pi loop with a scripted provider and
an in-memory relay; Python independently consumes its request using the existing
worker parser/canonical digest. No listener, service, provider request, protected
file effect or live capture is involved. Bounded fixture outcomes are not
admission, health, effect, deployment or qualification evidence.

## Dependency and check constraints

Prepare only exact approved package versions/integrities with lifecycle scripts,
audit and funding requests disabled; do not fetch absent optional peers or
silently resolve a different graph. Preserve source-lock effective edges when
translating workspace paths. Local offline execution uses the explicitly recorded
host Node interpreter with type stripping; this is **not** the pinned Linux
compiler/build or target-runtime qualification. Bind the host binary and prepared
dependency tree in a reviewed check-input record, verified before any fixture
execution. No runtime code uses that developer record as security authority.

Only the new Pi worker stage and the directly affected finite pipeline-capacity
checks may run. Raising the full registry's bound is necessary to register the
new stage; it does not authorize rerunning other stages whose runner fingerprint
changes. Preserve all prior attempt records and do not retry unchanged failures.

## Claim ceiling and next dependency

This slice can establish offline Pi-loop/Aragorn-protocol composition and honest
failure propagation. It does not finish D2. Protected launcher/peer-to-bundle
authentication, admitted consumed-byte custody, isolated Linux packaging, actual
provider mediation/data policy/secret custody, positive broker effects and
meaningful health remain required before a useful deployed pilot. The existing
HTTP reader service remains refusal-only. No executable successor acceptance
manifest/evaluator is introduced in this batch.

## Completed offline checkpoint

Implemented `runManagedPiWorker` and explicit `createLegacyRelay`, exact package
manifest/lock, pinned developer tool/dependency record, and the connected offline
fixture. The real Pi Agent/EventStream runs with scripted provider responses and
an in-memory relay. The existing Python worker parser and canonical digest
independently consume emitted requests. No predecessor code was changed.

The worker rejects invalid Unicode and ambiguous fields, preflights whole tool
batches, serializes bounded actions, rejects duplicate call IDs and duplicate
action bytes, and retains exact validated source results. BLOCK, uncertain
transport, provider errors, cancellation and budgets stop further dispatch.
Partial/final provider output and retained reports are bounded. Unsettled or
omitted transcripts explicitly report `transcriptComplete: false`; cancellation
does not claim external shutdown.

Dependency preparation installed exactly 89 approved runtime occurrences with
all 215 effective edges and five absent optional peers preserved. npm lifecycle
scripts, audit and funding were disabled. An initial npm configuration refusal
(the same `/dev/null` used for two config roles) occurred before installation;
using separate empty config locations corrected it. Actual preparation used
host Node26.3.1/npm11.16.0, **not** the target Node24.22.2/npm11.19.1 or Linux
compiler. Node and dependency bytes are bound in `offline-toolchain-v1.json`.
This is executable offline source evidence, not type checking or a target build.

### Focused verification and retained failure

| Stage | Result | Exact fingerprint |
| --- | --- | --- |
| `pipeline-capacity` | 4 affected checks PASS, once | `sha256:907167f68fbd7c7ee51d8f0ec6f803063f2bafd7f15b200fb5f91a8ac3f3e3a0` |
| `pi-core-worker-offline` initial | FAIL before any scenario: fixture used CJS `require.resolve` against Pi AI's import-only export | `sha256:46c41743db56232a3fab73d5fbd0a391b96f0e508b69e48f2b070844664ccaab` |
| `pi-core-worker-offline` corrected | 28 focused methods / 40 inert scenarios PASS | `sha256:a021c2fa1be297e2cc3b2b88919556e2c031bf01e884f4acdd2ab9f56ba69e73` |

Only the fixture's import was corrected to the exact published ESM target before
the affected stage reran. Worker, dependency tree and lock remained unchanged.
All initial 28 methods depended on that failed import; no successful scenario
was redundantly replayed. The capacity PASS was not rerun. Results, pre/post
fingerprints and logs remain in `.aragorn/phase3-pipeline/<stage>/<fingerprint>/`.
No failure was erased or invalidated by irrelevant input changes.

Input closure: the registered 15 explicit files plus the runner and Python lock;
test setup verifies host Node and every prepared dependency byte before fixture
execution and again afterward. A separate source reviewer checked the dependency
translation, Unicode/refusal boundaries, bounded-output correction and ESM fix.
No broad regression, services, listeners, model calls, live effects, captures or
performance/acceptance samples were run. UI render review is not a product test.

The enclosing signed implementation commit is the batch checkpoint; its verified
hash and confirmed remote branch SHA are reported in the milestone handoff. Only
batch-owned files are committed; unrelated drafts and worktrees remain preserved.

## Remaining plan

1. **Done:** design, exact dependency pins, approved 29-requirement mapping and
   first offline Pi-loop/request-protocol implementation.
2. **D2 next:** connect protected admitted-bundle launch/peer identity and the
   credential-isolated provider route; compile/pin the Linux deployment, then
   separately authorize a useful positive effect/health/cleanup observation.
3. **D3:** complete managed lifecycle, RUN events/responses, workload/timing paths
   and independent semantic consumers on that same deployment.
4. **D4–D5:** implement the approved executable acceptance contract, inventory
   every supported/denied surface, freeze, then separately authorize fresh
   acceptance and verify cleanup. Phase 3 and Phase 4 remain unqualified.
