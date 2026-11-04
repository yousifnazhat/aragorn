# Roadmap: approved Pi-core managed capability profile

Date: 2026-11-02. Status: **design and mapping approved; first connected offline
implementation, compiled/bootstrap, OS/supervisor and identity-registration slices released**. Authoritative design: [managed capability SDD](pi-core-managed-capability-sdd-v1.md).
Research baseline: `dc3fc10f38db62343c85bbe2d9c263d843d2e12a`.

Step-2 checkpoint, 2026-11-02, prepared from signed `3c94e48`:
[dependency pins and provenance limits](pi-core-dependency-pins-v1.md) are now
recorded, including the transitive [pin inventory](pi-core-dependency-pins-v1.json).
The complete [48-row acceptance crosswalk](pi-core-phase3-acceptance-mapping-v1.md)
defines 29 managed-profile logical requirements and is **approved by the user**.
The subsequent [batch-1 release](../phase3/coordinator/pi-core-connected-batch-1.md)
authorizes only offline implementation and new/affected checks, signing and push.
No live operations are authorized. The compiled adapter now has an artifact
checkpoint; a static OS closure is prepared while installed deployment identities remain future outputs.
The complete deployment is not frozen.

Batch-1 checkpoint: the actual pinned Pi loop is now connected offline to the
existing Aragorn request/result protocol. 28 new focused methods and four
affected capacity checks pass; the retained initial fixture-import failure was
corrected before only the affected stage reran. See the linked batch record for
exact fingerprints, evidence limits and remaining D2 integration.

Batch-2 [launch/identity checkpoint](../phase3/coordinator/pi-core-launch-identity-batch-2.md):
protected admission/tree preparation, one-shot activation publication and a
PIDFD-bound relay guard are implemented offline. The future confined launcher
must consume the exact prepared bundle and install this guard; no process is
launched and no loaded-JavaScript or deployed-identity result is claimed.
Its 50 new checks and four affected capacity checks passed once; no old suite
or live operation ran.

Batch-3 [compiled/bootstrap checkpoint](../phase3/coordinator/pi-core-compiled-launch-batch-3.md):
the pinned Linux arm64 compiler produces `worker.js` and `entrypoint.js` with the
exact preserved dependency/legacy layout. Root-side guarded planning joins
compiled/runtime/OS/configuration expectations to admission and the authenticated
post-exec bootstrap. Native startup remains provider-unavailable and the
actual supervisor is not implemented. OS installation, lifecycle/cleanup custody,
action-relay identity handoff and provider mediation remain D2 dependencies.

Batch-4 [OS/supervisor checkpoint](../phase3/coordinator/pi-core-os-supervisor-batch-4.md):
reuses the retained compiler artifact and cached digest-pinned OS source. A static
ELF dependency closure, descriptor-safe absent-only installer and one-shot native
supervisor are implemented. The supervisor composes existing protected admission,
post-exec activation binding and bootstrap; it owns exact lifecycle resources and
fails closed on uncertain cleanup. Inert checks do not establish installation,
actual confinement, runtime compatibility or cleanup. Native startup still reports
provider-unavailable; action identity handoff, provider/data mediation and the
connected useful task remain D2 dependencies. No live operation is released.

Batch-5 [protected identity-handoff checkpoint](../phase3/coordinator/pi-core-identity-handoff-batch-5.md):
the native supervisor registers its measured worker identity with the unprivileged
relay over an authenticated, one-use local channel. The relay receives only a
bounded activation record and PIDFD, not protected process files or credentials.
Registration is withdrawn before the worker is released. This is **not request
or effect authority**: exact request provenance, broker-bound enforcement and
credential-isolated provider/data mediation remain the next D2 work. The legacy
action endpoint remains masked and native bootstrap stays provider-unavailable.

Batch-6 [request/broker checkpoint](../phase3/coordinator/pi-core-request-broker-batch-6.md):
root reads the actual authenticated Pi request and holds its identity through an
independently authenticated broker channel. The create-only broker requires that
provenance inside its durable grant/effect path and separately verifies matching
sensor attribution, grants, lineage and current policy/health/revocation. Existing
relay-attributed sensor output correctly refuses; native request/sensor/channel
wiring, Pi-aware effective-receipt recovery/rotation, and protected provider/data
mediation remain before the useful D2 pilot. Frozen recovery/archive routines
refuse the new effective-BLOCK receipts; this one-shot caller does not use them.
This is not a deployment or Phase 3 result.

## Goal

Deliver a useful controlled-environment capability-security V1 by reusing
Aragorn's security core and replacing the integration target with a narrow
Pi-core worker. Finish a connected positive enforcement path before expanding
coverage. Preserve historic work and distinguish pilot readiness, integrated
implementation and actual Phase 3 qualification.

## Assumptions and constraints

- Approved: Linux, one bundle/fresh context, explicit managed lifecycle, thin
  TypeScript worker, existing Python authority and external OS enforcement.
- Only the connected offline batch is released; no service activation, live
  capture, provider request or acceptance campaign.
- Preserve all frozen predecessors, lane drafts, signed ancestry, retained
  successes/failures and unresolved cleanup/private-retention holds.
- No parallel second runtime campaign, speculative framework, Go rewrite,
  general coding assistant or Phase 4 scaling.
- Existing Phase 3 v1 is unchanged. The successor mapping is approved;
  excluded OpenClaw paths are not automatically PASS or N/A.

## Research: where we actually are

The reusable predecessor includes RUN bootstrap (`ec171a6`, checkpoint
`dc3fc10`), followed by the Pi slices above. Admission context67, broker service44 and bootstrap69 have focused
component evidence. The service's current profile is `HTTP_REFUSAL_ONLY`; real
positive composition, installed/loaded-source custody, complete health,
remaining routes and actual measurements remain incomplete. More leaf tests
alone do not remove those deployment gaps.

Modules: `src/aragorn/` security/evidence, `scripts/` staging/collection,
`packaging/systemd/` containment and service custody, `packaging/openclaw/`
legacy adapter, `benchmark/` fixed acceptance/workloads, `tests/` focused checks.
Current entrypoint remains the root Python `aragorn` launcher. The selected
Pi/Node/build dependency pins now live in the linked step-2 inventory. The
request-only `packaging/pi-core/worker.ts` is implemented and exercised offline;
the compiled target artifact and protected native supervisor now exist as
implementation, but no installed complete OS deployment is evidenced.
Supervisor-side preparation, guarded confinement, bootstrap, accepted-peer
identity and protected relay registration are composed in source. Batch 6 adds
the source-level root-read request handoff, mandatory create broker enforcement,
and independent sensor-channel caller. Genuine Pi sensor/native channel wiring,
Pi-aware effective-receipt recovery/rotation and credential-isolated provider
routing remain next; no useful native task has run.

Key contracts to reuse: CAS and admission receipts; action request/decision and
one-use grants; process/active lineage; broker/reader health; seven-dimension
deployment identity; independent measurement/semantic replay. Current profile
and service-name assumptions must be inventoried before reuse.

## Analysis and decision

Chosen: Pi core as an untrusted engine with Aragorn-owned lifecycle. Keeping
OpenClaw as the immediate target would preserve richer native-plugin compatibility
but retain the lifecycle surface the user explicitly chose to exclude. Building
a new agent loop or rewriting in Go would discard reusable work without proving
the security or performance benefit. Preserve OpenClaw as historical evidence
and a possible later compatibility integration.

Risks: hidden bypasses, mutable dependency closure, ambiguous effect retries,
worker/descendant identity, provider data leakage, unknown telemetry loss and
mislabelled historical evidence. The SDD defines the required failure behavior.

## Q&A results

The architecture and initial profile exclusions are settled by user approval.
The user has also approved the versioned 29-requirement acceptance crosswalk
and released the first offline implementation batch. Original v1's 21 literal
OpenClaw routes remain unchanged and unqualified. Do not reopen these decisions
or infer permission for live operations or weaker numerical gates.

## Dependency-ordered delivery plan

These are deliverable stages, not equal-sized sprints or a promise of a finish
date. Runtime estimates would be speculative before a pinned deployable worker
and connected positive path exist. Each future batch must end at a usable
interface or observable behavior, not an arbitrary clock interval.

| Stage | Output and ownership | Exit and next dependency |
| --- | --- | --- |
| D0 — approved design | Root: this SDD, roadmap and current-document pointers | **Complete as documentation.** No implementation or gate is closed |
| D1 — freeze the delivery contract | Pi/Node/dependency pins, approved full acceptance crosswalk and batch-1 interface/ownership release; design-level load surfaces specified | **Approved and released for the first offline slice.** Adapter/OS outputs and complete source-bound inventory remain future freeze inputs; not a frozen deployment |
| D2 — one connected useful path | Root owns launcher/deployment/broker/provider wiring; Admission supplies bundle custody; RUN supplies identity/health; Workloads supplies independent positive output/effect observation | One admitted bundle performs an authorized file/API task; changed bytes and forbidden effects refuse; actual consumed-source identity, health, outcome and cleanup are retained. Pilot only |
| D3 — complete managed lifecycle and required security coverage | Existing Admission, RUN and Workloads lanes under nonoverlapping contracts | Supported/denied activation routes, updates, revocation, all required events/responses, HTTP/DNS/destructive paths, cancellation/unknown outcomes and paired tasks are connected on the same deployment |
| D4 — independent inventory and freeze | Root with separate verifier review | Every approved requirement maps to real producer, raw evidence and independent consumer; no unknown prerequisite; one exact deployment frozen |
| D5 — final qualification | Root schedules separately authorized isolated acceptance; independent verifier reviews retained output | Required fresh acceptance under the approved contract, actual metrics, offline semantic replay and verified cleanup. Only then claim that exact profile's Phase 3 result |

### D1: delivery contract scope and prepared state

The linked step-2 documents prepare a bounded **compatibility-and-acceptance
contract**, not another generic framework. The remaining release obligations are:

1. Preserve the selected immutable Pi-core, Node and transitive/build-tool pins.
   The actual adapter artifact is now pinned in `packaging/pi-core/compiled-artifact-v1.json`.
   Pin the managed OS closure and installed custody once implemented; no
   placeholder digest may stand in for those bytes. Publish the exact worker
   entrypoint with the later implementation contract.
2. List every load/activation surface: managed install/replacement/restart;
   direct writes/rename/symlinks; project/home discovery; native extensions;
   dynamic scripts/imports; reload/session restore; model-provider/tool routes.
   Each is supported with a gate or unsupported with an enforceable denial.
3. **Approval recorded:** the mapping of all 48 original IDs, including
   all 21 old route IDs. The approved contract retains security properties and numeric
   thresholds under 29 logical managed requirements; it does not set a test-case
   cap. Retain original v1 and its incomplete result; no fictional equivalents
   or old PASS flags.
4. Name concrete reused callers and exact changes. New likely directory:
   `packaging/pi-core/` for only the thin worker and dependency/build manifest;
   target-specific Python changes belong at the existing adapter/launcher
   boundary. Batch 1 releases only the thin request-only worker and its checks.
5. **Released:** one connected offline vertical-slice contract after the user's
   implementation request. Carry exact failure/cancellation/health/data semantics from the
   SDD. Resolve any new material product choice before coding it.

### D2: prove the integration risk early

Use a fabricated owned-lab task with real computation and observable effects,
for example reading explicitly allowed documents and producing a verified output
plus one scoped API interaction. The real selected task/input manifests belong
to the batch; a prose example is not a measurement sample.

Reuse the CAS/admission path; add the thin request-only worker; bind the actual
loaded deployment; connect the existing broker/reader and protected health;
establish provider egress/secret handling; retain useful authorized output and
one necessary changed-behavior denial. Do not complete separate launcher,
adapter, health and verifier campaigns without composing their owning caller.

Likely affected anchors: `runtime_action_worker.py`, `runtime_process_profile.py`,
`runtime_active_skill_lineage_v2.py`, broker service/bootstrap/submission modules,
`native_phase3_common_process_verifier.py`, selected `packaging/systemd/` and
staging/identity inventories. Inspect and change only actually coupled paths;
do not rewrite every frozen successor.

### D3–D5: expand and qualify without churn

Reuse current admission/policy helpers for exact bytes and denied mutations;
RUN health/response primitives for actual sensor progress, loss and containment;
HTTP/DNS/destructive workload helpers for real sinks and cancellation; the four
existing paired-task designs for real baseline/instrumented execution. Verify
digest-specific quarantine and future-start revocation, not just one service
mask. Capture all required event classes, including exposed context mutation.

The common deployment and its complete independent-verifier inventory precede
freeze. Final acceptance is a fresh evidence acquisition obligation, not a
redundant unit regression. Do not overlap live captures/performance measurements,
recapture history, or manufacture replacement samples. Use the existing evaluator
machinery only after an approved successor contract is implemented and reviewed;
do not build a competing gate engine.

## Worktree coordination

Retain current worktrees and original signed history. The batch-1 contract
releases nonoverlapping files to local subagents in the integration checkout;
it does not instruct other chats to continue old worktree assignments or mutate
their drafts. Inspect their current state before any later worktree release.

| Owner | Future bounded responsibility | Shared boundary |
| --- | --- | --- |
| Root/coordinator | Delivery contract, Pi adapter/launch, deployment identity, registry, integration and qualification mapping | Own shared files; release exact leaf paths when needed |
| Admission | Supported closure, immutable installed/consumed bundle and update/revocation admission paths | No runtime loader, registry or service changes without transfer |
| RUN/health | Authenticated process/reader health, real loss accounting and response readback | No independent service activation or live capture |
| Workloads/verifiers | Actual benign/adversarial lab effects, timing, paired tasks and independent consumers | Consume shared identity contract; no fabricated success/timing |

Parallelize only dependency-ready nonoverlapping paths after the common contract.
Integrate promptly; maintain original signed ancestry. A lane is ready to
integrate when its owned diff is reviewed, required new/affected checks have
valid results, its signed commit verifies and its handoff identifies evidence
and limitations. That is not permission to mark Phase 3 green.

## Verification plan: no redundant testing

**Batch 1:** documentation/source review, one new offline Pi integration stage
and the directly affected four finite registry-capacity checks. No live operation
or acceptance execution. Documentation-only changes require no behavioral check.

**All implementation batches:** publish the exact reviewed input closure and
select only new/affected stages through `scripts/phase3_pipeline.py` using
`benchmark/phase3-pipeline-v1.json`. Batch 1 raises the full 128-row registry
bound to 129 only to add its new stage. No other stage is scheduled merely
because the runner's new digest changes its fingerprint.

- Reuse exact unchanged successful results under their actual source, runner,
  toolchain, environment and checkout fingerprint. Do not copy caches across
  worktrees or label historic component PASS as deployed qualification.
- Never rerun an unchanged failed/timed-out/interrupted fingerprint. Diagnose
  and correct the relevant cause; preserve the original record.
- No broad regression, whole-schema sweep, historical recapture, automatic
  effect retry or cosmetic input change to defeat the no-retry rule.
- Each spec requirement gets a targeted positive/negative check only where
  necessary, plus independent deployed evidence for claims unit models cannot
  establish. Start with loadout, peer/action binding, bypass, changed bytes,
  expiry/revocation, unknown health, cancellation and useful output.
- Live validation requires separate operational release, exact owned isolated
  disposable resources, prerequisite guards, bounds, retained evidence and
  verified cleanup/prior-state restoration. Existing cleanup holds remain.
- After a reviewed batch, commit only owned code/checkpoint files with a verified
  signature, inspect remaining changes and ordinary fast-forward push under the
  user's standing authorization. Never force-push or call a branch push a
  production deployment. No empty commits; no unrelated drafts.

## Reporting and remaining plan

Always report **designed / implemented / connected / evidence-verified /
qualified** separately. Do not derive a completion percentage from commits or
test counts. Restate these stages at each future handoff:

1. Design, dependency pins and 29-requirement acceptance mapping approved;
   first connected offline implementation slice passed its focused checks.
2. Build and verify the connected useful Pi managed-profile path (D2).
3. Complete managed admission, RUN/health, workload and verifier coverage (D3).
4. Freeze and run separately authorized final acceptance (D4–D5).

Phase 4 remains blocked until the applicable explicitly approved Phase 3
qualification is genuinely complete. A useful pilot can arrive earlier, but
must be named as that narrower milestone.
