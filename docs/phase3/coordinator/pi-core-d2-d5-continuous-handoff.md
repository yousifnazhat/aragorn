# Aragorn D2–D5: continuous completion handoff

Prepared 2026-11-16. This is an execution handoff, not evidence of completion or
permission to activate anything. Begin the campaign when the user submits this
handoff to the next coordinator. Continue dependency-ready work without asking
for a manual continue after each batch; stop for missing authority or a material
decision. A single continuous campaign does not bypass the pilot/final-run gates.

## 1. Verified starting point and sources of truth

Current D2 host handoff: [batch 43: dedicated backend and isolated boot approval packet](pi-core-isolated-boot-approval-batch-43.md).
An EC2 M4 Mac Dedicated Host running the named macOS 27 release is a catalog
candidate, not an allocated machine. No trust store or VM has been created.
Before spending, choose an observation objective: the retained guest has
refusal messages but no positive disk/mount/PID 1 receipt. Keep acquisition,
per-guest enrollment, one compatibility boot and the pilot separately gated.
Reuse [batch 42: proposed image trust and read-only NVMe preflight](pi-core-firmware-trust-batch-42.md).
Reuse the [batch 41 immutable ARM64 disk and inventory](pi-core-immutable-guest-image-batch-41.md).
The disk contains the [batch-40 clients](pi-core-immutable-host-clients-batch-40.md),
retained CPython, and [batch-39 physical loader layout](pi-core-immutable-host-layout-batch-39.md).
Reuse the output pins and retained media; do not rebuild them for a status check.
The outer EFI image remains unsigned; its proposed firmware hash entry is not
enrolled. The Apple host accepted read-only NVMe attachment descriptors, not
a booted namespace. Guest read-only flags, logical geometry, effective firmware
policy, actual PID 1 and installed identities remain unverified. Do not enroll,
boot or enable a provider without separate authorization.
The older starting point below is historical; do not reset to it. Reuse the
retained [batch-38 CPython and patched client sources](pi-core-host-client-inputs-batch-38.md).
The immutable lifecycle is approved; boot readiness, pilot authorization and
public Git delivery are distinct gates.

- Repository: `/Users/yousi/Documents/Commits/aragorn`.
- Coordinator branch: `codex/phase3-runtime-prevention`; delivery branch: `main`.
- Implementation checkpoint: signed merge
  `7787ad2fa7c7bafaae5fc9da954492333e1ea801`, containing signed source
  `e904a902378ce57ed1619900869f1b3dd667dbaa`.
- Both remote branches matched that merge at handoff preparation. This
  documentation delivery will follow it; inspect current ancestry before work.
- Tracked tree was clean; 985 unrelated untracked files were present. Preserve
  all drafts, duplicate-named files, frozen predecessors and retained failures.
- No implementation, tests, builds, provider calls or live operations were
  performed to prepare this handoff.

Read these repository-relative files, then inspect the specific next caller and
dependencies. Do not reread all history or recapture old evidence:

1. `docs/phase3/coordinator/pi-core-provider-custody-batch-21.md` — latest work,
   exact focused result fingerprints and explicit evidence limits.
2. `docs/design/pi-core-managed-capability-sdd-v1.md` and
   `docs/design/pi-core-managed-profile-roadmap-v1.md` — approved architecture.
3. `docs/design/pi-core-phase3-acceptance-mapping-v1.md` — approved 29 logical
   requirements. Its older “not yet executable” wording is superseded by batch
   16's delivered entrypoint, not by a completed qualification.
4. `docs/phase3/coordinator/pi-core-managed-completion-batch-16.md` and
   `docs/phase3/coordinator/pi-core-managed-qualification-handoff.md` — existing
   qualification implementation and independent-consumer contract.
5. `benchmark/pi-core-managed-phase3-v1.json` and
   `src/aragorn/pi_core_phase3_qualification.py` — reuse the implemented managed
   contract; do not build a replacement.
6. `docs/phase3/coordinator/ownership-and-release-v2.md`,
   `benchmark/phase3-pipeline-v1.json`, and `scripts/phase3_pipeline.py` — ownership,
   reviewed input closures, scheduling, cache and delivery rules. Historical
   OpenClaw assignments do not override the approved Pi-core target.

First inspect branch/status, active agents, worktree ownership and retained
pipeline results. Continue any active batch rather than launch overlapping work.
Compare current remote ancestry before integration. If the checkpoint advanced,
read its new handoff and continue from it; never reset to the hash above.

## 2. Fixed mission and reuse

Deliver one controlled Linux arm64/systemd deployment where Pi performs useful
work through externally enforced capabilities. Keep the Python security core,
Pi adapter, installers, broker, sensors, collectors, verifiers and pinned
dependencies. No runtime rewrite, second runtime campaign, generic framework,
Phase 4 expansion or speculative refactoring.

The first useful pilot is fabricated numbers → one OpenAI Responses model call
→ one authorized JSON-file creation → independent output/effect verification.
The model, trust/address profile, key setup and spending bound still require
operator approval. Pi must never receive the key or general network access.

Already implemented offline: protected launch and service configuration,
independent source-observer/gate components, inventory preparation, provider
listener/native dispatch and additive START, one-shot completion/retirement,
held credential/profile custody and activation-bound approval. Batch 21 passed
122 distinct new/affected checks once, with zero reruns. The managed qualification
entrypoint passed its 43 focused checks once in batch 16. Reuse those exact
successes only while their complete fingerprints are unchanged.

These are source-level accomplishments, not installed-view, consumed-source,
sensor-health, kernel-enforcement, timing, useful-pilot or qualification proof.
The default provider-unavailable path remains fail closed.

## 3. Execute in dependency order

### D2 — close the common connected path first

1. Inspect the actual managed bootstrap and its installed inventory/observation
   callers. Assemble one common changed-artifact successor from existing
   components; preserve predecessors. Fix missing caller connections before
   adding more disconnected helpers.
2. Complete preparation and validation of exact installed protected inventories.
   Actual read-only installed views must bind source, loader/interpreter,
   configuration, policy, admitted bundle, process and unit invocation to the
   same deployment/activation. A writable checkout or future mount specification
   is not installed evidence.
3. Connect genuine fresh root request observations and meaningful sensor
   progress/loss accounting to the existing mediator. Batch 21 checks preexisting
   observation structure, not attribution for the future activation. Missing,
   stale or incomplete health must prevent protected work.
4. Preserve source-consumption semantics: trusted services verify and execute
   the same pinned bytes; the protected out-of-process observer independently
   witnesses worker loading against immutable file/process identities. Worker
   self-reports and `/proc` hashes alone do not qualify consumed source. Do not
   turn file-read evidence into claims about arbitrary in-memory JavaScript.
5. Complete recovery and full end-to-end timing collection using existing
   collectors/independent consumers. Preserve cancellation, permanent replay
   claims, ambiguous effects and ownership-safe cleanup; never retry an effect
   automatically.
6. Prepare a precise pilot readiness packet. Under separate authorization only,
   install the exact candidate in the dedicated owned VM, verify prerequisites,
   run calculate-and-save, independently verify output/effect, and demonstrate
   changed-byte and unauthorized-target refusal in separate owned contexts.
   Exercise necessary recovery and retain actual timings and cleanup evidence.

Do not hide these concrete unresolved feasibility questions:

- Enabled lifecycle currently requires **systemd 257 or newer**. Observe the exact
  manager credential directory absent before provider start and after exit.
  Residue preserves a cleanup hold; never delete or adopt it to obtain a pass.
- Verify actual credential delivery, protected inventories and Node loading.
  Matching systemd IP properties is **not** proof of effective kernel/cgroup
  filtering. Required enforcement must be demonstrated in the authorized VM.
- Existing request/approval authority lasts **at most five seconds, including
  service startup**. Preserve its absolute times: no renewal, widened deadline,
  hidden retry or omitted startup timing to make it pass. If the mandatory path
  cannot meet the approved contract, stop with the exact property and smallest
  proposed remedy for an operator decision.

D2 closes only with independently evidenced useful output, authorized effect,
necessary denials, consumed-source identity, required health, actual full timing
and cleanup. A successful bootstrap does not close D2.

### D3 — parallel source lanes, one shared deployment

Release dependency-ready offline work during D2. Coordinator owns shared callers,
contracts, registry, inventories/pins, scheduling, integration and delivery. Each
lane receives exact writable paths, interfaces, failure semantics, required raw
evidence, independent consumer and proposed focused checks. Use nonoverlapping
ownership and the repository's signed assignment/release process.

| Lane | Finish the connected requirement paths |
| --- | --- |
| Admission | Managed install/update/restart; exact bytes; write/rename/symlink protection; discovery/reload/unsupported-loader denial; policy failure and tampering. |
| RUN/health | Actual protected acquisition and complete loss accounting; all seven event classes and six responses, including context mutation, process-tree containment, digest quarantine and future-start denial. |
| Workloads/verifiers | HTTP/DNS/truncate/unlink; genuine unattributed destructive control; independent sink observations; cancellation; real baseline/instrumented task execution. |

Existing lane paths are `../aragorn-phase3-admission`,
`../aragorn-phase3-run-health` and `../aragorn-phase3-workload-verifiers`.
Their presence does not establish readiness. Inspect ownership, ancestry and
drafts before reuse; do not reset, cherry-pick away signed ancestry or mutate
an active owner's worktree. Internal agents may use explicit disjoint files in
the coordinator checkout. Lanes do not independently schedule checks or push.

Reuse integer sum, line count, SHA-256 and allowed-file copy/readback tasks and
verifiers. Connect actual equivalent baseline/instrumented contexts; do not build
another collector. Unknown loss is not zero loss; a refusal-only broker is not a
positive useful path. D3 closes only when required producers, retained raw
evidence and independent consumers are connected on the common deployment.

### D4 — finish evidence consumers and freeze, not another checker

Reuse `qualify_pi_core_phase3_exit` and `pi-core-managed-phase3/v1`: exactly
29 `MP1/` logical requirements, all 12 surface groups, complete concrete
source-bound supported/denied surfaces and seven deployment bindings. Preserve
the original 48-ID/OpenClaw contract unchanged.

Complete and independently review the producer → raw evidence → semantic
consumer inventory throughout D2/D3. There is no default production verifier
registry: wire real independently chosen source-pinned consumers. Source hashes,
inventory shape and synthetic PASS callbacks cannot establish semantic coverage.
Keep missing/extra/duplicate IDs, N/A shortcuts, mixed deployments, unpinned
verifiers, forged PASS records and incomplete surfaces rejected. Pin reference
task sources independently of the evidence being judged.

Resolve every mandatory prerequisite, review the full inventory and freeze one
deployment once. D4 remains open until those obligations are genuinely met.

### D5 — separately authorized fresh qualification

After prerequisite closure, freeze and explicit final-run authorization, serialize
all live captures and measurements on that deployment:

- Run the complete managed admission surface inventory. **29 requirements are
  not 29 cases; the historical 31-case campaign is not the Pi inventory.**
- Acquire **100 actual attempts**: HTTP25, DNS25, truncate25, unlink25, including
  the genuine unattributed destructive control.
- Require attribution **≥99%**, and **100% residue-free pre-effect blocking
  separately for exfiltration and destructive families**.
- Require nearest-rank p95 **<500 ms** over full
  `REQUEST_ACCEPTED → DECISION_FINALIZED` intervals in the validated
  `CLOCK_BOOTTIME`/time-namespace domain.
- Execute **100 actual baseline/instrumented pairs**, 25 per existing task,
  equivalent inputs/fixture state, baseline first without overlap. Use full task
  boundaries; aggregate overhead must be **<10%**:
  `100 × instrumented_total < 110 × baseline_total`.
- Retain failed/indeterminate samples. No replacements, synthetic final samples,
  dropped timing segments or inference of residue-free blocking from restored
  files. Verify cleanup and prior-state restoration, then independently replay
  retained evidence offline.

Only a complete pass establishes **Pi-core managed-profile Phase 3 qualification**,
not OpenClaw compatibility, universal EDR coverage or production-release readiness.

## 4. Continuous-run controls and delivery

- Use only new/affected stages through `scripts/phase3_pipeline.py` with reviewed
  closures in `benchmark/phase3-pipeline-v1.json`. Review before executing. Reuse
  exact unchanged successful results; do not rerun checks merely because a new
  batch or merge occurred. Documentation-only batches need no behavioral tests.
- Preserve failed/timed-out/interrupted fingerprints. Diagnose and fix the actual
  cause before any affected rerun; never erase records or alter irrelevant inputs
  to unlock a retry. No broad regression, historical recapture or whole-schema
  sweep per batch. Offline synthetic developer fixtures are not final samples.
- After each completed reviewed batch: stage explicit batch-owned paths only;
  make and verify a signed commit; safely integrate with a verified signed merge
  into `main`; keep the coordinator branch caught up; normal-push and read back
  exact remote hashes. Preserve unrelated work and original signed lane ancestry.
  No empty/unsigned commits, force-push, branch-protection bypass or releases.
- Serialize live work. Use only newly necessary checks in the exact authorized,
  owned disposable fixture with bounded runtime, isolation/prerequisite guards
  and verified cleanup/restoration. Provider egress is only the explicitly
  approved exception. Never activate host services or test third parties.
- Continue independent source work while operational authorization is missing;
  do not pretend the missing gate is satisfied or loop on status-only checks.
  When no further dependency-ready authorized work remains, give one precise
  consolidated blocker/request and stop. Do not promise success against an
  unproven mandatory property.
- At each meaningful milestone, report signed source/merge hashes, remote
  readback, new/reused check counts, retained failures, connected paths completed,
  concrete remaining blockers and numbered D2–D5 status. Distinguish implemented,
  locally checked, actually observed and qualified. Do not launch another
  automation or require a manual continue for ordinary in-scope batches.

## 5. Operator gate — still unsupplied

Before any VM installation/activation or useful pilot, obtain and record:

1. Exact fresh dedicated Linux arm64/systemd VM identity and ownership authority,
   supported systemd/kernel prerequisites, fixture and restoration plan.
2. Approved OpenAI model, exact provider address/trust/CA profile and narrowly
   scoped egress; do not choose current provider addresses from old fixtures.
3. User-controlled key setup through the existing protected service credential
   mechanism. Never ask for the secret in chat or print, copy or commit it.
4. Explicit spending bound, operation/request limits, permitted pilot cases,
   runtime bounds and authorization to execute that exact pilot.
5. Separate D5 execution authorization after D2–D4 closure and freeze.

No live authorization is conveyed by “one-shot,” “finish,” commit/push authority,
this document or an offline PASS. Preserve all existing operational/cleanup holds.

## Remaining plan at handoff

1. **D2:** installed inventories; genuine observation/health; credential, Node and
   kernel-enforcement feasibility; recovery/full timing; separately approved pilot.
2. **D3:** remaining connected admission, RUN/health and workload coverage.
3. **D4:** complete real independent-consumer/surface inventory and freeze.
4. **D5:** authorized fresh acceptance, actual measurements, cleanup and replay.
