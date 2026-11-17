# Pi-core batch 27: actual provider observation and retained evidence

Base: signed source `f570f5134708af91d3fa2f789bd18899e0be46e3`, signed merge
`09fe25fd3a533b5e2d735f660bad258ebb10a70f`. Both remote branches were read back
at that merge. Batch 26 passed 111 new/affected checks once; all 985 unrelated
drafts remain. This assignment authorizes offline source work only.

## Connected dependency and ownership

D2/MC-09 and MC-12 need actual provider-request attribution, retained raw source
and decision inputs, and honest cancellation evidence. The native path already
authenticates the worker/activation, holds lineage and challenges the independent
Node observer. The mediator currently discards returned challenge snapshots and
evaluates an old observation instead of publishing the actual acquired request.
Do not create another collector or refresh global health from that observation.

1. `handoff_gate_review`: new `src/aragorn/pi_core_provider_evidence.py` and
   `tests/test_pi_core_provider_evidence.py` only. Fixed held CAS retention.
2. `timing_recovery_review`: new `src/aragorn/pi_core_provider_observation.py`,
   `src/aragorn/pi_core_provider_approval.py`, and new
   `tests/test_pi_core_provider_observation.py` only. Actual request publication
   and inactive pre-start observation support, without health fabrication.
3. `inventory_dependency_review`: independent source/input-closure review and
   producer-to-existing-verifier inventory, read-only. No qualification callback
   that merely checks shape or echoes a supplied PASS.
4. Coordinator: mediator/native caller integration in
   `src/aragorn/pi_core_provider_mediation.py` and
   `src/aragorn/pi_core_native_provider.py`, the consumed publisher-source join in
   `src/aragorn/pi_core_coordinator_entry.py`, new focused composition tests,
   registry/capacity, docs, scheduling and signed delivery.

No lane executes tests, imports repository code, builds targets, modifies Git or
activates anything. Release coding only after this contract is signed/published.
Review changed callers and exact input closures before coordinator execution.

## Fixed raw-evidence store

`hold_provider_evidence(config, control_fd, *, activation, deadline)` yields a private owner
whose `retain(kind, value)` canonicalizes one actual acquired JSON record and
returns `{kind,digest,bytes}`; `observation` returns detached storage status,
references and fixed uncertainty metadata, never raw content. `kind` is a fixed
finite producer label, not a pathname. There is no activation/qualification
authority. The owner is not an effect-retry mechanism.

Borrow, do not close, the exact already-held root provider control descriptor.
Hold its protected ancestry and the fixed existing child
`provider-evidence/blobs/sha256`, root:root 0700, no symlinks or replacement.
Absence refuses; this caller does not provision control/store directories.
Pin mutable-safe device/inode/mode/uid/gid, not self-mutated size/mtime. Check
held/named ancestry and original deadline around every store/readback operation.

Reuse CAS `put_expected` and verified reads through a narrow private held-root
adapter. Duplicate the held SHA directory; do not reopen an unpinned path.
CAS's normal shard creation is allowed inside this owned store. Initial CAS
root/internal preparation must only validate existing custody. Record the actual
temporary filename allocated by the existing writer; after return require its
absence because CAS suppresses temporary-unlink errors. Preserve ambiguous
temporary/blob state without deletion/retry. Explicitly verify durable readback
even for an already-present digest. Close each newly owned handle once; unknown
close state remains a cleanup hold. Never guess or re-close an uncertain fd.

Before permission, create one absent-only `attempt-<activation_id>.jsonl` index
inside the held evidence root. Derive its name only from the validated actual
activation. Open exclusive/nofollow, root:root 0400; retain the writable owned
descriptor for this attempt only. Fsync the header and directory, then append
one bounded canonical reference line and fsync after each successful blob
readback. Pin the held/named index and verify exact acquired prefix. Failure or
partial append is retained, not rewritten, deleted or resumed. Existing index
means no automatic retry. This locates durable blobs after an interrupted caller;
an incomplete index is not a completed capture or cleanup receipt. Per-index
bound is 64 KiB; no record body, prompt, completion or key is stored in the index.

Maximum per record remains 4 MiB; at most 64 records per attempt. The fixed kinds
are `SOURCE_HEALTH`, `REQUEST`, `ACTIVATION`, `MEASUREMENT`, `LINEAGE`, `APPROVAL`,
`POLICY`, `REVOCATIONS`, `GLOBAL_HEALTH`, `OBSERVATION`, `DECISION`,
`SERVICE_REQUEST`, `SERVICE_CHECK`, `SERVICE_PERMIT`, `SERVICE_RESULT`,
`PROVIDER_RESULT`, `SOURCE_BOUNDARY`, `FAILURE`. No credential/header secret enters this path.
Return compact refs under existing report ceilings; never widen those ceilings.

## Actual request observation

`publish_provider_observation(control_fd, config, *, request, approval,
activation, measured, lineage, grant, source_capture, boundary_boottime_ns,
now_unix)` returns the actual new observation. It owns no lock or descriptor:
the mediator already holds worker, lineage, broker-lock and source custody.

Reuse existing request/approval/activation/lineage validators and the broker's
fixed runtime-action observation format. Derive active and measured-action
fields from the actual accepted request and measured activation/lineage, never
worker-supplied attribution. Join the exact policy sensor pin to the retained
grant; this label is not independently measured producer-code identity. Before
the protected managed call, coordinator requires the exact new publisher module
in the existing loader's consumed-source rows with its independently pinned
source digest. Preserve that source record and host/deployment joins for replay;
do not infer source identity merely from a copied `sensor_digest` field.

Require the actual Node owner's returned v2 HELD snapshot, matching worker,
deployment/runtime/executable and clock identities, complete retained loss/read
accounting and a fresh final CHALLENGE. Preserve the existing 100 ms challenge
budget, unique nonce, all-task stopped/progress proof and at-most-200 ms boundary
age. Pending ordinary waits/classified IO are not missing syscall evidence; do
not require an incorrect zero for every pending syscall. Full independent replay
remains the existing Node-source verifier's responsibility, not a new live replay.

Read and validate the existing observation anchor; never create one from absent
or corrupt state. Advance its sequence once with `_publish_control_locked` for
`observation_path` only. Keep issue/expiry within the existing action/observation
limits. Do not use `_publish_observed_state_locked`, renew global health, alter
replay state, or mint an ALLOW. The normal broker decision still follows and
must refuse missing/stale/incomplete global health or revoked authority.

Approval pre-start readiness accepts an existing fully inactive observation only
when both `active` and `measured_action` are null; populated records retain their
old validators, and a half-populated record refuses. Require its sensor pin to
match current policy. All policy/revocation/global-health checks remain intact.

## Coordinator integration and evidence consumers

Open the evidence owner under the existing control lock before policy/effect
permission. Retain actual canonical request, activation, measured identity,
lineage, approval and exact current policy/health/revocation records. Preserve
returned source snapshots at PRE_POLICY and immediately before CONNECT/SEND
permits, each with actual boundary clock/challenge metadata. Store before granting
permission; a failed store cannot authorize submission. Retain the published
observation, actual decisions, authenticated service packets and terminal result.
Never retain Authorization headers or credentials. A locally rendered request
body is not independently observed HTTP traffic.

Keep old guard checks; no automatic challenge/effect retry. Any evidence failure
after attempted service submission stays INDETERMINATE. Global health remains
independent of source acquisition. Root request publication does not qualify all
seven RUN event classes or six responses.

Attach fixed `pi_provider_mediation_observation` on cancellation before rethrow,
using the existing mediation schema plus compact retained-evidence metadata.
The native caller consumes that exact private record at the direct call boundary
before accepted-stream cleanup can replace the exception. Unknown cleanup and
unretained raw evidence stay explicit. No second request, permit or cleanup.

Existing `verify_pi_node_source_observation` consumes each retained source blob
with independently pinned expected profile/inventories/worker/clock/gate/root
peer/challenge/boundary values. Existing broker semantic decision machinery
consumes retained actual control snapshots. Inventory all missing joins honestly;
storage success, replay shape or declared pins do not close D4. No synthetic
sample is promoted to pilot or qualification evidence.

## Verification, delivery and remaining plan

### Completed offline implementation

The protected provider-service path now publishes the actual acquired request,
retains the raw inputs and decisions in the existing CAS, and preserves compact
storage/cancellation evidence through the native caller. Legacy non-service
mediation remains unchanged. The root entrypoint joins the publisher module to
its independently pinned consumed-source record before managed execution.

The evidence index retains a `pending_reference` for an attempted/unindexed blob;
that reference is not a successful durable append. `CLOSED` means the acquired
index prefix and owned handles closed successfully, not a complete capture.
Source snapshots have pre-permission storage boundaries and separate final
freshness-check boundaries. The latter are retained after publication or permit
delivery and are not independently observed HTTP-send timestamps. Successful
permit delivery is counted before subsequent retention can fail. All cleanup
owners are invoked even when an earlier owner reports uncertainty.

Coordinator-owned affected fixtures are `test_pi_core_coordinator_entry.py`,
`test_pi_core_provider_egress.py`, `test_pi_core_provider_mediation.py` and
`test_pi_core_source_health_enforcement.py`. They now provide complete inert
acquired records and return the source guard's actual snapshot. New composition
and failure-retention files explicitly select only their new/affected methods.
The source-boundary helper is `validate_provider_source_capture`; it validates
the acquired final challenge and accounting without claiming full replay.

All **126 checks passed on their first execution: 106 new and 20 affected**.
No failed fingerprint or retry was introduced. Exact input closures were reviewed
independently (92/98/103/98 paths); pipeline capacity is 210, not a suite expansion.

| Stage | Checks | Successful fingerprint |
|---|---:|---|
| `pi-core-provider-evidence-offline` | 37 | `b39f7ee73064504adcbb57ab15e2228861fd2a0f29cd11bff91a8a5a4ccdeefb` |
| `pi-core-provider-observation-offline` | 42 | `9233bd0aca392306205eac4051de7be96e61e047795ba0764ca21749f2793d5a` |
| `pi-core-provider-evidence-composition-offline` | 25 | `e067c50ce45a634b27adadfbb73d48fc824ceb53793cf8508966ad9d713256bd` |
| `pi-core-provider-failure-retention-offline` | 18 | `5005fa93874e319e0ca1347315d5458ddb59fff78846008f1ec5c7253df055ef` |
| `pipeline-capacity` | 4 | `2ab3eb876afe7dd80770ac88be519efc0c4a12f90648acf0d9f77b245f697c43` |

Retained pipeline records are under `.aragorn/phase3-pipeline/<stage>/<fingerprint>/`.
Execution used local Python 3.14.6, not the Linux deployment. No target execution,
build, installed materialization, provider call, live operation or qualification ran.

### Producer to existing consumer inventory

- `SOURCE_HEALTH` plus `SOURCE_BOUNDARY`: existing
  `verify_pi_node_source_observation`, with independently pinned expected worker,
  profile, inventories, gate, clock, root peer, endpoints and challenge/boundary.
  Root publisher consumption is separate evidence; the policy sensor label is
  not code identity. These acquired rows do not close full RUN/global health.
- Actual policy/revocation/global-health/observation and `DECISION`: existing
  `evaluate_runtime_action`, retaining the evaluated time and required floors for
  a canonical result comparison. Replay-state/claim-state joins remain open.
- Authenticated service packets: existing packet/codec validators check syntax
  and binding, not external network traffic or effect absence. Rendered payloads
  and authenticated results do not replace independent HTTP/effect observations.

Real acquisition, complete global loss accounting, external effects, full timing
and the complete independent semantic inventory remain prerequisites. No retained
unit fixture or shape-valid packet is promoted to pilot or D4/D5 evidence.

New/affected stages only: exact raw CAS/readback and custody refusal; request
publication from acquired identity; stale/foreign/incomplete source snapshots;
inactive anchor versus malformed/absent state; unchanged global health; provider
submission/permit ordering; source/evidence failure; cancellation and ambiguous
cleanup. Reuse exact unchanged successes, retain failed fingerprints and repair
actual causes before affected reruns. No broad suites, target rebuilds or live
operations. Publish verified signed source and main merge; push normally and
read back both exact remote hashes after the reviewed batch.

1. **D2:** this batch connects actual provider observations/raw retention;
   concrete installed views, genuine global health, recovery/full timing and the
   separately authorized useful pilot remain.
2. **D3:** remaining connected admission, RUN/health and workload coverage.
3. **D4:** complete independent semantic inventory/prerequisites, then freeze.
4. **D5:** separate authorization for fresh acceptance, measurement and cleanup.
