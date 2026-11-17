# Pi-core batch 30: fresh action-broker base installation

Base: verified signed source `b075a88a8f1f9f3209c260239c8055dfb250bd1b`, signed
main merge `e2626c31d1648baa5d577e300af267c7130d6b72`. Both remote branches
read back exactly. Batch 29 passed 111 distinct focused checks; only its
14-check wrapper stage reran after a reviewed fixture assertion correction.
All 985 unrelated drafts remain. No live installation or activation is authorized.

## Missing connected prerequisite and ownership

The explicit protected grant-preparation caller now exists, but its action-owned
base roots, lock and current empty broker state have no Pi installer. Existing
OS/service/configuration installers cover immutable code/configuration only.
Complete a fixed absent-only base installer and connect it to the existing root
preparation entrypoint. Do not create another grant initializer or collector.

1. `timing_recovery_review`: new `src/aragorn/pi_core_broker_base_provision.py`
   and `tests/test_pi_core_broker_base_provision.py` only.
2. `handoff_gate_review`: existing `src/aragorn/pi_core_broker_preparation_entry.py`
   and new `tests/test_pi_core_broker_base_entry.py` only; additive fixed base
   installation branch, reusing its custody/admission/cleanup flow.
3. Coordinator: fixed wrapper selector/report and new
   `tests/test_pi_core_broker_base_wrapper.py`, exact affected fixtures if needed,
   registry, reviewed scheduling, documentation and signed integration.
4. `inventory_dependency_review`: independent read-only review of source/callers,
   focused checks and exact input closures. No implementation ownership.

Lanes do not import repository modules, run checks/builds, activate anything or
perform Git operations. Begin coding only after this contract is signed/published.

## Fixed installer interface and custody

`provision_pi_broker_base(*, configuration, base_state, base_state_digest, deadline)`
accepts the exact held `PiServiceConfiguration`, derives action UID/GID from its
validated static joins, and uses only fixed `/var/lib/aragorn-runtime-action`.
Require Linux root, original bounded deadline and repeated held-configuration
guards. The operator's canonical base input must independently match its digest,
parse exactly as the current broker v2 state (no migration), have positive
revocation-generation and mediator-health-epoch floors, empty consumed list and
null effect journal. These floors are freshness constraints, not evidence of
current policy or healthy telemetry. No default values or generated authority.

Open the existing protected `/var/lib` parent with no-follow descriptor custody;
require the entire fixed destination absent. Create a root-owned non-writable-by-
others outer directory (0755), action UID/GID control/protected roots (0710),
staging (0700), empty exclusive broker.lock (0600), and canonical state.json
(0400) only. Reuse existing descriptor-relative exclusive-create, complete-write,
fsync, ownership, inode and independent readback primitives. Do not use migrating
`_load_state`, replacing `_atomic_publish_at`, or control publishers that require
preexisting state. Require exact final tree/file inventory and same-filesystem
protected/staging roots. Close only owned descriptors once; preserve partial
destinations and uncertain cleanup. Never adopt, repair, delete or retry.

Return schema `aragorn/pi-core-broker-base-installation/v1`, authority
`FRESH_BASE_CONTROLS_ONLY_NOT_POLICY_HEALTH_GRANT_OR_PHASE3`, status `INSTALLED`
only after readback/owned-handle cleanup; otherwise retain `REFUSED`,
`PARTIAL_OR_INDETERMINATE`, or `CLEANUP_HOLD` on the original exception through
`pi_broker_base_observation`. Include configuration/base-state digests, fixed
destination, actual installed identities/readback, `mutation_attempted`,
`owned_handles_closed`, and false `activation_performed`, `service_ready`,
`current_grant_authority`, `phase3_exit_eligible`. Keep bounded raw evidence.

## Existing root caller and fixed CLI

Reuse `pi_core_broker_preparation_entry.run` with strict local
`install_base: bool = False`; only a literal `--install-broker-base` wrapper route
sets True. No incoming command negotiation, arbitrary destination, shell, module,
role, privilege switch or generic operation framework. Existing preparation
callers/default behavior remain unchanged. Existing five independently pinned
wrapper arguments remain unchanged.

Base-installation plan is the existing coordinator plan plus exactly one
`broker_base_state` canonical path/digest reference. Read it through `_Inputs`;
strip only that known extra field before the unchanged `_plan` validator. Default
preparation rejects the extra field. Require UNAVAILABLE/provider null. Hold the
same runtime/configuration/public inputs and admitted bundle before calling the
installer once; independently verify consumption of the pinned installer source
module at this boundary. Never start action/sensor/provider/worker or call the
grant initializer during installation. Post-call custody and outer cleanup
remain required before public success.

Installation root result schema `aragorn/pi-core-broker-base-result/v1`, authority
`PROTECTED_BASE_INSTALLATION_ONLY_NOT_ACTIVATION_OR_PHASE3`; success
`BASE_CONTROLS_INSTALLED_NOT_READY_OR_QUALIFIED`. Use explicit
`base_installation_attempted` and `base_installation_result` alongside common
root-custody metadata. Preserve original partial/failure evidence through outer
cleanup. The wrapper produces bounded digest-only metadata; raw controls/state
and exception text are never public. Preparation remains a separate later call.

## Checks, delivery and gates

Only new/affected focused stages: exact input/identity substitution; malformed,
migrating or nonempty state; symlink/existing/partial destination refusal;
no-follow/exclusive creation; changed config/parent/file readback; short writes;
deadline/cancellation; failure retention and close uncertainty; root selector,
admission/custody and no service/init activation. Review closures before pipeline
execution; retain failures and reuse unchanged passes. No redundant rebuild or
whole suite. Signed source/main merge, normal push and exact remote readback after
the completed reviewed batch.

1. **D2:** base installation caller connected offline; separate provider controls, actual
   installed views, genuine global health, raw action evidence/full timing and
   separately authorized useful pilot remain.
2. **D3:** remaining connected admission, RUN/health and workload coverage.
3. **D4:** complete independent verifier inventory/prerequisites, then freeze.
4. **D5:** separately authorized fresh acceptance, measurements and cleanup.

## Reviewed implementation checkpoint

The fixed `--install-broker-base` route now selects the existing protected root
entry's additive local installation branch. It reads the pinned base-state
reference, holds the existing runtime/configuration/public/admitted-bundle
custody, verifies consumed installer source, invokes the fresh-only installer
once and preserves failure evidence through post-call and outer cleanup. Default
grant preparation rejects installation-only plan fields and remains separate.

The installer creates only the fixed base tree under protected parent custody,
keeps the root inaccessible until its empty contents are written, independently
reads back exact names/bytes/identities, and retains reached created-member and
readback prefixes on failure. Existing/partial/symlink targets are never adopted,
repaired or deleted. No policy, health, observation or AVAILABLE grant is emitted.
Public wrapper output is bounded metadata/digests only.

Independent source/caller/fixture/closure review preceded the single pipeline run.
**All 81 checks passed once: 69 new and 12 affected. No reruns.** The three input
closures contain 95/98/115 files; registry capacity is now 221. All unchanged
historical stages were left alone, including the retained batch29 failed result.

| Stage | Checks | Retained passing fingerprint |
| --- | ---: | --- |
| `pi-core-broker-base-provision-offline` | 30 | `e1e3f8f3e7c31f006b5bcaede01817b0bdb6aad7f8d1ebc4e360bf3c1216af60` |
| `pi-core-broker-base-entry-offline` | 31 | `c060d3dcc50eb2ae4a353287cfb0bfed542d998febf283808e1a8cb1e242e5cd` |
| `pi-core-broker-base-wrapper-offline` | 16 | `19871ac8f7642a77fd2ee949692dab845b935f205937446a1bbf21b657f30d5e` |
| `pipeline-capacity` | 4 | `e80e1b3f9d9478f1bb361b115816e8a2f5ea5baf735295e39e34a5b24af622c6` |

Raw developer logs remain under `.aragorn/phase3-pipeline/<stage>/<fingerprint>/`.
The installer checks used owned temporary trees with simulated Linux/root and
role identities; they do not prove installed Linux ownership or enforcement.
No broad regression, target build, VM/service/provider activation, live capture
or qualification ran. All 985 unrelated drafts and frozen predecessors remain.
Verified signed source/main merge hashes and exact remote readback are recorded
in the milestone and next batch base, without self-referential commit hashes.

D2 still needs actual installed-view preparation, genuine global health and full
loss coverage, separate provider control inputs, action raw-effect/full-timing
retention, recovery and the separately authorized useful pilot. D3 coverage,
D4 semantic inventory/prerequisites/freeze and D5 fresh qualification remain open.
