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

1. **D2:** base installation caller next; separate provider controls, actual
   installed views, genuine global health, raw action evidence/full timing and
   separately authorized useful pilot remain.
2. **D3:** remaining connected admission, RUN/health and workload coverage.
3. **D4:** complete independent verifier inventory/prerequisites, then freeze.
4. **D5:** separately authorized fresh acceptance, measurements and cleanup.
