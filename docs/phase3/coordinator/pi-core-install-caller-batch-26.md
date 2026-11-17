# Pi-core batch 26: managed materialization and native failure evidence

Base: verified signed and published
`da4e1fef3d2a7d81c65c5d9725768513b625aab6` (source `df72bbd`).
Status: offline implementation assignment only; no installation or live operation.

## Requirements and ownership

The existing Pi fresh-start caller consumes protected context v2 and immutable
lineage, but the operator install/update caller still pins the legacy target.
Connect managed materialization to those existing consumers for MP1 install,
update, exact bytes and restart. Do not rebuild discovery/restart frameworks or
relabel old OpenClaw probes. Preserve current supported bundle bounds; executable
scripts and descendants remain a separate D3 gap, not automatically qualified.

1. `handoff_gate_review` owns new `src/aragorn/pi_core_bundle_install_entry.py`
   and `tests/test_pi_core_bundle_install_entry.py` only.
2. `timing_recovery_review` owns `src/aragorn/pi_core_native_supervisor.py` and
   new `tests/test_pi_core_native_failure_evidence.py` only, for the existing
   held-launch teardown evidence-loss dependency under MC-09/MC-12.
3. `inventory_dependency_review` independently reviews both lanes and root
   composition, read-only. Provider evidence-sink/request publication design is
   retained for the next dependency-ready batch, not implicitly released here.
4. Coordinator owns `packaging/pi-core/coordinator.py`, new
   `tests/test_pi_core_bundle_install_dispatch.py`, the narrow native-exception
   consumer in `src/aragorn/pi_core_managed_bootstrap.py` with new
   `tests/test_pi_core_native_failure_composition.py`, docs, registry/capacity,
   checks, signed integration and publication.

Lanes do not execute tests/import probes/builds/target programs, mutate Git, use
services/VMs/providers or alter other worktree drafts. Independently reviewed
input closures precede all execution through the existing pipeline.

## Fixed managed install/update route

Add literal `--install-bundle` before the existing five root arguments; no
command/module/callback selector. Reuse the same protected host and source
loader before importing fixed `aragorn.pi_core_bundle_install_entry.run` with
the established plan-pin/deadline/source-loader/host-custody signature.

Plan schema `aragorn/pi-core-bundle-install-plan/v1`, exact fields:

- `schema`, `host_profile_digest`;
- `context`: independently pinned `{path,digest}` for an existing valid
  `protected-install-context/v2`, never a synthesized ALLOW or fixture issuer;
- `candidate_cas_root`, `predecessor_cas_root` (null for install; independently
  retained read-only predecessor CAS for update);
- `deployment` and `launch`: protected `{path,digest}` references;
- `runtime_conformance_digest` and `revocations`: protected `{path,digest}`
  reference with exact `protected-install-revocations/v1` context-ID inventory.

Operation, target and expected predecessor come only from verified context v2;
allow install/update, not rollback/force/reload. Destination is fixed to
`/var/lib/aragorn/admitted`; independently expected device/inode come from that
context's destination. This route issues no context, grant, activation or START.

Reuse root `_Inputs`/`_custody`, require this entry's consumed-source row, open
candidate/predecessor CAS read-only, and preserve original at-most-30-second
deadline. Hold prepared input and CAS ancestry. Hold destination parent ancestry,
then the no-follow root handle with exact approved device/inode and protected
owner/mode. Do not compare self-mutated root mtime/size as an external pin.

Bind context policy to deployment.policy and runtime/conformance to independently
approved plan pins. Reuse actual protected OS/runtime `_tree`, compiled receipt
`_runtime_inventory` and `confined_configuration_digest` checks; join these to
the existing seven deployment declarations without claiming unmeasured dimensions.
Preserve current Pi materialization bounds (64 files, 1 MiB total, supporting
depth at most one directory, nonexecutable files, UTF-8 SKILL.md at most32KiB).
Unsupported inputs refuse before mutation. Validate fresh context/revocations
and existing exact bytes/decision semantics, not caller boolean claims.

Acquire the exact owned destination's exclusive lock nonblocking before invoking
existing `protected_install_v2._publish_protected_install_transaction` once.
Reuse its quarantine, active predecessor, durable claim and recovery semantics.
The fixed local preclaim function rechecks held inputs/current revocations and
original deadline and returns fresh wall time; no supplied callback. Preserve
any recovery record. Nested publisher locks share an open-file description and
may unlock it; explicitly reacquire nonblocking for post-return readback or keep
unknown custody. No automatic publisher, lock-wait, cleanup or effect retries.

## Entry result and public projection

Result schema `aragorn/pi-core-bundle-install-result/v1`, authority
`PROTECTED_MATERIALIZATION_ONLY_NOT_ACTIVATION_OR_PHASE3`; success is
`INSTALLED_NOT_ACTIVATED_OR_QUALIFIED`. Other statuses are
`REFUSED_OR_INDETERMINATE` or `CLEANUP_HOLD`.

Reuse common root fields: host/source before/after, plan/deployment digests,
owned_inputs_closed, input_cleanup_uncertainty, phase3_exit_eligible false,
managed_call_attempted false and managed_result null. Add context_digest,
installation_attempted, owned_destination_closed, publication_state
(`NOT_ATTEMPTED`, `PUBLISHER_RETURNED`, `RECOVERY_RECORD_RETAINED`, `UNKNOWN`),
transaction and recovery. The last two are private existing publisher records
or null; no replacement transaction format. Exception `.observation` retains
the same structure. Any escaped attempted-publisher failure stays a cleanup/
recovery hold; missing recovery metadata never proves the context unconsumed.

The CLI emits fixed bounded custody/status metadata plus canonical transaction,
recovery and cleanup-uncertainty digests, never raw plan/publisher/task content.
Outer host/source/descriptor cleanup failure cannot become install success.

## Native producer and managed consumer

Retain the existing native supervisor result before exiting the held launch
scope, then return only after clean scope exit. If that exit fails, attach
`pi_native_supervisor_observation` to the same escaping exception using existing
`aragorn/pi-core-native-supervisor-result/v1` and authority. Preserve already
collected terminal/cleanup records; top status is CLEANUP_HOLD with fixed
failure-stage metadata for uncertain held-plan cleanup. Do not repeat cleanup,
erase ambiguous effects or replace the original exception while snapshotting.
If no valid terminal result exists, keep unknown evidence, not a fabricated one.

Managed composition consumes only this fixed producer attribute/schema/authority
at the direct native call boundary and snapshots it before service cleanup can
replace the exception. Its existing partial-result/root/public-projection route
then preserves that record. Do not adopt arbitrary exception attributes as
authority or expand report ceilings. This remains in-process evidence, not
durable capture or independently verified cleanup.

## Verification and continuous delivery

Use new focused entry/dispatch/native/composition stages with only selected
affected cases. Include inert actual existing install/update publisher and Pi
launch-consumer composition where feasible, exact predecessor/replay/quarantine,
changed policy/runtime/config/root/source, stale/revoked preclaim, busy lock,
ambiguous publication/close, and same native exception with retained terminal
evidence. No full historical admission or native suite. Do not discover imported
fixture test classes. Retain failures and fix actual causes before any rerun.

After completed review/checks: signed source commit, verified signed main merge,
normal push, exact remote readback. Preserve all unrelated drafts and evidence.

1. **D2:** managed install/update and native failure propagation are this batch;
   provider raw capture/fresh observations, actual views/global health, timing
   and separately approved useful pilot remain.
2. **D3:** remaining connected admission, declared scripts/descendants, RUN/health
   and workload paths remain, with common-deployment evidence required.
3. **D4:** complete actual semantic consumers/surfaces and freeze remain.
4. **D5:** separately authorized fresh acceptance/measurements/cleanup/replay.
