# Pi-core batch 25: preserve connected failure observations

Base: verified signed and published
`c8e81b32cf9b1d5cba6f3f8c41bf79ae83abe4ce`.
Status: offline source assignment; no live operations authorized.

## Named dependency and scope

D2 recovery/evidence and MC-09/MC-12 require preserving observations already
obtained when a later owner fails. Today `run_native_pi_service_bootstrap` can
lose a returned worker result when service cleanup raises. Its fixed root caller
likewise does not consume partial managed observations attached to failures.
This batch repairs that connected propagation path without adding a collector,
storage format, effect retry, activation permission or qualification claim.

Existing service lifecycle observations and the managed-result schema are reused.
Raw material remains available only to the trusted in-process caller; the fixed
CLI continues to emit bounded custody/status metadata and the managed-result
digest, never raw task/provider content or arbitrary exception text. Protected
durable raw capture and independent semantic replay remain distinct obligations.

## Nonoverlapping owners and interface

1. `timing_recovery_review`: `src/aragorn/pi_core_managed_bootstrap.py` and new
   `tests/test_pi_core_managed_failure_evidence.py` only. Preserve the original
   raised exception and attach `pi_managed_bootstrap_observation`, using the
   existing `aragorn/pi-core-managed-bootstrap-result/v1` structure with partial
   worker/services observations and false qualification/useful-task flags.
   Missing records remain null/unknown, never fabricated successful cleanup.
   Preserve already returned worker evidence when service acquisition, guard,
   worker execution or service teardown fails. No retry or second cleanup.
2. Coordinator: `src/aragorn/pi_core_coordinator_entry.py`, new
   `tests/test_pi_core_coordinator_failure_evidence.py`, shared docs, registry,
   minimal capacity adjustment, focused execution and signed delivery. Capture
   the attached managed observation at the actual call boundary before outer
   holders can replace the exception. Validate the fixed schema/status and
   detach canonical data. Retain it through holder/input cleanup failures;
   preserve child cleanup holds. Keep the public root projection unchanged.
3. Available admission/RUN lanes continue read-only dependency assessment until
   separately released exact code contracts. An independent available owner
   reviews this batch before checks; no reviewer executes tests or live work.

The concrete caller is the existing protected root entry; there is no new
callback/module selector or new entrypoint. Existing normal returned results
remain compatible. Original deadlines, service/worker ownership, ambiguous
effects and exception chaining remain intact. A returned bootstrap is still
not useful-task proof. No missing raw capture may be replaced by a digest.

## Focused checks and release conditions

Use inert existing fixtures without discovering old test classes. Cover failures
before/after worker return, service acquisition/guard/cleanup, simultaneous
worker and cleanup failures, missing/invalid partial observation, outer holder
cleanup replacement, original exception preservation, one invocation, no
additional cleanup, and redacted root report composition. Select only directly
affected existing normal/failure cases. Review complete source/fixture input
closures before registering two new stages and affected capacity checks through
the existing pipeline. No unchanged failure retries or historical full suites.

After review and applicable PASS, explicitly stage owned paths, verify signed
source and main-merge commits, normal-push both branches and read back exact
remote hashes. Preserve all unrelated drafts, predecessor artifacts and records.

## Continuous campaign position

1. **D2:** preserve connected failure observations, then remaining protected
   install/caller, real health, durable raw capture and full timing dependencies;
   separately approved VM/provider inputs and useful pilot still required.
2. **D3:** connected managed admission, RUN/health and workload coverage pending.
3. **D4:** complete real independent-consumer inventory and freeze pending.
4. **D5:** separately authorized fresh acceptance, measurements, cleanup/replay.
