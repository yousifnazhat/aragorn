# Pi-core batch 25: preserve connected failure observations

Base: verified signed and published
`c8e81b32cf9b1d5cba6f3f8c41bf79ae83abe4ce`.
Assignment: signed source `b7984e4`, published in verified signed merge
`375b6d44967f20161ea198702fb9e11eb9e1418e` before implementation.
Status: implemented and independently reviewed; 58 new/affected checks passed
once. No live operations authorized or performed.

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

### Completed source and validation

Managed composition now snapshots returned worker evidence before service
teardown and attaches structured partial observations to the same escaped
exception. Existing service acquisition observations survive ordinary OS errors,
and a final observation-getter/classification failure retains the worker snapshot
without retrying the getter. Missing/malformed owner records remain null with
fixed uncertainty reasons; borrowed authorities are untouched.

The root caller consumes this exact failure interface at its call boundary before
outer holders can substitute a cleanup exception. It retains child cleanup holds,
reports replacing holder failures as cleanup holds and preserves the original
exception chain. The existing public CLI projection remains unchanged and
digest-only. This is private in-process propagation, not durable raw retention.

| Stage | Checks | Result | Fingerprint |
|---|---:|---|---|
| `pi-core-managed-failure-evidence-offline` | 26 new + 10 affected | PASS | `sha256:226c8133aab31a0e44ed9853dd58c21b34f382808f7eae7794b6c5c2d23cfb54` |
| `pi-core-coordinator-failure-evidence-offline` | 13 new + 5 affected | PASS | `sha256:be1f7457bdde24d9cd75c08024306599113101cc8738599d3f532c3f5dba8c47` |
| `pipeline-capacity` | 4 affected | PASS | `sha256:38a9f34c2baefc6b8f7450f969f79f3104834a15ced697a0561f7738c0c045aa` |

All 58 checks (39 new, 19 affected) passed first execution with no reruns. Reviewed
closures contain 104 and 94 paths, including the fixture's import-time build-script
module; no compiler or target code executes. Capacity increased only 200 to 202.
Logs and results remain under `.aragorn/phase3-pipeline/<stage>/<fingerprint>/`.
Local Python 3.14.6 checks are not Linux arm64 Python 3.12 execution evidence.

The existing 4 MiB public managed-result ceiling is unchanged. A larger aggregate
failure envelope is not trimmed to fit; the root marks it unavailable while the
original private exception retains it. No snapshot or report establishes durable
storage. Native launch-context teardown can still lose its own not-yet-returned
observation; that narrower producer gap remains before complete raw retention.

1. **D2:** connected managed/root failure propagation implemented; next protected
   install/caller, real health, durable raw capture and full timing dependencies;
   separately approved VM/provider inputs and useful pilot still required.
2. **D3:** connected managed admission, RUN/health and workload coverage pending.
3. **D4:** complete real independent-consumer inventory and freeze pending.
4. **D5:** separately authorized fresh acceptance, measurements, cleanup/replay.
