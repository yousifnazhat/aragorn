# Pi-core batch 23: protected VM-host coordinator entrypoint

Base: signed published `735e9e35fba6d13d9a5032c0996041c193abbcdb`.
Status: approved bounded offline implementation assignment, not activation.

## Approved decision and fixed boundary

The user approved the pinned dedicated-Linux-VM-host coordinator profile. The
root coordinator uses independently reviewed VM Python 3.12, standard library,
loader/native-library, control-tool and source pins, with the existing fixed
`/opt/aragorn/src` source origins. This is not permission to use macOS/ambient
Python, execute a relocated child image as the host runtime, or add a fourth
child-service role. Preserve child contracts and frozen artifacts unchanged.

No concrete VM, host manifest, model, secret or spending limit is selected here.
No installation, activation, provider request or acceptance is released. Actual
host closure and timing feasibility remain separate observed prerequisites.

## Released nonoverlapping lanes

1. `inventory_dependency_review` owns only new
   `packaging/pi-core/coordinator.py` and
   `tests/test_pi_core_coordinator_wrapper.py`.
2. `handoff_gate_review` owns only new
   `src/aragorn/pi_core_coordinator_entry.py` and
   `tests/test_pi_core_coordinator_entry.py`.
3. `timing_recovery_review` independently reviews both lanes, read-only.
4. Coordinator owns shared docs, reviewed registry/input closures, bounded
   capacity adjustment, focused execution, integration and signed publication.

Lanes do not execute tests/builds/import checks, mutate Git or use live resources.
Authored fixtures must trap process/service/network/credential operations. Reuse
existing fixtures without discovering their historical suites.

## Wrapper and host custody contract

The sole CLI is `PROFILE_PATH PROFILE_DIGEST PLAN_PATH PLAN_DIGEST DEADLINE_NS`.
Both expected digests are independently supplied, never self-derived from inputs.
Require root Linux arm64, isolated/no-site/no-bytecode Python 3.12, the safe
environment and one original deadline. No command, callback or module selectors.

The exact host profile fields are `schema`, `target`, `python_executable`,
`wrapper_path`, `stdlib_roots`, `sys_path`, `absent_sys_path`, `files`:

- Schema `aragorn/pi-core-coordinator-host/v1`, target `linux-arm64-cpython312`;
  wrapper `/opt/aragorn/bin/coordinator.py`.
- Sorted unique absolute file records have exactly `path`, `digest`, `size`.
  Bind protected no-follow file/parent identities and content, fixed control
  tools, actual executable and file-backed mappings to this closure.
- Exact `sys.path`, complete standard-library subtrees including bytecode and
  protected Aragorn sources prevent unpinned import expansion. Approved absent
  search paths are only missing Python-3.12 zip placeholders, rechecked absent.
  `-B` alone is never evidence that bytecode cannot be loaded.
- Sealed `PiCoordinatorHostCustody`, registered in
  `_aragorn_pi_coordinator_bootstrap`, exposes `manifest_digest`,
  `guard(deadline=None)` and `snapshot()`. It retains the owner PID, original
  deadline and exact file custody; closes owned descriptors once.
- Verify and execute the existing `pi_core_service_source.py` bytes; install
  its loader before any Aragorn import. Root handler imports use that loader,
  not a new import framework. Initial interpreter, wrapper, bootstrap stdlib,
  native/builtin/frozen code remain explicitly trusted pinned bootstrap TCB,
  not retrospectively proven arbitrary in-memory execution.

The fixed call is `entry.run(plan_path, expected_plan_digest,
deadline_ns=..., source_loader=..., host_custody=...)`. Public CLI output is
bounded/redacted status metadata, not plan bodies, keys or task/provider content.

## Fixed prepared plan and connected caller

Schema `aragorn/pi-core-coordinator-plan/v1`; exact fields:
`schema`, `mode`, `host_profile_digest`, `cas_root`, `context`, `deployment`,
`revoked_context_ids`, `runtime_conformance_digest`, `launch`, `service_runtime`,
`service_configuration`, `provider_inputs`, `provider`.

`mode` is `UNAVAILABLE` or `PROTECTED`. Document references are exactly
`{path,digest}`, root-owned single-link mode-0400 bounded canonical JSON held
under protected ancestry. The independent plan pin transitively binds references.
`revoked_context_ids` is a sorted unique digest list. Match the host profile pin
to exact wrapper-held custody; no arbitrary environment/command/secret fields.

- `service_runtime`: deployment_path, receipt_digest, manifest reference,
  runtime_binding reference.
- `service_configuration`: deployment_path, receipt_digest, manifest reference,
  configurations reference.
- `provider_inputs`: deployment_path, receipt_digest, manifest reference.
- `provider`: null for unavailable; otherwise credential_source metadata path,
  root_broker_config reference and approval_intent reference. Never key bytes.
- `launch`: exact existing `PiConfinedLaunchConfig` fields with its three
  directory strings converted to paths; require native request mode and exact
  unavailable/protected route agreement. Reuse its existing validation.

Acquire existing runtime/configuration/public-input holders. Derive grant,
process profile and worker binding from held action/sensor configuration. Use
read-only CAS and fixed admitted root, actual wall time, original downward-rounded
deadline and existing five-second cleanup budget. Protected mode additionally
acquires the existing credential and approval holders. Invoke
`run_native_pi_service_bootstrap` once; preserve failures and owned cleanup.
Do not manufacture health, observations, grants, policy, replay state or retries.

Retain root source-consumption/host snapshots and plan/deployment joins separately
from the managed result. A caller report alone is not independent qualification.
No provider observation publisher or global health refresh is released here.

## Review, verification and remaining plan

Review malformed pins/paths/bytecode/runtime substitution, preimported source,
stale custody/deadlines, plan extras/mode confusion, holder acquisition failure,
one-call composition and ownership-safe failure cleanup. Schedule only the new
wrapper/entry stages and affected capacity cases through the reviewed pipeline;
no broad regression, target build or live check.

1. **D2:** approved VM-host root entrypoint; then real host/installed inventories,
   genuine observation/health, recovery/full timing and separately approved pilot.
2. **D3:** remaining connected admission, RUN/health and workload coverage.
3. **D4:** real producer/evidence/independent-consumer inventory and freeze.
4. **D5:** authorized fresh acceptance, measurements, cleanup and offline replay.
