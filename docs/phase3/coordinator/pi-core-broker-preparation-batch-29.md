# Pi-core batch 29: explicit protected broker preparation

Base: verified signed source `52c0e95570c3b24baf766010b380d1188a4c637a`,
signed merge `db0914fb3e7a2af8dae642c43f5fc41ea3446f6a`; both remote
branches read back exactly. Batch 28 passed 131 focused checks once. All 985
unrelated drafts remain. This releases offline source work only, not activation.

## Dependency and owners

D2/MC-02 and MC-09 require explicitly prepared one-shot broker state before
normal service readiness. The existing Pi initializer is uncalled in production;
request handling correctly only recovers and refuses non-AVAILABLE state.
Root must not invoke the initializer with a substituted UID or drop its own
identity. Use the existing action image, unit, identity, source handshake and
owned lifecycle for a separate finite preparation operation.

1. `handoff_gate_review`: `src/aragorn/pi_core_service_lifecycle.py` and new
   `tests/test_pi_core_broker_preparation_lifecycle.py`. Action-only lifecycle,
   fixed startup command, independent state readback and cleanup.
2. `timing_recovery_review`: `src/aragorn/pi_core_service_entry.py` and new
   `tests/test_pi_core_broker_preparation_service.py`. Fixed authenticated action
   startup command and existing initializer/result acknowledgment.
3. Coordinator: new `src/aragorn/pi_core_broker_preparation_entry.py`,
   `packaging/pi-core/coordinator.py`, new
   `tests/test_pi_core_broker_preparation_entry.py`,
   `tests/test_pi_core_broker_preparation_wrapper.py`, exact affected fixtures,
   registry/capacity, review, scheduling, documentation and signed delivery.
4. `inventory_dependency_review`: independent read-only source/closure review.

No lane runs tests, imports repository modules, builds, changes Git or activates
anything. Release implementation only after this contract is signed/published.

## Exact action startup command

After successful verified-source startup, action alone receives one authenticated
root command. Legacy `source_loader=None` keeps its existing behavior. No peer
negotiation, arbitrary command string or new service role is accepted.

Schema `aragorn/pi-core-action-start/v1`; exact fields `schema`, `kind`, `nonce`,
`configuration_digest`, `grant_digest`, `deadline_ns`. `kind` is exactly
`RUN_REQUEST` or `PREPARE_GRANT`, nonce is 64 lowercase hexadecimal characters,
and the two digests bind the actual held action configuration and its grant.
Original command deadline cannot exceed the wrapper's original deadline. No grant
bytes, paths, shell/module selector, credential or retry budget enter this packet.
The normal lifecycle sends RUN_REQUEST after source startup and before waiting
for the actual action listener. Only the explicit preparation route selects
PREPARE_GRANT; it never accepts a sensor or reads a worker request.

Service entry calls existing `initialize_pi_broker_request_service(config,
deadline=bounded)` exactly once under its captured nonroot action identity.
Then sends a packet with the same bound fields, `kind=PREPARED`, plus `result`
containing that actual initializer observation. It waits once for root's
`kind=ACK`, same fields plus `result_digest`, under the original deadline.
Validate original channel credentials and bounds before/after the exchange.
Missing/ambiguous result or ACK never authorizes automatic retry or an effect.

## Lifecycle and root caller

`prepare_native_pi_broker_control(*, deployment, configuration, provider_inputs,
binding, deadline, cleanup_timeout_seconds=5.0)` reuses the exact held types and
fixed owned lifecycle. No credential holder is accepted. Require all three fixed
units absent, pinned source-enabled image, original input guards and safe manager
environment. Prepare owned channel/root resources with existing helpers, but
start only action. Retain the captured process/unit and authenticated consumed
source evidence. No worker, sensor, provider, request listener or egress starts.

Preinstalled controls remain explicit prerequisites: action-owned protected
control/protected/staging roots, safe existing broker.lock, and canonical current
state.json with no unresolved effect journal. A narrow read-only preflight may
reuse `_readiness`'s root/lock/base-state checks without demanding an AVAILABLE
grant before explicit initialization. Normal readiness remains unchanged and
still requires AVAILABLE. Never create/repair roots, base state, policy, health,
observations or grants in this root preflight. Preserve pending/terminal state;
the existing initializer alone performs its existing guarded reconciliation.

After the exact PREPARED result arrives, root independently reacquires the existing
broker lock and reads the actual base/grant state, requiring AVAILABLE, matching
grant/state digests, no current pending/receipt/archive and unchanged roots.
Recheck captured action generation and held inputs before ACK. Retain raw command,
result, readback and source/unit observations. Close/stop only owned resources
through existing lifecycle cleanup, preserving failure evidence and uncertain
starts. No reset/retry or returned success before verified owned cleanup.

The fixed root CLI adds `--prepare-broker-control` followed by the existing five
independently pinned arguments. Reuse the existing coordinator plan and require
mode UNAVAILABLE/provider null. Reuse `_Inputs`, exact held runtime/config/public
inputs, read-only CAS and `hold_prepared_pi_bundle` to verify the admitted bundle,
deployment/context/grant joins before preparation; no worker launch is performed.
Require the new entry module's independently pinned consumed-source row. Return
bounded root-custody and preparation metadata; public output is digest-only and
never claims useful output, effect, health, activation or qualification.

## Verification and remaining plan

New/affected offline checks only: command/config/grant/deadline substitution,
source-handshake failure, ordinary RUN path, initializer once and correct identity,
no sensor/provider/worker starts, preinstalled-control refusal, exact independent
readback, partial/cancelled preparation, original error/evidence retention,
root report bounds and ownership-safe cleanup. Preserve all frozen wrappers and
artifacts. Reviewed pipeline stages only; unchanged successes are not rerun.
After review/pass: signed source, signed main merge, normal push and exact remote
readback. No live operations or target build are released by this contract.

1. **D2:** explicit preparation connected offline; actual installed controls/views, genuine
   health, raw action effects, recovery/full timing and authorized pilot remain.
2. **D3:** remaining connected admission, RUN/health and workload coverage.
3. **D4:** complete independent semantic inventory/prerequisites, then freeze.
4. **D5:** separately authorized fresh acceptance, measurement and cleanup.

## Reviewed implementation checkpoint

The fixed root route now holds the admitted bundle and installed-runtime/configuration
custody, starts only the existing action role, sends the authenticated PREPARE
command, retains the actual result and independently locked readback, then releases
its ACK and verifies owned cleanup. Normal source-verified startup sends RUN_REQUEST;
legacy role entry remains unchanged. Partial starts, original failures, helper
acquisition/read/close uncertainty and outer-holder cleanup remain honest holds.
Public reports retain only bounded metadata/digests, not raw private records.

Independent source, caller, fixture and input-closure review preceded execution.
The four new stages have 97/99/96/113 explicit inputs. Registry capacity is 218.
**111 distinct checks passed: 96 new and 15 affected.** The first run passed 110;
the wrapper privacy assertion falsely matched the legitimate macOS `/private/tmp`
host-executable path. Only that assertion changed to test the actual private
fixture payloads and absence of the raw result. After review, only its 14-check
wrapper stage reran; the other 97 passing checks were not rerun. The failed
fingerprint and full logs remain retained. No source behavior or acceptance
threshold was relaxed for that correction.

| Stage | Checks | Retained passing fingerprint |
| --- | ---: | --- |
| `pi-core-broker-preparation-service-offline` | 32 | `3013f7cb8b41cc4b60bc0dc2fec4552e03be7061fef27f1bf8f42c90de2b9cec` |
| `pi-core-broker-preparation-lifecycle-offline` | 42 | `a34a37e10bb4148a356133f3cb1243b009863b6d105101bd6d8c117da2dd0e3b` |
| `pi-core-broker-preparation-entry-offline` | 19 | `4ac93e19c46b0d7779b3cacbe648fd511719d693c4133a9619396b38e59a4385` |
| `pi-core-broker-preparation-wrapper-offline` | 14 | `ab53c37f5b5785a8b1d3515d59acceded0761d1162e3b6d018b4134d9a9045c5` |
| `pipeline-capacity` | 4 | `ab9ed9a924a7e1620f72bf9d6f1a76c3fa9ab6e468fe63767274b9210764b243` |

Wrapper failed fingerprint: `43407c119273af97fae5f36b77257c3a8853b1b5509439b8a47c813199be8bcb`.
Evidence is retained under `.aragorn/phase3-pipeline/<stage>/<fingerprint>/`.
No broad suite, target build, service/VM/provider activation, capture or qualification
ran. All 985 unrelated drafts and frozen predecessors remain untouched. Signed
source/merge hashes and exact remote readback are recorded in the milestone and
the next batch's base record, avoiding a self-referential commit hash.

The next connected dependency is fresh-only installation of the action-owned
base controls. Grant preparation does not provision them, manufacture current
policy/health, rotate an ambiguous effect, or close D2. Separate root-owned
provider controls, genuine loss/progress, action raw effects/full timing and the
authorized pilot remain open; D3/D4/D5 retain every existing hold.
