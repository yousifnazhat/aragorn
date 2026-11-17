# Pi-core batch 28: bounded action/sensor terminal lifetime

Base: verified signed source `8767a35ce4eb955dbae272ef79167fbd9bfc1c2e`,
signed main merge `c4f0146174b51328253c58fc3c80a125ca3a86c9`; both remote
branches read back exactly. Batch 27 passed 126 focused checks once, 106 new and
20 affected. All 985 unrelated drafts remain. Only offline work is authorized.

## Connected dependency and ownership

D2 useful-create completion has a concrete lifetime race: after action sends the
result/EOF, sensor sends DONE and exits before action's final CHECK; root still
requires both service processes live. Action can likewise exit after DONE before
the root's final custody checks. Do not remove those checks or infer authority
from a dead peer. Add bounded authenticated terminal acknowledgments, reusing the
existing channels, packet validators, one-shot authority and retirement guards.

1. `handoff_gate_review`: `src/aragorn/pi_core_service_channels.py`,
   `src/aragorn/pi_core_service_lifecycle.py`, and new
   `tests/test_pi_core_request_retirement.py`. Exact action/sensor atomic retirement.
2. `timing_recovery_review`: `src/aragorn/pi_core_sensor_channel.py`,
   `src/aragorn/pi_core_request_sensor.py`, and new
   `tests/test_pi_core_sensor_terminal.py`. Additive sensor barrier and caller.
3. Coordinator: `src/aragorn/pi_core_request_handoff.py`,
   `src/aragorn/pi_core_request_service.py`, `src/aragorn/pi_core_native_request.py`,
   `src/aragorn/pi_core_service_entry.py`; new
   `tests/test_pi_core_request_terminal.py`,
   `tests/test_pi_core_terminal_composition.py`; exact affected fixtures if needed,
   registry/capacity, documentation, execution and signed delivery.
4. `inventory_dependency_review`: read-only independent source/caller/input-closure
   review and next dependency audit. No tests, imports, builds or Git by lanes.

Release implementation only after this contract is signed and published.

## Fixed protocol and caller contract

Preserve v1 schemas/default APIs and wire behavior. Add literal
`aragorn/pi-core-request-handoff/v2` and `aragorn/pi-core-sensor-custody/v2`.
A strict local `terminal_ack: bool = False` selects the expected schema at both
ends before the first challenge. Never negotiate, infer support from an incoming
packet, or fall back. Source-verified service entry explicitly selects True for
action and sensor; the native root selects True only with its exact held
`PiServiceChannels`. Bare historical channels remain v1.

V2 ACK has the protocol's existing bound nonce/request/deadline fields (also
activation for action), plus `done_digest`, the canonical digest of the entire
exact DONE. It grants no future operation. No new socket, process, listener,
deadline, retry or configuration framework is introduced.

Both child services finish their existing per-request cleanup, send DONE once,
then wait for the authenticated root ACK under the original deadline. Do not
close a handle twice or treat missing ACK as a safe effect retry. Original
kernel peer credentials and packet credentials authenticate the ACK even after
per-request PIDFDs close. Only v2 waits; v1 behavior is preserved.

Root validates action DONE and result, calls sensor ticket `finish(result)` to
validate the matching sensor DONE, then performs the unchanged full live
native/worker/lineage/source guard. `PiNativeRequestCustody.retire_requests()`
joins its exact held service lease and calls `retire_requests(deadline=...)`.
The service lease checks all live custody before one irreversible atomic
`requests_retired` transition covering action and sensor. There is no preterminal
exit waiver. PIDFDs remain owned until the original cleanup scope ends.

Root releases sensor `acknowledge()` and action ACK once after retirement. A
partial send or cancellation is uncertain and cannot restore request authority.
After retirement, service/lifecycle guards still verify held image/configuration,
original socket/peer and unit generation. Reuse the provider's exact terminal
generation logic: a live process retains full checks; an exited process must
have no replacement unit or residual cgroup. Provider semantics stay unchanged.
Retirement is not proof of process exit, successful effect, or cleanup.

The native request remains one-shot and new dispatch/request entry must refuse
retired request roles. Post-terminal cleanup guards still work. Existing sensor
FS-identity restoration, owned stream-duplicate closure, action sensor-PIDFD
closure, worker source health and no-retry enforcement remain intact.

## Evidence, verification and delivery

The terminal packet digests and lease's `requests_retired` flag describe actual
protocol state, not independent effect verification. Existing runtime-result,
packet and service-generation validators consume their respective records.
Durable action-side raw-effect retention and full timing remain separate work;
this barrier also supplies the later live post-decision clock acquisition point.

Focused checks cover strict version selection/mixed versions, exact ACK binding,
late/missing/forged ACK, one-shot failed sends, owned-handle cleanup, final CHECK
ordering, both DONE joins before retirement, preterminal death, post-terminal
generation replacement/residue, unchanged provider retirement, and native/entry
selection. Reuse unchanged successes; coordinator runs only reviewed new/affected
stages through the existing pipeline. No live operations or broad suites.

After review/pass, explicitly stage owned changes, verify signed source and main
merge, push normally and read back both exact remote hashes.

1. **D2:** terminal lifetime repair in progress; actual installed views, genuine
   global health, raw effects, recovery/full timing and authorized pilot remain.
2. **D3:** remaining connected admission, RUN/health and workload paths.
3. **D4:** complete executable semantic inventory/prerequisites, then freeze.
4. **D5:** separately authorized fresh acceptance, measurements and cleanup.
