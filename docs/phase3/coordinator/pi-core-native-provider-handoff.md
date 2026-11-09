# D2 native provider dispatch — offline handoff

## Scope and evidence ceiling

This successor connects one worker-facing provider endpoint to the existing
protected provider mediator and authenticated service lifetime. It does not
activate a service, provision a key, create provider egress, perform a request,
produce a useful pilot, or qualify Phase 3. Existing unavailable START remains
the default. The current owned service profile still has no provider credential
or external networking; the separately approved deployment successor is pending.

Lane-owned files:

- `src/aragorn/pi_core_native_provider.py`
- `tests/test_pi_core_native_provider.py`
- this handoff

## Coordinator interface

`PiNativeProviderChannels(config, services)` requires the existing root-owned
provider policy and exact `PiServiceChannels` with exact `PiServiceLifecycle`
custody. Its request channel must be the same object used by the native action
dispatcher; the coordinator checks this when composing the owners.

`hold_native_pi_provider_dispatch(owned, provider_channels, *, grant,
protected_root, deadline, cleanup_deadline=None)` owns only the singular
`provider/provider.sock` child of the held bootstrap directory. The worker path
is fixed at `/run/aragorn-pi-bootstrap/provider/provider.sock`. The directory is
created absent-only, root-owned `0711`; the root-owned socket is `0660` with the
worker group. No existing name is adopted or repaired.

The yielded exact `PiNativeProviderDispatch` exposes:

1. `require_start(activation, *, deadline)`: join authenticated capture to the
   held unit generation, activation bytes, service channels and sealed attached
   source observer. Bound the exact Node owner session lock and require ready,
   live, nonfailed owner custody; never invoke its thread-private budget guard
   from the supervisor. Pin the START caller's once-anchored `maxRunMs` deadline.
   Do not claim full source coverage before the dynamic provider module loads.
2. `listener` and `serve_once(deadline)`: consume the sole attempt before accept;
   recheck actual worker identity and full source/loss health before forwarding.
   Pass exact held services, observer and expected request to the existing
   `handle_pi_provider_connection(..., provider_service=True, expected_request=...)`.
3. `require_completed(deadline)`: require authenticated terminal receipt,
   irreversible provider retirement, exact request digest, delivered frame/EOF,
   closed mediator handles and still-held broker/sensor/source protection before
   any action can be accepted. Provider retirement never closes other services.
4. `observation` and `close()`: report detached nonqualification evidence and
   remove only the verified owned endpoint. Uncertain remote custody, changed
   names, failed close or cleanup retains a hold and forbids automatic retries.

The expected request is rebuilt from held START v3: exact activation, route,
model, prepared system prompt and task, timestamp-zero initial transcript, and
the existing fixed `aragorn_runtime_create` tool. The user message is Pi's exact
single text-part array, not a plain string. The mediator compares the actual
validated worker frame before claiming authority or sending provider data.

The supervisor owns `provider_attempted`, `provider_dispatch_active` and the
exact `_pi_provider_dispatch` pointer. The provider flag/pointer are installed
immediately after successful directory creation and are cleared only after
verified removal and owned descriptor closure. The supervisor includes this
directory in its whitelist and refuses cleanup completion while a hold remains.

## Outcome and cleanup rules

Clean `NOT_SUBMITTED` without transfer can return a refusal but never allows an
action. Submitted or ambiguous work without authenticated terminal retirement
or confirmed local response delivery remains `PROVIDER_INDETERMINATE` with
`CLEANUP_HOLD`. An authenticated indeterminate terminal may release this
adapter's local resources but still cannot authorize action or a retry. One
failed accept, malformed request or failed provider attempt cannot get another
provider slot. Borrowed bootstrap/broker/sensor/provider handles are never closed
by this adapter. Ambiguous closes are not repeated.

## Focused verification handoff

The lane authored 39 inert test methods, with every native operation forbidden
unless explicitly mocked. Coverage includes exact START/request projection,
unavailable defaults, budgets, original identity and source custody, service
role/handle separation, one-shot acceptance, clean refusal versus uncertainty,
required terminal retirement, continuing action/sensor guards, ownership-safe
cleanup, and no retry after ambiguous close.

No checks, build, task-code import execution, live operation or Git mutation was
performed by this lane. The coordinator owns review, reviewed pipeline input
closure, scheduling and recorded results. Tests reuse the inert native-request
base and existing confined-launch model fixture; those fixture dependencies
must be included in the stage input closure. The actual Pi START fixture should
also compare its emitted request with this native projection without creating
another capture or rerunning unrelated client fixtures.

## Remaining plan

1. D2: actual installed protected inventory, provider-enabled service/profile
   successor and approved provider setup; recovery/timing and separately
   authorized useful pilot. No deployed or consumed-source claim follows here.
2. D3: connected remaining admission, RUN/health and workload coverage.
3. D4: complete independent producer/evidence/verifier inventory and freeze.
4. D5: separately authorized fresh acceptance, measurements and cleanup evidence.
