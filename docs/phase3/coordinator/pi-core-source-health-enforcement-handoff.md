# D2 mandatory independent source-health enforcement

This source-only batch connects the new observer's exact custody type to the
existing native action and protected-provider authorization guards. It does not
provide pre-exec launch integration, enable native provider START, acquire live
observations, publish health JSON, or qualify Node/the managed deployment.

## Owned changes

- `src/aragorn/pi_core_native_request.py`: additive optional
  `PiNativeRequestChannels.source_observer`, default `None`; every protected
  `PiNativeRequestCustody.guard` requires exactly `PiSourceObserver`, held by the
  same `native._Owned`, and calls
  `guard_source_health(activation=self._activation, deadline=self._deadline)`.
- `src/aragorn/pi_core_provider_mediation.py`: additive keyword-only
  `source_observer=None`; exact type required before request reading or claims;
  the guard receives the authenticated activation and original/tightened
  deadline before payload processing, before service submission and during each
  existing CONNECT/SEND authorization check.
- `tests/test_pi_core_source_health_enforcement.py`: focused inert enforcement
  checks and five explicitly selected affected cases.
- `tests/test_pi_core_native_request.py` and
  `tests/test_pi_core_provider_mediation.py`: existing positive fixtures supply
  an exact-class inert observer and one mocked guard, explicitly distinct from
  acquisition proof. Helpers accept an explicit `source_observer=None` for
  refusal checks. The unavailable-bootstrap case explicitly removes the
  observer and verifies no source-health call. Production defaults are unchanged.

The observer method—not worker JSON, a callback, or a recorded PASS—checks
source acquisition, source coverage, independently challenged progress and its
supported loss/custody semantics. The native path also rejects an exact observer
for a different captured worker. Subclasses and lookalikes do not qualify.

Current service channels still supply `None`; protected work therefore refuses.
No-request native bootstrap and provider-unavailable START are unchanged.
The first producer is deliberately a limited single-thread/read backend and
refuses normal dynamically mapped/threaded Node. These changes must not be
described as useful-path readiness or as a positive native health observation.

Source checks are not renewed at the provider's terminal cleanup-only boundary:
that boundary grants no CONNECT/SEND/effect authority. Existing worker identity,
authenticated terminal, provider retirement and owned-handle cleanup checks
remain. Failure before submission is NOT_SUBMITTED; failure after submission
remains INDETERMINATE with the permanent claim retained. Native request attempts
stay one-shot even when health refuses. Cancellation and cleanup ownership are
unchanged; there are no automatic retries or larger deadlines/permission leases.

## Proposed reviewed pipeline selection

Stage: `pi-core-source-health-enforcement-offline`.
Test selector: `test_pi_core_source_health_enforcement`.
`needs: []`, `timeout_seconds: 120`.

**30 checks: 25 new, 5 selected affected.** No broad historical suite is selected.
The affected cases are:

1. Existing native NO_REQUEST/provider-unavailable bootstrap selection.
2. Existing default authenticated service-channel construction.
3. Existing authenticated provider terminal-before-exit behavior, invoked by a
   single wrapper case with an explicitly supplied exact-class inert observer.
4. One native request-dispatch/accepted-stream-cleanup case to exercise the
   adapted positive native fixture through its real dispatch caller.
5. One legacy provider-mode policy/claim/handoff/cleanup case to exercise the
   adapted positive provider fixture outside the service-v2 path.

Observer guards are mocked in these caller tests; they prove enforcement wiring,
not acquisition/health correctness. Producer and independent consumer have their
own focused stages. New cases reuse each fixture's one autospec patch rather
than autospeccing an existing mock; provider keyword overrides are merged once
so explicit `None` cannot collide with fixture defaults. The lane ran no checks,
imports, builds, live operations or
Git mutations; coordinator owns registration, review, execution and publication.

## Explicit input closure

The coordinator's static import-closure review expanded the proposed closure to
**91 inputs**: 83 source paths (including the package initializer) and eight test
paths. This is input hashing only; it does not select any additional tests.
Start with the 66 source paths in `pi-core-service-integration-offline`, add
`src/aragorn/pi_core_source_observer.py`, and include the following 16 additional
reachable source modules under `src/aragorn/`:

- `pi_core_provider_provision.py`
- `pi_core_request_broker.py`
- `pi_core_request_recovery.py`
- `pi_core_request_sensor.py`
- `pi_core_request_service.py`
- `pi_core_service_configuration.py`
- `pi_core_service_entry.py`
- `pi_core_service_lifecycle.py`
- `runtime_action_broker_v2.py`
- `runtime_action_broker_v3.py`
- `runtime_action_broker_v4.py`
- `runtime_action_broker_v5.py`
- `runtime_action_observation_publisher_v2.py`
- `runtime_action_observation_publisher_v4.py`
- `runtime_capability_grant.py`
- `runtime_lineage_capability_issuer.py`

Use exactly these eight test paths, replacing rather than selecting the old
service-integration test module:

- `tests/test_pi_core_source_health_enforcement.py`
- `tests/test_pi_core_native_request.py`
- `tests/test_pi_core_provider_egress.py`
- `tests/test_pi_core_provider_mediation.py`
- `tests/test_pi_core_confined_launch.py`
- `tests/test_pi_core_request_handoff.py`
- `tests/test_runtime_action_decision.py`
- `tests/test_pi_core_service_channels.py`

No unchanged old stage is a prerequisite execution. Reuse prior successes only
when their exact inputs are unchanged. The coordinator must preserve every
failed fingerprint and use only corrected affected selections after diagnosing
an actual failure.
