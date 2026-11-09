# D2 additive protected START handoff

Scope: offline source integration only. The lane did not run checks, build,
launch a process/service, call a provider, install artifacts, or use Git.
Coordinator review and the affected pipeline stage remain required.

## Contract

- `PiConfinedLaunchConfig.provider_route_digest` defaults to `None`. With no
  opt-in, the existing v1/v2 START and configuration digest shapes remain
  unchanged, and bootstrap continues to return `PROVIDER_UNAVAILABLE`.
- Opt-in requires native requests, a pinned source-observation profile, exactly
  one provider turn and one tool call. Configuration v4 pins the route plus the
  existing task/model/limits/source profile. START v3 carries `PROTECTED` and an
  exact provider object: `route_digest`, `max_requests: 1`, and
  `request_timeout_ms`, derived from the pinned `limits.maxRunMs`.
- No provider socket override, credential, import path, callback or arbitrary
  transport is accepted over START. The fixed provider client uses
  `/run/aragorn-pi-bootstrap/provider/provider.sock`; the existing fixed native
  action client remains `/run/aragorn-pi-bootstrap/requests/request.sock`.
- The root exchange accepts enabled START only with the exact independently
  held `PiNativeProviderDispatch` for the same plan, plus native lifecycle
  callbacks. After binding the actual worker activation and before sending
  START, it invokes `require_start(activation, deadline=deadline)`. The provider
  dispatcher owns source/service readiness and exact prepared-request checking.
  Full dynamically loaded source coverage is required at protected provider
  mediation, not falsely asserted before the worker can load `provider.js`.
- The worker calls the existing `runProtectedNativePiEntry`; both client
  transports are fixed internally. Original deadlines can only shorten. A v3
  route cannot be replaced by a caller option. No request/effect retry or
  assistant continuation is introduced.
- Result v2 includes only activation, bounded status, the existing non-effect
  authority label, and six worker-summary fields. No prompt, provider content,
  transcript, credentials or raw broker evidence is returned through bootstrap.
  `WORKER_COMPLETED` may be a text-only outcome. It is not independent effect,
  provider-delivery, source-consumption, cleanup, D2 or Phase 3 proof. Root must
  require its actual provider completion/retirement and broker observations.
- Stopped and unsettled outcomes remain distinguishable. Exceptions or expired
  outer deadlines do not produce a success result; client abort does not claim
  process termination. Native ownership remains responsible for containment.

## Focused checks for coordinator scheduling

`tests.test_pi_core_provider_start` defines 26 checks (13 pure contract checks
and 13 pinned-Node in-memory client checks). Toolchain setup/teardown is reused
without inheriting historical behavioral tests. Its new JS fixture prohibits
live network/server/process operations and supplies authored local peer and
filesystem metadata; it does not supply acceptance samples.

Coverage includes strict opt-in/schema/route/timeout and one-shot limits,
configuration binding, legacy unchanged behavior, source prerequisites,
dispatch-shape refusal before I/O, exact prepared prompt/model projection,
in-memory provider-to-tool completion and refusal, ambiguous provider outcomes,
missing response cancellation, expired original deadline, wrong release, and
rejection of false or expanded worker summaries. The completed effect peer
reply is explicitly authored; no file is created and no effect is qualified.

Input closure must include both changed production files, the two new test
files, the existing fixed provider/worker clients and legacy codec dependency,
the existing confined-launch/entrypoint test helpers, their transitive imports,
the reviewed offline toolchain/lock/dependency tree, and the new native provider
dispatcher imported by the enabled exchange. The coordinator owns exact closure
registration and successful native exchange/lifecycle orchestration tests.

## Remaining plan

1. **D2:** complete protected installed inventory/source successors and native
   provider ownership/lifecycle integration, recovery and real timing; then a
   separately authorized useful pilot on the dedicated Linux VM. Current
   source changes do not activate provider credentials or egress.
2. **D3:** remaining admission, RUN/health and workload coverage.
3. **D4:** complete independent producer/evidence/verifier inventory and freeze.
4. **D5:** authorized fresh acceptance, measurements and cleanup evidence.
