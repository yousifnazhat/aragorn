# Pi-core protected one-shot completion handoff

Status: source implementation and review only; focused checks are prepared but
have not been run by this lane. No build, import execution, live operation,
registry change, commit or push was performed by this lane.

## Change and claim boundary

`runManagedPiWorker` accepts one additive, exact-true option,
`completeAfterSingleToolResult`. It rejects this option unless both provider-turn
and tool-call limits are exactly one. Without the option, behavior is unchanged.

The protected entrypoint alone selects this option in the shipped compositions.
It fixes both limits to one. After one parsed COMPLETED/ALLOW tool reply, Pi's
existing `finishTurn` hook returns `{ action: "end" }`. It does not call abort,
manufacture an assistant continuation, reclassify a refusal, retry a request, or
change any received effect/result bytes. The normal Agent promise is allowed to
settle; the existing bounded cancellation/deadline path remains active.

The report remains `ADAPTER_CORRELATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY`.
COMPLETED means the adapter loop settled, not independently verified task or
effect success. A text-only completion can still have no effect/result. The
future pilot must require and independently verify its authorized output.
`nativeMain` and bootstrap START remain provider-unavailable; no START v3 or
native provider activation is introduced.

## Reviewed pinned Pi behavior

The locally retained `@earendil-works/pi-agent-core` 1.4.0 source was inspected
without importing it:

- `dist/types.d.ts`: `FinishTurn` runs after assistant and tool-result messages;
  `{ action: "end" }` is a supported decision.
- `dist/agent-loop.js`: the hook follows `executeToolCalls` and finalized result
  messages; the end decision emits `turn_end`/`agent_end` and returns before a
  further provider request.
- `dist/agent.js`: the run settles through `finishRun` in `finally`; abort is an
  interruption signal and may produce an aborted failure message. It is not
  used for successful one-shot completion.

Review covered exact opt-in validation, preflight rejection of two tool calls,
unchanged default TURN_LIMIT behavior, immutable correlation-only replies,
provider failure/abort, relay ambiguity and preserved cancellation/deadline
outcomes. No behavioral pass is claimed from this source review.

## Proposed focused stage

- ID: `pi-core-one-shot-completion-offline`
- Tests: `test_pi_core_one_shot`
- Count: 17 unittest methods (19 scenario subprocesses because the malformed
  opt-in/limit method selects three cases).
- Needs: `[]`
- Timeout: 120 seconds, retaining the existing bounded per-scenario subprocess.
- No broad worker/provider suite or unchanged arithmetic checks are requested.

Exact input closure:

```text
docs/design/pi-core-dependency-pins-v1.json
packaging/pi-core/package.json
packaging/pi-core/package-lock.json
packaging/pi-core/offline-toolchain-v1.json
packaging/pi-core/worker.ts
packaging/pi-core/entrypoint.ts
packaging/openclaw/aragorn-runtime-action-worker/index.js
packaging/openclaw/aragorn-runtime-action-worker/package.json
src/aragorn/__init__.py
src/aragorn/oci_worker_protocol.py
src/aragorn/runtime_action_broker.py
src/aragorn/runtime_action_decision.py
src/aragorn/runtime_action_service.py
src/aragorn/runtime_action_worker.py
tests/test_pi_core_worker.py
tests/test_pi_core_one_shot.py
tests/fixtures/pi_core_one_shot_offline.ts
```

The Python wrapper reuses only the existing pinned Node/dependency setup and
teardown methods, not its test methods or fixture execution. The dependency tree
and executable are checked against `offline-toolchain-v1.json` by that setup.
The new TypeScript fixture runs the real retained Pi lifecycle. Network/process
entrypoints are forbidden. Broker replies are fabricated in-memory data. The
protected-entry scenario substitutes only its two transport factories with
in-memory callbacks; it does not validate protected socket identity, provider
mediation or credentials. Actual `provider.ts` is intentionally not imported by
this narrow fixture.

## Remaining plan

1. D2: review/register/run only this new stage, then integrate the reviewed
   batch. Native provider listener/dispatch, consumed-source/health, recovery,
   real timing and separately authorized pilot remain open.
2. D3: complete connected admission, RUN/health and workload coverage.
3. D4: complete the executable 29-requirement mapping and independent verifier
   inventory, then freeze one deployment.
4. D5: separately authorized fresh attempts/pairs, measurements, cleanup and
   retained-evidence replay. This one-shot source slice closes none of those
   qualification gates by itself.
