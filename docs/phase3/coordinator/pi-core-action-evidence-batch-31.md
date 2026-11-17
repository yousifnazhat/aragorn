# Pi-core batch 31: connected raw action evidence

Base: verified signed source `41bca6bed61f5248b1020e130baa936d7bafdb8d`, signed
main merge `a35c4867b5fb268c0164b3dfb9bda4f549bda776`; both remote branches
read back exactly. Batch30 passed all81 focused checks once. All985 unrelated
drafts remain. Only source implementation and focused offline checks are released.

## Connected gap and ownership

The action broker already durably writes its original profile receipt and
CONSUMED grant state. Root joins authenticated action/sensor DONE messages but
discards the raw conversation and returns only a worker projection. Retain those
actual records before pair retirement/ACK; reuse the existing protected CAS and
broker records, not a new collector or synthetic effect sample.

1. `timing_recovery_review`: `src/aragorn/pi_core_provider_evidence.py` and new
   `tests/test_pi_core_action_evidence_store.py`: fixed action sibling index.
2. `handoff_gate_review`: new `src/aragorn/pi_core_action_evidence.py` and
   `tests/test_pi_core_action_evidence.py`: exact native custody, root-owned store
   handle, read-only locked action-control acquisition and original receipt join.
3. Coordinator: `src/aragorn/pi_core_native_request.py`,
   `src/aragorn/pi_core_request_handoff.py`, `src/aragorn/pi_core_sensor_channel.py`,
   new `tests/test_pi_core_action_evidence_composition.py`, selected affected
   fixtures, registry/scheduling, documentation and signed integration.
4. `inventory_dependency_review`: independent read-only review and closure audit.

No lane imports repository modules, runs tests/builds, changes Git or performs
live operations. Code release follows this contract's signed/published checkpoint.

## Fixed storage sibling

Add `hold_action_evidence(config, control_fd, *, activation, deadline)` alongside
the unchanged provider holder, reusing its exact sealed owner/CAS and all limits.
Use the same preinstalled root-owned `provider-evidence/blobs/sha256` store but
an exclusive `action-attempt-<activation_id>.jsonl` index, never the provider's
`attempt-...` index. No namespace argument, reopen, resumption, deletion, retry,
changed deadline or reset. The existing provider schemas/defaults stay unchanged.

Action observation/index/reference schemas are respectively
`aragorn/pi-core-action-evidence-observation/v1`,
`aragorn/pi-core-action-evidence-index/v1`,
`aragorn/pi-core-action-evidence-reference/v1`. Authority remains storage-only.
Fixed record kinds: REQUEST_FRAME, REQUEST_CONTEXT, CHECK, CURRENT_ATTEMPT,
ACTION_DONE, SENSOR_DONE, ACTION_RESULT, CONTROL_READBACK, FAILURE. Preserve the
existing64-record,4MiB-record,64KiB-index bounds, ordered immutable references,
readback/fsync and uncertain-prefix/close rules. Failure attachment is
`pi_action_evidence_observation`; provider attachment remains unchanged.

## Exact native owner and independent receipt readback

New `hold_native_action_evidence(custody)` yields sealed `PiNativeActionEvidence`
with finite `retain(kind,value)`, `complete(*,done,sensor_done,result)` and detached
`observation`. Require exact active `PiNativeRequestCustody`, its captured
`PiServiceChannels`/`PiServiceLifecycle`, and the same completed/retired provider
dispatch whose service lease is identical. Reuse its root-owned provider config
for the CAS, opening a new owned no-follow control handle; never borrow private
approval handles or substitute the action UID. The holder closes only its owned
handle/storage and preserves original failures plus uncertain cleanup. This
connects the provider-enabled useful path; unavailable NO_REQUEST stays unchanged.

At completion, retain actual action DONE, sensor DONE and worker result first.
Under full live custody, independently open fixed action control root with its
configured UID/GID/mode0710 and existing broker.lock UID/GID/mode0600/nlink1/size0.
Acquire the lock once nonblocking; do not retry. Reuse lifecycle `_read_at` for
canonical state.json, capability-grant-state.json and profile-receipt.json, with
existing bounded reads and no migration/recovery/initialization. Preserve actual
bytes and reached readback/identity/absence prefixes even if parsing fails.

Reuse `broker._state` and require exact current schema/no unresolved journal.
Reuse `grants._state` with the held grant digest. Current producer returns DONE
only after profile receipt and CONSUMED state are durable, including effective
BLOCK; preclaim refusal raises and has no completed DONE. Thus completed readback
requires CONSUMED, no pending/current-grant archives and the existing pure
`pi_core_request_recovery._result_record(claim,receipt)` relation. Join the receipt
broker result exactly to DONE, and its bound request digest to the envelope.
Recheck root/lock/held configuration and process generation before releasing the
lock. No side effect, repair or new semantic qualification occurs. Missing,
nonterminal or mismatching state is evidence refusal, not invented successful
blocking; actual handle/storage uncertainty remains a cleanup hold.

## Caller and terminal boundary

Native request handling owns the evidence scope for the protected service path,
passes its exact owner to the handoff and retains observation in the existing
request-dispatch record on success, failure and cancellation. The scope must
close before returning useful success. Missing evidence custody refuses the
protected path; historical bare channels and unavailable NO_REQUEST remain inert.

Handoff takes additive optional `action_evidence`, checks the exact class and
native-custody join, and uses it only at actual acquisition boundaries. For this
path compose existing frame header/receive/EOF/parser primitives so bounded raw
header/body bytes can be retained as base64 before parsing; short-read bytes not
returned by the existing primitive remain unavailable, never invented complete
capture. Preserve actual validated request/activation/measurement/lineage/grant
context before OFFER, incoming CHECK and outgoing CURRENT_ATTEMPT before send.
The latter is attempted authority, not proof of delivery.

Add a detached `SensorTicket.terminal_receipt` getter available only after its
actual finish and before ACK in an active scope; no new receive or health claim.
After actual action DONE, sensor finish and full guard, call evidence.complete
before pair retirement and either ACK. Evidence failure must never release a
successful terminal barrier or retry the effect. Retain original errors/prefixes;
public worker/result contracts do not acquire raw private content.

This batch does not add timing estimates or qualify source/global health, sink
residue, capture completeness, cleanup of external effects, or Phase3. Full
decision/task/recovery timing and independent semantic replay remain separate.

## Verification and remaining plan

Review exact source/caller/closure before new/affected pipeline stages. Cover
provider/action index separation, wrong owner/custody/pins, changed controls,
ALLOW/effective-BLOCK receipt joins, pending/ambiguous/missing records, frame and
protocol retention order, storage failure before ACK, cancellation, partial
prefixes and close uncertainty. Reuse unchanged successful stages; no broad
regression, target rebuild, historical recapture, live operation or qualification.
After review/pass: verified signed source and main merge, normal push, exact
remote readback, preserve every unrelated draft and frozen predecessor.

1. **D2:** action evidence next; actual protected views, separate provider controls,
   genuine health, recovery/full timing and separately authorized useful pilot.
2. **D3:** remaining admission/RUN/health and real declared-script task contexts.
3. **D4:** complete independent semantic inventory/prerequisites, then freeze.
4. **D5:** separately authorized fresh acceptance, measurements and cleanup.
