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

Retain actual action DONE immediately after authenticated receipt, before binding
checks; completion joins that retained digest without a duplicate write, then
retains sensor DONE and worker result before readback.
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
header/body bytes can be retained as base64 before parsing. Retain an available
header-only prefix before the bounded body read; short-read bytes not returned by
the existing primitive remain unavailable, never invented complete capture.
Preserve actual validated request/activation/measurement/lineage/grant
context before OFFER, incoming CHECK and outgoing CURRENT_ATTEMPT before send.
The latter is attempted authority, not proof of delivery.

Add a detached `SensorTicket.terminal_receipt` getter available only after its
actual finish and before ACK in an active scope; no new receive or health claim.
After actual action DONE, sensor finish and full guard, call evidence.complete
before pair retirement and either ACK. Evidence failure must never release a
successful terminal barrier or retry the effect. Retain original errors/prefixes;
public worker/result contracts do not acquire raw private content. The protected
handoff defers worker-result delivery to native ownership; only after the evidence
scope closes and its detached completion record passes validation does native
deliver the original result. Legacy handoff delivery is unchanged.

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

## Completed offline implementation

The protected native caller now retains available request-frame prefixes, exact
request/offer context, CHECK/CURRENT attempts and actual action/sensor terminal
records in the existing CAS through a separate absent-only action index. The
fixed native owner independently reads the original locked action controls,
retains their raw bytes before parsing, and joins CONSUMED state, profile receipt,
request projection and terminal responses. It never initializes or repairs those
controls. Effective BLOCK remains distinct from a policy ALLOW and from verified
sink residue. Storage/handle uncertainty survives the original failure.

Review corrected two caller-order gaps before execution: retain an available
header before a body read can fail; defer protected worker-result delivery until
the evidence holder closes. The caller uses one detached validated completion
record, so a second observation getter cannot fail after successful delivery.
Historical bare channels and unavailable NO_REQUEST remain unchanged.

Independent source/test/closure review completed. All **113 focused checks passed
on the first attempt**: 96 new and 17 affected, zero reruns, zero old stage runs.
The three reviewed input closures contain 94, 94 and 102 paths; the bounded
registry now contains 224 stages. Retained pipeline records:

| Stage | Checks | Successful fingerprint (sha256) |
| --- | ---: | --- |
| pi-core-action-evidence-store-offline | 28 | `79d96a2cf1bd9944d926ab54b75cdd6ad2451bac8bfb078925cd64d4ce72ea1d` |
| pi-core-action-evidence-offline | 37 | `f1a494a6aa4a9aa2f185a3da29e180eb479612b352440752371812c06d7ba770` |
| pi-core-action-evidence-composition-offline | 44 | `d81651b2fbc3c7a8c01ddce62247094eb09b73e29d7e19ac07fc911461534c29` |
| pipeline-capacity | 4 | `44050fe5a8daeb2a5f7cc310b1f1f857f4e950307dee4adb831d3a38a4760236` |

No target build, VM installation, live service, provider call, capture or
qualification ran. The retained-record join is not independent sink, full
timing, complete sensor health or deployed-source qualification. No approved
threshold or operational hold changed; all 985 unrelated drafts remain outside
this batch. Signed source/merge hashes and exact remote readback accompany the
delivery milestone; this document cannot contain its own resulting commit hash.

The next connected offline dependency is fresh root-owned provider control/CAS
base preparation, distinct from the action-owned base delivered in batch30.
Genuine health and initial pinned control publication remain separate obligations;
no healthy or authoritative record may be manufactured by the base installer.
Declared-script task contexts are already within the approved SDD; an additional
runtime selection is not required, but their actual confined producer and full
task-boundary measurement connections remain unimplemented.

1. **D2:** raw action retention connected offline; actual protected views, separate provider controls,
   genuine health, recovery/full timing and separately authorized useful pilot.
2. **D3:** remaining admission/RUN/health and real declared-script task contexts.
3. **D4:** complete independent semantic inventory/prerequisites, then freeze.
4. **D5:** separately authorized fresh acceptance, measurements and cleanup.
