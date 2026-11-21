# D3 batch 77 — the source observation used for an action's CURRENT

The [action evidence owner](pi-core-action-evidence-batch-31.md) already
retained the broker's CHECK and the outgoing CURRENT intent. The handoff
also performed a final native source-health check, but discarded its return
value. Looking at the observer later cannot establish which check preceded
this send. This successor changes that boundary on the managed action path.

The native caller returns the trace snapshot from the existing guard on
the owned worker. The handoff makes that return available only after its
activation and worker-identity checks. The owner binds the exact received
CHECK, request, activation, sequence and outgoing packet to that trace;
retention and verification consume the original freshness and deadline budgets.
An absent, incomplete, expired or oversized trace is not replaced by a
second challenge. There is no automatic repeat of a CURRENT or an effect.

| Record | What a later reader may infer |
|---|---|
| CHECK | An incoming broker check in this request's authenticated transport path; not permission in a different request. |
| Versioned CURRENT_ATTEMPT | The exact outgoing intent and the source evidence used to prepare it. Durable intent alone does not prove submission. |
| Local before-send and normal-return times | A bracket around the sender call on the original boot clock, not the broker's receipt, a remote timestamp, sink evidence or a complete decision interval. |

Do not infer a denial or absence of an effect from a missing send return, a
failure record, or an unverified cleanup. The existing terminal broker/sensor
joins and independent sink observations remain separate. No provider egress,
worker, broker or sensor is authorized by these records.

## Independent replay

Use [the read-only boundary reader](../../../src/aragorn/pi_core_action_boundary_verify.py)
with a separately identified ordered action index, protected activation/request,
broker nonce and original deadline. Supply the independently expected source
bindings, worker, clock, gate, peer/endpoints, inventories and challenges.
For each selected attempt, export the canonical bytes of its original embedded
`source_capture` under their digest into the private replay CAS. Preserve the
original attempt unchanged; a missing trace cannot be supplied from a later
snapshot. The reader compares the embedded bytes with that standalone object
and calls the existing Node source verifier at the recorded pre-send boundary.

The complete local-send finding requires every sequence from one through the
retained summary, with no forked trace, reordered check or missing normal
return. Its trust ends at the independently obtained index and expected pins:
it does not authenticate caller-selected pins or prove acquisition on a VM.
The 16-check, 64-record, 4 MiB record and 64 KiB index limits stay unchanged.
The action route uses one summary, not one extra indexed object per CHECK;
an unconfirmed write is never retried.

| Affected stage | Passed | Final fingerprint |
|---|---:|---|
| `pi-core-action-current-capture-offline` | 18 | `991aabe4f5782debaa9628a2c7cbf8f4bcf0c3256db5c06c3610bafa602e5224` |
| `pi-core-action-current-replay-offline` | 8 | `c2d2bcfa20320e55f9fddefe8f3a17011c64f16348a01d53fc63c23fcdd72828` |

The first sender fingerprint (`ee3c2dcb103578c79c6443e29da4fd0dd00f22b4ea151164d0c0c8d4e88ca183`)
is retained: one test incorrectly expected another write after uncertain
storage. The corrected test demands no further append and a retained cleanup
hold. Only the changed sender stage reran; the replay stage passed once.
No ptrace, socket traffic, installed worker, live sensor, service or spending.

1. **D2 open.** The operator selected one directly attached LUKS2 device with
   the header on that same device. Implement the corresponding read-only
   checks and separate provenance/freshness evidence. Worker-view proof,
   installed health, recovery/timing and authorized pilot remain. B49 stays null.
2. **D3 open.** One source-health boundary is connected in code; complete the
   remaining admission, seven event/six response and workload paths.
3. **D4 not frozen.** Finish independent coverage for all 29 requirements.
4. **D5 not authorized.** After freeze and separate approval: fresh admission,
   100 attempts, 100 paired tasks, cleanup and independent evidence replay.
