# Bounded retained acquisition records — agreed inert contract

This contract refines the design-only READER_ACQUISITION_CONTRACT.md. Coordinator
review agreed the corrected inert contract before implementation; no shared
schema or runtime-custody change is authorized. Implementation base is signed
combined checkpoint `371cea7318f0e1326539de0e0e3ac8bdbec9cc4e`.

## Agreed ownership

RUN owns only new `native_phase3_run_acquisition.py`,
`native_phase3_run_acquisition_verify.py`,
`tests/test_native_phase3_run_acquisition.py` and this lane's handoff/checkpoint.
Coordinator owns shared schemas/registry, staging, real reader/transport/loss
provisioning and broker submission state. The contract below is an inert local
retained-record contract, not a claim of trusted acquisition or deployment.

## Proposed API and bounded records

`project_acquisition(raw: bytes, *, bindings: dict) -> bytes` produces canonical
bytes for the existing progress window. No acquisition, I/O, clocks or side effects.
`verify_acquisition(raw: bytes, window: bytes, decision: dict, *, bindings: dict,
expected_raw_digest: str) -> dict` independently reconstructs the projection and
calls existing `verify_progress`. It imports neither the acquisition producer nor
its parsing/join helpers. Existing progress code remains unchanged.

Input: canonical ASCII JSON, <= 32768 bytes, exact fields and strict integer types;
noncanonical/duplicate-key/extra-field/overflow input refuses with ValueError.
Unsigned measurements must fit [0, 2**63); positive durations. All digest pins
are lowercase sha256 strings. Null is allowed only where explicitly listed.

Caller-held bindings: exact digest keys `epoch`, `challenge`, `request`, `process`,
`clock`, `loss_scope`, `policy`. They are supplied from independent retained
authority, never derived from the bundle by the verifier. Consumer additionally
pins the entire raw bundle. Digests establish joins, not authentication.

Top-level exact keys: `schema`, `epoch`, `challenge`, `reader`, `loss`, `submission`.
Schema: `aragorn/native-phase3-run-acquisition/v1`.

- epoch: `process`, `clock`, `loss_scope`, `policy`, `deployment_digest`.
  Its canonical digest equals bindings.epoch. process is a caller-pinned canonical
  identity object: `boot_id` (UUID), `reader_pid`, `reader_start_ticks`, `sensor_pid`,
  `sensor_start_ticks`, `reader_uid`, `reader_gid`, `sensor_uid`, `sensor_gid`,
  `reader_source_digest`, `sensor_source_digest`, `stream_digest`,
  `program_map_digest`. PIDs/start ticks positive; UIDs/GIDs nonnegative.
  clock: `boot_id`, `clock_id`=CLOCK_BOOTTIME, `time_namespace_inode` (positive).
  Clock boot must match process boot. loss_scope is a sorted unique list of 1–32
  sha256 series identities (each binds metric name, labels and source applicability
  externally). policy: `timeout_ns`, `max_age_ns`, both positive. Digests of these
  four records must match caller bindings.
- challenge: `epoch_digest`, `request_digest`, `boundary`, `nonce` (64 lowercase hex),
  `issued_ns`, `deadline_ns`, `sequence_before`. Digest equals bindings.challenge;
  joins epoch/request pins; deadline=issue+policy.timeout_ns without overflow.
  boundary MUST equal the immutable local value BEFORE_FIRST_EFFECT. It is never
  a send-after-connect boundary. One request/first-effect boundary only; replays
  are a coordinator ledger concern.
- reader: `epoch_digest`, `challenge_digest`, `request_digest`, `process_before`, `process_after`,
  `clock_before`, `clock_after`, `peer`, `status`, `sequence_after`, `ack_ns`, `received_ns`.
  Before/after identity objects must equal pinned epoch records (with strict
  scalar validation). peer is null only for TIMEOUT; otherwise exact integer
  `pid`, `uid`, `gid` equal the caller-pinned reader identity (acquired by the
  monitor from the actual sender; this offline join cannot authenticate that
  acquisition). status=ACK requires ack/receive times, sequence strictly
  greater than baseline, issue<=ack<=receive<=checked. status=TIMEOUT requires
  null ack/receive and unchanged sequence; no invented progress. Malformed or
  incomplete identity observations refuse, never become a timeout. ACK can be
  late or stale; preserve actual timestamps for the existing leaf to classify.
- loss: `epoch_digest`, `challenge_digest`, `request_digest`, `scope_digest`, `before`, `after`. Each sample is null or
  exact `start_ns`, `end_ns`, `counters`; before.end<=issue and after.start>=deadline;
  sample brackets ordered and <=checked. counters is a list matching the pinned
  scope order exactly, each value nonnegative integer or null. Missing/unknown
  samples/counters project null for that side. Every per-series decrease makes
  both projected totals null so another increase cannot conceal a reset. Sum
  known counters only when the entire inventory is present; overflow refuses.
- submission: null OR `epoch_digest`, `challenge_digest`, `request_digest`,
  `checked_ns`, `custody`, `intent`, `effect_possible`. custody is EXCLUSIVE or
  PARTIAL; intent/effect_possible are strictly true/false/null. With a record,
  checked_ns closes the window (>=deadline and >=receive and final loss end).
  True intent OR true effect_possible -> SUBMITTED; otherwise EXCLUSIVE with
  both exactly false -> NOT_SUBMITTED; all other cases -> UNKNOWN. False/null
  never overrides a positive indication. Bindings must match even for partial
  records. Missing submission cannot provide checked_ns: refuse projection,
  retaining raw evidence and operational ambiguity (never imply unsubmitted).

Every nested epoch_digest, challenge_digest, request_digest and scope_digest MUST
equal the corresponding caller-held epoch/challenge/request/loss_scope binding,
wherever present in challenge, reader, loss or submission. Syntax-only checks are
insufficient, including for TIMEOUT, unknown loss and PARTIAL submission records.

Projection uses epoch/challenge caller pins, policy freshness, challenge baseline,
reader acknowledgement, loss totals/nulls and broker state, without inventing
timestamps. Calls to evaluate_progress remain with the existing caller; the new
independent consumer joins the decision through verify_progress only. Return
claim flags remain false, including acquisition authenticity, sensor health,
effect authorization and RUN qualification. A refusal never supplies an effect
verdict; caller must preserve INDETERMINATE for possible submitted effects.

## Explicit coordinator interfaces and review gates

Real reader supplies challenge-bound loop acknowledgement only; protected monitor
supplies process/clock/source/scope readbacks, brackets and raw retention; broker
supplies serialized request/submission records and one-use challenge state.
Neither finite projector nor verifier validates live peer credentials, loaded
programs, authenticity, replay exclusion or actual delivery completeness.
Missing applicability must reach null, not a zero total. Actual raw metric/peer
records and a future acquisition-custody consumer remain separate prerequisites.

HTTP post-connect continuation is not wired: this verifier preserves INDETERMINATE
after submission, even with clear reader progress. That policy gap remains open.

Proposed focused cases: independent expected projection; ACK/timeout/stale/late;
positive/missing/reset/overflow loss; every caller binding and nested identity
mutation; canonical/shape/size/scalar refusal; submission truth table including
partial records and absent state; raw/window/decision tampering; static independent
consumer import boundary. No shared fixture imports or historical test reruns.
Exact source/test/stdlib closure and stage proposal follow agreed implementation.
Coordinator registration and scheduling precede execution; then one signed batch.

Status: corrected contract agreed by coordinator thread
`01a12dd9-a3af-7a10-9a3e-66b049477354` before implementation, after requiring
explicit nested pin equalities and immutable BEFORE_FIRST_EFFECT binding.
Lane fast-forwarded to the combined checkpoint and verified its signature.
Implementation/check status is recorded in ACQUISITION_RECORD_HANDOFF.md.
Cleanup hold and every qualification ceiling remain unchanged.
