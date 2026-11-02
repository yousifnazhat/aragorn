# Serialized reader evidence and HTTP submission design

Status: read-only source review and proposed coordinator integration design.
This document does not release implementation, a registry stage, deployment,
protected storage, IPC, live operations, private retention or cleanup. The
protected root provider and broker integration described below do not exist yet.

## Reviewed source findings

These anchors refer to repository source; deployed rendered successors must be
reviewed separately before integration. A file or method name is not evidence of
deployed source identity.

| Source anchor | Observed behavior and consequence |
| --- | --- |
| `src/aragorn/runtime_http_broker.py:210` | Recovery, observation publication, policy evaluation and request consumption run within the existing broker lock. Reuse this serialization boundary. |
| `src/aragorn/runtime_http_broker.py:253` | Existing consumed request/observation records reject replay. Their presence alone does not distinguish connect intent, payload intent or completed effects. |
| `src/aragorn/runtime_http_broker.py:285` | The internal authorization callback can run exactly twice and reevaluates policy/revocation/health state. Final measurement is recorded only at its first invocation. |
| `src/aragorn/runtime_http_action.py:413` | Callback 1 runs after execution guards and before the connect attempt. |
| `src/aragorn/runtime_http_action.py:417` | Connect occurs before callback 2 at line 421. Refusal at callback 2 cannot establish an unsubmitted action, even if payload bytes remain zero. |
| `src/aragorn/runtime_http_action.py:423` | `sent` becomes unknown before the single send call. Short writes, interruption, malformed replies and cleanup failure cannot authorize retry. |
| `src/aragorn/runtime_http_action.py:37` | The existing total transport budget is 0.5 seconds, enforced using `time.monotonic()`. |
| `src/aragorn/native_phase3_run_acquisition.py:94` | The projected window requires submission checking at or after the challenge deadline. |
| `src/aragorn/native_phase3_run_acquisition.py:123` | Before-loss must end before challenge issuance; after-loss must start at or after the challenge deadline. An early ACK does not close this window. |
| `src/aragorn/native_phase3_run_acquisition.py:133` | A per-series counter reset makes projected loss totals unknown. Preserve raw reset evidence; do not represent this as zero loss. |
| `src/aragorn/native_phase3_run_progress.py:72` | `SUBMITTED` and `UNKNOWN` always produce `INDETERMINATE`, including when health reason codes are empty. |
| `src/aragorn/native_phase3_run_reader_store.py:82` | Reader storage requires Linux, root real/effective/saved UID/GID, and the original main process/thread. |
| `src/aragorn/runtime_broker_decision_measurement.py:114` | Broker measurement requires a non-root broker process. Calling the root-only reader store directly from this process is invalid. |
| `src/aragorn/runtime_broker_decision_measurement.py:263` | Existing request acceptance precedes grant claim and protected input verification. Preserve that full accepted-to-finalized interval. |
| `src/aragorn/runtime_endpoint_journal.py:1` | Endpoint journal events are best-effort observations and explicitly provide no durable retention or RUN authority. They cannot replace submission state. |

## Smallest proposed broker change

Keep `runtime_http_action.execute_http_effect` unchanged. Add a durable broker
submission provider and exact pinned hooks in the rendered HTTP broker. The
existing callback order distinguishes `BEFORE_CONNECT` from
`BEFORE_PAYLOAD_SEND`; there is no need to add configurable callbacks or a second
transport abstraction.

Proposed coordinator-owned paths, not released assignments:

- `src/aragorn/runtime_http_run_submission.py`: fixed protected provider client,
  durable submission state and retained observations under the existing lock.
- `scripts/materialize_runtime_http_run_guard.py`: finite, reversible changes to
  the exact HTTP broker successor and its actual deployed source inventory.
- `tests/test_runtime_http_run_submission.py`: new mocked provider and rendered
  call-site checks, after complete dependency review and stage registration.
- `docs/phase3/coordinator/serialized-reader-broker-contract-v1.md`: future exact
  contract, required before implementation release.

Proposed independent consumer assignment, also not released:

- `src/aragorn/native_phase3_run_submission_verify.py`
- `tests/test_native_phase3_run_submission_verify.py`
- `docs/phase3/run-health/SUBMISSION_EVIDENCE_HANDOFF.md`

The intended internal interface is:

```python
guard = begin_http_submission_locked(
    control_fd, lock_fd, config,
    request_digest=request_digest,
    effect_digest=effect_digest,
    expected_epoch_digest=expected_epoch_digest,
)
guard.before_connect(deadline_monotonic=deadline)   # exact bool
guard.before_payload(deadline_monotonic=deadline)   # exact bool
guard.observe_transport(result_or_error)
guard.final_readback()
```

The caller retains its existing lock and descriptors. The guard must not acquire
that lock again. A Boolean `locked=True` supplied by arbitrary code is not proof
of custody: exact source wiring, original broker process identity and held/named
lock/control identities form part of the protected acquisition contract.
The expected epoch must come from pinned protected deployment configuration,
not from a digest calculated over an untrusted response. The precise configuration
source and its join to the grant/measurement context remain unresolved below.

## Fixed root-to-broker boundary proposal

A root provider owns reader acquisition, the root-only claim/evidence directory,
and actual reader/loss/program/map observations. The broker remains unprivileged.
Do not loosen reader storage permissions or elevate the broker to connect them.

The smallest proposed production boundary is one fixed Linux AF_UNIX
SOCK_SEQPACKET endpoint at `/run/aragorn-phase3-reader/guard.sock`. This path is a
proposal, not an installed endpoint or accepted final contract. A provisioned
root-owned parent and broker-group traversal, plus a root-owned socket restricted
to the exact broker group, would allow only the broker transport access. The
actual UID/GID values, directory/socket modes and service source/identity pins
must be fixed in the final contract. Filesystem access alone is insufficient:
both sides must check actual peer credentials, pinned process start/boot identity,
PIDFD liveness, time namespace and exact connection epoch. No caller-selected
path, socket type, credentials, optional callback or fallback transport is allowed.

One connection belongs to one validated broker request and spans the two guards.
Requests would name only the fixed phase and pinned request/effect/epoch/context;
they cannot supply reader records, arbitrary paths, fixture data, clock values or
claims of successful retention. The root provider selects its real reader and
telemetry sources from protected configuration. Phase order is consume-once:
`BEFORE_CONNECT`, then optionally `BEFORE_PAYLOAD_SEND`, then terminal close.
Unexpected/repeated/out-of-order packets, ancillary descriptors, truncated packets,
identity changes, closed peers and ambiguous exchange all refuse. Every installed
descriptor must be accounted for and closed without ambiguous close retries.

The response carries bounded canonical original evidence and explicit retention
readbacks, with all request/epoch/source/observer bindings. Broker acceptance
requires actual transport identity and the independent consumer's matching raw
records. A purported digest or a root-looking UID in JSON is insufficient.
The exact response schema, bounds, credential ABI and descriptor-cleanup rules
must be specified before this endpoint can be implemented.

The root provider must not acquire the broker serialization lock, publish broker
health through a path that needs it, or wait for work that needs it while serving
the locked broker. It acquires raw reader/telemetry evidence and returns it. The
broker retains its ordinary policy/revocation/health gates and records the
serialized submission state itself. This avoids a root-provider/broker deadlock.

A separately pinned pre-acquired handoff is an alternative only if its producer
can bind the actual validated request before effect dispatch, retain the complete
window and expose a fixed protected read-only handoff without opening the private
reader store. It must also support fresh second-guard observations. The current
code does not provide this handoff; arbitrary caller-provided JSON is not a
substitute. Prefer the single fixed IPC boundary unless an existing equivalent
protected handoff is found during full integration review.

## State and the two guard boundaries

Use a fixed namespace under the already-held broker-owned control root. Bind
each immutable record to request, effect, epoch, grant/context, broker identity
and deployment source pins. Publish with exclusive final-name creation, bounded
canonical bytes, file and directory fsync, and held/named readback. Do not use an
idempotent-existing-record helper, erase partial files or treat missing terminal
records after restart as permission to repeat an action.

1. After durable request consumption and before any connect intent, retain the
   fresh serialized `NOT_SUBMITTED` snapshot. It is valid only for the current
   uninterrupted exclusive custody interval and exact request.
2. Callback 1 obtains a complete independently checked reader/loss window and
   performs the existing policy checks. Missing or malformed observations,
   reset/lost/unknown counters, stale ACK, timeout or failed retention refuse.
3. Before callback 1 can return `True`, durably record connect intent. The
   conservative state becomes `SUBMITTED`. A crash between that record and the
   actual syscall never permits reverting it to `NOT_SUBMITTED`.
4. Callback 2 records its separate `BEFORE_PAYLOAD_SEND` observation. It must
   reject new health/policy failure, but preserve `SUBMITTED` and its associated
   `INDETERMINATE` disposition. Requiring `CONTINUE_OTHER_GATES` here would reject
   every normal HTTP action; relabeling the state as unsubmitted would be false.
5. Before payload authorization succeeds, durably record payload intent. Retain
   the final validated transport result or partial/error record. Short writes,
   interruption and retention/cleanup failures preserve explicit ambiguity and
   permanent consumption.

Retain the existing acquisition submission object with its exact fields. Put
phase, lock/source identities, journal sequence and raw record references in a
separate versioned supplement; extra fields cannot be silently added to the
frozen parser's schema. `intent=True` or `effect_possible=True` projects to
`SUBMITTED`; partial custody or unavailable facts stay `UNKNOWN`.

The second guard may reuse the original immutable ACK only while its original
age bound still holds and after fresh protected identity/loss readback. This is
a bounded freshness claim, not proof that the reader never hung after that ACK.
It must not consume or resend the original challenge. A newly issued post-connect
challenge cannot truthfully use the frozen `BEFORE_FIRST_EFFECT` boundary;
requiring one needs a new explicit payload-stage challenge contract and consumer.

## Timing and independent replay

The original acquisition contract requires a closed CLOCK_BOOTTIME window. The
before-loss sample must end before issuance; after-loss must start at or after
the challenge deadline; checked time must follow the after sample. Retaining an
early ACK does not satisfy these joins. Any intentional wait must remain inside
the preexisting overall HTTP deadline and its own verified clock domain.

HTTP currently limits the entire operation to 0.5 seconds using monotonic seconds.
Reader acquisition uses CLOCK_BOOTTIME nanoseconds with pinned time namespace.
Do not compare the numeric values directly, assume equal offsets across suspend,
silently extend the HTTP budget, or shorten the evidence window. The final
contract must choose a reader timeout/max-age and bound collection/IPC/retention
cost so the complete valid path can fit. If it cannot, fail closed and report the
budget conflict; do not claim the common path is ready.

Preserve the existing `REQUEST_ACCEPTED -> DECISION_FINALIZED` measurement from
the accepted v4 submission through the first effective broker decision. Include
new pre-connect provider work before finalization. Retain payload revalidation
timing as additional evidence, without moving or replacing the original
acceptance timestamp. Final metrics also need independently validated boot/time
namespace joins; the current measurement identity's mount namespace is not a
substitute for the time namespace.

Independent replay needs original epoch/challenge/reader bytes; seven bindings;
caller-held observer identity and connection epoch; exact raw loss counters and
scope; program/map identity; broker process/boot/time-namespace pins; request,
effect and grant/context joins; immutable state records and custody metadata;
distinct phase and clock readings; transport results and all failure/cleanup
evidence. Reconstruct the existing acquisition/progress projection and monotonic
submission transitions. Preserve per-series counter reset explicitly even when
the existing projection represents its totals as unknown. A missing receipt is
never evidence of non-submission.

## Exact unresolved contract decisions

- Provisioned root-provider executable, systemd unit, fixed endpoint ancestry,
  socket mode/owner/group, broker caller identity and independent server identity
  source, including the boot/start/source pins that survive no restart implicitly.
- Root-provider access to the actual reader's accepted transport and meaningful
  idle read-loop checkpoint; existing root storage supplies neither.
- Fixed epoch/config source and the source-to-loaded-config join used by both
  broker and root provider; exact propagation of accepted v4 grant/context pins
  into the inner HTTP broker, including explicit refusal outside that context.
- Exact canonical IPC request/response fields, byte limits, packet credential
  ABI, connection-epoch issuance, freshness rules, readback acknowledgment and
  interruption/cleanup evidence. These cannot be left as arbitrary callbacks.
- Actual loss/program/map provider inputs, missing/reset semantics and fresh
  second-guard acquisition; no fabricated zero counters or cached health flag.
- Timeout/max-age values compatible with the closed window and existing 0.5
  second HTTP budget, plus verified CLOCK_BOOTTIME/time-namespace binding.
- Exact broker-owned journal names/schema, publication/readback helpers, permanent
  residue handling, serialization ownership and independent consumer schema.
- Full generated-source/staging/service/identity inventory updates and the new
  focused check closure. The original root-only reader store and frozen HTTP
  predecessors must not be repinned as if unchanged after rendering changes.

No tests, imports, generated-source execution, IPC, protected writes, Git actions
or live observations were performed for this design. These findings identify the
next concrete shared-path contract; they do not close a RUN requirement or
establish Phase 3 implementation readiness or qualification.
