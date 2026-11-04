# Pi-core D2 batch 6: request-bound handoff and create enforcement

Date: 2026-11-03. Base: `b9f07f9d6ec43933d7a5eef87bce9896e0e1f43c`.
Release: source implementation, only new/affected offline checks, verified signed
commit and ordinary branch push. No live operations or deployment is authorized.

## Connected path

`handle_pi_request_connection` consumes the actual authenticated Pi stream, not
a caller-supplied request/PID/digest. It reuses protected activation readback,
socket-associated PIDFD, live profile measurement and held installed lineage.
The worker request must use the existing canonical frame plus write-side EOF;
this is a distinct connection from the multi-turn bootstrap protocol.

A fresh, independently authenticated root-to-broker packet channel carries the
exact request, activation and digests, original bounded deadline, fresh broker
challenge and one worker PIDFD. Broker custody is an exact-type scoped object
minted from this channel, not a JSON receipt or arbitrary caller callback. It is
one-use and cannot renew the activation's deadline. Sequence-bound CHECK/CURRENT
round trips require fresh protected remeasurement while root retains custody.

`handle_pi_broker_request` joins that protected origin to a **separate** accepted,
authenticated sensor stream. `mediate_pi_runtime_create` requires both. It
compares the complete file-create request, target/payload, session/run/tool call,
runtime/policy/skill pins, grant/install lineage and measured worker identity.
Ordinary relay assertions cannot create origin authority. Supplied sensor
attribution must actually match Pi; current relay-attributed observations refuse.
The root attestation is not converted into a fabricated sensor issuance.

The create-only mediator reuses the frozen grant, profile receipt, lineage,
protected lock, current-policy/health/revocation, replay and effect-journal leaves.
It composes the existing durable state transitions with mandatory Pi checks:
inside the grant-claim lock, during effect authorization, and after durable PENDING
immediately before the existing atomic file-publication primitive proceeds.
The final check also rejects expired or changed existing grant/lease/policy/health
state; a fresh root acknowledgement cannot renew any of those authorities.

The Pi receipt composition preserves the original policy verdict separately from
the effective outcome. A policy ALLOW followed by protected-request refusal, or
an exact replay BLOCK without a new policy decision, can be terminally consumed
without fabricating a policy BLOCK. Existing generic grant-state readers accept
the retained terminal record. Frozen recovery/archive routines still refuse
these effective-BLOCK receipts; they are not used by this one-shot caller. Pi
recovery and rotation must use the same reviewed distinction before repeated
native service operation. No record is reset or discarded to bypass this hold.

Ambiguous journal, publication, response, receipt or cleanup outcomes retain
their no-retry/recovery obligations. No claim is reset to AVAILABLE. Owned handles
are closed before the root receives a successful final result. Caller-owned
channels remain caller-owned and must be closed after this one-shot invocation.
The service conservatively reports uncertainty if mediation has been entered
but its result or delivery cannot be established; it does not fabricate success.

## Reuse, ownership and unchanged surfaces

- Two implementation lanes own the root handoff and broker mediator. The
  coordinator owns the connected service, registry, checks and release; a third
  lane independently reviews correctness/security before execution.
- Existing identity transport is factored into bounded authenticated packet
  leaves. Its identity-only wrappers remain strict and cannot authorize requests.
- Frozen v1/v2/v4/v5 brokers, their materialized predecessors, compiled Pi artifact,
  static OS closure, historic evidence and operational holds remain unchanged.
- This batch is file-create only. It does not expand HTTP/DNS/destructive coverage
  or claim that a fixed HTTP canary is provider mediation.
- No listener is created or unmasked, no service is installed, and no target
  binary, provider, VM or live workload is run. Native bootstrap remains
  `PROVIDER_UNAVAILABLE`; the legacy action endpoint remains masked.

## Evidence ceiling and remaining deployment prerequisite

This is a connected source-level request path, not a native useful-task pilot.
The caller must provision both channels under the final protected service
identities, route actual Pi requests through the new root reader, and supply a
genuine Pi-attributed sensor issuance. The existing relay-attributed sensor path
is deliberately insufficient. Credential-isolated provider/data mediation and
that native request/sensor composition are the next D2 prerequisites.

Temporary owned-file fixtures may exercise the existing durable create machinery;
kernel identity, transport, service and lineage boundaries remain explicitly
mocked. Authored fixture observations are never deployment, timing, sensor-health
or qualification evidence. No Phase 3 completion or Phase 4 release follows.

## Focused verification

Three new stages cover handoff, broker and connected service; only affected
identity transport compatibility cases and four registry-capacity checks are
included. The registry capacity changes from 142 to 145. Historical suites and
frozen qualification campaigns are not scheduled merely because shared
source/runner hashes change. All 94 selected new/affected checks passed after
review; there were no live operations or unchanged successful check reruns.

- `pi-core-request-handoff-offline`: 39 passed once;
  `sha256:3703f97ce533a2098a901f15843a4592b865d4afe0253c84c8e7f9b43cf72c0b`.
- `pipeline-capacity`: 4 affected checks passed once;
  `sha256:5207d106f6bc4487a1307027390eb51a8f3471248a07442d96c5afa3757236bd`.
- `pi-core-request-service-offline`: 15 passed once;
  `sha256:2931ddc7adb9f5108cc08623ed88d2c6ff7a32ab74621f6ba59c84b2c0862fea`.
- `pi-core-request-broker-offline`: 36 passed after the fixture repair below;
  `sha256:471ad98dfbd3deb5e4d144a5ec52a76c0751212f58dda50d7a28d7bd2f98fb6c`.

The first broker fingerprint
`sha256:ba12d9feee0b857a749367d7b5231ecbd558962d6776c13e57fa239abbde3196`
is retained as FAIL: all 36 checks stopped in setup, before any test body. The
pipeline's restricted environment omits TMPDIR, so the default temporary path
resolves under world-writable `/private/tmp`, correctly refused by the existing
protected-ancestry guard. The fixture correction uses a unique, automatically
cleaned temporary directory under the already-safe ignored repository state
directory. No production permission guard or unrelated parent mode changes.
Only the affected broker stage ran after this fixture correction; the unchanged
handoff, service and capacity successes are retained without reruns. The failed
fingerprint was not retried, altered or erased. Temporary broker fixture
directories were removed by their owned cleanup; historical resources remain
untouched. This is unit-fixture cleanup, not native-deployment cleanup evidence.

## Remaining plan

1. **D2:** wire genuine Pi sensor attribution, protected channel/native request
   routing, Pi-aware effective-receipt recovery/rotation, and credential-isolated
   provider/data mediation on the same runtime.
2. **D2 pilot, separately authorized:** provision the pinned controlled Linux
   deployment; show useful allowed/blocked work, independent output/health evidence
   and verified owned cleanup. No live authority is granted by this checkpoint.
3. **D3:** complete managed lifecycle/update/revocation, required RUN/sensor-health
   and real workload/timing coverage on that deployment.
4. **D4:** executable approved 29-requirement contract, complete independent
   producer/verifier inventory, then one deployment freeze.
5. **D5:** separately authorized fresh acceptance, verified cleanup and offline
   replay. Phase 3 remains incomplete until these obligations genuinely pass.

The containing verified signed commit and ignored post-push release checkpoint
record this batch. Original 48-ID results and historical cleanup holds are intact.
