# Reader acquisition contract — reviewed design, not deployed behavior

Reviewed against `c374e524a9d66ead94f1f8e6600d6b1173ccc11a` on 2026-10-11.
This lane-owned design precedes shared runtime changes. It defines a finite
acquisition adapter for the existing progress producer and independent verifier;
it does not change their schema or claim ceilings. No runtime code changes here.

## Existing boundaries and review conclusion

- `PHASE3_ROADMAP.md`, sequential plan step 2: common staging has no Tetragon
  reader, protected progress marker or sensor/map/program binding provisioning.
  The staged sources provide no actual reader to attach this contract to yet;
  live deployment state was not inspected.
- `runtime_action_observation_publisher_v4.py:serve_runtime_action_observation_publisher_v4` uses blocking accept and
  request handling. A responsive publisher is not proof of telemetry-reader
  progress; adding a timer to that process would not satisfy this contract.
- `runtime_tetragon_process.py:normalize_process_capture` consumes caller
  reports, while `runtime_tetragon_loss.py:analyze_tetragon_loss_window` explicitly
  disclaims acquisition, continuity and health. Reuse parsing, not their outputs
  as authenticated health authority. Missing sparse BPF counters remain unknown.
- `runtime_http_broker.py:mediate_observed_http` holds the broker lock and checks
  authorization before connect and send. `runtime_http_action.py:execute_http_effect`
  marks the operation attempted before connect; failures after that are ambiguous.
  A consumed replay entry or profile-pending entry is not proof of no submission.

Review verdict: suitable as the proposed interface for a finite acquisition
successor, subject to the prerequisites below. NOT ready for shared deployment
wiring: real reader and loss-source provisioning are absent, and post-connect
authorization is outside the progress verifier's current contract. No new health
authority, transparent HTTP wrapper, stage or source pin is approved by this file.

## Ownership and trust

The sensor reader supplies only loop sequence and a challenge acknowledgement.
It MUST NOT supply the authoritative epoch, policy clock limits, effect_state,
expected pins, or a self-declared healthy flag.

A protected external monitor owns challenges, evidence retention and acquisition
readbacks. The broker owns request identity, submission state and final decision
time. Root provisioning binds the monitor, reader and sensor identities to the
same frozen deployment. Runtime/worker input cannot write monitor or broker state.
This is a local protected-process boundary, not hostile-root attestation.

Proposed transport: one bounded AF_UNIX connection from the reader to the monitor,
using an endpoint provisioned by the coordinator in a protected directory. On
accept, the monitor verifies SO_PEERCRED against the exact expected reader PID,
UID/GID and a held process identity; same UID alone is insufficient. It holds a
pidfd and checks boot/start-time and namespace bindings through acquisition.
Bind each message to kernel-supplied sender credentials as well; prevent connection
FD inheritance/transfer so connection-time credentials cannot stand in for a new
sender. Exact process-custody checks must refuse PID reuse during initial binding.
Reject truncated/oversized frames, duplicate keys, extra fields and ancillary FDs.
Use bounded framing and reads, no arbitrary filenames or runtime-selected socket.
Socket creation, owner/mode rules and service credentials belong to coordinator
staging. Do not use socketpair creation-time credentials as proof of a child PID.

The acknowledgement path MUST NOT acquire the broker lock or synchronously call
the broker. The monitor's immutable completed evidence must be independently
readable while the broker holds that lock; otherwise acquisition can deadlock
behind the very operation it is monitoring. Existing protected file/credential
helpers should be reused once the coordinator chooses the exact projection.

## Epoch, challenge and reader loop

The monitor retains a canonical epoch record and its SHA-256 digest. The record
binds: deployment/source/configuration/policy digests; kernel boot ID; reader and
sensor PID/start-time/UID/GID identities; held process handles for live checks;
clock/time-namespace identity; sensor stream identity; loaded sensor program/map
identity evidence; and the exact required loss-counter inventory/labels. Handles
are not serializable evidence: retain their acquisition/readback records as well.
Restart, stream reconnect, sequence reset, program/map replacement or changed
configuration ends the epoch. Never patch an old epoch with a new PID.

For one reader, allow only one outstanding challenge. Before issue, retain a
baseline sequence and loss inventory under the same epoch. Construct a canonical
challenge record containing epoch digest, fresh 256-bit CSPRNG nonce, request
digest and exact pre-effect boundary, baseline sequence, issued_ns, deadline_ns
and max_age_ns. Its SHA-256 digest is the verifier's challenge pin. The expected
epoch/challenge pins come from these monitor-held records, never the reader's
response. A challenge is consumed once under broker serialization; restart or
retention ambiguity invalidates it. No acceptance based on nonce equality alone.

The actual telemetry loop multiplexes its sensor stream and the challenge channel
with bounded waits. On receipt it records the pending challenge but acknowledges
ONLY after a subsequent successful read-loop checkpoint:

1. Recheck the same stream/producer identity and perform a nonblocking sensor read
   or bounded poll. EAGAIN/idle timeout may count; EOF/disconnect/read error may not.
2. Validate and deliver every record read in that iteration into the protected
   downstream path with accounted backlog. Parser failure, discarded records or
   blocked downstream delivery prevent a success acknowledgement. Bound each batch
   so continuous traffic cannot starve challenge handling.
3. Increment the per-epoch sequence once after that checkpoint, stamp
   CLOCK_BOOTTIME and send the exact pending challenge digest, epoch digest,
   sequence and checkpoint timestamp. Sending from a heartbeat thread, socket
   handler, before the poll, or merely on traffic arrival is forbidden.

An idle checkpoint establishes reader-loop responsiveness only. It does not prove
that kernel production is alive or that all events were delivered. Those require
separate producer/program/map and loss coverage; unknown coverage cannot turn into
a healthy grant. A monitor receiving no response closes the window as no progress
without waiting for the hung reader or interpreting socket liveness as progress.

## Projection into the existing 4096-byte window

All raw acquisition records are retained separately; the compact progress window
is their projection. New acquisition record schemas and inventory registration
remain coordinator-owned. All times are integer nanoseconds in the SAME verified
CLOCK_BOOTTIME domain, without translating wall time or namespace offsets.

| Existing field | Authoritative source and validation |
|---|---|
| schema / clock_id | Fixed existing window schema / CLOCK_BOOTTIME. |
| epoch | Digest of the monitor's complete epoch record after live identity recheck. |
| challenge | Digest of the retained one-use challenge record for this request/boundary. |
| issued_ns | Monitor's timestamp immediately before publishing the challenge. |
| deadline_ns | issued_ns plus the positive timeout in protected policy; overflow refuses. |
| checked_ns | Broker clock read at the final serialized health decision; must be at or after deadline. |
| max_age_ns | Positive freshness limit from the same protected policy, never from the reader. |
| sequence_before | Last monitor-accepted sequence before issue; initial zero only for a newly bound epoch. |
| sequence_after | Sequence of the validated challenge response; if no response, unchanged baseline. |
| ack_ns | Reader checkpoint time, checked against issue <= ack <= monitor receive <= checked and common time domain; null if absent. |
| loss_before / loss_after | Conservatively projected complete scoped counters, as described below; null when unknown. |
| effect_state | Broker's protected request-specific state; the sensor has no authority over it. |

The monitor validates response identity, exact challenge, increasing sequence and
timestamp brackets before projection. Malformed/foreign responses are retained as
acquisition refusal, not replaced with invented observations. A valid but late
response can be retained with its real ack time so the existing deadline reason
is reconstructed. Do not refresh ack_ns to the receive time: queued old progress
must not become fresh. Do not invent an acknowledgement at the deadline.

The current leaf evaluates a CLOSED window: ack_ns < deadline_ns is timely;
checked_ns - ack_ns < max_age_ns is fresh. No early-ack shortcut is compatible.
Collect outside the broker lock, close at deadline, then join under that lock.
At every actual gate use a new checked_ns and re-evaluate freshness; a previous
CONTINUE_OTHER_GATES result is not a lease. Reject clock-domain changes or negative
time ordering. Policy timeout must fit the existing action deadline; this design
does not choose unmeasured latency constants or extend HTTP's 0.5-second budget.

## Loss accounting

Acquire before/after observations from the same producer epoch with raw source
bytes, observation time brackets and exact series identities. Baseline acquisition
must finish before issue; final acquisition must start at/after deadline and finish
before checked_ns. Per-series counters must be applicable, present and monotonic.
The projected total is the integer sum across the frozen required inventory,
including reader drop/error counters where defined; it is NOT an event count.
Every series is compared before summing so a reset cannot hide behind an increase
elsewhere. Reject overflow of the leaf's signed-63-bit range rather than clamp.

Missing series, scrape failure, unsupported applicability, changed labels or a
per-series reset invalidates the comparison: use null for the affected projection
and retain the detailed reason in acquisition evidence. Never invent zero or
relabel another metric as the missing BPF family. Reader and producer identity
change is epoch refusal, not merely a counter delta. Existing parser output alone
cannot meet these custody/continuity obligations. Positive baseline values remain
visible; no selected increase establishes only the scoped interval's observation.

## Broker submission state and in-flight handling

Submission state is joined by request digest, capability/profile claim, epoch and
effect boundary, under the existing broker serialization. It describes the whole
protected operation, not just the next network write.

| State supplied to verifier | Required broker evidence | Handling |
|---|---|---|
| NOT_SUBMITTED | Current exclusive request ownership; validated ledger/journal shows no submission intent or earlier possible effect; execution has not crossed the submission latch. | Clear window may continue other gates; failures hold. Neither result proves sink absence. |
| SUBMITTED | Durable submission-intent latch set before handing control to any effect-capable syscall/callback. Conservative even if the syscall later fails. | Always INDETERMINATE from this verifier; retain state, never retry. |
| UNKNOWN | Missing/corrupt ledger, ambiguous crash, lost exclusive custody, transport handoff without decisive retained state. | Always INDETERMINATE; never derive NOT_SUBMITTED from a missing receipt. |

The broker must persist/fsync the conservative submission latch BEFORE the first
possible effect, after all pre-effect gates; failed persistence prevents the call.
A crash between latch and syscall leaves SUBMITTED/UNKNOWN. Absence of a new latch
only proves NOT_SUBMITTED when the same exclusively owned request's complete
state has been validated; after recovery it is not a default. Reuse existing
pending/replay machinery, but its present fields do not yet implement this join.
No health recovery, timeout or fresh challenge clears the latch or old ambiguity.

For HTTP, the first possible effect is connect, not payload send. The new finite
gate can be composed before connect. Once connect may have occurred, the second
authorization callback MUST NOT pass effect_state=NOT_SUBMITTED to get a clear
result. This verifier is not an in-flight continuation authorizer: healthy progress
still returns INDETERMINATE for the whole operation. Until a separately reviewed
in-flight policy/consumer exists, do not wrap both HTTP callbacks with this leaf
and claim a functioning integrated transport. Health loss after submission stops
further attempts, invokes the existing retained suspension path where authorized,
and preserves INDETERMINATE; it never proves rollback or residue-free blocking.

A point-in-time gate cannot eliminate the gap between clock check and syscall, or
cancel an in-flight kernel action. A response deadline and observed suspension
need separate evidence. Do not turn this finite contract into continuous health
or bounded response-latency proof.

## Independent acquisition consumer and evidence closure

The existing verify_progress independently checks only the projected raw window
and decision. A RUN-lane acquisition consumer must first validate the external
epoch, challenge, peer/process/clock readbacks, response/timeout, loss snapshots,
request ledger/latch and timing brackets; reconstruct the exact window; and compare
its bytes/digest to the retained projection. It then calls verify_progress with
the caller-held pins. That consumer must not import the acquisition producer or
trust its summary booleans. No such acquisition consumer is implemented here.

Retain raw records, their digest inventory, refused/partial records, the exact
window and decision. A digest made by the producer is an integrity join, not
independent acquisition proof. Preserve any private credential custody limits;
this design neither authorizes copying private state nor changes the cleanup hold.

## Focused checks to propose after implementation

Coordinator registers/schedules only changed stages, after full source/test/fixture
closure is known. No executable stage is claimed for this documentation batch.

| Proposed boundary | Inert cases required before runtime integration |
|---|---|
| Reader acquisition | Idle poll acknowledges; pre-poll/timer-only response rejected; blocked parser/delivery or hung reader times out; busy stream cannot starve control; EOF/error never healthy. |
| Identity/custody | Same-UID wrong PID, PID reuse, reader/sensor restart, reconnect, boot/time namespace/program/map change, forged challenge and stale sequence refuse. |
| Freshness | Ack/deadline and age equality boundaries, delayed buffered response, clock rollback, closed-window wait budget, final-lock delay and reused challenge refuse. |
| Loss projection | Missing sparse family, per-series reset concealed by another increase, label changes, overflow and scrape error remain unknown/refused; positive baseline preserved. |
| Submission join | Crash before/after fsync and syscall, missing receipt, lock loss and corrupt ledger; no possible submitted outcome becomes HOLD_UNSUBMITTED or authorized. |
| Independent consumer | Tamper each raw join and projected field; producer/consumer disagreement refuses; no caller pin derived from untrusted summary. |
| Response integration | Broker lock held without reader-channel deadlock; post-connect health loss stays ambiguous; interrupted stop retains existing pending response. |

Review completed by source inspection against the current leaf and shared call
sites. Found and addressed in this contract: timer-only false progress, reader
ownership of submission state, stale buffered acknowledgements, sum-hidden counter
resets, broker-lock deadlock and the post-connect disposition mismatch. This is
self-review, not independent-agent or executed-test evidence. Exact deployment
paths, service projections, selected sensor stream and measured policy timeouts
remain coordinator prerequisites; no implementation readiness claim is made.

## Batch checkpoint

Documentation only. Existing PASS retained at fingerprint
`sha256:1ebdd044c7dd535f86f7fba19322a03a6254e96a8aa81adac0ca153eeb5a7226`;
result.json reports equal pre/post fingerprints and exit_code 0. Leaf inputs,
runner and registry are unchanged in this batch; no behavioral check rerun.
New acquisition checks remain proposals, not registered/scheduled/results.
Commit only this lane-owned document, sign locally and verify the signature;
the post-commit report supplies the hash. No push or integration is performed.

1. Integration/cleanup hold unresolved; shared HTTP94 repair remains coordinator-owned.
2. Checked finite leaf retained; acquisition contract reviewed, not implemented.
   Seven event classes, six responses and full RUN attribution remain unfinished.
3. Independent acquisition consumer, combined verifier inventory and freeze pending.
4. Final acceptance blocked; no captures, services or campaign operations performed.
