# Broker submission release and DNS acquisition decisions

Base: verified signed and published
`454b30fac68e29a80c025385a96333eec1795128`.
The containing signed checkpoint is the new base for the assignments below.

## Ready parallel implementation

Root accepts `broker-reader-provider-contract-v1.md` as the exact contract for
the protocol envelope, durable broker journal and independent transcript replay.
It keeps root-only reader storage behind authenticated root acquisition. The
non-root broker retains its own exclusive journal and conservative effect state.
Neither an accepted packet nor an opaque reader summary authorizes an effect.

Root owns only the following new paths for this released implementation:

```text
src/aragorn/native_phase3_broker_reader_protocol.py
src/aragorn/runtime_http_run_submission.py
tests/test_native_phase3_broker_reader_protocol.py
tests/test_runtime_http_run_submission.py
docs/phase3/coordinator/broker-reader-provider-handoff.md
```

Admission's policy-tamper delivery is already integrated. Reuse that existing
worktree immediately for independent submission replay after owner verification,
fast-forward and contract agreement. Its exact new write allowlist is:

```text
src/aragorn/native_phase3_run_submission_verify.py
tests/test_native_phase3_run_submission_verify.py
docs/phase3/admission/SUBMISSION_REPLAY_HANDOFF.md
```

Reconstruct canonical bytes, phase order, context/identity/timing joins and
conservative submission state independently. Do not import either producer,
its parser or fixtures. Terminal evidence before intent remains UNKNOWN; after
intent it remains SUBMITTED. Retained bytes cannot attest OS lock custody.
No health, authenticity, authorization or qualification flag becomes true.

RUN's three-path listener/notice/accepted-connection assignment from v3 remains
released. Root retains real telemetry/checkpoint/loss, IPC service/client,
shared broker hooks, launch/staging and source/config/identity inventories.
This checkpoint releases no successful production health gate or new test stage.
Both new implementations submit stable source hashes, complete actual dependency
closure and proposed focused cases before Root registers/schedules execution.

## DNS: reviewed decisions, dependency still pending

Root accepts the bounded decisions in `dns-provider-contract-v1.md`: fixed UDP
endpoint and exact separate readiness bytes, owned cancellation, retained raw
socket loss/process/clock evidence, independent replay and explicit incomplete
sampling. Unknown/reset/increased loss cannot become zero. A reply send cannot
establish client receipt; a receive-queue sample cannot establish quiescence.

This is **not a source implementation release**. The contract's producer imports
the Workloads DNS builder, whose actual approved result and original signed
delivery are still pending. The proposed extra DNS provider owner needs a later
signed base containing that dependency. No additional worktree is requested yet.
Once ready, reassess capacity: preserve Workloads for destructive operations and
the real a100 control, and request an operator-created DNS provider worktree if
that independent split shortens completion. Supply the exact base, branch/path,
five-path contract and expected benefit at that point.

## Evidence, delivery and remaining steps

Completed: original signed Admission integration, corrected DNS source review and
single-stage release, signed guarded reader contract, reviewed broker submission
and DNS acquisition/context contracts. The existing ledger remains 48 entries;
these contracts do not change requirement-level validation or qualification.

Admission's actual 26-check PASS, RUN's original 14-check PASS, Root's 16-check
reader store, six-check runner and HTTP 14+7 results remain unchanged. Reuse
their unaffected fingerprints. Workloads alone runs the scheduled
`native-workload-dns-canary` stage after checking its exact reviewed source pins
and existing results in `dns-delta-review-and-scheduling-v1.md`.

All three owners acknowledged and fast-forwarded themselves to `4ec18f8`.
Newer release delivery/agreement remains unconfirmed: outbound task read/send
failed at localhost:54152. These versioned documents are copyable handoffs.
Do not retry that unchanged bridge failure or claim delivery from publication.
Root has not changed any lane worktree.

Released: RUN guarded transport, Admission independent submission replay, Root
protocol/journal implementation and Workloads' selected DNS validation stage.
Pending: DNS actual result/signed delivery; owner acknowledgment of new releases;
real reader-loop/checkpoint/loss and protected admission/loaded-policy sources;
complete DNS observation closure, destructive custody, actual a100 and paired
contexts; shared dispatch/deployment integration. The operational hold remains.

1. Implement/review the ready parallel provider slices, run only newly scheduled
   focused checks and integrate original signed deliveries promptly.
2. Connect the shortest complete HTTP causal path; extend it to DNS/destructive
   actions, remaining admission/RUN behavior, full timing and all four paired tasks.
3. Close every real path, independent consumer and loaded-source identity in the
   48-entry ledger before publishing one reviewable deployment freeze candidate.
4. After separate operational release, run the same-deployment 31 cases,
   100 actions and 100 pairs, independently replay, evaluate the existing gate
   and verify separately approved cleanup. Only then claim Phase 3 complete.

No historical tests, unchanged retries, cache copies, live operations, private
retention or cleanup are released. No extra worktree is needed for the ready
RUN, Admission or Root assignments; their existing owners can work concurrently.
