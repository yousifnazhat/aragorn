# Phase 3 broker submission implementation checkpoint

Base: verified signed and published
`743f9bbed27f220c5012196eccce77722f4dcaa8`. This checkpoint contains Root's
reviewed protocol/journal implementation, the actual selected result handoff and
the updated existing 48-entry coverage ledger. It is not a freeze candidate.

## Completed and verified

- Original signed Admission `d3c5ffed8dbbf0520c9b8d2e9d798e204d09f96d` was
  verified and merged preserving ancestry at `f13af109a21a1fc0f4cc4f24753b1f032716317a`.
  Its actual 26-check PASS was read in its owning worktree; it was not rerun.
  RUN's original signed reader-evidence delivery was already integrated.
- Corrected DNS full-marker source and complete six-file closure were reviewed.
  Only Workloads' 13-method `native-workload-dns-canary` stage is scheduled;
  its actual result and original signed delivery remain pending.
- Published signed reader transport and broker submission contracts assign exact
  non-overlapping paths to RUN, Admission and Root. The DNS acquisition/context
  contract is reviewed but its later source release needs the signed DNS builder.
- Root implemented canonical bounded root/broker packets and the immutable
  six-event non-root broker journal. It checks actual local identity, borrowed
  lock fdinfo, protected boot/time namespace, file custody, complete clock budgets,
  readback and conservative attempted/submitted ambiguity. It supplies no health
  verdict and is not wired into a successful production gate.
- Stable source/full dependency review preceded signed stage registration.
  `native-phase3-broker-reader-submission` passed all 28 new focused tests on its
  first execution, 0.075 seconds, exit 0, fingerprint/post-fingerprint
  `sha256:d36e14e55f23068293e2159caa74311a9519b23ce61ab7816108035d58ef574b`.
  Root inspected its original result/logs. Exact hashes and limits are in
  `coordinator/broker-reader-provider-handoff.md`; no cache was copied.

The selected stage exercises changed codec/journal composition through the real
public lifecycle with mocked OS/proc/clock boundaries. It imports the unchanged
broker helpers in its explicit closure. Cross-lane independent submission replay
composition still awaits Admission's implementation; it is not replaced by a
producer-shaped fixture or a placeholder PASS.

## Current releases and delivery

| Owner | Current action | Source of exact permission |
| --- | --- | --- |
| RUN | Implement the guarded listener, atomic notice and accepted reader transport in its existing worktree | `coordinator/reader-transport-contract-v1.md`, `provider-release-v3.md` |
| Admission | Implement the independent submission transcript verifier, test and handoff | `coordinator/broker-reader-provider-contract-v1.md`, `provider-release-v4.md` |
| Workloads | Run only the approved corrected DNS stage if no matching actual result exists; deliver one original signed commit | `coordinator/dns-delta-review-and-scheduling-v1.md` |
| Root | Integrate delivered leaves and complete real acquisition/IPC, serialized broker caller, launch/staging and inventories | Existing shared ownership; publish each later bounded contract first |

All three lane owners confirmed receipt/fast-forward to corrected checkpoint
`4ec18f80164c0cc11e387c2f292e0716f54df208`. Delivery/agreement for newer releases
is unconfirmed. Outbound task bridge read/send failed at localhost:54152; copyable
handoffs are provided. Root did not mutate active lane worktrees. Owners verify
the new published checkpoint and fast-forward their own branches, preserving
drafts; divergence/conflicts require a report, never reset/stash/force update.

No extra worktree is requested at this checkpoint. Available RUN and Admission
owners have ready independent assignments; the prospective DNS provider split
still lacks its signed builder dependency. Once that delivery is integrated,
reassess whether an operator-created DNS worktree shortens completion while
Workloads takes bounded destructive/a100 work under its next exact contract.

## Blockers and numbered remaining Phase 3 steps

The real reader loop still lacks reviewed stream/bridge/sensor launch custody,
separate raw checkpoint retention, second-phase refresh and complete loss scope.
Concrete source findings and accepted narrow direction are recorded in
`coordinator/reader-loop-next-release-review-v1.md`. Protected admission lifecycle/
loaded policy, full DNS observation closure, destructive object custody, real
a100, cancellation and actual paired environments remain incomplete.

1. Finish the released RUN/Admission implementations and DNS validation; review
   stable closures, schedule only necessary focused stages and promptly merge
   original verified signed deliveries. Preserve this Root result unchanged.
2. Complete and wire the shortest actual HTTP causal path, then DNS/destructive
   actions, all required admission/RUN behaviors, full decision/task intervals
   and the four existing tasks in real baseline/instrumented contexts.
3. Close every real execution path, protected source/loaded identity and
   independent consumer in the existing 48-entry ledger, then publish one
   reviewable freeze candidate. No placeholder PASS or commit-count completion.
4. After separate operational release, collect 31 cases, 100 actions and
   100 pairs on one deployment; independently replay, evaluate the existing exit
   manifest and verify separately approved cleanup. Only then is Phase 3 finished.

Historical suites, repeated unchanged staging, cache copying, automatic unchanged
retries, live operations, private retention and cleanup remain held. Actual kernel
ABI behavior, deployed custody and latency feasibility were not tested here.
