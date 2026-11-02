# Shared provider and RUN integration checkpoint

This checkpoint follows published, signed `b4ffd1341e9666e4dd6afb73d322221772eb3684`.
The exact 48-entry ledger remains `coordinator/implementation-coverage-ledger.md`.
No implementation-exit or final-qualification claim is made.

## Completed and verified

- Accepted HTTP repair and composition remain unchanged: 14 and 7 prior checks,
  original fingerprints and the actual 94-file staged report. Root verified the
  report still has 68263 bytes and SHA-256
  `88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9`.
  No repeated staging or historical check was run.
- Root's durable reader claim/retention provider and owning caller passed 16 new
  mocked checks, fingerprint
  `sha256:920a28df3aa7a8f1fab8b55f6d29dea566b16bf070a44b510994e1e13d82e9e8`.
- The shared scheduler's selected-closure fix passed 6 new inert checks,
  fingerprint
  `sha256:2a60c15d0dd00e688ede1be936232eb8aa07ac59435fe85b162c6b7f49535b9e`.
  RUN's earlier pretest refusal is retained, with no fabricated fingerprint.
- Original RUN commit `33f54e2aca224b216a4ae67f0a73588e03252939` has a verified
  ED25519 signature and exactly three assigned paths. Its actual 14-test PASS,
  exit 0, equal pre/post fingerprint and all original log hashes were checked
  read-only in the owning worktree. Fingerprint:
  `sha256:855ae03253e17074a4ff66c5e4d060f7906cc70a2b25efadb6ca36492cd655c9`.
  Signed merge `506b9bf9274cd996d1ede432084d2108affa89f7` preserves its ancestry.

Composition review confirmed the integrated RUN source/test are byte-identical
to the reviewed delivery and Root's provider/runner bytes remain those tested.
All 109 preexisting registry rows are unchanged; four new reviewed stages are
additive. The new independent consumer still has only stdlib imports, and the
store/caller closure is unchanged. No historical or lane suite was rerun in Root.
This is source/dependency composition validation, not a real integrated telemetry
exchange: the protected transport, actual read loop and broker provider wiring
remain missing and cannot be inferred from these independent passing components.

## Released and pending assignments

Each owner verifies the published checkpoint hash supplied by Root and fast-forwards
their own branch with `git merge --ff-only <hash>`. Preserve drafts and report any
divergence/conflict without reset, stash, replacement worktree or forced update.
Root has not mutated any active lane worktree.

Admission: reviewed five-file closure and 26 focused methods remain approved in
`coordinator/lane-review-and-scheduling-v3.md`. Acknowledge the corrected runner
checkpoint and run only `native-admission-policy-tamper` in your own worktree;
retain actual results, sign exactly the four assigned paths and return the original
verified commit. No new result is claimed before that handoff.

RUN: your signed delivery is integrated. Fast-forward to the new published tip.
Do not rerun the 14 checks. The next checkpoint/stream or submission-state consumer
requires the Root provider's exact schema and ownership release; the design notes
below are not that release. Root must resolve those interfaces promptly.

Workloads: no DNS stage is scheduled. Correct the consumer and independent fixture's
QNAME length from 0x13 to 0x14 and preserve the full 20-byte marker; add the
partial-prefix non-presence regression, refresh hashes and resubmit for delta review.
Existing six-file closure and other contract checks were reviewed. Preserve both
prior drafts. After approval, Root will register only the new DNS stage.

Earlier three-owner contract agreement is confirmed. Delivery of the newer
Admission/DNS handoff remains unconfirmed because the outbound task bridge fails;
RUN acknowledged and completed through the published fallback. This document and
`lane-review-and-scheduling-v3.md` are copyable instructions. Feature pushes are
unnecessary in the shared repository; Root alone pushes the integration branch.

## Concrete shared blockers

Three source-reviewed design notes record the next provider decisions:
`coordinator/reader-transport-and-loop-design.md`,
`coordinator/dns-provider-design.md` and
`coordinator/serialized-reader-broker-design.md`. They publish findings and source
references, not new implementation permission or claimed provider completion.

The real reader needs one protected listener lifetime across fresh campaign
requests, actual pipe/read-loop checkpoints and separate reader/bridge/sensor
identity. An idle reader ACK does not prove upstream responsiveness; the selected
Tetragon bridge has output-error/retry boundaries that must be accounted for.
DNS needs actual per-socket loss evidence, active-versus-child time-namespace
offset joins, independently confirmed readiness and real submission quiescence.
Missing counters remain unknown; a final empty queue alone is insufficient.

The broker is non-root while the new reader store requires root. A protected
evidence-service interface must cross that boundary without taking the already-held
broker lock. Callback 1 is before connect; callback 2 is after connect and before
payload. The latter must preserve submitted ambiguity. A new post-connect challenge
cannot be labeled BEFORE_FIRST_EFFECT. Full acquisition windows must fit the
existing deadline without equating MONOTONIC and BOOTTIME or narrowing the mandated
REQUEST_ACCEPTED → DECISION_FINALIZED interval.

Admission's actual protected policy/lifecycle acquisition, remaining route ports,
all required RUN event/response paths, destructive custody/a100, fresh workload
contexts, cancellation, TASK_ACCEPTED → TASK_COMPLETED and real baseline/instrumented
selection remain open in the ledger. No placeholder semantic PASS is added.

1. Finish the actual common provider path and publish its concrete cross-process
   contracts before releasing the next dependent implementation slices.
2. Complete the current Admission/DNS handoffs and remaining admission, RUN and
   workload paths; integrate original signed commits with focused changed checks.
3. Close every real path/acquisition/consumer gap in the 48-entry ledger, complete
   source/loaded-identity custody and publish a reviewable implementation freeze.
4. After a separate operational release, execute the same-deployment 31 admission
   cases, 100 action attempts and 100 task pairs, independently replay the evidence
   and perform separately approved cleanup before evaluating final qualification.

No live operations, private retention, cleanup, cache copying, historical-suite
reruns or unchanged retries occurred. Work remains in flight; Phase 3 is unfinished.
