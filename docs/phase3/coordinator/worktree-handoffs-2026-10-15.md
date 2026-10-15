# Phase 3 critical infrastructure: worktree handoffs, 15 October

Source review base: verified signed published
`6af32a0f127999ef44dfddf37763789ba3fef52c`. This package takes effect only at
its containing verified signed published checkpoint. Root supplies that exact
hash after normal push and remote-tip verification. Substitute that hash for
`PUBLISHED_CHECKPOINT` in the common startup steps; the old review base alone
does not contain a new release.

## Shared startup and operating rules

Paste the common rules together with the selected owner's prompt below.

1. Work only in your existing assigned worktree/branch. Inspect `git status
   --short --branch` and `git branch --show-current`; preserve every draft.
2. Run `git verify-commit PUBLISHED_CHECKPOINT`, then
   `git merge --ff-only PUBLISHED_CHECKPOINT` in your own worktree. Stop and report
   the exact conflict/divergence. No reset, stash, replacement tree or forced update.
   Root never changes an active lane worktree.
3. Read `ownership-and-release-v2.md`, its Hard coordinator rule and Mission and
   scope discipline, the applicable release and exact contract. Acknowledge the
   exact commit, paths and contract. Publication is not confirmed delivery.
4. Every change must close an existing Phase 3 requirement or a specific blocker
   in its real execution path. Preserve the existing exit manifest and 48-entry
   ledger. No additional framework, runtime, speculative redesign or contract churn.
5. Before any project import, compilation or test execution, submit stable hashes,
   complete actual import/generated-source/fixture closure, focused cases and a
   proposed stage. Root reviews closure, owns registry and publishes the selected
   schedule. A source release alone is not execution permission.
6. Use `/opt/homebrew/bin/python3.12`. Execute only the scheduled new stage in its
   owning worktree. Retain every actual result/log/fingerprint, including FAIL.
   Diagnose failures before a reviewed changed-input/environment retry. Never
   invent a combined PASS from separate results.
7. No historical-suite reruns, cache copying, unchanged retries, live operations,
   private retention or cleanup. Reuse evidence only for unchanged actual behavioral
   inputs and relevant environment; changed source does not justify unrelated checks.
8. After reviewed PASS, stage exact assigned paths, create one `git commit -S`,
   run `git verify-commit HEAD`, and hand Root the original hash, changed paths,
   actual result/fingerprint, requirement closed, evidence limits and blockers.
   No lane feature push is required. Root integrates original signed ancestry,
   pushes normally and verifies the remote tip; never force or rewrite lane history.
9. End every handoff with completed work, released/pending assignments, exact
   blockers and the four numbered remaining Phase 3 steps at the end of this file.
   Implementation, native custody, verified evidence and qualification are distinct.

## Coordinator prompt

Worktree: `/Users/yousi/Documents/Commits/aragorn`
Branch: `codex/phase3-runtime-prevention`

Objective: finish the existing Phase 3 manifest as quickly as possible on one
supported deployment. Reassess the critical path at every checkpoint, blocker
and completed handoff. Release ready non-overlapping infrastructure immediately;
lanes proceed as soon as their contract is ready, concurrently with Root.

1. Confirm owner receipt of this published checkpoint. No unchanged retry of the
   unavailable outbound bridge. Publish these copyable prompts and record receipt
   unconfirmed until each owner acknowledges the exact commit/contract.
2. Admission's context draft is unchanged and its two published corrections are
   unapplied. Review only its refreshed three-path source and complete closure;
   then register/schedule the first necessary focused stage. Do not rerun its
   integrated 33-method submission replay or broaden its ownership.
3. RUN's original signed DNS `a32477b0b38248f7dca825ec022ad4c0e467558d` is
   already integrated. Preserve its actual 50-method PASS fingerprint
   `sha256:3b989508ec43b9ab89102eae7723aeefcf5bff8702b1266f21a770099a0bb88c`.
   Release v12's three-path fixed bootstrap to RUN immediately at this signed
   publication; do not ask it to repeat DNS or edit Root-owned service/renderers.
4. Release the bounded genuine-a100 peer lookup to Workloads when its v11
   contract is published. Preserve the real runtime -> sensor -> broker topology,
   exact loaded singleton bytes and the registered worker's actual positive
   lineage hold. A conditional comparison cannot supply loader authenticity or
   complete destructive enforcement by itself.
5. Root owns actual protected launch-input acquisition, bootstrap endpoint and
   provider readiness, cancellation/PIDFD transfer and lifetime. Connect the real
   broker/reader/HTTP caller, complete bridge/source closure and generated/deployed
   inventories. Follow the reviewed bootstrap and HTTP94 successor decisions;
   bind the actual predecessor report
   `sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9`.
   Do not rerun unchanged staging or relabel an old report as a successor.
6. Preserve original accounts, root-only protections, credential ABI and separate
   bootstrap/session readiness. Missing loss is UNKNOWN and yields
   REFUSED/LOSS_UNAVAILABLE; refusal-only plumbing is intermediate. Finish actual
   authenticated stream/loss/program/map and policy/lifecycle acquisition for
   usable positive enforcement. Full REQUEST_ACCEPTED -> DECISION_FINALIZED and
   TASK_ACCEPTED -> TASK_COMPLETED remain mandatory, with original deadlines and
   explicit post-submission ambiguity.
7. Finish the destructive execution contract: valid ingress/claim/intent,
   exclusive target mutation custody, observer/readiness/quiescence/drain/loss/
   retention/clock, real control launch and independent consumer. Retain source-
   backed decisions already made; do not reopen them without a concrete defect.
   Then assign the next exact Workloads leaf. Root owns actual paired baseline/
   instrumented contexts and all four benign tasks' timing/cancellation wiring.
8. Integrate each reviewed original signed delivery promptly, validate only
   newly changed composition where necessary, update the same coverage ledger,
   sign/verify a checkpoint, push normally and verify the remote hash. Supply that
   hash to owners for their own fast-forward. Do not leave consumers disconnected.
9. Existing worktree capacity is sufficient for the current split. Request an
   operator-created additional tree only when a ready independent assignment
   cannot be taken promptly by an available owner and shortens completion. Supply
   exact published base, proposed branch/path, write allowlist, dependencies,
   copyable prompt and expected benefit. Repeat capacity review at each handoff.

## Admission prompt

Worktree: `/Users/yousi/Documents/Commits/aragorn-phase3-admission`
Branch: `codex/phase3-admission`

Requirement: actual protected broker-context acquisition, an existing missing
provider in the serialized HTTP causal path. Read `provider-release-v9.md`,
`broker-reader-context-contract-v1.md` and `broker-context-source-review-v1.md`.

Write only:
- `src/aragorn/native_phase3_broker_reader_context.py`
- `tests/test_native_phase3_broker_reader_context.py`
- `docs/phase3/admission/BROKER_READER_CONTEXT_HANDOFF.md`

1. Preserve the existing 55-method draft. Its source/test pins remain
   `c0f16a10c1ee4760c6a01261b2c646af5eb67711e5b6d46af80f5087d51a02ee` /
   `105acb27b97a285fe990da8856e2d23f26a3cc15418b77582821413133bb904b`;
   both published corrections are still unapplied as of this read-only inspection.
2. Correct close ordering: finish all fallible flags/PIDFD-association observations,
   then recheck held identity, original owner and current borrowed aliases
   immediately before the consumed-once close. Uncertain/substituted/borrowed
   ownership must not close a foreign descriptor. Preserve original failures.
3. Correct read ordering: after seek/timing/prior-read observations, recheck
   ownership, held identity, readonly/nonblocking flags and borrowed aliases
   immediately before every actual read. Preserve bounded original prefixes;
   never read a known substituted or newly borrowed descriptor.
4. Add narrow late-armed fabricated-boundary cases asserting no foreign read or
   close, not merely eventual refusal. Preserve public API, deadline, strict
   schemas, shared-GID and dual-mount joins; do not edit shared dependencies.
5. Submit refreshed exact source/handoff hashes, actual complete closure and case
   inventory. No context stage is currently scheduled. After Root schedules,
   execute only that stage, retain the actual outcome and submit for review.
6. After reviewed PASS, sign/verify one exact-path commit and hand it off. Root
   still owns actual accepted caller/request/receipt origins, protected expectations,
   bootstrap, cancellation and installed HTTP integration. Do not claim those
   from this bounded leaf or rerun the completed submission-replay suite.

## RUN / health prompt

Worktree: `/Users/yousi/Documents/Commits/aragorn-phase3-run-health`
Branch: `codex/phase3-run-health`

1. Verify/fast-forward this checkpoint in your own worktree and acknowledge
   availability. DNS acquisition delivery is accepted, signed and integrated.
   Retain its actual 50-method PASS and original result/logs/fingerprint. Its old
   handoff's integration-pending wording is historical, not a missing delivery.
2. Preserve completed transport/reader/DNS evidence, including original failures.
   Do not rerun DNS, repeat its implementation, copy caches or promote incomplete
   observation/readiness into health or qualification.
3. Read `provider-release-v12.md` and `broker-reader-bootstrap-contract-v1.md`.
   Implement only these new paths:
   - `src/aragorn/native_phase3_broker_reader_bootstrap.py`
   - `tests/test_native_phase3_broker_reader_bootstrap.py`
   - `docs/phase3/run-health/BROKER_READER_BOOTSTRAP_HANDOFF.md`
4. Implement the actual fixed seqpacket HELLO -> HANDLES -> RECEIVED -> RELEASE
   handshake. Authenticate kernel credentials/PIDFD, transfer exactly cancellation
   read end then supervisor PIDFD once, report actual receiver FD numbers, and
   join the protected final provision. Preserve the original 4-second startup
   cap, session deadline, checked local ordinary buffers and account protections.
5. Consume the separate real provider-ready pipe under its protected endpoint
   expectation. Require actual session construction and guard listener readiness
   in the Root-owned caller; never read its private state or substitute a Boolean.
   Keep bootstrap notification separate from reader/session readiness. Retain
   actual successful and failed packet/process/descriptor observations in the
   frozen bounded artifact schema, not only their digests.
6. Preserve exact descriptor ownership, partial failure/send ambiguity and
   cancellation/exit priority. No arbitrary truth callback, expected proc fields
   relabeled as reads, reconnect/resend/reset or weaker accounts. Client-inaccessible
   Root proc views stay null. Root retains unit/source/launch acquisition,
   service/client/renderers, actual configure integration and deployed readiness.
   Proposed IPC drafts alone grant no shared edits or execution permission.
7. Submit stable full closure and focused new cases before Root schedules the
   owning stage. After reviewed PASS, sign/verify exact paths and hand off the
   original commit and actual evidence. No feature-branch push or extra tree.

## Workloads / verifiers prompt

Worktree: `/Users/yousi/Documents/Commits/aragorn-phase3-workload-verifiers`
Branch: `codex/phase3-workload-verifiers`

Requirement: actual peer-lineage lookup prerequisite for genuine unattributed
control a100; existing unlink requirement, not a new gate. Read
`provider-release-v11.md` and `destructive-lineage-contract-v1.md` when explicitly
published in this checkpoint. Preserve completed destructive design, DNS and
benign-task evidence; do not repeat the design or duplicate RUN's DNS provider.

The v11 write allowlist is exactly:
- `src/aragorn/native_phase3_workload_destructive_lineage.py`
- `src/aragorn/native_phase3_workload_destructive_lineage_verify.py`
- `tests/test_native_phase3_workload_destructive_lineage.py`
- `docs/phase3/workload-verifiers/DESTRUCTIVE_LINEAGE_HANDOFF.md`

1. Acknowledge the exact release and implement the bounded acquisition API over
   the actual borrowed runtime-to-sensor frontend socket, worker PIDFD and
   cancellation descriptor. The backend broker's immediate sensor peer is not
   the runtime. Do not alter sensor accounts, FSUID/FSGID or capabilities.
2. Preserve raw peer credentials/PIDFD/proc/cgroup/namespace/boot observations,
   original clock/deadline and finite descriptor custody. Consume immutable
   loaded-binding bytes and the real registered worker's positive summary only
   under the explicit Root caller obligations; never claim this leaf authenticates
   opaque loader/source/hold summaries.
3. Derive MATCH only for the actual registered worker. Derive configured-scope
   NO_MATCH only for a different live peer in a different stable cgroup while
   the complete configured singleton/registered-positive joins hold. Everything
   missing/malformed/changed/ambiguous is UNKNOWN/refusal. No attempt-label denial,
   fabricated control attribution or generic exception converted to absence.
4. Preserve the existing lineage version-path representation. Its omitted
   context_id cannot be replaced by context_digest. Preserve sequential resolved
   calls in the repeated sensor process; poison only unresolved acquired ownership,
   with no reset API, automatic retry or new one-attempt daemon.
5. Implement an independent stdlib consumer over actual retained bytes; no producer
   parser/private helper imports. All authority/qualification flags remain false.
   Prepare focused mocked acquisition/replay cases including positive and genuine
   different-cgroup comparison, malformed/stale inputs, cancellation, descriptor
   substitution/cleanup and resolved versus poisoned sequential ownership.
6. Submit stable actual complete closure/cases. This source release schedules no
   execution. After Root's focused schedule and reviewed PASS, sign/verify the four
   exact paths and hand off original commit, actual result/fingerprint and limits.
7. Full a100 enforcement remains pending actual valid ingress, positive lineage
   hold, authenticated broker decision and continuous destructive interval evidence.
   Root owns those providers. Do not edit shared broker/observer/launcher files or
   claim completed control blocking from this conditional lookup alone. Take the
   next destructive execution leaf as soon as its concrete contract is published.

## Remaining Phase 3 steps

1. Implement/integrate released providers with only newly necessary focused validation.
2. Wire full HTTP, DNS/destructive, all admission/RUN paths, genuine a100,
   cancellation, full timing and four actual paired tasks.
3. Close the existing 48-entry path/consumer/source-custody inventory and freeze.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. Final qualification remains pending; all operational holds stay.
