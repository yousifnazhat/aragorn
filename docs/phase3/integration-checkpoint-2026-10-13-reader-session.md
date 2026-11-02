# Reader writer and Root session implementation checkpoint

This signed checkpoint integrates the four v8 implementation/test paths after
stable source/closure review, independent review and the actual selected results
recorded in `coordinator/reader-session-handoff.md`. Root publishes the exact
containing hash after normal push and remote-tip verification. The original
Admission, RUN and DNS signed commits remain ancestors; no lane tree was changed.

The reader source now consumes bounded telemetry, publishes immutable checkpoint
artifacts before completion/ACK, preserves the original ACK during refresh and
fails closed on custody, framing, deadline or cancellation failures. The Root
session joins the actual listener, permanent reader retention, protected
checkpoint acquisition and both independent retained-byte consumers. No actual
launch, IPC/broker deployment or complete loss provider is implied by those calls.

## Actual evidence and reuse

- Initial combined stage: 59 methods, 57 ok, **aggregate FAIL**. The two failures
  were diagnosed as fake poll/clock expiry before the intended writer test seam.
  Fingerprint `sha256:0e4c30d84cc8e12c9a7c5e708ecc611e7b2f598216a4989bf0d4e1a0e99b9ed5`.
- After reviewed test-fixture correction and published schedule
  `54a7071fcda4849870193e5f64efdba2fa10fa89`, writer-only 31 methods **PASS**,
  fingerprint `sha256:d12e062c205649df1c382c07296637e9167944092d02bec2f961172eac0dba6c`.
- All 28 session methods passed in the original actual log. Their complete input
  closure and environment remain unchanged, so those method results are reused.
  There is no successful 59-method aggregate. Both actual reports/logs remain in
  their original coordinator cache, with lengths/hashes in the handoff.

Only the writer fixture changed after execution; production stayed byte-identical.
Root reviewed final source pins and composition without repeating unaffected
checks. The transport 30, checkpoint 53, broker 28, DNS 13 and HTTP evidence were
not rerun. The same 48 ledger IDs/order and all final qualification flags remain.

## Current assignments and critical path

Read-only lane inventory still shows Admission at `95b676e`, RUN at `5193a2f`
and Workloads at `11dabe6`. Their drafts remain intact. Publication is not receipt:
newer lane handoff delivery/agreement remains unconfirmed while the outbound
bridge is unavailable. Use the copyable instructions and exact new published tip;
each owner verifies and fast-forwards only their own existing worktree.

| Owner | Released next work | Boundary |
| --- | --- | --- |
| Admission | Its already reviewed/scheduled 33-method independent submission replay, then original signed delivery | Only the existing three replay paths; do not redo integrated policy tamper |
| RUN | v7 DNS acquisition/context/independent consumer assignment | Exactly the five paths in `provider-release-v7.md`; no DNS stage until stable closure review |
| Workloads | Destructive-action/real-a100 design review | Only `docs/phase3/workload-verifiers/destructive-next-release-review.md`; source needs its exact later contract |
| Root | Actual provider IPC/bootstrap, serialized HTTP caller and launch/source integration | Shared files remain Root-owned; the future IPC draft is not a source release |

No additional worktree is requested: the available RUN owner can take the ready
DNS split. The two v8 internal implementations are complete. Reassess/delegate
another bounded leaf as soon as its exact contract and paths are concrete.

Root's next concrete decisions are protected context/bootstrap acquisition,
actual broker-service cancellation FD transfer without widening credentials or
Root storage access, generated measurement/caller integration using the actual
HTTP94 report pin, and Linux peer/socket/bridge compatibility. Preserve the
REQUEST_ACCEPTED -> DECISION_FINALIZED interval and post-connect submission
ambiguity. The strict bridge post-exec CLOEXEC prerequisite remains unsatisfied.
Complete authenticated stream/loss/program/map acquisition, protected policy/
lifecycle and workload/paired-context providers remain open. Missing loss is
UNKNOWN and must yield REFUSED/LOSS_UNAVAILABLE. Keep failed-detach references
in their owning process until exit; no prompt blocked-syscall cancellation claim.

No historical suites, cache copies, unchanged retries, live operations, private
retention or cleanup were authorized or performed. No freeze or qualification
is claimed. Implementation readiness and final qualification remain separate.

1. Complete and integrate ready shared providers/consumers, especially launch,
   IPC/broker, protected loss and pending lane deliveries; schedule only necessary
   focused checks in the owning worktree.
2. Wire full HTTP, DNS/destructive, all admission/RUN paths, real a100,
   cancellation, full timing and four actual paired tasks.
3. Close all 48 existing path/consumer/source-custody conditions and publish a
   reviewable freeze candidate with no placeholder PASS.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. Phase 3 remains unfinished.
