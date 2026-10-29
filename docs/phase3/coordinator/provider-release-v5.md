# DNS delivery integration and next provider release

Parent source: signed checkpoint `95b676eca174ae5cb117fe778d3359f0e924b425`
plus original verified signed DNS delivery
`11dabe6ffeeaddc9e317fc46f93e188ae7fff614`, merged preserving ancestry.
The containing signed and published coordinator checkpoint is the required new
base. Root supplies its exact hash after remote-tip verification.

## Reviewed delivery and agreements

Root verified both signatures, four assigned paths, all six actual dependency
hashes, and original Workloads result/log bytes. The selected DNS stage passed
13 checks once with identical pre/post fingerprint
`sha256:89b7cb5add286a2fc0de48c41797455250b5e26f34367fc577aed04f566fe262`.
The handoff retains exact result/log pins. No cache was copied or check rerun.
Only bounded builder/retained-consistency implementation is established.

Admission and RUN explicitly verified/fast-forwarded to `95b676e`, accepted
their exact released contracts and began independent replay/guarded transport.
Workloads likewise accepted v4 and delivered DNS. These inbound acknowledgments
resolve the earlier agreement uncertainty; outbound bridge delivery remains
unconfirmed and its unchanged failure is not retried. Use copyable handoffs.

Admission's stated interpretation is accepted: a null expected terminal pin
allows only CONSISTENT_OPEN_PREFIX even if supplied events include TERMINAL;
intent still yields SUBMITTED. A non-null terminal pin requires the exact final
TERMINAL event. A phase-two REFUSED response may retain unavailable loss as null;
present loss preserves the phase-one baseline and obeys the fresh bracket. No
intent may follow missing loss. Raw lock/OS/source custody is an external
independently held obligation, not an inferred property of transcript bytes.

## Released additional DNS owner

The signed DNS dependency now exists. Release `dns-provider-contract-v1.md`
unchanged to a proposed additional worktree:

```text
Branch: codex/phase3-dns-provider
Worktree: /Users/yousi/Documents/Commits/aragorn-phase3-dns-provider
Base: exact containing published signed checkpoint supplied by Root
```

Operator creates this additional worktree only if the branch/path is unused;
report an existing path or divergent branch instead of replacing it. Root does
not create or mutate an active lane worktree. Expected benefit: isolate actual
UDP/proc/clock/cancellation acquisition while Root handles reader/broker wiring
and Workloads prepares destructive actions/a100. No source file overlaps.

Copyable assignment:

> Verify the supplied checkpoint; inspect your branch/tree and preserve drafts.
> Read ownership-and-release-v2.md, provider-release-v5.md and the complete
> dns-provider-contract-v1.md. Acknowledge agreement. Implement only:
> `src/aragorn/native_phase3_dns_acquisition.py`,
> `src/aragorn/native_phase3_dns_context.py`,
> `src/aragorn/native_phase3_dns_acquisition_verify.py`,
> `tests/test_native_phase3_dns_acquisition.py`, and
> `docs/phase3/dns-provider/ACQUISITION_HANDOFF.md`.
> Use the integrated DNS builder; do not duplicate it. Implement actual fixed
> socket/owned context operations with independently parsed raw evidence. Keep
> all completeness/readiness/retention/authority flags false as contracted.
> Submit stable hashes, complete import/generated/fixture closure and focused
> cases before any execution. Root alone registers/schedules the new stage.
> After reviewed PASS preserve actual result/fingerprint, commit only assigned
> paths with git commit -S, verify it, and hand off original hash, paths, result,
> requirement slice, limits and blockers. No feature-branch push. No historical
> reruns, cache copying, unchanged retries, live operations, private retention
> or cleanup. Python is /opt/homebrew/bin/python3.12.

No new test stage is registered or scheduled here. Complete DNS client receipt,
quiescence, final drain, protected retention and dispatch remain Root-owned later
integration work; this source assignment does not make the interval complete.

## Existing owners continue

- Admission: independent submission verifier/test/handoff, three v4 paths.
- RUN: guarded reader listener/test/handoff, three v3 paths.
- Workloads: DNS delivery complete. Root explicitly releases only a design review
  path next: `docs/phase3/workload-verifiers/destructive-next-release-review.md`.
  Inspect the existing truncate/unlink/broker fixtures and propose concrete native
  entry points, continuous object/name custody, real unattributed a100 route,
  evidence/independent consumer, cancellation and focused cases. Preserve all
  drafts; no source edits or execution are released by this review assignment.
  Root will publish the implementation contract and exact paths after review.
- Root: stream/bridge/sensor, raw checkpoint/refresh/loss contracts and actual
  provider/IPC/broker integration, shared files, launch/staging and inventories.

## Blockers and remaining Phase 3 steps

The ledger still has the same 48 entries. DNS updates rows 38 and 48 only as
partial implementation; no full row becomes wired, evidence-verified or qualified.
Actual reader/bridge continuity, complete loss acquisition, protected policy and
lifecycle, destructive/a100, paired contexts and deployment remain incomplete.

1. Finish released shared providers and consumers, review stable closures,
   schedule only necessary focused stages and integrate original signed commits.
2. Wire full HTTP, then DNS/destructive actions, every admission/RUN path,
   cancellation, full timing and all four actual paired tasks.
3. Close all 48 real paths, independent consumers and deployed-source custody;
   publish a reviewable freeze candidate only then.
4. After separate operational release collect 31 cases, 100 actions and 100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. Implementation readiness is not final qualification.
