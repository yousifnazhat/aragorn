# Reuse the available RUN owner for the ready DNS acquisition slice

Root has integrated original verified signed RUN transport commit
`5193a2fcdd0cb4173ddeeaa7188aa74fd2c7b09f` and reviewed its actual first 30-check
PASS. The owner is available. The DNS builder's original signed `11dabe6` and its
reviewed 13-check result are already integrated. The containing signed published
coordinator checkpoint is this assignment's exact base; Root supplies its complete
remote-verified hash. Verify it and fast-forward your own existing branch.

## Concrete reassignment and non-overlapping ownership

The ready five-path DNS acquisition contract moves from v5's proposed additional
owner to the existing RUN owner:

```text
Owner: existing RUN owner, now implementing the bounded DNS provider slice
Worktree: /Users/yousi/Documents/Commits/aragorn-phase3-run-health
Branch: codex/phase3-run-health
Base: containing published signed coordinator checkpoint, exact hash from Root
Contract: docs/phase3/coordinator/dns-provider-contract-v1.md, unchanged behavior
```

This explicitly supersedes v5's additional-worktree owner assignment only. Its
schemas, APIs, identity/clock/failure rules and evidence limits remain unchanged.
The proposed additional DNS path is absent and creation/agreement was never
confirmed. An extra DNS worktree is no longer requested for this slice. Do not
create, remove or replace a worktree. If an operator has independently started
that earlier creation, report it before overlapping source work; preserve all
work rather than moving or deleting it.

Root's read-only check found none of these five new paths in either Root or RUN.
Only these exact paths are released to the RUN owner:

```text
src/aragorn/native_phase3_dns_acquisition.py
src/aragorn/native_phase3_dns_context.py
src/aragorn/native_phase3_dns_acquisition_verify.py
tests/test_native_phase3_dns_acquisition.py
docs/phase3/dns-provider/ACQUISITION_HANDOFF.md
```

Read the complete DNS contract, ownership rules and this release; acknowledge
agreement and begin this implementation without waiting for Root's reader/session
work. Preserve the finished transport and original HTML. Do not edit existing
transport, DNS builder/verifier, shared helpers, dispatch, launch, inventories or
registry. No feature-branch push is needed.

Implement the actual fixed UDP owning context, bounded receive journal and
independent raw consumer. Reuse the integrated public DNS readiness builder;
do not duplicate it. The consumer imports no producer/context/private parser.
The bounded sample always reports incomplete observation, unconfirmed client
readiness and false completeness/retention/authority flags. It cannot establish
absence of in-flight traffic, quiescence, complete retained observation or blocked
exfiltration. Do not execute the owning API against a real socket during development.

Before execution submit stable hashes, actual full import/generated/fixture
closure and proposed focused mocked cases. Root reviews source and owns registry
changes and the first selected stage in this same RUN worktree. Python remains
`/opt/homebrew/bin/python3.12`. No stage is scheduled by this release. Preserve
actual results/fingerprints on every outcome; no historical rerun, cache copy,
unchanged retry, live operation, private retention or cleanup.

After reviewed PASS stage exactly the five paths, create one git commit -S,
verify it and return original hash, changed paths, actual result/fingerprint,
requirement slice, claim limits and blockers. Root integrates preserving ancestry,
signs a checkpoint, pushes normally and verifies the remote tip.

## Critical-path ownership and remaining work

Expected benefit: begin an already reviewed independent infrastructure assignment
immediately using available capacity, avoid operator setup delay, and keep Workloads
available for destructive actions/real a100. Root continues the connected reader
writer/session/refresh contract and will use available internal owners for its
non-overlapping implementation after exact release. A design draft is not permission
to edit those future source paths. Admission's scheduled replay delivery remains
pending; no completed lane slice is reimplemented or rerun.

Root retains DNS client receipt, complete readiness/quiescence/drain/retention and
common dispatch integration, all shared broker/IPC/launch/source inventories,
bridge/sensor/loss, protected policy/lifecycle, cancellation and paired contexts.
The same 48-entry ledger applies, with no new gate or promoted qualification.

Completed: signed transport integration and ready DNS reassignment.
Released: the five paths above to the existing RUN owner. Receipt/agreement remains
pending until the owner acknowledges this published base. Blockers: actual DNS
implementation and reviewed validation; remaining shared paths and final campaign.

1. Implement and integrate ready providers/consumers with selected focused checks.
2. Wire full HTTP/DNS/destructive, admission/RUN, real a100, cancellation, full
   timing and four actual paired tasks.
3. Close all 48 paths/consumers/source-custody conditions and publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs;
   independently replay, evaluate the existing gate and verify approved cleanup.
