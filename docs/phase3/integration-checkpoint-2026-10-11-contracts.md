# Phase 3 agreed lane contracts checkpoint

Previous published checkpoint: `b3fca83615cd6fd69b463ca8cebcebc660990dec`.
Branch: `codex/phase3-runtime-prevention`.

## Original signed planning inputs

| Lane | Verified signed commit | Exact planning paths |
| --- | --- | --- |
| Admission | `f9b7dab0512952fb3316c6acfbbb201d8c1d3137` | `docs/phase3/admission/RESTART_PLAN.md`, `restart-stage-proposal.json` |
| RUN/health | `21516e0605deb9ea30a4305b23deab4fe98c9c16` | `docs/phase3/run-health/READER_RESPONSE_PLAN.md` |
| Workloads/verifiers | `1e533b051522e651b802d0b3bf3386bbe59a530f` | `docs/phase3/workload-verifiers/copy-readback-plan.md`, `copy-readback-stage.json` |

Each commit has the previous checkpoint as its sole parent and a verified SSH
signature from the configured trusted ED25519 signer. Integrate these original
commits by merge, preserving their identities and ancestry. These are agreed
planning handoffs; they contain no newly checked runtime implementation.

The coordinator supplies four new documents under `docs/phase3/coordinator/`:

- `ownership-and-release-v1.md`: exact lane/shared ownership and release sequence.
- `restart-lifecycle-contract-v1.md`: native command and denial schemas, reviewed
  package-member identities, protected lifecycle API, source and clock semantics.
- `reader-response-contract-v1.md`: accepted transport, one-use claim, retention,
  process/clock acquisition and actual reader checkpoint obligations.
- `copy-readback-context-contract-v1.md`: protected request/context mapping,
  fresh directories, collector/replay signatures and cancellation custody.

Lane agreement binds contract SHA-256 values respectively:
`94f169bb5bae0fe3103c52bb3278683ed365fee5ed376adbffeabae5b0cdd579`,
`7a9592f9f885cf6e0c508a095804ccc20bed0108dd39b843592c0f60c38bc777`,
`e7603891206595999ea9cc2a857768e69be7099ad836210c1711bb0b646b3a50`.
Actual protected providers and deployed composition remain coordinator work.

## Verification and publication boundary

Review checks original signatures, parentage, exact changed-path inventories,
contract digests, merged signed bytes and staged whitespace. No behavioral test
is necessary for this documentation-only checkpoint. The 104-row pipeline
registry, implementation sources and original passing fingerprints stay unchanged.
No pipeline cache, private fixture state or local HTML review surface is copied
into this commit. Post-commit signature and remote-tip verification are recorded
separately so the checkpoint does not claim its own future hash.

Only the coordinator publishes the integration branch. Feature-branch pushes
are unnecessary for these shared local worktrees. After publication, each lane
owner preserves local drafts and fast-forwards to the exact supplied checkpoint.
An explicit implementation release is separate from test scheduling. Proposed
stage closures require review against actual stable source before registration.

## Next work and current coordinator blocker

1. Coordinator finishes the offline HTTP94 credential/import-cycle successor.
   Static review found that its draft `/proc/sys/kernel/random/boot_id` read is
   incompatible with service `ProcSubset=pid`. Reuse the broker's protected
   boot-ID bind and add the corresponding worker/sensor unit joins. The draft
   renderer/stager/test are unfinished and excluded from this checkpoint.
   Then review the full source closure, schedule one focused credential/staging
   stage, retain its actual public report, and complete the separately reviewed
   helper/capture/source/identity composition against that exact report pin.
2. Admission implements the finite mocked native RESTART producer/independent
   consumer; RUN implements the authenticated response acquisition leaf;
   workloads implement guarded copy/readback and its independent file consumer.
   Each lane owns only its new permitted files and reports a stable closure
   before any check. Root providers and real paired environment selection remain
   coordinator-owned; mocked leaf success cannot establish their deployment.
3. After each reviewed new focused stage passes, its owner stages exact paths,
   makes one signed commit, verifies it and hands its original hash/result to
   the coordinator for the next composition checkpoint and normal push.

## Remaining Phase 3 steps

1. Shared runtime integration and the recorded retention/cleanup hold remain
   open. Offline repair is current; no live listener/effect proof is added.
2. Complete admission families, real RUN acquisition/enforcement/attribution,
   remaining workloads, actual paired environments and measurements.
3. Complete independent verifier coverage and deployed source/identity custody,
   then freeze one deployment.
4. Final same-deployment 31-case and 100-attempt/100-pair acceptance, independent
   replay and retained cleanup remain blocked. All qualification flags are false.

No live operation, private retention, cleanup, historical-suite rerun, cache
copying or automatic unchanged retry is authorized by this checkpoint.
