# Phase 3 third source integration checkpoint

Branch: `codex/phase3-runtime-prevention`.
Previous published checkpoint: `371cea7318f0e1326539de0e0e3ac8bdbec9cc4e`.

## Original signed inputs preserved

| Lane | Original signed commit | Completed bounded slice |
| --- | --- | --- |
| Admission | `149c8081c97c9a2a5bc1e80330da713f9986f205` | Fixed upload-disabled native INSTALL execution leaf |
| RUN/health | `b16afa3601970c786ace9170b6fc8356a53ae051` | Retained acquisition projection and independent raw-record consistency consumer |
| Workloads/verifiers | `0e1dce1d955be45a340c279c478c8fe2247325c1` | BENIGN_SHA256 callback and independent result consumer |

All three have the previous checkpoint as their sole parent and valid SSH
signatures from the configured trusted ED25519 signer,
`SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk`.
Their original worktrees were clean. The coordinator merged these commits without
conflicts, preserving their identities and ancestry. No rebase, cherry-pick,
reset or force push is part of this batch.

## Verification and evidence reuse

Read-only checks confirmed that every merged lane source, test and document has
the exact signed feature-commit bytes. Each registered stage and every declared
input, plus the runner and requirements lock, matches its original signed source
closure. All 101 historical registry rows are unchanged; exactly three rows were
added. The existing registry validator and staged whitespace check passed.

Independent review checked the retained result metadata and both log digests in
each original worktree. Selected pipeline `status` queries report SKIP_PASS at
these exact pre/post fingerprints:

| Stage | First focused execution | Exact fingerprint |
| --- | --- | --- |
| `native-admission-install-leaf` | 17 mocked checks, PASS | `sha256:62afde843001570524bafaed58dfcfab678f3a2dd1ac9e61712e7ff0a8217882` |
| `native-run-acquisition-records` | 10 inert checks, PASS | `sha256:c135daacf0473b0d2e80cc6f6ebc4671c429a2a3681c3e51433db46abe057ead` |
| `native-workload-sha256` | 8 inert checks, PASS | `sha256:5c26a3df4d6f464ba8458d7ef60139bcc7e74c3f473044654edc3b22739c779f` |

These 35 new methods ran once in their owning lanes after source/closure review
and explicit coordinator registration/scheduling. The coordinator reran zero
behavioral tests. Historical INSTALL recorder, RUN progress, JSON-sum and
line-count results remain retained without rerun. Results remain bound to their
original worktree/toolchain/environment; no cache was copied or relabeled as
integration-checkout evidence.

No capture, VM/container/service action, live workload, measurement, private
retention, cleanup or acceptance campaign ran. The October 9 evidence/cleanup
hold is unchanged and was not refreshed against live state. The verified
containing commit and remote result belong in an ignored post-commit receipt.

## Proof limits and next ownership

- Admission's leaf validates its native caller, pinned sources, bounded command
  execution and failure retention, including SIGTERM interruption. Its mocked
  checks do not attest a real launch. Outer source/liveness custody, namespace
  launch, common dispatch, staging and exact fixture cleanup remain coordinator
  work. The fixed upload-disabled denial does not cover every INSTALL family.
- RUN independently checks retained raw-record consistency with caller-held
  bindings. It supplies no actual reader, protected transport, source authenticity,
  exclusive custody or replay exclusion. Submitted ambiguity stays INDETERMINATE;
  post-connect HTTP continuation requires a separate policy boundary.
- SHA256 independently checks the actual fixed task result and declared timing
  boundaries. It supplies no real baseline/instrumented selection, attribution,
  sink-residue proof or native latency measurement. Guarded copy/readback is next.

Keep the existing three worktrees. After publication, each lane owner fast-forwards
to the exact combined checkpoint. Only the coordinator publishes the integration
branch; separate feature-branch pushes are unnecessary. Preserve any new drafts
and stop if fast-forward is refused rather than resetting them.

Next work is divided by boundary: admission covers the next missing admission
execution family with its independent consumer; RUN closes the acquisition and
post-connect authority design gaps before another runtime implementation; workload
completes guarded copy/readback and its independent consumer. Coordinator owns
the HTTP94 protected-credential/import-cycle successor, shared dispatch/staging,
source/identity inventories, real environment selection, registry scheduling and
publication. Source closures and proposed new stages are reviewed before any
new focused execution. This checkpoint does not schedule further tests or live
operations.

## Remaining Phase 3 steps

1. Shared runtime integration and recorded retention/cleanup hold remain open.
   Repair the HTTP94 successor offline; same-broker listener/effect evidence
   still requires separately authorized live work.
2. Complete admission families/routes, real RUN acquisition/enforcement/
   attribution and event/response coverage, remaining workloads, paired
   environments and measurements.
3. Complete the independent verifier inventory and deployed source/identity
   custody, then freeze one deployment.
4. Final same-deployment 31-case plus 100-attempt/100-pair acceptance, independent
   replay and retained cleanup remain blocked. All qualification flags stay false.
