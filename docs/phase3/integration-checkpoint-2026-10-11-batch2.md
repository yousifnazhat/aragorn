# Phase 3 second source integration checkpoint

Branch: `codex/phase3-runtime-prevention`.
Previous published checkpoint: `014cc41f52966a5f46c4fdd3eb5eda09abfe0dc2`.

## Original signed inputs preserved

- Admission recorder: `e4dc089cfaf85850945ab82f7f7184c9ad81b8c9`.
- RUN acquisition design: `99883f6272f439c0767d66a76079bab87ddad39d`.
- Line-count callback/verifier: `7bf76a462efcf45c024c4faa8adf7cf2cee5d2ca`.
- Existing signed line-count integration:
  `74a45b16e2efcd53abf56092e062af526ae8239e`.

All four signatures verified against the configured trusted signer,
`SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk`.
The earlier line-count merge was preserved when coordinator work overlapped;
no commit was reset, rebased, cherry-picked or replaced. Admission and RUN were
then merged into that existing integration without conflicts. The containing
signed checkpoint preserves all original feature commits in its ancestry.

## Verification and evidence reuse

Read-only integration checks confirmed exact signed source, test, document,
registered input, runner and lock bytes for all three slices. The combined
registry is byte-identical to the preserved line-count merge and passes the
existing registry validator. The staged diff passes its whitespace check.

Selected read-only pipeline status in each original worktree reports SKIP_PASS:

| Stage | Existing passing checks | Exact fingerprint |
| --- | --- | --- |
| `native-admission-install` | 16 (six affected consumer, ten new recorder) | `sha256:0d3692546c31cc2733070f93f85a83a7ee6cd13b45f1d93b8974b53c6cd105c2` |
| `native-run-reader-progress` | 3; current delta is documentation only | `sha256:1ebdd044c7dd535f86f7fba19322a03a6254e96a8aa81adac0ca153eeb5a7226` |
| `native-workload-line-count` | 7; first focused execution passed once | `sha256:79464c1432034d5d5a0298be6c1645e328dba1859bd75c5611fb73fb55480d0b` |

The coordinator executed zero behavioral tests during integration. Results stay
bound to their original worktree/toolchain/environment; no cache was copied or
promoted into integration-checkout evidence. No live operation, private retention,
cleanup, service activation, capture, measurement or acceptance campaign ran.
The containing commit's verified hash and remote result belong in an ignored
post-commit receipt rather than a self-referential document.

## Next lane boundaries

- Admission: one bounded native upload-disabled INSTALL execution leaf around
  the recorder, with gateway namespace/privilege/source custody and newly
  necessary mocked checks. Preserve denial exit code 1 separately from catalog
  command exit code 0. Shared dispatch/staging/lifecycle remain coordinator-owned.
- RUN: one pure acquisition-record projection and independent consistency
  consumer after exact contract agreement. Caller-held nested pins and a fixed
  BEFORE_FIRST_EFFECT boundary must be explicit. This does not supply actual
  acquisition custody, replay exclusion or post-connect continuation authority.
- Workloads: BENIGN_SHA256 next, then guarded copy/readback in a later batch.
  Collector dispatch, real environment selection and identity/source inventories
  remain coordinator-owned.

Active lane drafts are preserved. Each lane must fast-forward to the exact new
combined checkpoint before its next implementation/check batch, without folding
those drafts into this merge. Coordinator publication and stage scheduling are
centralized to prevent duplicate integration or test work.

## Remaining Phase 3 steps

1. Shared runtime integration/recorded cleanup hold: unresolved. HTTP94 protected
   credential/import-cycle successor and same-broker listener/effect evidence
   remain necessary; no live retry is authorized here.
2. Complete admission families, real RUN acquisition/enforcement/attribution and
   event/response coverage, workloads, paired environments and measurements.
3. Complete independent verifier inventory, deployed source/identity custody and
   deployment freeze.
4. Final same-deployment 31-case and 100-attempt/100-pair acceptance, independent
   replay and retained cleanup remain blocked. All qualification flags stay false.
