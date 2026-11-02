# Phase 3 source integration checkpoint

Integration branch: `codex/phase3-runtime-prevention`.
Base: `eb13d0d3eb0d7c29e613c25570cd47fafe6baffb`.

The containing signed merge preserves these original signed commits:

| Slice | Verified commit | Existing focused tests |
| --- | --- | --- |
| Upload-disabled INSTALL denial consumer | `52be73dcf68eaafb7ec507805524d27d33fc6501` | 6 |
| Finite reader-progress decision and verifier | `c374e524a9d66ead94f1f8e6600d6b1173ccc11a` | 3 |
| JSON-sum callback and independent verifier | `43c0decd2bba922f482002bb24ca7207296efeee` | 6 |

All three signatures verified against the configured trusted signer with key
`SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk`.
The merge was conflict-free. Read-only integration checks confirmed that each
feature's source, tests, handoff, complete registered input closure, pipeline
runner and dependency lock are byte-identical to its signed feature commit.
The combined registry passes its existing structural/dependency validator,
preserves every historical stage row, and adds exactly the three reviewed rows.
The staged diff passes `git diff --cached --check`.

Selected read-only pipeline `status` queries in the original feature worktrees
returned `SKIP_PASS` with these unchanged fingerprints:

- `native-admission-install`:
  `sha256:9f936cf6e0b82656ac1230777b99920e121b8b6f3626f199dd53779abd62e049`
- `native-run-reader-progress`:
  `sha256:1ebdd044c7dd535f86f7fba19322a03a6254e96a8aa81adac0ca153eeb5a7226`
- `native-workload-json-sum`:
  `sha256:9d5945fdbad517531b6cc61d32645596ded265683cbf82504651274557f16a82`

Zero behavioral tests ran during integration. The existing 15 focused passes
remain bound to their original worktrees and environments; no cache was copied
or relabeled as an integration-checkout pass. No live operation, VM inspection,
service activation, private retention, cleanup, capture or measurement ran.
This is source integration only, not deployed behavioral integration.

The containing commit's signature, exact hash and remote push result are recorded
after commit in an ignored local receipt to avoid a self-referential hash.

## Remaining Phase 3 steps

1. Resolve the recorded retention/cleanup hold and shared HTTP94
   credential/import, startup/capture/listener integration. This checkpoint does
   not refresh live state or authorize a retry.
2. Connect the three integrated slices to native producer/dispatcher, actual
   reader acquisition and enforcement, and collector/replay dispatch. Complete
   remaining admission families, RUN/event/response/causal-attribution coverage,
   workload callbacks, paired environment selection and real measurements.
3. Complete the independent verifier inventory, same-deployment source and
   installed-identity custody, and deployment freeze.
4. After prerequisites close, perform final same-deployment acceptance,
   independent replay and cleanup, including the required Final31 and
   100-attempt/100-pair gates. Phase 3 exit eligibility remains false.

Detailed scope and open dependencies remain in [admission](admission/HANDOFF.md),
[RUN health](run-health/HANDOFF.md), and
[workload verifiers](workload-verifiers/json-sum-handoff.md).
