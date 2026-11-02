# Coordinator ownership and release v1

Starting signed checkpoint: `b3fca83615cd6fd69b463ca8cebcebc660990dec`.
Keep the existing three worktrees. Only their owners edit or fast-forward them.
Coordinator integrates original verified signed commits, preserves ancestry and
publishes `codex/phase3-runtime-prevention` with an ordinary push.

| Owner | Next finite slice | Concrete contract | Shared work retained by coordinator |
| --- | --- | --- | --- |
| Admission | Native safe in-process RESTART leaf and independent retained-byte consumer | `restart-lifecycle-contract-v1.md` | Protected lifecycle acquisition/transport, launch, native source/config/environment inventory, shared admission dispatch and staging |
| RUN/health | One authenticated reader challenge/response acquisition leaf | `reader-response-contract-v1.md` | Accepted protected socket, permanent consume-once ledger, retention provider, actual reader checkpoint, sensor/loss custody and serialized broker submission |
| Workloads/verifiers | Guarded BENIGN_COPY_READBACK leaf and independent retained-file consumer | `copy-readback-context-contract-v1.md` | Protected request/context inventory, fresh directories, top-level collector/replay dispatch, cancellation, actual paired environment selection |
| Coordinator | Offline HTTP94 protected-credential/import-cycle successor and composition | Successor handoff and focused stage records | Frozen predecessors, launchers/materializers, measurement/source/identity pins, registry, integration and publication |

The linked contracts supply callable/schema decisions for finite mocked leaves.
They do not represent running protected providers or actual deployed integration.
Implementation release is explicit, after the relevant lane agrees the contract
and the containing signed checkpoint is published. Release covers new lane-owned
source/test/handoff only. Existing shared sources remain read-only in lanes.

No test is scheduled merely by agreeing a contract or publishing this document.
When an implementation is stable, submit exact paths, imports, fixture/reference
inputs and proposed stage. Coordinator reviews the complete closure and safety
boundaries, registers only that stage, then schedules its single focused run in
the owning worktree. Preserve its actual result/fingerprint and failures. A
changed-input rerun requires a diagnosed cause and renewed review. Historical
successes remain applicable only at their unchanged original closures.

Once reviewed and passing, the lane stages exact paths, makes one `git commit -S`,
verifies `git verify-commit HEAD` and hands off its hash, changed paths, exact
result/fingerprint and blockers. No cache copying, historical-suite execution,
automatic unchanged retry, private retention, live operation or cleanup.

Coordinator checks signatures, ancestry, signed input bytes, registry composition
and retained original result/log identities without rerunning their behavior.
It merges original commits, makes and verifies a signed checkpoint, pushes the
integration branch normally and checks that the remote tip equals local HEAD.
It then supplies that exact hash for lane owners to fast-forward themselves.
No force push, cherry-pick, reset or active lane-worktree mutation is authorized.

## Four-step position

1. Shared runtime integration is open. The offline HTTP94 successor is selected;
   the October 9 retained refusal and cleanup hold remain unchanged. No current
   broker listener/effect proof is supplied by offline checks.
2. Admission families, actual RUN acquisition/enforcement/attribution, remaining
   workloads, actual paired environments and measurements remain incomplete.
3. Complete the independent verifier inventory and deployed source/identity
   custody before freezing one deployment.
4. Final same-deployment 31-case and 100-attempt/100-pair acceptance, independent
   replay and retained cleanup remain blocked. All qualification flags are false.
