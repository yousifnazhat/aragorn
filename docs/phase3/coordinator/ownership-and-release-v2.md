# Phase 3 evidence consumers: ownership and release v2

Base: verified signed and published `27e9844e6d5f0924b79382a8a084099ee06e2ed6`.
This document succeeds v1 only for the next bounded implementation assignments.
All existing provider and operational holds remain. Worktree capacity follows
the standing coordinator rule below.

## Hard coordinator rule: fastest complete Phase 3

Operator instruction, 2026-10-12: minimize elapsed time to complete Phase 3,
including final qualification. At every checkpoint, new blocker or completed
handoff, reassess the existing coverage ledger and dependencies; identify the
critical infrastructure blocking complete execution paths and immediately release
the next independent, bounded assignments. Do not wait for all coordinator work
to finish before starting a lane whose contract is ready.

Each assignment must name its requirement, verified published base, owner,
exact writable paths, concrete interfaces and failure semantics, dependencies,
required raw evidence and independent consumer, proposed focused validation,
and acceptance/handoff conditions. Publish the signed contract before release.
Keep shared-file ownership explicit; delegate non-overlapping provider leaves
when the coordinator becomes the bottleneck. Integrate completed consumers with
their providers promptly, and confirm delivery/agreement rather than assuming it.

Reuse or reassign existing worktrees when they can take the work promptly. When
additional capacity can shorten the critical path, request that the operator open
the necessary additional worktree(s). Supply the proposed branch/path, exact
verified published base, copyable assignment, dependencies and expected benefit.
Prepare the assignment before requesting capacity; continue independent work
while awaiting the operator. Do not serialize ready work merely to keep a fixed
worktree count, or add worktrees with no independent ready scope. This supersedes
earlier blanket advice against new worktrees only for deliberate capacity
expansion; preserve drafts and never create replacement worktrees or mutate an
active owner's worktree.

Repeat assignment, implementation, review, necessary focused validation, signed
integration and capacity reassessment until the existing exit manifest is
satisfied. Reuse unaffected evidence; do not add a gate framework, redundant
tests or speculative scope. The operational/private-retention/cleanup holds
remain, and implementation readiness is distinct from final qualification.
End every checkpoint with completed work, released/pending assignments, concrete
blockers, any operator capacity request and numbered remaining Phase 3 steps.

## Existing released assignments

| Existing branch | Contract | Exact implementation write allowlist |
| --- | --- | --- |
| `codex/phase3-admission` | `admission-policy-tamper-contract-v1.md` | `src/aragorn/native_phase3_admission_policy_tamper.py`, `src/aragorn/native_phase3_admission_policy_tamper_verify.py`, `tests/test_native_phase3_admission_policy_tamper.py`, `docs/phase3/admission/POLICY_TAMPER_HANDOFF.md` |
| `codex/phase3-run-health` | `reader-evidence-contract-v1.md` | `src/aragorn/native_phase3_run_reader_evidence_verify.py`, `tests/test_native_phase3_run_reader_evidence_verify.py`, `docs/phase3/run-health/READER_EVIDENCE_HANDOFF.md` |
| `codex/phase3-workload-verifiers` | `dns-canary-contract-v1.md` | `src/aragorn/native_phase3_workload_dns_canary.py`, `src/aragorn/native_phase3_workload_dns_verify.py`, `tests/test_native_phase3_workload_dns.py`, `docs/phase3/workload-verifiers/dns-canary-handoff.md` |

Contracts live in `docs/phase3/coordinator/`. Each owner verifies the containing
signed checkpoint, preserves local drafts, fast-forwards their own worktree,
reads the contract's final coordinator decisions, and acknowledges agreement.
That releases only the listed source/tests/handoff implementation. A concrete
incompatibility should be reported before changing shared files or widening scope.
Owners need not wait for completion of the coordinator's HTTP repair.

The admission scope deliberately uses the existing baseline-present native force
route; target absence and protected policy-request acquisition remain separate
root obligations. A source-confirmed policy hook is not an observed invocation.
RUN evidence may describe a success even after retention failed; verification
does not prove retention or leaf return. DNS completeness fields and counters
remain retained consistency claims until real protected providers are joined.
All native authenticity and qualification flags stay false.

## Review, one selected stage, then signed handoff

Once source is stable, submit exact changed paths and hashes, actual imports,
fixture/reference dependencies, test methods and proposed stage in the handoff.
Root reviews complete behavioral closure before registering and scheduling only
that newly necessary stage in its owning worktree. No test is scheduled here.
Mutable handoffs and stage outputs are not behavioral inputs. Do not copy caches
or rerun historical suites; preserve unaffected original success fingerprints.
On failure retain the actual failure/fingerprint and diagnose before any changed
retry. No automatic unchanged retries.

After review and PASS: stage exact paths, create one `git commit -S`, verify with
`git verify-commit HEAD`, and send original hash, paths, actual result/fingerprint
and remaining blockers. Root merges original signed commits preserving ancestry,
validates composition, signs/verifies a checkpoint, pushes normally and verifies
the remote tip. Only then do owners fast-forward themselves to the supplied hash.
Root does not mutate active lane worktrees. Feature branch pushes are unnecessary.

## Coordinator's continuing ownership

Root owns shared dispatch, source/config/identity inventories, launch/staging,
actual protected lifecycle and policy observation, reader/loss/broker providers,
workload context and fresh directories, cancellation, full decision timing and
real baseline/instrumented environment selection. Root also owns the registry.
HTTP first stage fixes protected credential/boot-ID/cold-import joins and retains
one actual public staging report. The separately reviewed composition stage must
use that actual report pin without repeating unchanged staging.

## Four-step checkpoint

1. Current: publish these contracts; continue offline HTTP repair and shared
   runtime integration. Existing private-retention/cleanup hold remains open.
2. Implement the three released finite slices; finish remaining admission/RUN/
   workload families and actual providers, attribution and paired measurements.
3. Complete independent replay and deployed source/identity custody; freeze one
   deployment only after the full coverage map is ready.
4. Final same-deployment 31-case and 100-attempt/100-pair acceptance, independent
   replay and authorized verified cleanup remain pending.

No live operation, private retention, cleanup, historical rerun or qualification
claim is released by this checkpoint.
