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

## Mission and scope discipline

Operator direction, 2026-10-14: finish Phase 3 and prevent scope drift after
prolonged implementation. Aragorn's purpose is exact reviewed-capability
admission and externally enforced runtime containment. The Phase 3 deliverable
is one real supported runtime/deployment where approved digests are activated,
protected attempts are causally attributed, prohibited or unattributed attempts
are blocked before protected impact, and required containment/revocation and
sensor-loss responses work. Evidence must independently support that behavior.

The existing `benchmark/phase3-exit-gate-manifest-v1.json` and existing 48-entry
coverage ledger define the complete finish line. This instruction creates no new
gate or requirement. Keep their thresholds, evidence limits and operational holds.

Every next assignment must name the existing requirement it closes or the
specific missing dependency preventing that requirement's real execution. Name
the owning caller, exact paths, acquisition and independent consumer. Prioritize
a connected end-to-end path over additional disconnected leaves. Publish the
minimum concrete contract needed to release implementation promptly; do not
reopen settled interfaces or keep redesigning a released contract without a
concrete correctness/security defect or changed dependency.

Root's immediate priority is protected bootstrap inputs/readiness/cancellation,
actual broker/reader/caller wiring and its exact deployment inventory. Admission
and RUN continue their already released context and DNS work concurrently. Root
must resolve and release bounded destructive/a100 work promptly. First connect
HTTP, then reuse shared infrastructure for DNS/destructive actions and all other
required admission/RUN paths, full timing and the four real paired tasks.

Do not expand into additional runtime integrations, A2A, Phase 4 scaling, a new
sensor/gate framework, generic platform abstractions or unrelated refactoring.
Do not create planning/contract churn, speculative hardening or further standalone
verifiers unless necessary for a named existing requirement or a concrete defect
in its actual dependency path. Required custody and fail-closed repairs remain
in scope; urgency never substitutes unknown loss for zero or removes evidence.

Judge checkpoints by complete requirement paths, concrete blockers removed and
ready assignments delivered/acknowledged. Commit, module and test counts are
supporting implementation facts, not completion measures. A refusal-only slice
with unknown sensor health is an intermediate state; it cannot establish usable
runtime prevention or completed benign-task behavior.

Reuse unaffected evidence, run only reviewed newly necessary checks, integrate
original signed deliveries promptly and stop expanding implementation once the
existing freeze conditions are met. Final qualification still requires the
separately released same-deployment campaign and independent gate evaluation.
If a mandatory guarantee cannot be implemented on the selected target, report
the exact failed property and bounded remedy or apply the architecture's existing
kill/pivot criteria; do not conceal the problem behind more framework work.

## Existing released assignments

| Existing branch | Contract | Exact implementation write allowlist |
| --- | --- | --- |
| `codex/phase3-admission` | `admission-policy-tamper-contract-v1.md` | `src/aragorn/native_phase3_admission_policy_tamper.py`, `src/aragorn/native_phase3_admission_policy_tamper_verify.py`, `tests/test_native_phase3_admission_policy_tamper.py`, `docs/phase3/admission/POLICY_TAMPER_HANDOFF.md` |
| `codex/phase3-run-health` | `reader-evidence-contract-v1.md` | `src/aragorn/native_phase3_run_reader_evidence_verify.py`, `tests/test_native_phase3_run_reader_evidence_verify.py`, `docs/phase3/run-health/READER_EVIDENCE_HANDOFF.md` |
| `codex/phase3-workload-verifiers` | `dns-canary-contract-v1.md` | `src/aragorn/native_phase3_workload_dns_canary.py`, `src/aragorn/native_phase3_workload_dns_verify.py`, `tests/test_native_phase3_workload_dns.py`, `docs/phase3/workload-verifiers/dns-canary-handoff.md` |

### Next bounded RUN provider release

The published signed `provider-release-v3.md` releases
`reader-transport-contract-v1.md` to the existing RUN owner after agreement:
`src/aragorn/native_phase3_run_reader_transport.py`,
`tests/test_native_phase3_run_reader_transport.py`, and
`docs/phase3/run-health/READER_TRANSPORT_HANDOFF.md` only. The original signed
reader-evidence consumer is integrated and remains unchanged. This explicit
delegation transfers the new listener/notice/accepted-connection leaf to RUN;
Root retains launcher/service/provisioning, real telemetry/checkpoint/loss,
independent transport replay, broker wiring and all shared files. No new test
stage is scheduled until the actual stable source closure has been reviewed.

### Next bounded broker submission release

The signed `provider-release-v4.md` releases the ready portions of
`broker-reader-provider-contract-v1.md`. Root retains the new protocol codec,
broker journal, their two tests and coordinator handoff. The available Admission
owner receives exactly `src/aragorn/native_phase3_run_submission_verify.py`,
`tests/test_native_phase3_run_submission_verify.py`, and
`docs/phase3/admission/SUBMISSION_REPLAY_HANDOFF.md`. This explicit independent
consumer assignment follows the integrated policy-tamper delivery; it does not
transfer broker wiring or any existing shared file. No producer code or fixtures
may be imported by the independent consumer/tests. Each owner submits its stable
actual dependency closure before Root registers or schedules a new focused stage.

`dns-provider-contract-v1.md` records the reviewed acquisition/context decisions
and proposed five-path split. Its source assignment is pending the original
signed DNS builder delivery and an exact later published base. Do not create a
worktree or begin those paths from a checkpoint lacking that dependency.

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
