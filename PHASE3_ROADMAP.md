# Phase 3 completion roadmap

Planning date: 2026-10-04. Assessed implementation: `0a51326` on
`codex/phase3-runtime-prevention`. This document is a plan, not new test evidence
or a qualification result. The fixed [exit manifest](benchmark/phase3-exit-gate-manifest-v1.json)
remains authoritative; this roadmap does not weaken or expand it.

## Outcome and current position

Finish one exact native runtime deployment with independently verified admission,
runtime prevention, responses and quantitative acceptance. Phase 3 completion
does not by itself authorize an installer, the EDR label or public release.

- The development executor wires 14 of 31 admission cases. Seventeen integration
  entries remain: 12 ports and five entries classified as missing adapters by the
  frozen registry. This is not a completion percentage.
- One of those five, plugin-package skill replacement, now has a separate native
  local-marketplace update adapter and retained denial observation. Integrate it;
  do not build it again or call it coverage of ClawHub/npm/Git update branches.
- Native receipts, bounded create mediation, health-expiry suspension, restart
  prevention and idle sensor-exit shutdown have retained development evidence.
  Seven-event/six-response coverage and general causal attribution are incomplete.
- Deployment identity, measurement preparation/collection, receipt retention,
  offline replay and exit composition exist. Their complete production adapters
  and independent semantic-verifier registry are not connected.

The fastest path is **one target, parallel implementation, one final freeze,
one required acceptance campaign**. The old V3 admission parent and native
runtime have different identities. Do not finish ports on the old parent and
then port them again. See the [existing completion analysis](README.md#completion-implementation-2026-10-01).

## Time allocation: effort is not machine runtime

These are provisional code-reading planning allowances, not measured forecasts
or promised calendar dates. An engineering-day means about six focused hours;
it is not six hours of autonomous agent execution. Packages overlap, so do not
sum them or divide their sum by the number of agents to promise a finish date.
Runtime telemetry and attribution are the largest uncertainties.

| Order / owner lane | Work package | Provisional effort allowance | Machine use | Exit condition |
|---|---|---|---|---|
| F0 / integration lead | Shared native target, attribution/evidence contract, controller readiness | 1–3 engineering-days; first checkpoint after 2–4 focused hours | Static inspection first; one changed-behavior integration check when ready | All lanes agree on the seven deployment dimensions, event joins, callback interfaces and environment prerequisites |
| A / admission | Reuse 14 checks; integrate existing update adapter; finish remaining admission families | 8–20 engineering-days, medium/low confidence | Offline checks first; bounded fresh fixtures only for changed behavior | All 31 cases have real execution paths and independent semantic consumers on the chosen target |
| R / runtime, critical path | Complete seven event classes, causal attribution and six responses, including meaningful health loss | 12–25 engineering-days, low confidence | Short isolated captures after each new boundary is implemented | All 15 RUN requirements have implementation and verifier coverage; no unsupported claim is promoted |
| M / measurement | Real execution/identity/verifier callbacks; full timing and sink evidence | 6–15 engineering-days, low confidence; overlaps R | Small changed-path checks; no 100-sample campaign yet | Required attempts, negative control and paired tasks can be collected and independently replayed |
| G / integration lead | Close verifier map, review the common deployment, freeze | 2–5 engineering-days, overlaps lane reviews | Offline verification; no new historical campaign | All 48 required entries have reviewed consumers and exact input bindings |
| Q / acceptance operator | Required frozen campaign and final composition | Machine budget calculated below; repair work is not pre-estimated | One serialized acceptance campaign, then offline replay | Every mandatory requirement and numeric threshold passes on the same deployment |

Re-estimate after F0 and after the first real OS telemetry/enforcement boundary.
Do not silently extend a failing timebox or advertise these allowances as an ETA.
There is substantial implementation left; skipping acceptance cannot remove it.

## Dependency order and least-rework implementation

### F0 — establish the common path and expose the hard risk early

1. Select the current native startup profile as the common implementation line.
   Incorporate the existing receipt-retaining measured-broker successor where
   needed, without editing frozen predecessors or claiming staging is activation.
2. Reuse [phase3_deployment.py](src/aragorn/phase3_deployment.py) for runtime,
   adapter, configuration, worker, OS profile, policy and Aragorn identities.
   Select the target now; freeze the final hashes only after implementation.
3. Agree on one causal chain: admitted digest → actual activation/session → tool
   attempt → authenticated process/cgroup → capability → decision/result.
   Missing attribution must block; an asserted digest is not causal proof.
4. Map the existing 48 gate entries to owners, source files, raw evidence and
   independent consumers. Use the existing inventory, not a new gate framework.
5. Diagnose the documented intermittent PID-controller availability issue before
   a long run. A prerequisite refusal stops the run for diagnosis; it does not
   trigger repeated VM restarts or permission/limit weakening.
6. In parallel with the first easy adapter integration, timebox the OS
   telemetry/enforcement feasibility check to four focused hours. Establish a
   viable existing sensor, binary identity, loss accounting and attribution path.
   Surface missing capability now, not after every easy port is finished.

   Initial read-only risk finding: the retained Tetragon v1.7.0 scrapes lack
   `tetragon_bpf_missed_events_total`, which the existing process adapter requires.
   Other missed-link/prog-probe counters are not automatically equivalent. The
   next loss-accounting implementation must establish coverage against the exact
   pinned sensor source; absent loss metrics remain unknown, never synthetic zero.
   The local source lock has hashes, not the metric implementation bytes. Acquire
   its already-pinned `pkg/observer/observer_stats.go`, `pkg/observer/metrics.go`
   and `pkg/metrics/errormetrics/errormetrics.go` at commit
   `1de2ed8ebea18e56257dc59597aa13bf8f0e471e`; verify their existing byte/digest/Git-blob
   pins with `verify_upstream_source_file`. Inspect and retain any additional
   defining files from that exact upstream tree before changing the contract.

F0 first deliverable: one existing native case connected through the shared
request/evidence contract and a real independent consumer. Start with the
already-built plugin-update adapter. Reuse retained observations for development
where their scope permits; do not change a registry flag to manufacture a pass.

### A — admission lane: group by shared setup

| Sequence | Cases / work | Reuse and completion rule |
|---|---|---|
| A0 | Existing native plugin-package update; compatibility of the 14 existing semantic checks | Adapt request/evidence interfaces once. Preserve each observation's exact branch and proof limits. Rebind to final deployment once, after freeze. |
| A1 | Nine ports: exact admitted bytes; install, direct-write, rename, symlink, auto-discovery, restart; policy failure and policy tampering | Share protected fixture construction, byte-identity joins and policy-control setup. Keep each required case isolated and independently evaluated. |
| A2 | Six reload cases: config invalidation, filesystem-watch invalidation, plugin-skill-directory activation; manual-plugin invalidation, remote eligibility, sandbox-per-run rescan | Share cache/prompt/session observation primitives. Prove the actual trigger and protected consumer state; CLI discovery alone is insufficient. |
| A3 | ClawHub tracked replacement | Implement the distinct tracked lifecycle. Do not reuse marketplace output as evidence for this route. |

A1 accounts for nine of the twelve ports; A2 accounts for the other three ports
and three missing adapters. A0 and A3 cover the other two adapter entries.
The fourteen previously wired cases are reused, not discarded or rebuilt.

### R — runtime lane: implement and verify boundaries together

1. **Semantic events:** skill activation/completion, tool attempt/result and
   exposed prompt/context/memory mutations. Reuse the native receipt and protected
   session paths. Bind real runtime boundaries, not reconstructed transcript guesses.
2. **OS events and enforcement:** process execution/ancestry; file read/write,
   rename and executable creation; network/DNS attempts; credential/canary access.
   Reuse established host telemetry and confinement. Add missing joins, loss
   accounting and synchronous enforcement where required. Do not create a custom
   eBPF sensor. Denying an unsupported operation is not proof of observing it.
3. **Responses:** connect alert/evidence retention, pre-effect block, process-tree
   termination, digest quarantine, future-start revocation, and health-loss
   isolation/suspension to that same runtime. Reuse existing stop/mask/quarantine
   machinery instead of replacing it.
4. **Meaningful health:** authenticated, freshness-bound sensor progress and loss
   reporting must distinguish an idle responsive sensor from an alive-but-hung
   sensor. Reuse the existing suspension/restart-barrier response path.
5. **In-flight outcomes:** establish what happened at submission/decision/effect
   boundaries under health loss and response contention. Post-submission ambiguity
   stays `INDETERMINATE`; do not count it as a pre-effect block or replay an effect.

Write each independent semantic consumer alongside its implementation. The RUN
gate has two properties, seven event classes and six responses: fifteen entries.
Existing idle-exit and accepted-health-expiry observations are reusable development
references; they do not settle hung/stale, telemetry-loss or in-flight behavior.

### M — measurement lane: remove the final-campaign blockers early

1. Implement trusted `execute`, `verify` and live `identity_reader` callbacks for
   [the existing collector](src/aragorn/phase3_measurement_collector.py). Keep
   execution and verification separate, and use the existing CAS and preparation API.
2. Retain actual `REQUEST_ACCEPTED` → `DECISION_FINALIZED` boundaries in a verified
   Linux `CLOCK_BOOTTIME` domain. The current V4 validated-submission interval is
   narrower and cannot be relabeled. A common boot ID alone does not prove clocks
   have matching time-namespace offsets.
3. Support both exfiltration and destructive families, the one required
   unattributed negative control, and independent attribution/protected-sink
   residue evidence. Fix incomplete block-receipt paths before counting samples.
4. Implement 100 caller-bound baseline/instrumented task pairs with actual
   task-accepted/task-completed boundaries. Baseline and instrumented tasks must
   have the same task, input and host-profile bindings.
5. Put bounded subprocess deadlines and owned-resource cleanup in concrete
   adapters. The generic collector currently has no callback timeout or automatic
   retry; it is not a watchdog. Never retry an ambiguous submitted effect.
6. Connect [offline semantic replay](src/aragorn/phase3_measurement_replay.py) and
   the [exit composer](src/aragorn/phase3_exit_qualification.py). Reuse the broker
   receipt verifier for the joins it establishes, not as policy/causality/residue proof.

Start callback interfaces after F0; final semantics depend on R. Do not wait until
all admission routes are finished to discover that timing or negative-control
collection is impossible.

## Small-wave execution and concurrency policy

- Continue through dependency-ready implementation batches automatically; do not
  stop for a user prompt or run checks merely because a time interval elapsed.
  Use internal 30–90-minute work segments and a checkpoint after 2–4 focused hours
  on one package. A checkpoint records a closed requirement, a concrete code delta,
  or an exact blocker and next diagnostic—not another general reassessment.
- After F0, run admission, runtime and measurement engineering in parallel, with
  the integration lead owning shared interfaces. Avoid concurrent edits to common
  files; verifier authors may review another lane's implementation read-only.
- Serialize live captures on the shared VM. Do not overlap latency/overhead
  samples with builds, other captures or CPU-heavy work. Independent engineering
  may continue elsewhere if it does not change the frozen capture checkout.
- Reuse immutable runtime images, dependencies and read-only volumes. Use fresh
  owned mutable state, credentials, grants and receipt streams where required.
  Build once per changed image; never reuse consumed grants to save time.
- Preserve cleanup, signed-source checks and before/after deployment identity.
  These are execution safeguards, not redundant regression tests.

### Activated local verification pipeline

The local [pipeline runner](scripts/phase3_pipeline.py) uses the reviewed
[stage registry](benchmark/phase3-pipeline-v1.json). It starts with only the new
pipeline checks and native plugin-update binding checks; it does not populate its
cache by rerunning the historical suite. Run from the repository root:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py status
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run
```

`status` plans without executing tests. `run` batches registered checks in
dependency order. An exact unchanged successful fingerprint is reused. An
unchanged failed, timed-out or interrupted attempt blocks instead of retrying.
The private ignored `.aragorn/phase3-pipeline` directory retains attempt state and
logs; a lock prevents overlapping runs. Source changes during execution prevent
a result from being reused as a success. Documentation-only changes do not
invalidate unrelated checks.

The runner needs permission to terminate its own child process groups. The first
attempt exposed a macOS cleanup bug: signaling a group whose leader has exited
but is not yet reaped can return `EPERM`. A separate ready-confirmed inert helper
accepted `SIGTERM`, then returned `EPERM` for the later signal; this was not proof
of missing execution permission. The failed test attempt and subsequent preflight
refusal remain retained; the dependent binding tests did not launch in either.
Cleanup must hold the leader identity while signaling, reap it, then confirm the
group is absent with a read-only probe. Never signal after reaping. Genuine
permission refusal remains a prerequisite failure, not grounds to disable cleanup,
erase an attempt, or blindly retry the same fingerprint.

The fingerprint covers declared source/test/fixture inputs, prerequisite stage
fingerprints, runner, interpreter/toolchain identity and controlled execution
settings. Input lists require review when imports, fixtures or dependencies change;
the runner does not claim automatic complete dependency discovery. Its local cache
is a development scheduling aid, not tamper-proof evidence, a semantic verifier or
Phase 3 qualification. Do not erase state, alter irrelevant inputs, or widen
timeouts merely to bypass a recorded failure.

Future implementation batches add only their affected checks and full declared
input closure to this registry, then invoke the pipeline once after code review.
Do not register historical full suites or live side-effectful campaigns here.
Final acceptance remains a separately frozen operation behind the checklist below;
the local unit runner cannot enable it. A recurring continuation in this chat
advances implementation between batches; a cache hit means move to the next
unfinished dependency, not wait for another testing interval.

Activation checkpoint, 2026-10-04: nine new pipeline checks passed in 1.851 seconds
and five new plugin-update binding checks passed in 0.124 seconds (unittest's
reported execution times, not whole-turn time). Read-only `status` then returned
`SKIP_PASS` for both; it executed no tests. Pipeline fingerprints are
`72eb97083794bbf8387875cc050255c7c39d8c27a18864b7ffdfe16bc028016f`
and `bab1c5be52f3c3c955571b20bff53aafe949f3228e6c39f1a9297812d4e31a80`,
respectively; their local attempt directories retain the logs. Earlier runner
failures were preserved and only relevant fixes were reverified, including removal
of an unintended `platform.uname()` helper subprocess. No historical product
suite or live capture was rerun. No admission, RUN or final exit gate closed in
this automation/binding slice.

## Machine-runtime budget

Two retained native observation windows were about 15 seconds (idle sensor exit)
and 24 seconds (plugin update). These are the recorded invocation windows, not
complete cold-start/build durations or a forecast for other cases.

| Operation | Allocation / guardrail |
|---|---|
| Documentation-only change | No behavioral test run; diff and link review only |
| New unit/static behavior | Run the affected checks once; target a short local check, investigate an unexpected slow run rather than widening scope |
| One changed native case | Existing guest invocation bounds are 240 seconds; allow explicit provisioning and cleanup time outside that bound. Stop on refusal; no blind retry loop. |
| Final 31 admission cases | Reserve a provisional 1–3-hour warm-host window. Recalculate from required changed-case setup/capture/cleanup timings before scheduling; this is not a measured upper bound. |
| Final 100 attempts + 100 pairs | Compute from the formula below after real callbacks/workloads exist; no credible fixed duration is available now. |
| Verification after capture | Offline replay of retained evidence, not a second live campaign |

Measurement wall time = `100 × mean attempt wall time + 100 × (mean baseline task
wall time + mean instrumented task wall time) + provisioning + retention + cleanup`.
Include any per-sample fresh-state provisioning in those means, exactly once.
Use timing from necessary changed-behavior checks; do not add a benchmark campaign
solely to estimate the benchmark. Setup/teardown wall time is a scheduling cost,
not part of the decision-latency metric unless the defined boundary includes it.

## No-redundancy rule and failure handling

Record for each verification: requirement/case ID, check command, implementation
and dependency pins, deployment/fixture/input pins, result, evidence location,
elapsed time and cleanup. Use these to decide whether prior evidence applies.

| Situation | Required action |
|---|---|
| Same relevant code, dependencies, inputs, deployment and check | Reuse the retained result; no live rerun |
| Relevant behavior or dependency changed | Run only the affected checks, including directly dependent safety boundaries |
| More analysis needed from valid retained bytes | Replay/inspect offline |
| Historical success belongs to another deployment | Keep it as development evidence; do not relabel it as final acceptance |
| Refusal or timeout | Retain the failure, diagnose once, fix a concrete cause; rerun only with a documented reason |
| Frozen deployment identity changes | Start a new qualification identity; do not splice old and new campaign samples |

No whole-suite regressions, repeated DET-01/idle-exit/expiry captures, per-wave
whole-schema sweeps, automatic retries or synthetic replacement samples. A focused
regression check is justified only by a relevant change; an unchanged check is not.
The final fresh same-deployment campaign is required acceptance, not redundancy.
Current collection/dispatch paths do not establish general resume support: never
claim a failed collection can resume or mix partial runs without an explicit,
verified contract permitting it. Preserve partial evidence as non-qualifying.

## Freeze checklist and definition of done

Before starting Q, every item below must be satisfied:

- [ ] All 31 admission cases have reviewed execution adapters for the chosen common runtime and independent consumers; this does not require an extra full pre-final campaign.
- [ ] All 15 RUN requirements have complete implementations and independent consumers.
- [ ] External broker/out-of-process sensor boundary evidence is supported.
- [ ] Measurement callbacks support full boundaries, both families, the unattributed control, residue checks and paired tasks.
- [ ] Controller prerequisites and owned cleanup are reliable enough to schedule the campaign; unresolved refusals are not dismissed.
- [ ] The exact 48-entry verifier/evidence inventory is wired; no default or recorded-PASS shortcut exists.
- [ ] All seven deployment dimensions, source/verifier pins, campaign contract and measurement schedule are frozen before execution.

Then execute the 31 isolated admission cases and the committed measurement
schedule. Evaluate RUN/boundary evidence on that same deployment. Replay retained
raw evidence independently and compose the final result. Required metrics:

- At least 99% attributed attempts across the fixed 100-attempt schedule.
- 100% pre-effect, residue-free blocking for both required action families.
- Exactly one unattributed control, blocked pre-effect without residue.
- Nearest-rank p95 synchronous decision latency strictly below 500 ms.
- Aggregate paired-task overhead strictly below 10% across 100 pairs.

Done means every mandatory semantic requirement and numeric threshold passes,
the final same-deployment qualification artifact is retained, and cleanup is
confirmed. Commit/push the evidence without changing the measured deployment.
Neither a roadmap checkbox nor a passing unit test can set Phase 3 eligibility.

## Scope lock and first next operation

Defer A2A lineage, additional runtimes/platforms, dashboards, custom eBPF,
general-purpose runner rewrites and public-release work. If a required path cannot
be supported safely, report the precise blocker; do not quietly delete it from
the gate or replace implementation with another planning document.

**Activated F0 slice:** the new
[read-only plugin-update consumer](src/aragorn/native_phase3_plugin_update_binding.py)
joins the retained v2 observation to all seven reported-identity artifacts in the
existing deployment envelope. It recomputes bounded record-level predicates;
it does not attest a live deployment or close an admission/RUN gate.

**Next implementation batch:** connect fresh native collection to the common
deployment request/evidence contract and its consumer; do not recapture merely
to exercise the new offline binding. In parallel, resolve the pinned Tetragon
loss-counter coverage and implement a bounded raw-scrape/identity adapter before
one newly necessary native OS-event integration check. Then advance the admission
ports and measurement callbacks in the dependency order above.

Progress updates should report: closed gate entries, entries still needing
implementation, changed-behavior checks performed, active engineering time,
machine time, and the next dependency. Do not report an unsupported overall
percentage or an arbitrary number of equal-sized waves remaining.
