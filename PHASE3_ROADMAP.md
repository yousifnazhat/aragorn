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
   exact pinned sensor source was investigated without a live recapture. Three
   originally selected observer/error-metric files matched their existing size,
   SHA-256 and Git-blob pins. The subsequently identified definitions/collectors
   are retained in a [six-file source slice](benchmark/tetragon-loss-source-v1/README.md).
   `eventmetrics/bpfcollector.go` emits only positive `SentFailed` counts and
   silently omits them on map-open/lookup failure. Thus absence is ambiguous,
   not evidence of zero. The link/program counters measure other failures.
   The new [raw-scrape adapter](src/aragorn/runtime_tetragon_loss.py) preserves
   that unknown and refuses counter resets or changed series inventories.
   Source inspection does not establish live map availability or sensor identity.

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

Follow-on checkpoint, 2026-10-04: all three new stages passed on their first
pipeline run; the two unchanged stages returned `SKIP_PASS`.

| New stage | Focused tests | Unittest time |
|---|---:|---:|
| Native observation collection/replay | 9 | 0.263 s |
| Offline collection CLI | 3 | 0.080 s |
| Raw loss-window accounting and new source custody | 7 | 0.009 s |

The complete five-stage pipeline invocation took 0.844 seconds as reported by
the command runner, excluding approval/tool overhead. Its new stage fingerprints
are `0885631e616695890d39bedeac1fee7a1f09f0d3288987e60baadf7df4dc1806`,
`5afbd750771f4f7ff3cea04e5c42b51d689a9ff51507ef8ccee17e1893268a58` and
`5aebfd2536889f409f1846ea2ef5840c36a0e1d5f8afff4d55be3b812cb7dff4`,
respectively. No old check ran, no VM was started, and no live capture or final
acceptance was attempted. The code/source-custody gaps narrowed; live native
identity, sensor-map availability, attribution and qualification remain open.

Live-reader checkpoint, 2026-10-05 UTC (2026-10-04 local): the new native identity
reader and read-only Tetragon stats-map reader are implemented and independently
code-reviewed. They do not modify frozen capture scripts or activate a deployment.
Source review caught the fixed Python launcher symlink, OpenClaw's rewritten
process title and the worker's supplementary gateway group before live use.
The BPF lookup's no-length buffer contract required an additional real-sysfs
mount/namespace guard, backed by retained boot-static possible-CPU-mask source.

- Native identity: 14 focused tests passed in 0.011 seconds, fingerprint
  `ccff9cca7bdab10620bfeb33b7c36f7b6f546084e969d0efaab8810b27bb32ed`.
- Stats-map readback: eight focused tests passed on their first pipeline run in
  0.010 seconds, fingerprint
  `fc30e36cb6e1e8b3fd3fa162b8d49cddf9fe7cd5e89f86fb25e4b923ff08abf0`.
- The initial native fingerprint
  `d9761eeb499a968b5246bbe72c61fae03d25a6c492c251d51b1554ec3646fb8a`
  remains a retained failure: macOS `/tmp` inherited GID 0 under the pipeline's
  clean environment, while the test assumed process GID 20. Only the shared
  temporary-fixture setup was corrected to establish its exact group; production
  custody checks were not weakened. The changed fingerprint was then verified.
- All seven current stages now report `SKIP_PASS` on read-only status. No old
  product check, historical capture, VM activation or actual BPF syscall ran.
  The three test invocations together used about 0.890 seconds of command-runner
  wall time, excluding approval/tool overhead; active engineering time was not
  separately instrumented and must not be equated to these runtimes.

Zero admission/RUN/final gate entries closed in this building-block batch.
Next is the concrete outer capture integration and sensor/program/map applicability
join described below, not another verification-only wave. The final acceptance
campaign remains blocked and the implementation heartbeat remains active.

Successor-integration checkpoint, 2026-10-05 UTC: implemented the concrete
host/guest capture path and its separate independent readback consumer, preserving
all frozen predecessors and retained evidence. Review corrected a genuine
merged-`/usr` unit-path mismatch using a held/rechecked exact `/lib -> usr/lib`
alias guard; it does not normalize away the original systemd readback. Review
also removed atime-sensitive custody comparisons and restored every inherited
observation/cleanup/claim-ceiling acceptance predicate in the new host wrapper.

One selected pipeline invocation passed all four affected/new stages on their
first attempts. It reused unchanged `pipeline-unit` and
`native-plugin-update-binding` results without executing them. The registry
declares the reviewed source/import/writer-contract input closure for each stage.

| Stage | Tests | Unittest time | Fingerprint |
|---|---:|---:|---|
| Native identity with merged-`/usr` guard | 18 | 0.017 s | `d41456699438f22162de1f8737c83e6da4bf49e5472b6f278d3fb5bf3ef9e792` |
| Provisioning-pin/update guest | 9 | 0.033 s | `af75f2cdf8b29b281f78a625c487dbdb1f04ca8c0d6932f26877d3a86c798b00` |
| Successor capture host | 8 | 0.003 s | `047a339224f90d3535994e06607a07765e4f9cc09740d0fd726f920da58534e7` |
| Independent local readback binding | 4 | 0.229 s | `c6aeef57f3fbdb34e5d11344f93248f9848ca1ea08fae87536e22c7429e9eeec` |

These are 25 new tests plus 14 affected reader tests, not 39 newly closed gates.
The verifier's constructed records are explicitly unit-contract data in memory,
not replacement acceptance samples or a rewritten historical capture. No broad
suite, historical recapture, VM/service activation, actual BPF syscall, live
update, performance measurement or final acceptance ran. Engineering wall time
was not separately instrumented; unittest time is not implementation runtime.
Zero admission/RUN/final gates closed in this batch. The next dependency is
independent Python/Node binary-pin provenance and one guarded successor capture,
alongside the pinned-source sensor/program/attachment applicability work. Local
signed checkpoint only; no additional automatic push authorization was received.

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

The [collection seam](src/aragorn/native_phase3_plugin_update_collection.py) and
[offline CLI](scripts/native_plugin_update_collection.py) now prepare a reported
identity proposal, retain caller-pinned capture/source/deployment bytes and
independently replay the complete CAS collection. Retention publishes its manifest
after checking child references; a manifest alone never proves successful replay.
This connects capture *output* to the common envelope, not the live execution
boundary. It imports no capture scripts and performs no live operations.

Invoke from the repository root using the capture producer's caller-held pins:

```sh
PYTHONPATH=src /opt/homebrew/bin/python3.12 -S -B -m scripts.native_plugin_update_collection prepare \
  --capture "$CAPTURE" --expected-capture-digest "$CAPTURE_DIGEST" \
  --expected-source-digest "$SOURCE_DIGEST" --expected-source-commit "$SOURCE_COMMIT"
```

Review the returned reported-identity proposal. `retain` uses the same flags plus
`--deployment`, `--expected-deployment-digest` and `--cas`; supply the exact UTF-8
bytes displayed in `result.deployment_raw.text`, without adding a newline.
`replay` takes the caller-held capture/source/deployment pins, `--cas` and
`--expected-collection-digest`, with no capture/deployment file arguments.
Replay opens the store read-only. Preparation does not write; retention writes
only to the selected CAS. These commands neither execute nor authorize a fresh
capture, and must not be used to approve a live deployment merely from its report.

The next F0 implementation slice adds concrete
[native identity readback](src/aragorn/native_phase3_live_identity.py) and a
[read-only stats-map reader](src/aragorn/runtime_tetragon_stats_map.py).
The native reader checks selected fixed files and loaded credentials through
PIDFD-pinned process roots, bracketed by kernel/systemd identity checks. Whole
runtime-tree/image, complete installed profile and signed-source bindings still
belong to the existing outer fixture adapter. It must not infer executed script
provenance merely from the gateway's rewritten process title.

The map reader uses only read-only OBJ_GET, GET_INFO_BY_FD and key-zero LOOKUP_ELEM,
with exact caller-held expectations and before/after continuity checks. Its
[source slice](benchmark/tetragon-stats-map-source-v1/README.md) establishes the
selected map's 256-by-7 u64 layout and sequential per-CPU copy ABI, not the running
sensor's image or program-map ownership. A successful map read does not turn an
absent Prometheus counter into qualifying zero-loss evidence.

**Successor capture integration:** the new
[host entrypoint](scripts/capture_runtime_native_plugin_update_identity_check.py)
and [guest wrapper](scripts/runtime_native_plugin_update_identity_check.py)
reuse the unchanged native update adapter and its owned cleanup. The original
observation, 13-file input bundle and outer runtime/image/profile/source guards
remain intact. The wrapper freezes seven hashes from actual provisioning writer
arguments before activation, then brackets exactly one update-adapter invocation
with live reads. Eleven static file pins must be supplied independently; eight
are cross-checked against the staged profile and the entrypoint against the
existing runtime pin. The new offline preparer derives Python/Node expectations
from the fixed September 3 record for the exact fixture image, cross-joining
Python to the native update record. These historical expectations are not a
current image attestation. Never learn them from the same readback being verified.

The [independent live-binding consumer](src/aragorn/native_phase3_plugin_update_live_binding.py)
consumes the entire successor capture, retaining the original reported-identity
verification and adding selected file/process/credential/provisioning joins. It
requires a read-only CAS containing the seven deployment artifacts, three exact
helper source blobs and canonical static-pin manifest at caller-held digests.
It does not import the reader or capture code, trust a recorded comparison/PASS,
or make any deployment dimension fully live-attested. The existing offline
collection CLI now adds `retain-live` and `replay-live`: these retain the
original reported-identity collection plus the live envelope, static manifest,
exact three helper sources and independent consumer result. Replay recomputes
both consumers and rereads the complete closure; no recorded PASS is authority.
Original `prepare`/`retain`/`replay` behavior and formats remain unchanged.

The repo-local CLI uses the existing Python 3.12/standard-library toolchain:

```sh
/opt/homebrew/bin/python3.12 -B scripts/capture_runtime_native_plugin_update_identity_check.py --help
/opt/homebrew/bin/python3.12 -B scripts/capture_runtime_native_plugin_update_identity_check.py capture \
  --static-pins "$ABSOLUTE_CANONICAL_STATIC_PINS" \
  --expected-static-pins-digest "$STATIC_PINS_DIGEST" --out "$ABSENT_ABSOLUTE_OUTPUT"
```

`--help` is read-only; `capture` is the explicit live operation and must not run
until the owned-fixture prerequisites and independently sourced pins are ready.
The pin document has exactly `schema` (the fixed
`aragorn/native-plugin-update-identity-static-pins/v1`) and `file_digests` (the
eleven exact static paths), canonical JSON without a newline. No credentials or
global installation are required. Success stdout is a JSON object with `status`,
`path` and exact output `digest`; controlled execution refusal returns status
`REFUSED` and exit 2. Unexpected failures emit a fixed reason plus bounded
repository-relative Python frame locations, never exception text or locals.
There are no effect retries. Six observer monotonic stamps bracket the adapter;
they are not the required end-to-end decision latency measurement.

**Offline preparation and retention:** use the existing Python 3.12 toolchain:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/prepare_native_plugin_update_identity_pins.py prepare \
  --out "$ABSENT_ABSOLUTE_STATIC_PINS" --provenance-out "$ABSENT_ABSOLUTE_PROVENANCE"
```

Both output paths must be absent and direct (no symlink ancestry). Preparation
writes provenance first and the canonical eleven-file manifest last; partial
output on refusal is preserved and never treated as success. No VM, network,
credentials, installation, or capture execution is involved.

After a fresh reviewed successor capture, `retain-live` takes all original
capture/source/deployment pins plus `--expected-live-identity-digest`,
`--expected-static-pin-manifest-digest` and the exact three
`--expected-live-{host,guest,reader}-source-digest` pins. Supply direct files with
`--static-pin-manifest` and `--live-{host,guest,reader}-source` and the chosen
`--cas`. `replay-live` takes the same caller pins plus
`--expected-collection-digest`, without direct input files, and opens CAS
read-only. These are offline operations, not authorization for live execution.

The focused reviewed batch passed **36 new/affected unit checks**, including
12 new methods, on first attempt through the pipeline. Five unchanged dependency
stages reused their exact recorded passes. No live capture or final acceptance
was performed by those checks; no Phase 3 exit entry closed.

**First successor identity attempt (2026-10-05):** signed source `01b6673`
produced retained [v1 refusal evidence](benchmark/evidence/phase3-native-plugin-update-identity-development-v1-2026-10-05.json),
digest `sha256:dcd90962a80d36a63b5f5200c5db4db2fa188dffe9af486e856a523d65750afa`.
All seven writer pins froze before one activation, but `BEFORE_READ` refused
before any update-adapter invocation. The old guest erased the reader's failure
location, so the first thrown check cannot be reconstructed. Offline inspection
did identify a deterministic blocker: the reader required a root-owned runtime
entrypoint although the fixed read-only runtime volume and entrypoint are owned
by UID/GID 1000. The successor fix must retain exact ownership, digest and
read-only mount checks, not accept arbitrary ownership or writable runtime data.
No unchanged capture retry is permitted. Future refusal diagnostics retain only
bounded fixed-source locations, never exception text, credentials or locals.
The reviewed correction now enforces exact entrypoint ownership/mode and
before/after `ST_RDONLY` checks on the held file and all runtime ancestors in
both observer and gateway views. The independent consumer checks matching
ownership against both retained runtime mount snapshots. Its **60 new/affected
checks** (four new methods) passed on their first pipeline attempt; two unchanged
dependency stages reused their recorded passes. The failed v1 bytes remain
unchanged. A corrected-source capture is a distinct changed-behavior operation,
not an automatic retry or qualification sample.

The [operation checkpoint](benchmark/evidence/phase3-native-plugin-update-identity-operation-v1-2026-10-05.json)
records removal of the exact owned fixture and four snapshot helpers, unchanged
ID/name/state inventories for all 78 pre-existing containers, unchanged `default`
Docker context and restoration of `aragorn-bakeoff` to stopped. The guest window
was 16.34 seconds; this is neither total VM/capture runtime nor decision latency.
Active engineering time is not separately instrumented. No Phase 3 gate closed.

**Corrected successor identity integration (2026-10-05):** signed source
`dbffea9` produced [v2 live evidence](benchmark/evidence/phase3-native-plugin-update-identity-development-v2-2026-10-05.json),
digest `sha256:9c892c8d1ca42e9c7632c4feff511f8941725416c0d14a81c047faf5eb1e0f63`.
All eighteen selected file pins and four process epochs were read successfully;
the snapshots matched around exactly one existing local-marketplace update
adapter invocation. This exercised the real ownership fix, not another historical
recapture. The original denial result, frozen predecessors and failed v1 remain.

`retain-live` verified and retained the 19-blob closure, then `replay-live`
independently replayed a fresh CAS extracted from the
[transport](benchmark/evidence/phase3-native-plugin-update-identity-cas-v2-2026-10-05.tar.gz).
The [replay report](benchmark/evidence/phase3-native-plugin-update-identity-replay-v2-2026-10-05.json)
records `BOUNDED_LOCAL_READBACK_JOINS_VERIFIED`; collection digest
`sha256:15180762e874d2e01feddd915633a3a4a80dcfd7380898c484eb6e6ddadad9f4`,
verification digest `sha256:499421dd6d07ba42f694413c533424ff129a7905e5eeb10954698714b5f0c55d`.
This completes the selected F0 case's live-readback/retention connection, not F0's
entire deployment/telemetry contract or an admission/RUN/metrics exit entry.
All full-attestation and qualification flags remain false.

The [v2 operation checkpoint](benchmark/evidence/phase3-native-plugin-update-identity-operation-v2-2026-10-05.json)
records four inactive fixture services, removal of owned containers, unchanged
78-container inventories and `default` context, and restoration of the VM to
stopped. The guest window was 26.50 seconds, including the two identity reads;
it is not end-to-end decision latency. No live replay was used for retention.

**Native prepared-case implementation (2026-10-05):** the new fixed
`capture_native_phase3_plugin_update_case.py` entrypoint exposes `inspect`,
`capture`, and read-only `replay`. It composes the existing owned native fixture
and live collection. The caller retains a canonical fixed-route intent and its
complete CAS input closure; the host compares the signed source record, all six
controller/live helper sources, and the exact staged 70-file profile before the
guest operation. Shared controller identity and the case-specific four-probe
adapter remain separate artifacts. Only this one marketplace branch is wired;
the adapter map is not an inventory of all 31 cases.

The guest uses the existing identity wrapper's trusted internal preactivation
hook. After all seven writer inputs are frozen, it validates their cross-document
joins against the caller's deployment, publishes a nonsecret request to an
absent-only root-owned guest CAS, and reads it back **before** the activation
counter advances. Failure in that hook prevents activation. Raw provisioning
inputs stay in memory and are cleared; neither the gateway token environment
nor configuration bytes enter the request. This is guest-local custody, not a
host ACK or independent proof of execution ordering. Offline replay recomputes
both existing consumers and rechecks the complete nested evidence closure.

Repository-local command surface (existing Python 3.12, no installation or auth
configuration; uppercase arguments below are operator-supplied absolute paths
or `sha256:` pins, not ready-to-run values):

```text
python3.12 -S -B scripts/capture_native_phase3_plugin_update_case.py inspect --cas ABS_CAS --expected-intent-digest INTENT_PIN
python3.12 -S -B scripts/capture_native_phase3_plugin_update_case.py capture --cas ABS_CAS --expected-intent-digest INTENT_PIN --out ABSENT_ABS_OUTPUT
python3.12 -S -B scripts/capture_native_phase3_plugin_update_case.py replay --cas ABS_CAS --expected-intent-digest INTENT_PIN --expected-request-digest REQUEST_PIN --expected-collection-digest COLLECTION_PIN
```

`inspect` checks only the read-only input closure and reports
`INPUT_CLOSURE_VERIFIED`; it is not a live-readiness verdict. `capture` is the only
effecting command and requires the already running authorized isolated VM and
all inherited fixture guards; it never starts the VM or retries an effect.
It saves the raw capture/guest envelope to the absent output before offline
retention, so consumer refusal does not discard the executed observation.
`replay` is read-only and recomputes the retained request/collection joins.
All outputs are JSON envelopes. Refusals return code 2 and fixed reason/location
metadata, not raw exception messages or credentials. No generic command/route
escape hatch is exposed. Input-intent construction for the current signed
controller remains the next integration step.

Source review corrected the previous credential concern: the canonical gateway
configuration and worker binding are stable; the random token is written to a
separate environment file. Runtime/profile cgroups, grants and genesis remain
per-run inputs. Their **fresh writer bytes**, not v2 readback, determine the
request's seven provisioning hashes. The shared configuration/worker/policy
artifacts must still match those fresh inputs before activation.

No new live case capture, sensor observation or acceptance run was performed
for this implementation batch. Inert tests cannot establish deployment,
preactivation ordering in a real fixture, admission semantics, or any exit gate.
The [implementation checkpoint](benchmark/evidence/phase3-native-prepared-case-implementation-v1-2026-10-05.json)
records 69 passing new/affected tests (34 new methods), five unchanged prerequisite
stages reused, and 3.144 seconds summed stage wall time. The approximately
26.5-minute session window includes parallel implementation and review, not just
test runtime. The earlier registry preflight refusal occurred while a declared
host test file was still being authored; no stage started and no fingerprint
record was removed or retried. Zero exit-gate entries were newly qualified.

**Next integration batch:** construct the caller-held intent with the current
signed controller closure and existing pinned artifacts, then review the exact
owned fixture prerequisites for one newly necessary preactivation-boundary
check. Do not relabel v2 evidence as execution of this new request protocol.
The old `capture_openclaw_final_v3_campaign_case.capture_case` is only an API-shape
reference: its frozen-parent validator rejects the native target and must not be
weakened. The new request connection is not yet in the complete admission
dispatcher/verifier inventory. Preserve `OBSERVED`/`REFUSED` and qualification
ceilings until actual admission semantics are complete. Do not recapture this
branch just to exercise retention. Continue the dependency-ready admission
family ports after this common native seam is joined.
Complete Tetragon program/map/sensor applicability and join actual readback to
raw scrape accounting before one guarded native OS-event integration check.
The map/program association requires pinned producer/loader and Linux
program/link/PIDFD ABI source, now retained in the
[new source supplement](benchmark/tetragon-program-map-source-v1/README.md).
The source confirms that `used_maps` may include explicitly bound maps unused by
instructions, and perf-link info lacks enabled-state/responsiveness evidence.
Linux 6.8 name queries require a bounded input buffer, not inferred size discovery.
Some retained Tetragon event-output paths do not
update the selected stats map, so map membership alone cannot prove complete
event-loss accounting. Unsupported attachment/tail-call paths remain unresolved.
The new `runtime_tetragon_program_map.py` reader observes only a caller-selected
sensor-held exit-program/map/perf-link association. It uses bounded INFO queries,
checks held duplicates and fresh duplicates of the original sensor FD slots,
and closes every observer FD before returning. Duplicating descriptors extends
object lifetime; before/after checks do not prove continuous slot custody. The
reader does not claim program execution, enabled attachment, responsive sensor,
or loss completeness. Its eight new inert tests passed; three exact unchanged
prerequisite stages were reused from cache.
Do not create another offline collection abstraction or recapture only to
exercise retention. Then advance admission ports and measurement callbacks in
the order above. Final acceptance remains blocked.

Progress updates should report: closed gate entries, entries still needing
implementation, changed-behavior checks performed, active engineering time,
machine time, and the next dependency. Do not report an unsupported overall
percentage or an arbitrary number of equal-sized waves remaining.
