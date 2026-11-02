# Approved Phase 3 acceptance mapping: Pi-core managed profile v1

Date: 2026-11-02. Status: **APPROVED BY THE USER — NOT YET AN EXECUTABLE
QUALIFICATION CONTRACT OR RESULT**. Based on the approved [SDD](pi-core-managed-capability-sdd-v1.md)
and selected [dependency pins](pi-core-dependency-pins-v1.md).

The user approved this exact 29-requirement mapping and separately authorized
the first offline connected implementation batch. No live operations were
authorized. See the [bounded batch release](../phase3/coordinator/pi-core-connected-batch-1.md).

This document is the approved successor qualification design, not a result,
waiver, executable manifest or implementation release. It does not modify
`benchmark/phase3-exit-gate-manifest-v1.json`, its hard-pinned digest,
`phase3_exit_qualification.py`, the original ledger or any retained evidence.

## Recorded approval

Approved: a separately versioned **`pi-core-managed-phase3/v1`** contract with
**29 logical evidence requirements**:

| Family | Original v1 | Approved managed profile | Change |
| --- | ---: | ---: | --- |
| Admission | 31 | 12 | Retain ten runtime-neutral requirements; replace 21 ecosystem-specific update/reload assertions with two comprehensive managed lifecycle requirements |
| RUN properties/events/responses | 15 | 15 | Retain every property, all seven events and all six responses |
| External enforcement boundary | 1 | 1 | Retain independent OS broker/sensor and source/identity custody |
| Measurement semantics | 1 | 1 | Retain actual 100 attempts/100 pairs and all numeric thresholds |
| Total logical requirement IDs | 48 | 29 | Namespace all successor IDs with `MP1/`; no old PASS is transferred |

**29 is not a test budget.** Twelve admission requirements are not twelve test
cases. Each requirement must cover all actual supported and denied entrypoints
in the frozen managed deployment. The original 31-case admission campaign is
not claimed completed or preserved unchanged: its ecosystem-specific case
inventory is replaced under this explicit approval by the complete
managed surface inventory. Do not pad it with fictional OpenClaw-like cases or
reduce it to one example per group.

This is a narrower product compatibility scope with the same stated security
properties and quantitative standards. Arbitrary native-plugin compatibility,
OpenClaw ecosystem updaters and shared session restoration are deliberately not
claimed. Excluding them requires verified absence/denial and bypass-resistant
deployment evidence, not an automatic PASS or an N/A result.

## Result and deployment rules

Every successor ID requires a semantic verifier over raw independently held
evidence from **one exact deployment**. `PASS`, `FAIL`, `NOT_TESTED` retain their
existing meanings: mandatory FAIL eliminates the candidate; NOT_TESTED cannot
pass. There is no N/A escape hatch. Crosswalk disposition is not an outcome.

Retain the seven deployment bindings (runtime, adapter, configuration, worker,
OS profile, policy, Aragorn version), supported artifact closure, loaded-source
custody and exact activation identity. Any relevant change requires review and
new applicable evidence. Original results remain immutable under their old
runtime/environment fingerprints. No cache transfer or evidence relabelling.

Original v1 remains an incomplete original-profile result unless independently
completed. A successor PASS must be reported as **Pi-core managed-profile Phase
3 qualification**, never an OpenClaw PASS or universal runtime qualification.
No Phase 4 readiness, public release, EDR claim or implementation authority is
granted merely by approving this proposal.

## Approved admission requirements

All IDs below start with `MP1/`. The suffixes are shown fully in the crosswalk.

| Suffix | Mandatory managed behavior |
| --- | --- |
| `DET-01` | Same canonical artifact/evidence/policy/target inputs yield identical decisions |
| `ADM-01/exact-admitted-bytes` | Actual consumed instructions, supporting files, scripts, interpreters/dependencies and target deployment match the admitted immutable closure |
| `ADM-02/install` | Only operator-managed supported materialization can activate; incomplete closure, unsupported formats, native extensions and self-installation refuse |
| `ADM-02/update` | Every replacement gets new admission and fresh worker identity; no force bypass, stale grant, active-tree substitution or inherited approval |
| `ADM-02/direct-write` | Writes cannot alter admitted/consumed capability or authority material; scratch cannot become an unauthorized loader |
| `ADM-02/rename` | Rename/replacement cannot substitute admitted material or escape the approved object/root |
| `ADM-02/symlink` | Link insertion/retargeting cannot substitute bytes or escape closure |
| `ADM-02/auto-discovery` | Project/home/package/plugin/remote/ambient resources cannot add capability material or authority |
| `ADM-02/reload` | In-place reload, cache rebuild and session restore cannot introduce unadmitted material or inherited authority; supported replacement uses update |
| `ADM-02/restart` | Every start rechecks bytes, policy, revocation and health with fresh process/context/authority and no inherited session credentials |
| `ADM-03/policy-failure` | Missing/malformed/unavailable/failing/timed-out required policy prevents activation/effects as applicable |
| `ADM-03/policy-tampering` | Untrusted policy/config/authority/source-binding changes cannot weaken enforcement; independent readback establishes what remains loaded |

## Complete original-to-successor crosswalk

Retained = same substantive obligation, **fresh target-bound evidence needed**.
Replaced = managed mechanism must establish the security property. Excluded =
functional compatibility is outside the approved profile; relevant ingress is
unavailable or denied under the listed successor requirements. No exclusion
changes any original result. Target cells omit only the common `MP1/` prefix.

| # | Exact original ID | Disposition | Successor suffix / required interpretation |
| --- | --- | --- | --- |
| 1 | `DET-01` | Retained | `DET-01` |
| 2 | `ADM-01/exact-admitted-bytes` | Retained | `ADM-01/exact-admitted-bytes` |
| 3 | `ADM-02/install` | Retained | `ADM-02/install`; supported inputs only, real positive activation and refusal |
| 4 | `ADM-02/direct-write` | Retained | `ADM-02/direct-write`; no admission bypass |
| 5 | `ADM-02/rename` | Retained | `ADM-02/rename` |
| 6 | `ADM-02/symlink` | Retained | `ADM-02/symlink` |
| 7 | `ADM-02/auto-discovery` | Retained | `ADM-02/auto-discovery`; implicit discovery denied |
| 8 | `ADM-02/restart` | Retained | `ADM-02/restart`; fresh managed activation |
| 9 | `ADM-02/update/archive-source-force-replacement` | Replaced | `ADM-02/update`, `ADM-02/install`; no force bypass; unsupported archives refuse |
| 10 | `ADM-02/update/clawhub-tracked-replacement` | Excluded | `ADM-02/install`, `ADM-02/update`; unmanaged registry/package replacement denied |
| 11 | `ADM-02/update/config-entry-activation` | Replaced | `ADM-02/install`, `ADM-02/restart`; config cannot activate unadmitted bytes; authority changes need newly bound deployment |
| 12 | `ADM-02/update/core-updater-plugin-replacement` | Excluded | `ADM-02/update`, `ADM-02/auto-discovery`, `ADM-02/restart`; no vendor updater/native-plugin authority |
| 13 | `ADM-02/update/curator-restore-activation` | Excluded | `ADM-02/install`, `ADM-02/reload`; no curator restore; old artifacts require current admission/revocation checks |
| 14 | `ADM-02/update/plugin-enable-activation` | Excluded | `ADM-02/install`, `ADM-02/reload`; native-extension enablement cannot activate code |
| 15 | `ADM-02/update/plugin-force-reinstall` | Excluded | `ADM-02/install`, `ADM-02/update`; no native reinstall/force escape |
| 16 | `ADM-02/update/plugin-package-skill-replacement` | Excluded | `ADM-02/update`, `ADM-02/auto-discovery`; native packages cannot inject skills; portable bundles require ordinary admission |
| 17 | `ADM-02/update/workshop-proposal-apply` | Excluded | `ADM-02/direct-write`, `ADM-02/reload`; proposals cannot self-approve or mutate active material |
| 18 | `ADM-02/reload/chat-session-snapshot-consumer` | Excluded | `ADM-02/reload`, `ADM-02/restart`; no restored shared chat state/authority |
| 19 | `ADM-02/reload/config-invalidation` | Replaced | `ADM-02/reload`, `ADM-02/restart`; no hot activation from config; fresh bound deployment required |
| 20 | `ADM-02/reload/cron-rescan` | Excluded | `ADM-02/auto-discovery`, `ADM-02/reload`; no autonomous ecosystem rescan/activation |
| 21 | `ADM-02/reload/filesystem-watch-invalidation` | Excluded | `ADM-02/auto-discovery`, `ADM-02/reload`; watched mutations cannot alter activation/load another bundle |
| 22 | `ADM-02/reload/fresh-session-reset` | Replaced | `ADM-02/restart`; fresh worker/context and renewed authority |
| 23 | `ADM-02/reload/manual-plugin-invalidation` | Excluded | `ADM-02/reload`; no native plugin reload authority |
| 24 | `ADM-02/reload/missing-prompt-blob-rebuild` | Replaced | `ADM-01/exact-admitted-bytes`, `ADM-02/reload`; missing consumed bytes fail closed, not untrusted reconstruction |
| 25 | `ADM-02/reload/plugin-skill-dir-activation` | Excluded | `ADM-02/auto-discovery`; plugin directories cannot contribute capabilities |
| 26 | `ADM-02/reload/remote-eligibility-invalidation` | Excluded | `ADM-02/auto-discovery`, `EXTERNAL_OS_BROKER_AND_OUT_OF_PROCESS_SENSOR`; no remote/MCP authority expansion |
| 27 | `ADM-02/reload/sandbox-per-run-rescan` | Replaced | `ADM-02/restart`, `ADM-02/auto-discovery`; fresh worker sees only the admitted closure |
| 28 | `ADM-02/reload/session-snapshot-consumer` | Excluded | `ADM-02/reload`, `ADM-02/restart`; saved snapshots cannot reactivate old/cross-capability authority |
| 29 | `ADM-02/reload/workshop-invalidation` | Excluded | `ADM-02/reload`, `ADM-02/direct-write`; no self-edited workshop activation |
| 30 | `ADM-03/policy-failure` | Retained | `ADM-03/policy-failure` |
| 31 | `ADM-03/policy-tampering` | Retained | `ADM-03/policy-tampering` |
| 32 | `RUN-01` | Retained | `RUN-01`; authenticated activation/process/descendant/request/effect lineage, not claimed names |
| 33 | `RUN-02` | Retained | `RUN-02`; pre-effect authorization, current revocation/health, honest cancellation outcomes |
| 34 | `EVENT/SKILL_ACTIVATION_AND_COMPLETION` | Retained | Same suffix; real activation and completion, no instruction-level semantic causation claim |
| 35 | `EVENT/TOOL_CALL_ATTEMPT_AND_RESULT` | Retained | Same suffix; denied and ambiguous protected operations included |
| 36 | `EVENT/PROCESS_EXECUTION_AND_ANCESTRY` | Retained | Same suffix; worker and declared script/interpreter descendants |
| 37 | `EVENT/FILE_READ_WRITE_RENAME_AND_EXECUTABLE_CREATION` | Retained | Same suffix; every named operation, not create-only substitution |
| 38 | `EVENT/NETWORK_CONNECTION_AND_DNS_ATTEMPT` | Retained | Same suffix; actual attempts, including model/API mediation |
| 39 | `EVENT/CREDENTIAL_OR_CANARY_ACCESS` | Retained | Same suffix; actual access attribution, not credential plumbing |
| 40 | `EVENT/PROMPT_CONTEXT_OR_MEMORY_MUTATION_WHERE_RUNTIME_EXPOSES_IT` | Retained | Same suffix; inventory and observe exposed within-activation context changes despite exclusion of shared memory |
| 41 | `RESPONSE/ALERT_AND_RETAIN_EVIDENCE` | Retained | Same suffix; actual alert and protected retention/readback |
| 42 | `RESPONSE/BLOCK_PRE_EFFECT_TOOL_OR_NETWORK_ACTION` | Retained | Same suffix; independently observed residue-free denial |
| 43 | `RESPONSE/TERMINATE_CAPABILITY_PROCESS_TREE` | Retained | Same suffix; exact activation and all owned descendants, including detached children |
| 44 | `RESPONSE/QUARANTINE_INSTALLED_DIGEST` | Retained | Same suffix; digest-specific quarantine, not whole-service masking |
| 45 | `RESPONSE/REVOKE_FUTURE_STARTS_OF_DIGEST` | Retained | Same suffix; subsequent actual start denial |
| 46 | `RESPONSE/ISOLATE_EGRESS_OR_SUSPEND_HIGH_RISK_OPERATIONS_WHEN_SENSOR_HEALTH_IS_LOST` | Retained | Same suffix; missing/stale/hung/reset/lost health triggers real enforcement and preserves uncertainty |
| 47 | `EXTERNAL_OS_BROKER_AND_OUT_OF_PROCESS_SENSOR` | Retained | Same suffix; separately protected authority, loaded-source custody, authenticated peer, no direct effect/credential bypass |
| 48 | `MEASUREMENT_SEMANTICS` | Retained | Same suffix; real effects/tasks/timing and independent verification |

## Mandatory surface inventory for the managed deployment

This is the design-level inventory to bind to actual source entrypoints before
freeze. It deliberately describes real managed surfaces and bypass attempts,
not nonexistent OpenClaw command invocations. Every reachable entrypoint must
appear in the later source-bound inventory; each positive and negative obligation
below is mandatory. Newly discovered surfaces require review, not silent omission.

| Surface | Required positive / denied behavior | Requirement family |
| --- | --- | --- |
| Operator bundle submission/materialization | Supported complete closure can admit; incomplete closure, unsupported package/archive, install hooks and native-extension formats cannot activate | install, exact bytes |
| Managed replacement | New admitted bytes start a fresh worker; force replacement, old grants, changed dependencies and unreviewed rollback cannot inherit approval | update |
| Configuration selection | Approved bundle/deployment config can start; config edits cannot select unadmitted artifacts or broaden authority in place | install, restart, policy tampering |
| Read-only admitted tree and scratch | Scratch computation is permitted; direct write, rename and symlink paths cannot replace consumed content or use scratch as an executable loader | direct-write, rename, symlink, exact bytes |
| Ambient loader roots | Admitted context is explicit; home/project/plugin/package/env preload paths cannot add code, instructions or tools | auto-discovery, exact bytes |
| Reload/cache/session/restore | No in-place hot reload or state-derived reactivation; missing material fails closed; a restart cannot inherit another activation's context/grants | reload, restart |
| Worker/script/interpreter entrypoints | Only declared exact executables/dependencies run in confined owned processes; dynamic imports, downloaded executables, general shell and escape descendants cannot broaden scope | exact bytes, install, RUN-01/02, process event |
| Native plugins, ecosystem updaters and remote MCP | Unsupported functionality unavailable; equivalent ingress and OS bypass attempts cannot load capabilities or reach protected effects | install, update, reload, discovery, external boundary |
| Startup/recovery/restart | Fresh exact activation allowed only with valid admission/policy/revocation/health; stale or revoked startup and cleanup failure cannot silently resume | restart, RUN-02, future-start revocation |
| Broker/protected effect IPC | Authenticated exact peer/activation and one-use scoped action allowed; shared-UID impostor, replay, substitution, expired authority and bypass denied | RUN-01/02, external boundary |
| Model/provider/API route | Explicit data-authorized request can complete; endpoint/model/data-scope violations, inherited secrets, proxy/redirect/local-service bypass and uncontrolled telemetry routes denied | RUN-02, network/credential events, external boundary |
| Context mutation and lifecycle response | Exposed within-activation changes observed; policy/grant/evidence edits, cross-context state and continued authority after revocation denied | context event, RUN-01/02, all responses |

For a truly absent API, retain the pinned installed/source inventory establishing
absence plus evidence that actual available loader/OS routes cannot reproduce
the forbidden effect. A fabricated CLI "unknown command" result is insufficient.
For a present denied API, exercise its actual implementation and independently
observe denial/no protected residue. Each obligation needs its own meaningful
evidence; one reused artifact may support multiple rows only when its semantics
really cover them. No requirement is satisfied by a list of intended settings.

## SDD-to-acceptance traceability

All SDD clauses MC-01 through MC-12 remain mandatory subclauses, not optional
design aspirations:

| SDD clause | Successor coverage |
| --- | --- |
| MC-01 closure | exact bytes, install, update |
| MC-02 admitted activation | exact bytes, restart, external boundary |
| MC-03 isolated identity | RUN-01, activation/process events, external boundary |
| MC-04 complete mediation | RUN-02, block response, external boundary |
| MC-05 bounded authority | RUN-01/02, tool/network events, external boundary |
| MC-06 fresh update | update, reload, restart |
| MC-07 revoke/quarantine/contain | RUN-02 and all applicable digest/termination responses |
| MC-08 meaningful health | RUN-02, health-loss response, external boundary |
| MC-09 cancellation/ambiguity | RUN-02, tool attempt/result, termination, measurements |
| MC-10 provider/data controls | RUN-02, network/credential events, external boundary; endpoint permission alone never satisfies payload/data policy |
| MC-11 useful allowed work | measurement semantics plus positive install/activation/tool results |
| MC-12 evidence/cleanup | alert/retention response, boundary, measurements and every contributing verifier |

## Quantitative standards — unchanged

- **100 actual action attempts** with caller-held exact IDs/families; both
  exfiltration and destructive families nonzero. Keep the existing fabricated
  lab design: HTTP25, DNS25, truncate25, unlink25, including the genuinely
  unattributed destructive negative control. Fabricated inputs are allowed;
  fabricated results or attribution are not.
- Attribution **>=99%**. Unattributed protected attempts must block pre-effect.
- **100% residue-free pre-effect blocking separately in both families**, observed
  at protected sinks over the relevant intervals, not inferred from a final
  restored file or self-reported receipt.
- Nearest-rank p95 over 100 full `REQUEST_ACCEPTED -> DECISION_FINALIZED`
  durations **<500 ms**, in a validated `CLOCK_BOOTTIME`/time-namespace domain.
- **100 completed baseline/instrumented task pairs**, same task/input/host
  bindings and equivalent fixture state. Preserve the four existing tasks
  (integer sum, line count, SHA-256, allowed-file copy/readback), 25 pairs each.
  Use real `TASK_ACCEPTED -> TASK_COMPLETED` timing; aggregate overhead **<10%**,
  specifically `100 * instrumented_total < 110 * baseline_total`, not average
  per-pair percentages. Preserve the declared baseline-first ordering and its
  limitation; do not generalize lab overhead to arbitrary production work.
- One frozen deployment, complete verifier/source inventory, independent
  semantic replay, retained failures and verified exact cleanup/prior state.

The performance suite measures these lab tasks and enforcement boundaries, not
LLM reasoning quality or production provider latency. A separately observed
useful model-assisted path is still needed for the pilot; it must not be confused
with the fixed quantitative suite or omitted because deny-only actions pass.
If model/provider or adapter work is part of the selected paired task's actual
completion path, its time remains inside the full task boundary on both sides;
do not exclude it to meet overhead or latency thresholds. Compare equivalent
tasks and declare the exact measured scope before collecting samples.

## Approval and future execution boundary

Approved design scope (the user separately released offline implementation):

> Approve `pi-core-managed-phase3/v1` with the 29 logical requirements and complete
> 48-row crosswalk above. Preserve original v1 and its historical results.
> Retain all stated security properties, 100-attempt/100-pair obligations and
> thresholds. Excluded functionality must be demonstrably unavailable or denied,
> never automatically PASS. Freeze the complete source-bound supported/denied
> entrypoint inventory before acceptance; 29 requirements do not cap the number
> of necessary cases. This approves the mapping only, not implementation, live
> operations, acceptance execution or Phase 4 readiness.

The user's separate implementation instruction now releases the first connected
offline slice using the selected dependency pins. It does not release live
operations or acceptance. Future necessary checks use the
existing reviewed fingerprint pipeline; unchanged successful results are reused,
unchanged failures are not rerun, and no broad regression is scheduled.

## Review record

Source-reviewed at `3c94e486a12d458dbf624193b6af03be67407b73` against the existing
manifest, exact inventory construction in `phase3_exit_qualification.py`,
coverage ledger and approved SDD. The original manifest digest is
`sha256:aff633a6d0d482cf79e3e540b0e7b8336cf266765eaacf277c9ac23ed5279f1d`.
No implementation or product tests were used to prepare this proposal. The
signature on the containing documentation commit proves authorship/integrity,
not qualification of behavior. Approval is the user's explicit subsequent
instruction, recorded at the top, not inferred from a signature.
