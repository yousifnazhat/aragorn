# SDD: Pi-core managed capability profile v1

Status: **architecture and managed-profile scope approved by the user, 2026-11-02**.
Implementation: the user subsequently released the
[first connected offline batch](../phase3/coordinator/pi-core-connected-batch-1.md).
No live operations are authorized. No product checks or live
operations were run for the original design decision. Research baseline:
`dc3fc10f38db62343c85bbe2d9c263d843d2e12a`.

This is the software design description and behavioral specification for a
specification-driven implementation. The [roadmap](pi-core-managed-profile-roadmap-v1.md)
orders future work. The existing [Phase 3 manifest](../../benchmark/phase3-exit-gate-manifest-v1.json)
and historical qualification records are unchanged.

Step-2 follow-up: [exact dependency pins](pi-core-dependency-pins-v1.md) and the
[complete acceptance crosswalk](pi-core-phase3-acceptance-mapping-v1.md)
are recorded. The user approved the 29-requirement mapping; executable
qualification machinery and actual evidence remain outstanding.
Pinning upstream components does not pin the not-yet-built adapter or deployment.

## Goal and approved decision

Aragorn is a capability-security system: it admits exact reviewed artifacts,
limits the authority they receive, observes their execution, and contains or
revokes them when policy or required health no longer permits execution.
It is not a new general-purpose coding assistant or a claim to secure every
existing agent installation transparently.

Use **Pi agent-core as a replaceable, unprivileged agent loop**, a thin TypeScript
adapter, the existing Python security core, and an externally enforced Linux
execution profile. Aragorn owns acquisition, admission, immutable storage,
activation, policy, grants, update/revocation and evidence. Neither the model nor
Pi owns security authority. Do not adopt full Pi, oh-my-pi or OpenClaw's native
extension lifecycle as the trusted foundation. Do not rewrite the security core
in Go without a separately measured need.

The choice favors explicit ownership of the capability lifecycle. It is not a
claim that Pi is intrinsically more secure than PydanticAI, that TypeScript is
safer than Python, or that a performance comparison has been completed.

## Q&A results and boundaries

The user selected capability security, a controlled environment, mission fit
over migration convenience, and then explicitly approved this managed profile.

| Included in the first managed profile | Excluded from the first managed profile |
| --- | --- |
| Portable Agent Skills bundles: `SKILL.md`, supporting files, declared executable tools/scripts and supported dependency closure | Arbitrary vendor-native in-process extensions/plugins |
| One capability bundle in each fresh isolated execution context | Shared multi-skill conversations, cross-capability memory and delegated agents |
| Useful permitted file/API work through externally authorized routes | Unrestricted shell, general host access, arbitrary network access |
| Explicit immutable installation and fresh-worker updates | Self-installation, in-place hot reload and implicit project/home discovery |
| Linux managed workers on an owned, controlled deployment | macOS/Windows enforcement and remote MCP execution environments |
| Local CLI/control interface and retained independent evidence | Coding-agent UI/product features, cloud multi-tenancy and Phase 4 scale |

The format specification's `allowed-tools` metadata is an input declaration, not
an effective permission. Unsupported formats or incomplete dependency closure
must not receive an effective ALLOW. Existing resolver limits still apply; this
design does not claim general npm/PyPI/archive support.

No architecture-choice question remains open. Upstream dependency pins are now
selected in the step-2 inventory. A concrete worker OS policy, adapter build and
operational credentials/endpoints remain future delivery inputs, not permission
to improvise broader scope. The separate **Phase 3
qualification-contract decision** remains explicit in the mapping section below.

## Deployment and trust model

The initial finished product lives as **Aragorn-managed services plus disposable
workers on a controlled Linux host or VM**. A developer's Mac may be a client;
it is not the enforcement boundary. Later hosting location does not change the
security contract. No service is activated by this documentation update.

```text
Operator -> acquisition / immutable CAS -> admission -> protected launcher
                                                        |
                                      one bundle, fresh worker identity
                                                        v
                                    untrusted Pi core + thin adapter
                                                        |
                                       authenticated operation requests
                                                        v
                         external Aragorn broker -> scoped executor / sink
                                   ^                         |
                                   |                         v
                         protected health <--- independent observations
                                   \-------> evidence + offline verifier
```

Trusted: Linux kernel/administrator, protected launcher, CAS integrity path,
deterministic policy and grant enforcement, scoped broker/executor mediation,
sensor/health acquisition and protected evidence custody. Keep the trusted code
and its privileges small. A service signature or process name does not attest
its loaded bytes.

Untrusted: third-party artifacts, acquisition/parser/analyzer outputs, model
responses, tool arguments/results, Pi, the TypeScript adapter and capability
scripts. Third-party code never runs in the trusted broker or control-plane
process. Analyzer isolation limitations already documented in `ARCHITECTURE.md`
are not cured merely by introducing Pi.

The worker has no production credentials, writable host mounts, policy/grant
keys, broker-private state, container socket or general network route. It can
read its admitted materialization and use disposable scratch space. Protected
workspace changes, external API actions and model-provider requests require
authorized mediation. Scratch writes are explicitly scoped local computation,
not permission to modify protected files.

## Behavioral requirements

The identifiers below trace this design; they are not a new executable gate
framework or a substitute for the existing Phase 3 IDs.

| ID | Required behavior | Evidence needed before claiming it |
| --- | --- | --- |
| MC-01 | Resolve and retain the complete supported artifact/tool/dependency closure before admission; reject undeclared executable expansion | Exact source/CAS inventory and independent closure rederivation |
| MC-02 | Activate only the admitted materialization with the pinned runtime, adapter and policy | Protected install/launch and actual-consumption custody, not file-name equality |
| MC-03 | Give each activation one fresh context and authenticated OS identity | Launcher-to-process/cgroup/session joins, no cross-activation authority |
| MC-04 | Mediate every protected effect externally; no direct worker bypass | Positive authorized effect plus independently observed denied bypass attempts |
| MC-05 | Bound authority to the exact action, target, activation, policy, freshness and current revocation/health state | Grant validation at effect boundary, replay/expiry/substitution refusals |
| MC-06 | Replace a capability only through new admission and a fresh activation | Changed-byte refusal and old/new identity separation |
| MC-07 | Revocation denies new actions and starts, quarantines the exact digest where required, and contains the complete owned process tree | External response readback and subsequent denial, not only an acknowledgement |
| MC-08 | Treat missing/stale/lost required telemetry as unknown and fail closed for protected work | Real liveness/progress/loss/identity evidence, not an idle heartbeat alone |
| MC-09 | Retain honest effect/cancellation outcomes without automatic repetition | Distinct not-submitted, submitted, completed/failed and indeterminate outcomes |
| MC-10 | Protect provider credentials and constrain data sent to the model/API | Authorized endpoint, payload/data-scope decision and externally held secret custody |
| MC-11 | Demonstrate useful allowed work and actual performance | Independent output/effect verification and real end-to-end timings |
| MC-12 | Preserve evidence and verify exact resource cleanup and prior-state restoration | Raw evidence, immutable bindings and independently checked cleanup |

### Bundle and activation identity

The bundle identity covers instructions, supporting files, executable entry
points and the supported dependency closure. The deployment separately binds
the Pi package/source, Node/interpreter/tool runtime, lockfile/build outputs,
adapter, configuration and OS enforcement profile. Do not pin only `SKILL.md`
while mutable scripts or runtime imports remain outside the identity.

Reuse the existing seven deployment dimensions: `runtime_commit_or_image`,
`adapter`, `configuration`, `worker`, `os_profile`, `policy`, `aragorn_version`.
An activation joins those bindings to the admission transaction, installed tree,
fresh activation/session epoch and kernel-observed worker identity. PIDs alone
are insufficient; preserve the existing PIDFD/start/cgroup/identity protections.

Reported tool-call IDs and skill names are correlation fields, not authority.
The claim is attribution to an **isolated admitted capability activation**,
not proof that a particular sentence caused the model's reasoning. A single
bundle may contain many instructions; Aragorn does not infer semantic causation.

### Loading and lifecycle

1. Acquire into quarantine without executing repository setup hooks. Parse and
   analyze in the established isolated or explicitly limited analysis profile.
2. Resolve supported closure; deterministically decide over immutable evidence,
   policy and the target deployment. Incomplete acquisition/analysis cannot ALLOW.
3. Materialize from verified CAS under protected ownership; reject path escapes,
   unauthorized replacement, unsafe links and mutable external dependencies.
4. The launcher verifies bindings and required health, starts a fresh confined
   worker, and establishes its protected identity before enabling any action.
5. Use a new process with a clean environment, home and working/scratch directory;
   do not inherit conversations, grants, credentials or mutable runtime state.
   Supply only the chosen bundle's context and broker-request tools. No implicit
   project/home settings, extensions, discovery, hooks, MCP or inherited session
   state. Configuration must be operator-controlled and part of the deployment.
6. Execute allowed operations; emit correlation records, independently observe
   outcomes and retain the actual evidence outside worker control.
7. On completion, revocation, cancellation or failure, close authority and
   contain the owned execution tree; retain terminal evidence and verify cleanup.

Changing any executable/supporting bytes, runtime, adapter or authority-relevant
configuration creates a new admission/deployment question. Never transfer old
approval to an in-place hot reload. Historical evidence remains bound to its
original identity. No automatic fallback to a different runtime or weaker mode.

### Tool, script and broker contract

The thin adapter converts model tool requests into the existing broker protocol
where it fits. It does not perform privileged effects itself. The external
broker authenticates the peer against protected activation state; a self-reported
activation ID is insufficient. Requests bind a unique operation, canonical typed
arguments/target, deadline and bounded authority. Reject ambiguous or unknown
operations, replayed grants, oversized/unframed messages and identity mismatch.
The existing relay's UID/GID check alone does not bind a connecting process to
the capability bundle; the managed caller must supply that protected peer join.

The TypeScript/Python boundary must agree on exact canonical bytes, Unicode,
integer ranges, digest inputs and result schemas. Never silently round Python
clock/identity integers into JavaScript numbers; use an explicitly reviewed
lossless representation when values exceed the shared safe integer range.

Revalidate current policy, revocation, required health and grant state within
the actual serialized effect boundary. Preserve one-action bounded grants;
do not turn the adapter's tool list into a blanket session permission.

Declared scripts execute only in a separately confined execution process, never
as imported code in the broker. Bind their exact entrypoint and interpreter to
the activation, and include descendants in observation/containment. The current
sole-worker/no-delegated-descendant assumption requires explicit adaptation for
these tool processes; a process group alone is not proof that detached children
are contained. No general shell or dynamic package installation is introduced.

Filesystem mediation must bind the actual opened object and approved root across
rename/symlink races. Network mediation must constrain destination, DNS resolution,
connect/send and redirects as applicable; endpoint allowlisting alone is not
complete data authorization. This reuses existing action-specific enforcement,
not a new generic proxy framework.

### Model access and data handling

Provider access is a protected egress path, not a control-plane exemption. Keep
provider credentials outside the worker. The approved route binds provider/model,
request scope, permitted data classes, endpoint and bounded request budget.
Treat provider responses as untrusted input. Audit metadata/digests while
retaining sensitive raw material only under the existing protected-evidence
rules. Never publish secrets in receipts, logs, commits or a review page.

The first positive task should use public or fabricated owned-lab inputs
explicitly authorized for that provider. Once information is supplied to an
agent, mere endpoint permission cannot guarantee it will not be included in a
later model request; enforce the declared data policy outside that agent.
The current `runtime_http_action.py` is a fixed lab canary transport, not a model
provider gateway. This provider boundary is new integration work, including
streaming, bounded cancellation, redirect/proxy/local-service restrictions and
request/response limits; do not describe it as already implemented.

### Failure, cancellation and recovery

Admission denial/error/incomplete closure prevents launch. Missing identity,
expired authority, stale policy, unknown/lost health and revocation prevent new
protected effects. Denial-only behavior is insufficient for product usefulness.

Preserve the existing distinction between refusal before submission and an
effect that was already submitted. Cancellation of a model loop is not proof
that a tool stopped. Retain final or indeterminate effect state, block automatic
retries of ambiguous operations, and verify external worker/executor shutdown.
Revocation cannot promise to undo a completed external effect.

An operator may inspect retained evidence and authorize a new attempt only after
diagnosis and changed relevant inputs. Cleanup may not erase evidence or touch
unrelated resources. Existing paused-fixture/private-retention holds remain;
this architecture decision does not release them.

## Reuse and required changes

Reuse means retain code and bounded evidence, then review the actual caller and
identity assumptions. It does not mean these components are already a portable
SDK or that their historic passes qualify the Pi deployment.

| Area | Existing anchors | Treatment |
| --- | --- | --- |
| Content custody and analysis | `src/aragorn/cas.py`, `policy.py`, existing resolvers/analyzers | Reuse; keep current supported closure limits and analysis isolation caveats |
| Deterministic admission | `admission_decision.py`, `decision_receipt.py` | Reuse decision semantics; adapt target/profile-specific path and closure assumptions |
| Effect decisions and grants | `runtime_action_decision.py`, `runtime_capability_grant.py`, `runtime_lineage_capability_issuer.py` | Reuse; bind the managed activation and preserve current-state checks at the real caller |
| Process and active identity | `runtime_process_profile.py`, `runtime_active_skill_lineage_v2.py` | Adapt executable/service/installed-root bindings and confined script-descendant handling |
| Broker/reader integration | `native_phase3_broker_reader_service.py`, `native_phase3_broker_reader_bootstrap.py`, `runtime_http_run_submission.py`, `runtime_http_broker.py` | Reuse reviewed leaves; complete real positive composition and health acquisition. Current service profile is refusal-only |
| Pi adapter and provider route | Existing Node framing/client in `packaging/openclaw/aragorn-runtime-action-worker/index.js`; fixed canary `runtime_http_action.py` | Reuse bounded framing/outcome semantics where compatible; new compiled Pi entrypoint, dependency closure and credential-isolated provider mediation are required |
| Health and response | `runtime_tetragon_*`, `runtime_health_*`, `runtime_response_service.py`, `runtime_revocation_service.py`, `runtime_quarantine_service.py` | Reuse; complete real acquisition/loss coverage, digest-specific response and containment |
| Evidence/measurements | `phase3_deployment.py`, `phase3_measurement_collector.py`, `phase3_measurement_replay.py`, existing independent consumers | Reuse interfaces; adapt exact deployment pins and acquire genuine outcomes/timings |
| Controlled workload design | `benchmark/phase3-reference-workloads-v1.md`, existing HTTP/DNS/destructive/paired-task helpers | Reuse fabricated lab inputs and real workload implementations; never synthesize substitute timing/effect samples |
| Focused validation | `scripts/phase3_pipeline.py`, `benchmark/phase3-pipeline-v1.json` | Reuse unchanged fingerprints only under their actual closure/environment; registry capacity is a later minimal review |
| Runtime integration | `packaging/openclaw/…/integration.cjs`, OpenClaw-specific worker/verifier assumptions | Preserve as historical/later compatibility target; add a narrow Pi adapter, not edits to frozen predecessors |
| Packaging/launch | Existing `packaging/systemd/` and staging/identity helpers | Adapt a successor Linux profile after reviewing exact UIDs, sockets, credentials, mounts, egress and loaded-source custody |

Current response code targets fixed gateway/worker units and whole-profile
shutdown. Managed containment must bind the exact activation unit/process tree
and digest; the existing service-target list is not already per-capability
quarantine. Frozen staging transformations are not generic Pi packagers.

No new sensor framework, evaluator framework, generic agent platform, CAS rewrite
or speculative language migration is authorized. Current component checks
(including Admission67, service44 and bootstrap69) remain useful bounded results,
not a fully wired or qualified deployment. Preserve all active lane drafts.

## Effect on Phase 3

**Phase 3 remains incomplete.** This approval changes the forward implementation
target, not the truth of the old benchmark results. It supersedes old directions
to keep expanding the OpenClaw-specific runtime as the default target; it does
not retrospectively change releases, gate results or operational holds.

`phase3_exit_qualification.py` pins manifest digest
`sha256:aff633a6d0d482cf79e3e540b0e7b8336cf266765eaacf277c9ac23ed5279f1d`
and exactly 48 IDs: 31 admission, 15 RUN, one external boundary and measurements.
The original evaluator has no N/A result. Twenty-one admission update/reload
routes explicitly name the old ecosystem. They cannot simply be renamed or
marked PASS because Pi does not implement them.

| Existing obligation | Managed-profile design mapping | Qualification consequence |
| --- | --- | --- |
| DET-01 / ADM-01 / ADM-03 | Determinism, exact consumed bytes, fail-closed policy | Retain semantics; new target-bound evidence required |
| Eight activation classes | Managed install/update/restart gate; direct write/rename/symlink/discovery/reload gate or demonstrably deny | Prove actual deployed coverage, not merely disabled configuration |
| 21 named ADM-02 routes | Fresh managed replacement where supported; native plugin, ecosystem updater/cache/reload paths excluded | No automatic equivalence to the original named routes; explicit versioned mapping required |
| Seven RUN event classes, six responses, RUN-01/02 | Activation, tools, process ancestry, file activity, network/DNS, canary/credential and exposed context/memory changes; external responses | Remain substantive security obligations; no hidden omission because the loop is simpler |
| External broker and out-of-process sensor | Linux isolation plus separately protected mediation/health | Pi callbacks are not an OS boundary |
| Measurement and independent replay | Actual effects, actual tasks and externally bound timings | Old OpenClaw evidence and unit timings cannot qualify Pi |

**Approved qualification design, executable successor still outstanding:**
retain original v1 forever and implement the separately reviewed managed-profile
successor mapping. Preserve security properties and numeric thresholds, replace
ecosystem-specific route assertions with a complete supported-path/denied-surface
inventory, and account for every original ID as retained, replaced or out of
scope. Do not pad a route count with fictional cases. User approval of that exact
mapping is now recorded; executable contract review and actual evidence still
precede any revised Phase 3 completion. The alternative is to complete the original OpenClaw qualification
separately; that is not the recommended parallel implementation campaign.

With that decision, the first offline connected slice is released. A bounded
**Pi managed-profile pilot** still requires the remaining D2 work and operational
release. It is neither the original
Phase 3 PASS nor permission to proceed to Phase 4.

The unchanged original final gates require one exact deployment, 31 admission
cases, 100 actual action attempts and 100 completed task pairs; attribution
at least 99%; 100% residue-free pre-effect blocking in each exfiltration and
destructive family; nearest-rank p95 synchronous decision latency below 500 ms;
aggregate paired overhead below 10%; independent semantic replay and verified
cleanup. The successor proposal must retain the substantive standards and
explicitly disclose any route-inventory/count change for approval. No acceptance
campaign is released now.

## Risks, nonclaims and decision records

- Main risk: an apparently narrow adapter still bypasses mediation through
  Node, subprocesses, credentials, filesystem or provider egress. OS policy and
  authenticated effect-boundary checks must address this, not prompts/hooks.
- Reuse risk: OpenClaw-specific identities remain hidden in otherwise reusable
  Python modules. Inventory concrete callers before moving code.
- Evidence risk: enough mocked leaves exist to look complete while useful
  positive execution, real health and source custody remain missing. Prioritize
  one connected path, then expand only against named requirements.
- Attribution limit: activation identity is defensible; semantic attribution
  to individual instructions is not claimed.
- Timing risk: no evidence establishes Python as the bottleneck or Pi as faster.
  Measure actual decision/task boundaries before optimizing or rewriting.
- Support limit: portable format support is not arbitrary dependency/platform
  support, general EDR, a prompt-injection cure or proof that a bundle is safe.

## Reference basis

Repository sources at the research baseline: `ARCHITECTURE.md`,
`docs/phase3/coordinator/implementation-coverage-ledger.md`,
`docs/phase3/integration-checkpoint-2026-10-29-run-bootstrap.md`,
`src/aragorn/phase3_exit_qualification.py` and the reuse anchors above.

Architectural upstream references inspected 2026-11-02; exact release selection
and provenance limits are in the separate step-2 pin inventory:

- [Pi agent-core API](https://github.com/earendil-works/pi/blob/main/packages/agent/README.md): explicit host-supplied tools/context and tool execution callbacks support the request-only adapter design.
- [Pi security](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/security.md): runtime extension mechanisms do not establish Aragorn's external security boundary.
- [Agent Skills specification](https://agentskills.io/specification): portable instruction bundles with optional supporting resources and scripts.
- [NIST reference monitor](https://csrc.nist.gov/glossary/term/reference_monitor): basis for complete mediation outside the untrusted agent.

These general references are not installation, build, runtime-measurement or
qualification evidence. Selected release pins do not imply any of those results.
