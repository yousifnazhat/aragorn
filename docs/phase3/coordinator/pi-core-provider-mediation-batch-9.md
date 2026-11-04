# Pi-core D2 batch 9: protected provider/data mediation

Date: 2026-11-04. Base: `60a2d8bd79c2b2263765fa4709e364790b4c0de9`.
Scope: reviewed source, only new/affected offline checks, one affected isolated
compiler-only build, verified signed commit and ordinary branch push. No live
provider, runtime operation, deployment or acceptance is authorized.

## Connected behavior and reused components

The real pinned Pi loop now has a fixed, credential-free provider client and a
protected composition with the existing native action client. There is no
runtime rewrite, new dependency, generic gateway or modification to the frozen
OpenClaw codec. The existing HTTP canary remains a canary, not a model gateway.

`provider.ts` projects exactly one initial system/user transcript, the complete
fixed `aragorn_runtime_create` declaration and the exact model. It validates
local display timestamps then normalizes them to zero so a protected operator
can approve the complete semantic payload before execution. Strings/text blocks
and all tool/model fields remain in the canonical digest. Credentials, provider
options/callbacks, images, assistant continuation and tool results are not
forwarded. This profile does not yet authorize a second model turn.

`runProtectedNativePiEntry` binds v2 START to the fixed provider and action
factories. It takes no injected provider or relay callback and caps execution at
one initial provider turn. The native bootstrap still does not invoke it:
`provider_status` stays `UNAVAILABLE`. The old explicitly injected offline
composition and v1 START retain their previous roles and byte contracts.

The fixed provider endpoint is
`/run/aragorn-pi-bootstrap/provider/provider.sock`. Its root-owned ancestors,
root:Pi-GID directory (`0711`) and socket (`0660`) are checked before send and
after receipt, together with actual Linux real/effective UID/GID and no unrelated
supplementary groups. Node does not provide portable SO_PEERCRED here; this is
endpoint-ownership validation, not kernel peer-identity proof. The external
mediator authenticates the actual accepted worker process independently.

## External data gate, not an actual provider adapter

`pi_core_provider_mediation.py` receives caller-owned accepted Pi STREAM and
already-connected protected-service SEQPACKET channels. It opens no listener,
reads no credential and makes no HTTP request. The separate service role must
not share root, worker or independent-sensor UID/GID. Existing authenticated
channel helpers bind peer/PIDFD, nonce, original deadline and canonical request.

The gate reuses actual worker activation measurement, held v2 active/quarantine
lineage, protected directory/control readers and the existing broker lock,
policy, health, revocation, independent observation and replay-state decision.
No worker-provided label or caller boolean can replace those authorities.
Missing independent observation refuses; the gate never synthesizes it.

A root-owned `0400` `provider-data-approval.json` binds:

- Exact activation, complete payload digest and one request.
- Provider/API/model and exact HTTPS destination descriptor.
- Root-approved `PUBLIC` or `FABRICATED_OWNED_LAB` data class.
- Existing action request identity/policy, full provider-request tool-call digest,
  provider-operation digest and route/path digest.

The route is a descriptor, **not** verified network destination authority.
Exact model base URL matching is deliberately literal; no provider API path is
inferred. The real provider adapter must still enforce TLS, DNS/address policy,
proxies, redirects, current policy/health/revocation and data scope at the actual
network-send boundary. Selecting a concrete provider, endpoint and credential
custody profile is a remaining deployment decision, not silently defaulted here.

Before the protected-service handoff, the gate writes and reads back an absent-only,
durable `provider-activation-<id>.json` claim, then commits existing replay
consumption. The claim remains spent even if later policy changes, transport
fails or state publication is uncertain; it is never erased for a retry.
Approval, identity and the real decision are checked again before handoff.
Fractional wall time cannot extend action expiry, and an immediate pre-send
expiry/rollback check complements the original monotonic deadline. This is
handoff validation, not a claim of atomic network-send-time authorization.

The terminal response binds the exact request. It carries bounded text or one
known create-tool call, never raw provider errors or secret-bearing extra fields.
The client adapts a bounded buffered completion to real Pi start/done events;
there are no fabricated incremental token events. Token usage is untrusted
provider data, and required zero cost fields mean unknown/unpriced, not measured
cost evidence. A tool call still requires the separate existing action authority.

## Failure, cleanup and evidence limits

No automatic reconnect, budget renewal or provider/effect retry exists.
The client spends its slot even on malformed, cancelled or refused input.
An attempted service send followed by transport, identity, validation or cleanup
uncertainty remains `INDETERMINATE`. Explicit protected-service refusal remains
`NOT_SUBMITTED`; a completed model response is not effect or RUN qualification.

The mediator releases its control lock, lineage hold and owned process handles
before sending a completed worker response. It attempts all owned closes and
reports a cleanup hold on uncertainty. Caller-owned channels still require
their owner's verified cleanup. Delivery of frame and EOF is not client
acknowledgement. Retained observations contain metadata/digests only, not prompt,
response, destination or exception text.

No host service, target Node/worker, native supervisor, model provider, listener,
VM startup, effect or capture was activated. Developer Node ran only guarded,
in-memory fixtures using the real pinned Pi loop. Mocked identity, filesystem
and transport edges are not deployed identity, actual confinement, sensor-health,
effect, network-egress or cleanup proof. The gate reports
`provider_transport_implemented: false` and `phase3_eligible: false`.
The native no-request bootstrap still does not satisfy D2's useful-task exit.

## Review and focused verification

Three disjoint lanes owned the TypeScript client/composition, Python gate/checks,
and real-Pi inert fixture/checks. Coordinator and cross-lane source review
preceded execution. The code-review skill influenced exact payload approval,
credential exclusion, refusal/uncertainty handling, deadline fixes and the
explicit handoff-versus-egress evidence boundary.

All **86 new or affected checks passed once**, with no failed run or rerun:

| Selected stage | Checks | Exact successful fingerprint |
| --- | ---: | --- |
| `pi-core-provider-mediation-offline` | 34 | `sha256:8aa0502c6f699859c952e525a4d134a5963b0e076243553a0ba79dc73edc33e3` |
| `pi-core-provider-client-offline` | 41 | `sha256:220ea343727d29c144947e6f36a763b554772852bdf15e810842ff2e38d17d94` |
| `pi-core-provider-build-offline` | 6 | `sha256:361d55cce38589df8853481b9e675588429cfd9c5bc3e23ea2232ce5582f2b73` |
| `pipeline-capacity` | 4 | `sha256:995f91b66b15b11b784141b083c2f6b0a3f6089519d67564dfefc4e38238ad92` |
| `pi-core-linux-compile` | 1 | `sha256:71a76c07d39f042ae2d323e6ad029d361bf892e1cf1b65573f48adcc1bca5149` |

Only `scripts/phase3_pipeline.py` scheduled checks from reviewed explicit closures
in `benchmark/phase3-pipeline-v1.json`. Capacity rose from 151 to 154 for three
new stages. The six-check assembler slice selects two new checks and exactly
four affected old methods; imported helpers do not collect old classes.
No broad regression, historical stage, schema sweep or OS reassembly ran.
Successful/failed historical fingerprint records remain untouched.

The compiler verified pinned archives and the already-running explicit Colima
daemon, then ran the static Linux compiler in an owned network-none, nonroot,
capability-dropped, bounded scratch container. Target Node/worker code was not
executed. Container and image were verified absent afterward. Adapter source
compiled strictly; the existing upstream `skipLibCheck` limitation remains.

The new [compiled checkpoint](../../../packaging/pi-core/compiled-artifact-v3.json)
preserves both predecessors. It records `provider.js`, updated `entrypoint.js`,
unchanged `worker.js` and the exact receipt/cleanup:
deployment inventory `d41779d8a992e91b5adcc40d493ab9c26aa2d41f47eb1361972494a0728ec22a`
(12,695 entries).
Node and static library inputs are unchanged, so the OS closure is reused
without a fresh assembly or qualification claim. Binaries/full inventories stay
local, not published in Git.

Original 48-ID manifest, approved 29-requirement design mapping, frozen
predecessors, retained evidence, unrelated drafts and operational/private-retention
cleanup holds remain intact. The ignored
`.aragorn/pi-core-provider-mediation-batch-9-release.json` records the resulting
signed commit, signature verification and exact remote readback after push.

## Remaining plan

1. **D2 in progress:** choose/configure the concrete protected provider adapter,
   endpoint and credential/data-approval profile; implement actual send-time
   egress enforcement. Connect native provider/action service provisioning and
   lifetime, consumed-code custody and Pi-aware effective-receipt recovery/
   rotation. Then, only with separate live authorization, run the useful allowed/
   blocked pilot with independent health, outcome and cleanup evidence.
2. **D3:** complete managed lifecycle/admission, RUN/sensor-health, remaining
   actions/workloads and paired tasks on the same deployment.
3. **D4:** implement the approved 29-requirement acceptance contract and complete
   independent verifier inventory, then freeze the complete deployment once.
4. **D5:** separately authorize fresh final acceptance, retain real metrics and
   cleanup, then replay evidence offline. Phase 3 remains incomplete.
