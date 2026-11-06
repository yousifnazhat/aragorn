# Pi-core D2 batch 11: public provider inputs and durable request recovery

Date: 2026-11-05. Base: `50e31ce10fa6f0ed35a4016b81f69d43d0894ba9`.
Scope: connected source implementation, only reviewed new/affected offline
checks, verified signed commit and normal existing-branch push. No live operation,
credential setup, native service activation, pilot, freeze or qualification.

## Reuse and delivered behavior

Two parallel implementation lanes owned the public-input provisioner and durable
recovery respectively; a third lane independently reviewed custody, failure and
fixture behavior. Root owned request-service integration, registry and docs.
The code-review skill drove exact boundary and cleanup review, including the
named-file custody and final deadline fixes before execution.

### Public provider inputs

`pi_core_provider_provision.provision_pi_provider_inputs` reuses the existing
manifest parser, descriptor-safe copying, exact modes and failure-retention
helpers from `pi_core_os_provision`. It installs only these reviewed public files:

- `etc/aragorn/pi-provider-profile.json`: exact canonical approved profile bytes.
- `etc/aragorn/pi-provider-ca.pem`: bounded ASCII bytes matching that profile's
  CA digest. ASCII/digest validation is not TLS certificate trust validation.

The caller supplies the independently reviewed manifest and profile. Source
layout is exactly `etc/aragorn` and the two leaves; unexpected names refuse
before leaf reads. No unknown credential file is inventoried or read. Sources
and outputs cannot overlap; links, unsafe metadata, changed bytes and unreviewed
executable bits refuse. The destination must be absent; there is no overwrite,
automatic repair or rollback.

The new layout is `<parent>/<name>/root/...` plus the canonical
`provider-inputs-receipt.json`. Installed public files are root:root `0444`,
intermediate directories `0555`, and deployment/root directories `0755`.
Final checks bind named parent/deployment/root/receipt entries to held file
descriptors, with exact installed owner/mode/byte checks and receipt readback.
Close uncertainty suppresses completion; all partial output is retained.

Receipt status is `PROVISIONED_PUBLIC_INPUTS_ONLY_NOT_SERVICE_READY`.
`credential_read`, `activation_performed`, `service_ready` and
`phase3_exit_eligible` are false. This is not a Python/OpenSSL/service-code
installer, credential provisioner, unit template or loaded-code attestation.

### Pi-aware grant recovery connected to request startup

`pi_core_request_recovery` reuses frozen grant/profile locking, canonical state,
immutable archives and exact pending cleanup, plus the existing Pi effective
result validator. Frozen predecessors are unchanged.

- Reconciliation requires the configured protected broker identity, current
  canonical broker state, a clear effect journal and one original bounded
  deadline. It does not migrate legacy state or clear an unresolved journal.
- CLAIMED state becomes CONSUMED only when the retained receipt matches the
  exact grant/claim and, when present, pending bytes. Effective BLOCK and replay
  receipts retain their original policy decision; a BLOCK never becomes ALLOW.
  Pending cleanup follows durable publication. Missing/mutated evidence stays
  held, with no effect retry or invented abandonment.
- Explicit initialization may create missing grant state only with clean
  prerequisites. Rotation validates old terminal evidence, archives receipt then
  state, and only then publishes a distinct, already-authorized live grant.
  Archived authority cannot be reissued. CLAIMED state never rotates implicitly.
- Recovering AVAILABLE state also checks archived-terminal freshness, so a
  restored old AVAILABLE file cannot revive a consumed archived grant. Immutable
  archive readers can reconcile exact abandoned links; failures after that edge
  are conservatively uncertain, never success.
- Publication, archive, cleanup or original-deadline uncertainty preserves
  output and raises an indeterminate result. No automatic effect retry exists.

The existing `handle_pi_broker_request` now recovers before acquiring request
custody and requires AVAILABLE state. It never initializes or rotates a grant
because a request arrived. The separate explicit
`initialize_pi_broker_request_service` prepares durable state and returns only
its metadata/digests, with no service-readiness claim. A fresh grant still needs
independent admission and worker-activation binding by the lifecycle owner.

## Review and focused verification

All **94 distinct selected checks passed once**: 86 new, four selected affected
request-caller methods and four affected registry-capacity checks.

| Selected stage | Checks | Successful fingerprint |
| --- | ---: | --- |
| `pi-core-provider-provision-offline` | 37 | `sha256:f71827ca20a53be642ee137975799be976bdea5f85f1eabade379d896fcce84a` |
| `pi-core-request-recovery-offline` | 41 | `sha256:aacee0699542e15f2caaea362930b77ffe468f45db88f5188594d0e2010ecc3f` |
| `pi-core-service-recovery-offline` | 12 | `sha256:aa98f6fda8d6cba7c97536aeb9181582e6541f39c360a3d079b832bbb5ef7da5` |
| `pipeline-capacity` | 4 | `sha256:07bbaf8682626b8ee5815c967557a26c6bef1ece03d20ce0fb65651bffbad243` |

Only `scripts/phase3_pipeline.py` scheduled these stages from the reviewed
`benchmark/phase3-pipeline-v1.json` closure. Static import review identified
62/69/70 source/fixture inputs for the three new stages; imported historical
fixture classes were not scheduled. Registry capacity increased 158 to 161.
No test rerun, broad regression suite, whole-schema sweep, compiler, OS assembly,
historical recapture or live fixture ran. Prior successes/failures remain intact.

Provisioner checks used exclusively owned temporary public-file fixtures with
mocked Linux/root ancestry; their authored CA bytes are not a real trust store.
Recovery used an inert in-memory file table, real state/receipt codecs and mocked
durable I/O. Service checks used inert channels. The Python 3.14 traceback-fixture
issue from batch 10 was caught and corrected during review, before execution.
These developer checks establish no native deployment or recovery evidence.

The signed commit containing this checkpoint and exact remote SHA readback are
recorded in local ignored `.aragorn/pi-core-provision-recovery-batch-11-release.json`
and the chat milestone. Unrelated user drafts are excluded from the commit.

## Remaining plan and evidence ceiling

Native START remains `provider_status: UNAVAILABLE`. The retained Node-only
worker OS closure cannot establish provider service compatibility or code
identity: Python, its standard library/native extensions, OpenSSL and the actual
Aragorn service-source closure still need reviewed deployment custody. A public
input receipt is not consumed-code identity or proof that a service is running.
The 29-requirement mapping, historical exit manifest and operational holds remain
unchanged; no admission, RUN, Phase 3 or Phase 4 qualification is claimed.

1. **D2:** compose the reviewed service runtime/code closure, protected
   provider/action/sensor provisioning and authenticated channels, and exact
   service/process lifetime into native START. Bind actual consumed code and
   exercise recovery in that common deployment. Select the concrete model and
   deployment trust/credential profile without silently activating it. Then,
   only after separate authorization, run one useful controlled pilot with
   independent effect/output/health and verified cleanup.
2. **D3:** complete remaining admission, RUN/health and workload/paired-task
   coverage on that same deployment.
3. **D4:** implement the approved acceptance mapping and complete independent
   verifier inventory, then freeze the complete deployment once prerequisites close.
4. **D5:** required fresh final acceptance, real measurements and cleanup
   evidence, followed by offline replay. Only genuine gate closure completes
   Phase 3 and permits consideration of Phase 4.
