# Pi-core D2 batch 10: protected OpenAI adapter and service handler

Date: 2026-11-05. Base: `40bf8ee00d967528cceccd2ded12ef8968332bdc`.
Scope: source implementation, reviewed new/affected offline checks, verified
signed commit and normal branch push. No live operation, key setup, provider
request, native activation, deployment freeze or qualification is released.

## Decision and reuse

The user selected **OpenAI Responses API** as the first protected wire protocol.
This chooses how to address the model service, not a model, credential, budget
or permission to send data. Pi remains the unprivileged agent engine; Aragorn
remains the external capability-security authority. Intended deployment is
bring-your-own-key: each operator supplies a key to the protected service,
not to Pi, prompts, logs, receipts or Git. No real key was accessed in this batch.

Reused: exact Pi payload/result validators, existing fixed create-tool contract,
root data approval, policy/health/revocation and independent observation checks,
durable one-use activation claim, replay state, held lineage, authenticated
Unix channel/PIDFD helpers and protected file/credential readers. No dependency,
SDK, generic gateway or runtime rewrite was added. Frozen v1 handoff behavior
remains the default; source explicitly opts into the v2 service exchange.
TypeScript bytes and dependency pins did not change. Compiled-artifact-v3 and
OS-v1 remain the retained artifacts; no compiler or OS assembly was rerun.

Wire references reviewed: [Responses create](https://developers.openai.com/api/reference/resources/responses/methods/create)
and [function calling](https://developers.openai.com/api/docs/guides/function-calling).

## Connected source path

1. The root gate validates the exact initial system/user payload, explicit
   model and fixed function declaration against protected approval, then
   permanently consumes the existing activation budget before service handoff.
2. The pure codec independently renders identical request bytes in root and
   service. It fixes `POST https://api.openai.com/v1/responses`, explicit model,
   nonstreaming/nonbackground, `store:false`, disabled truncation and parallel
   tool calls. No hosted tools, continuation, extra provider options or model
   discovery is authorized. Request body is bounded to 64 KiB.
3. The v2 service authenticates its root peer and exact profile/wire bindings.
   Root retains worker/lineage/broker-lock custody. Before CONNECT and SEND it
   rechecks current policy, revocation, health, matching independent observation,
   unchanged approval/profile and retained spent claim. Permissions bind phase,
   sequence, nonce, request/wire digests and original integer deadline.
4. A local opaque one-use permit is consumed immediately before each edge.
   It lasts at most 100 ms, is bounded by every validated snapshot expiry and
   the original activation/action deadline, and cannot renew or retry a phase.
   This is **bounded freshness, not atomic instantaneous revocation** across
   processes or cancellation of an already in-flight network operation.
5. The distinct nonroot service reads its fixed protected credential and pinned
   CA, makes one public numeric-address connection, verifies TLS for
   `api.openai.com`, and makes one request write. No DNS, proxy/environment
   override, redirect, fallback, second write after a partial send or effect
   retry exists. TLS 1.2+ and HTTP/1.1 only; original deadlines remain in force.
6. Bounded HTTP framing and JSON parsing accept completed text or one known
   create-tool call. Refusals, incomplete output, unknown executable items,
   malformed framing and multiple calls fail closed. Output is untrusted,
   never itself effect authority. Native create still needs the separate broker.
7. Service-owned transport and root-peer handles close before terminal receipt;
   root-owned custody closes before worker completion. Cleanup uncertainty
   suppresses success. Possible connection/send failure is indeterminate and
   never automatically retried; the permanent claim stays spent.

The handler takes a caller-owned connected channel. It does **not** provision a
listener, start a systemd unit, own the caller's channel or prove service-process
exit. Those lifetime joins remain required native integration work.

## Protected deployment inputs, not provisioned here

- `/etc/aragorn/pi-provider-profile.json`: root:root, `0444`, exact schema
  `aragorn/pi-core-openai-profile/v1`, service UID/GID, canonical public numeric
  address and SHA-256 CA digest. Address is an explicit deployment input, never
  inferred from the authored test address.
- `/etc/aragorn/pi-provider-ca.pem`: dedicated root:root `0444` pinned trust
  bytes. No ambient CA store or mutable system-certificate symlink is used.
- `/run/credentials/aragorn-pi-provider.service/openai-api-key`: fixed private
  credential path under protected, descriptor-held ancestors. No environment
  key lookup; exact service UID/GID and cgroup are required.
- `/system.slice/aragorn-pi-provider.service`: exact expected service cgroup.

Public and credential reads retain/recheck directory identities, reject links,
unsafe permissions and file changes, and reuse existing readers. If an existing
reader raises, its internally owned descriptor's cleanup is uncertain: the new
wrapper reports a cleanup hold even if all outer parent handles close.
Python byte buffers cannot promise secret-memory zeroization. Model output is
not a general DLP classifier. No real credential provisioning or custody proof
was performed, and the public repository contains only explicit inert fixtures.

## Review and focused verification

Three parallel lanes owned codec, transport and service files; root owned
mediation, registry and integration. Root and cross-lane source review preceded
execution. The code-review skill drove exact boundary/failure review and the
hidden-reader-close fix before tests. Official OpenAI documentation informed the
wire projection; it did not authorize a live API call.

All **145 distinct new/affected checks pass**: 137 new checks, four selected
affected v1 mediation checks and four affected capacity checks.

| Selected stage | Checks | Successful fingerprint |
| --- | ---: | --- |
| `pi-core-openai-responses-offline` | 39 | `sha256:0de45cb3b7d29c45b012c11b552ebaab9973005197ed25bb2dce3958f69c635c` |
| `pi-core-openai-transport-offline` | 44 | `sha256:004c4f6d1823b136b44ae0994e12f202b8c3ea185a714418df1f671c7aa4e539` |
| `pi-core-provider-service-offline` | 38 | `sha256:38eb04e3a27faed99d9d017759f0b9b3edfb578a2b604e4329c5de25b2fc4c3e` |
| `pi-core-provider-egress-offline` | 20 | `sha256:fe909493d233c42b2094f9da27bb09fb49c9ff0970fe6d15265a16c3fbbb9569` |
| `pipeline-capacity` | 4 | `sha256:07c46c08785e5f5f3a56414af24702e08630e5e785c9a81b318942399e90d7bd` |

Only `scripts/phase3_pipeline.py` scheduled these five stages against reviewed
explicit closures in `benchmark/phase3-pipeline-v1.json`. Static import closure
review found 68/68/69/68 source/fixture inputs for the four new stages; imported
fixture classes were not automatically scheduled. Capacity rose 154 to 158.
No broad suite, historical recapture, whole-schema sweep or compiler ran.

Four stages passed once (101 checks). The transport stage's initial fingerprint
`sha256:4b62cfe9dba90ba27dd2faf45bf6ce3ee4f186e066c6e2a12d52bbe6e8100f6f`
failed at its first test because macOS does not expose Linux `SOCK_CLOEXEC`;
the fake Linux socket fixture now provides it while all socket calls stay
mocked. That fixture also trapped `os.stat` during traceback rendering.
The first diagnostics repair assumed a module-level `linecache.os`, but Python
3.14 imports it locally; this caused setup failures under fingerprint
`sha256:6ae5c863d85f2b387fb284a457dc20dd29b19b4654139a84f97cb151c6de1271`.
The corrected fixture suppresses traceback source-text lookup only, retaining
stack filenames/line numbers and every product I/O trap. Its final 44 checks pass.
Both failed records/logs remain intact. Only the genuinely corrected transport
stage reran (two fixture-only corrections); the other four successful stages
were reused without execution. No production code changed after the first run.

The signed commit containing this checkpoint and its remote exact-SHA readback
are recorded in the local ignored
`.aragorn/pi-core-openai-service-batch-10-release.json` and the chat milestone.
No unrelated user drafts are part of the batch commit.

## Evidence ceiling and remaining plan

Native START remains `provider_status: UNAVAILABLE`. These checks do not prove
installed/loaded code identity, OS confinement, real credential isolation,
provider egress, independent sensor production, useful task output, performance
or native cleanup. The original short action authority (at most five seconds)
was not widened for model latency; feasibility remains a controlled-pilot issue.
The 29-requirement mapping and historical exit manifest are unchanged. No
admission, RUN, Phase 3 or Phase 4 qualification is claimed.

1. **D2 next:** protect/provision and join exact provider/action/sensor channels
   and service/process lifetime into native START; finish consumed-source custody
   and Pi-aware effective-receipt recovery/rotation. Select the concrete model
   and deployment trust/credential profile without silently activating it.
2. **D2 proof:** after separate explicit authorization, run one useful controlled
   task with real independent output/effect/health and verified cleanup. No
   synthetic acceptance samples or automatic effect retries.
3. **D3:** complete remaining admission, RUN/health and workload/paired-task
   coverage on the same common deployment.
4. **D4:** finish the executable approved mapping and independent verifier
   inventory; freeze the full deployment once prerequisites close.
5. **D5:** required fresh final acceptance and measurements, then offline replay
   of retained evidence. Phase 3 completion and Phase 4 wait for genuine gates.
