# B99 — compare the provider proposal with the recorded pilot action

The existing [B93/B98 action replay](pi-core-recorded-action-lease-batch-98.md)
can now answer one additional question: did the recorded tool proposal and
worker request agree with each other **and** with the independently reviewed
[B95 pilot inputs](pi-core-public-pilot-inputs-batch-95.md)? It cannot answer
whether a particular model produced those bytes or whether a file was created.
Omit the two provider options for the original generic replay.

```sh
PYTHONPATH=src:. python3 -B -m scripts.verify_pi_core_retained_action \
  "$ACTION_EXPORT" "$ACTION_NOMINATION" \
  --pilot-provider-archive "$PROVIDER_EXPORT" \
  --pilot-provider-nomination "$PROVIDER_NOMINATION"
```

Both stores must already exist. Use independently held pins, not values
discovered from a submitted capture. In the provider store, nominate the
canonical JSON document (no trailing newline) with exactly these fields:

| Field | Independent expectation |
|---|---|
| `schema` | `aragorn/pi-core-pilot-provider-nomination/v1` |
| `index_digest` | Original B27 provider JSONL index, including the final LF. The originals named by its references must also be available. |
| `activation_digest`, `request_digest` | The same original worker activation as in the action nomination, and the original **provider** REQUEST (not the worker's create request). |
| `route_digest`, `profile_digest` | The expected model/route and the protected OpenAI service transport profile, respectively. Neither a test route nor a hash chosen from the submitted packet is an approved provider profile. |
| `nonce`, `deadline_ns` | Original provider exchange nonce and absolute monotonic deadline. Do not substitute the broker offer nonce or compare to today's clock. |

The reader checks the 41 references in order, their hash chain, and the
original canonical records. It compares the recorded service request,
CONNECT/SEND checks and permits, terminal service result and recorded tool
proposal. It checks the exact public prompt, original manifest, tree and active
skill, data classification and fixed tool declaration. The call ID is hashed
as UTF-8, just as in the worker. The name and content must match the original
worker request: `result.json`, exactly 11 bytes, no final LF. B98 independently
checks the spent lease and preserves the **recorded** broker verdict. A match
does not turn a recorded block into success.

Only pins and bounded findings are returned. Replaying a nominated index does
not re-authenticate an original peer, prove a provider request was delivered,
re-establish the owner’s cleanup, prove current health, or independently
re-evaluate the entire provider policy. No new recording, service permission
or export of a complete private managed result is introduced.

## Verification

Only `pi-core-public-pilot-recorded-correspondence-offline` ran. The first
attempt, `sha256:b29ac350a4231a1ec79d141c811bde31875dc806606b3d7efb6dc5c8bd28124d`,
was retained: setup failed before a test because the two producer fixtures
named different workers. The correction gave the provider fixture the action
fixture's original worker configuration, source record, clock and health
binding. Both production readers and the one-activation requirement remained
intact. **Six checks passed** on the corrected fingerprint
`sha256:f9460ff4b84960e424f592016bfd37a46cba3224b318f7144309786e92375af2`.
The positive check uses both existing record producers with inert OS,
transport and storage edges. It is not a pilot run.

## What remains before a pilot

| Pilot binding | Current limit or missing approval |
|---|---|
| VM and state | Proposed: one dedicated Linux arm64/systemd VM, immutable whole-image boot disk and one directly attached LUKS2 state disk with its own inline header. Actual owner, instance, volume, recovery head and evidence destination: **not nominated**. The [B49 compatibility boot](pi-core-boot-approval-packet-batch-49.md) is a different approval. |
| Provider and credential | OpenAI Responses is selected. Exact model, numeric address, CA pin and permitted egress are **not approved**. A designated operator would deliver their key only via the protected service's [`openai-api-key` credential](pi-core-provider-custody-batch-21.md), never via Pi, Git or chat. No key is needed for offline replay. |
| Budget and scope | Authorized now: **USD 0, zero boots, zero requests**. Proposed pilot: one fabricated calculation, one model call, one authorized create, no automatic retries. The operator must bind the all-in cap and window; the existing five-second approval is not renewable. Run changed-byte and unauthorized-target denials in separate owned contexts. |
| Evidence and cleanup | Before activation, assign an independent evidence custodian and cleanup owner; record prior state and target absence. Preserve original outcomes, independently read the exact file, close only owned resources, verify prior-state restoration. A lost host, ambiguous effect or uncertain cleanup stays on hold; never replay the effect to fill the gap. |

1. **D2.** Use the [B97 graph](pi-core-public-candidate-closure-batch-97.md)
   with an independently nominated admission policy, analyzer and trusted
   receipts. Keep the two socket directories non-listable. The private scope
   for the worker’s fixed lookup/link evidence is still undecided. Independent
   output verification needs an authorized read-only observer of the held
   output directory before and after creation; neither B27 nor B98 reads
   that file. Demonstrate protected storage, actual health, recovery, full
   timing and cleanup. B49 remains null. No guest, provider model/address/CA,
   key setup, budget or live pilot has been authorized by this change.
2. **D3.** Finish connected admission and RUN/health. Choose the workload
   carrier and isolated copy fixture before collecting pairs.
3. **D4.** Complete the independent 29-requirement inventory, close the
   deployment prerequisites, then freeze.
4. **D5.** Separately authorize fresh acceptance, 100 attempts and 100 pairs,
   with cleanup and independent replay.
