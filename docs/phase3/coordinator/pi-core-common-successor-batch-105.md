# B105 — common offline successor and evidence input pins

The [B105 payload preparer](../../../scripts/prepare_pi_core_b105_payload.py)
combines the retained B75 layout with the four
[B104 protected inventories](pi-core-installed-action-join-batch-104.md).
It reuses the signed source projection and the existing staging/readback,
checks an independent [payload review](../../../packaging/pi-core/managed-payload-b105.json),
and creates one new local directory. It preserves the B75 worker filesystem
and native binaries and does not modify B75, B94 or B104. This is a staged
layout, not bootable media or an observed deployment.

`~/Library/Application Support/Aragorn-B105-Offline/` contains the completed
root and the first two documents below. The layout has 1,787 entries, 816
host-profile files and 806 service files. There are 46 new or updated source,
wrapper and inventory files, including eight additions. The writer verified
the bytes it emitted before publishing its completion marker.

| Object | SHA-256 |
|---|---|
| `payload.json` | `b60330aef3582e9d52ed59001b0bd16d6d973549b0d18812934c8f53e739c81f` |
| `outcome.json` | `c9c53a68840e9a3d4d4be3f0fc731a0fc83235ad550288ba5fafab30bdbf3798` |
| [Evidence input catalog](../../../packaging/pi-core/managed-evidence-inputs-b105.json) | `418b0af14419bdfde7e80911b91d1f03362707cf37d3e8aac6ca700f80550224` |

The [read-only evidence input check](../../../scripts/verify_pi_core_b105_evidence_inputs.py)
matches the staged B104 documents to their originals and the references in the
outcome. It pins the unchanged worker binary and gate rows, the two observer
rows, the original B95 skill and LF-terminated task, the independent B95
review, the original B97 CAS manifest and graph, and the reviewed reader
sources. The oracle remains outside the candidate, and its expected bytes
are not an observed effect. No new source inventory or historical capture was made.

### What remains unbound

- A payload digest is not the raw seven-field deployment digest. Derive that
  identity only from the actual candidate runtime, protected configuration,
  and approved original admission and runtime policies. This packet is not
  an install plan, usable deployment, grant, or approval.
- The revised observer does not inherit the old B63 launch plan. B86 is a
  separate gate candidate, not part of B105. Bind the exact reviewed worker
  and observer before successor media preparation; preserve the approved
  socket confinement and evidence scope.
- Before a separately authorized attempt, nominate the approved source
  manifest, deployment, current install context and install plan. Once those
  producers run, independently retain their original outputs and nominate the
  install-owner report and the action evidence for the B104 join. Do not fill
  future capture slots using old or fixture records. An actual host and pilot
  approval are absent; B49 remains null.

### Focused verification

Only two new stages ran, both passing on their first run. The projection and
refusal stage did not create a duplicate full payload. The evidence stage then
read the one actual retained layout and tested a foreign payload refusal.

| Stage | Checks | Fingerprint (SHA-256) |
|---|---:|---|
| `pi-core-b105-common-payload-offline` | 3 | `34cf06b4217fc934f3c26b51cb59e7d2c53c1aa8cf4d142b46853f22fe01e7ec` |
| `pi-core-b105-evidence-inputs-offline` | 2 | `1d3f5269946d7381376866e60167489ea97d641ec07400549ba26f823b62927d` |

1. **D2:** Common layout and available evidence inputs are pinned offline.
   Bind the worker/observer and actual deployment before an authorized pilot;
   independent output, installed health, timing and recovery remain open.
2. **D3:** Finish connected admission, RUN/health and workload coverage.
3. **D4:** Close all 29 independent requirement bindings, then freeze once.
4. **D5:** Obtain separate authorization for fresh acceptance, 100 attempts
   and 100 pairs, cleanup verification and independent replay.

No media build, live install, boot, activation, provider call, capture, or spending.
