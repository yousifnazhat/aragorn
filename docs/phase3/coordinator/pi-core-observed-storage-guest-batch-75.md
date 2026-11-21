# D2 batch 75 — stage the stopped-worker and storage observers together

The [stopped-worker observer and independent receipt reader](pi-core-stopped-mask-observer-batch-59.md)
landed in signed merge `241427f`, directly after `332d579`. The
[retained B69 guest](pi-core-managed-guest-inventory-batch-69.md) did not
include the subsequent stopped-worker handle and sensor storage changes.
B75 stages those signed sources through [B74](pi-core-mounted-state-uuid-batch-74.md)
in one offline guest payload. It does not produce a bootable disk or a field observation.

The [source catalog](../../../packaging/pi-core/managed-sources-b75.json)
pins signed revision `80818a521459fb23112f71184cb42fa809f644c9` and tree
`5a661a00511f4dbd29b85be5de4a8759e2f9cb48`. The manager source set
contains 123 files (18 changed, six new); the service set contains 114
modules (16 changed, nine new). The common service wrappers include locally
importable dependencies, not new privileges or proof those functions ran.
The original Pi bundle, Node, gate, worker filesystem and native binaries
were carried forward unchanged.

The [payload catalog](../../../packaging/pi-core/managed-payload-b75.json)
pins the expected manifest, host profile, service manifest, runtime binding and
layout receipt independently of the writer. The writer checks the retained
predecessor, publishes once to a separate local directory, and verifies its
output. Result: 1,779 entries, 41 files changed (15 added), 812 host profile
files and 802 service manifest files. B69 was not overwritten.

| Retained B75 file | SHA-256 |
|---|---|
| `payload.json` | `91b41ff45ade64e691a95e95abf72611ba7ca27c1b146136e7b9079c876e7c31` |
| `outcome.json` | `dd7546345df15e772d9a0865b725280213c05f0d280f63afe1e429b6d6594d53` |

| Focused pipeline stage | Passed | Retained fingerprint |
|---|---:|---|
| `pi-core-b75-guest-inputs` | 7 | `884ea3914cf5300646d55fff5d662fb7c1240aa4249daa44fcf9ead3df4ba447` |
| `pi-core-b75-guest-preparation` | 1 | `2fd7aacfc879c55c060182b4955f5efad3c592c5414c3dae9925f0fddeb4f79f` |

No historical observation was recaptured. No worker, service or VM started,
no model was called, and nothing was spent. B49 remains null.

1. **D2 open:** the signed observer and replay path are staged, not exercised
   on an installation. Resolve the [remaining worker-view evidence](pi-core-worker-visible-tree-decision.md)
   and encrypted backing/writer/current-head evidence; obtain installed health,
   recovery and timing results and separate pilot authorization.
2. **D3 open:** connect the remaining admission, RUN/health and workload paths.
3. **D4 not frozen:** complete executable independent coverage of all 29 managed
   requirements and review the shared deployment before freezing it.
4. **D5 not authorized:** fresh admission inventory, 100 attempts, 100 task
   pairs, cleanup and independent replay require a freeze and separate approval.
