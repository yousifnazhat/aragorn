# D2 batch 53 — offline worker filesystem and writable-state seed

Starting signed integration: `55b333d`. The
[receipt and archive hashes](../../../packaging/pi-core/worker-filesystem-b53.json)
bind two separate offline outputs to the B44 disk/catalog and the exact B37
source plan. Original B3/B36/B37 inputs, B44 boot media, historical refusals
and the private B49 worksheet were not modified.

| Retained artifact | What it supplies |
|---|---|
| `worker-view.tar` | 22 directories and 13 files: the B3 OS files and the four B36 runtime files at their worker-visible paths. The gate, Node, two source/data paths and eight loader paths were checked against the B37 plan. |
| `writable-state.tar` | Two empty root-owned directory entries, `var` and `var/lib` (0755). Neither action nor provider destination exists yet; only the existing fresh-only service installers may create them. No policy, credential, effect or approval was seeded. |
| `worker-source-plan.json` | Exact B37 canonical bytes, SHA-256 `305679f5a4891465d0820e2f2adfb3402e60b9d50489c1ccd93bb6ea8bd66ac4`. |

Local artifacts: `~/Library/Application Support/Aragorn-B53-Offline/`. The
private directory contains both read-back archives, the source plan and
`outcome.json`; only the matching public receipt and code are in Git. Numeric
ownership and modes are archive metadata, not observations of an installed OS.

**Integration boundary.** The merged archive is a reference for the inventory
reader, **not** the launcher's underlying OS root. Preserve the empty B3
mountpoints; the launcher binds the retained runtime, admitted bundle and
bootstrap socket separately. In the actual deployment, compare the same
underlying file objects visible at launch, not inodes from an extracted copy.
Do not unpack the state seed over the guest or mount it over host `/var/lib`.
Worker scratch remains private; no broker or provider state is bound into Pi.
Selection and ownership of the writable backing, persistence across host loss,
runtime sockets and cleanup remain separate from this preparation.

## Verification

The new packaging stage compared the whole USTAR streams to the reviewed
input bytes and metadata. Its separate reader checked the source-plan hashes
directly against archive members. Traversal, writable code, collisions, links,
device entries, duplicates, extra bytes, substitution and overwrite were refused.

| Stage | Final checks passed | Fingerprint |
|---|---:|---|
| `pi-core-worker-filesystem-offline` | 5 | `74e67dc938d07622db6063f3431cbb267a53971f2267bee160a34bedcb1cf98c` |
| `pipeline-capacity` (one new slot, 282 → 283) | 4 | `d3445fb2532d7dcaf2ed12e1234279ed2ed34f579c66073c5f98d9508f6ff006` |

Two earlier packaging results and their partial outputs are retained. Fingerprint
`6ea58b3573685a0e5537e27536fcb9033071a218edec082fd5eabc31ea8c5a65`
rejected the literal plus signs in the pinned `libstdc++.so.6` filename; the
successor accepted that character and validated all names before writing.
Fingerprint `e1cdf3b913cd80d33d25081ad25337cba563c2e6cc49df868b544d76c9f8e490`
refused during readback of the archive under Documents. The file's change
time differed from its modification time; the responsible process is unknown.
The successor used a fresh, private Application Support destination, retaining
the strict file-identity check. Only the corrected packaging stage reran;
no previous fingerprint was retried. No build, VM, capture or provider call.

1. **D2 open.** Keep B49 held. Plan the separate service-state backing and
   custody without changing the B44 compatibility-boot contract. Only with
   separate authorization can an installed worker view, read-only mounts and
   file identities be verified. Sensor health, recovery, timing and the useful pilot remain.
2. **D3 open.** Finish connected admission, RUN/health and workloads.
3. **D4 not frozen.** Complete independent evidence coverage for all 29
   managed-profile requirements; freeze the common deployment.
4. **D5 not authorized.** After freeze and separate authorization, run the
   admission inventory, 100 actual attempts and 100 task pairs; verify thresholds,
   cleanup and independent replay.
