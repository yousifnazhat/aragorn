# D2 batch 52 — read the guest report from the verified host capture

Starting integration: `e13a175`. This changes the offline replay, not the
runner, approval packet, boot image or retained refusal.

The [B50 export/replay](../../../scripts/replay_pi_core_single_use_owner.py)
keeps its existing host `transcript` and `disposition` fields. Only a consistent
single-use transcript with no declared host loss reaches the [B44 reader](../../../scripts/inspect_pi_core_observable_serial.py).
It passes the original archived byte string already checked against recorder
EOF, count and digest, not a file reopened from the checkout or a reconstructed
line. It never treats the host attempt UUID as an independent guest boot ID.

Replay reads the B44 catalog from the signed artifact commit, requires identical
bytes at the authenticated prebuild ancestor, compares the catalog digest to
the signed B45 runner pin, and joins the disk digest across B44, B45 and B50.
There is no working-tree fallback. At the starting commit the B44 catalog
SHA-256 is `0ebd47b2380dcba15e60d9dfb1dd42838f613733d62ac8128a679cd1ec19e892`.

| Host disposition | Guest finding | CLI exit |
|---|---|---:|
| Consistent single-use transcript | Matching B44 record; report names the catalog and byte range | 0 |
| Consistent single-use transcript | Indeterminate: missing/untrusted pins or absent/conflicting guest record | 2 |
| Consistent held refusal | Not evaluated; no guest was expected | 0 |
| Conflicting, indeterminate or host loss | Not evaluated | 2 |

These are offline findings, not authority or evidence of independent boot,
firmware trust, restoration, worker health or qualification. Host loss does
not become a retry or cleanup grant. The retained refusal has no guest serial.

## Affected checks

| Reviewed stage | Passed once | Fingerprint (SHA-256) |
|---|---:|---|
| `pi-core-observable-serial-offline` | 7 | `27dfd51f24da53c3f240f5ca101c537e8621d093374ef6b7069858673f5816df` |
| `pi-core-single-use-replay-offline` | 10 | `5f928c2808f7b0fbf2ed46bb48f22cd074ac2cfecc92c43d08c1f7054ad0a0b0` |

The positive case used inert protocol fixtures, not a real guest or an issued
approval. No other stages, rebuilds, captures or live operations ran.

1. **D2 open.** The [B49 operational bindings](pi-core-boot-approval-packet-batch-49.md)
   remain incomplete. Without them and separate approvals, no allocation, enrollment or compatibility
   boot. After that, independently verify the protected worker view, sensor health,
   recovery and timing before closing D2 with a separately authorized useful pilot.
2. **D3 open.** Connect remaining admission, RUN/health and workload paths.
3. **D4 not frozen.** Complete independent verifier coverage for all 29 managed-profile
   requirements and freeze the common deployment.
4. **D5 not authorized.** After freeze and separate approval, obtain fresh admission
   evidence, 100 actual attempts and 100 task pairs, verify thresholds and cleanup,
   then replay independently.
