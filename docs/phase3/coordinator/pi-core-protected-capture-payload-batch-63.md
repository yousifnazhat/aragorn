# D2 batch 63 — package the protected capture caller

Signed source input: `95b8c5f08725beb2bef11667eee87e8c3edaed87`, tree
`e884e26f937f96b60188634fb69525172128958f`. The prior B60 package does
not contain the B62 wrapper. This successor replaces the wrapper and native
supervisor, adds the protected entry and release reader, and preserves every
other host source. All 115 project source paths were checked against the
reviewed hashes; static traversal includes the separately loaded source loader
and imports inside functions. This is not evidence of guest code consumption.

The 15 changed files relative to B41 (including the new host profile) are in
`~/Library/Application Support/Aragorn-B63-Offline/changed-files/`. This
single cumulative delta is suitable for a fresh image assembly, **not** for
installation over the B44 compatibility disk. The complete host profile has
804 files and the full physical payload manifest has 864 entries. The worker
source plan and ARM64 helper inputs are byte-identical to B60; nothing was
recompiled. The independent [reviewed pins](../../../packaging/pi-core/mask-host-successor-b63.json)
match the emitted files. Retained local `outcome.json` SHA-256:
`94e8986251e8d0035e501b66d3e67e448e3d81a0126e90301097aa88e5770204`.

| Affected stage | Passed | Retained fingerprint |
|---|---:|---|
| `pi-core-protected-capture-payload-inputs` | 7 | `2f3975670cb5a97171b7fbd1938651b70c83b35bc06e1512627885b439c6e53a` |
| `pi-core-protected-capture-payload-preparation` | 1 | `6a876d419eefa62b6bac932486eece4141352017470df4a7374bce72fbfc1c94` |
| `pipeline-capacity` | 4 | `6d5e16b3d23e033b84f410b062f67d033a8a8ac2965ae312cbc5e404e2fa9857` |

1. **D2:** compose the actual split OS/runtime worker tree (not the merged
   B53 inventory reference) with the immutable service mountpoints. Describe
   separate private storage for the capture ledger/evidence and a post-boot
   release; do not seed an approval or mount service state into Pi. Only then
   bind successor media, firmware and owner. Installed evidence, health,
   recovery, timing and a separately authorized useful pilot remain open.
2. **D3:** complete the remaining connected admission, RUN/health and workloads.
3. **D4:** finish independent verifier coverage for all 29 requirements and freeze.
4. **D5:** only after separate approval, run fresh acceptance, 100 attempts and
   100 task pairs with cleanup, restoration and independent replay.

B49 stays null. No VM, capture, provider call, spend or boot slot was used.
