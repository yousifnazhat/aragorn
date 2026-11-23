# B106 — bind the B105 worker and its exact observer sources

The [offline preparer](../../../scripts/prepare_pi_core_b106_worker_binding.py)
uses the retained [B105 payload and outcome](pi-core-common-successor-batch-105.md)
and the original [B63 source plan](pi-core-protected-capture-payload-batch-63.md).
The 37-row split worker layout (24 directories and 13 files) matches the
independent B64 projection at SHA-256
`26c5d0d1b43ef688845db21fcd3e9c9ce600078389ba2f2c469dc9ba4fa0ace9`.
There is no worker rebuild, selection of the B86 gate, or reuse of any release.

The canonical source-plan/v2 changes only `node_observer_digest`, from
`sha256:7eca9a6c0457089c32b3d2bf80a8809db0c820c4cb64cafc2118d64729be8c02`
to `sha256:82851dcea5299a9455574694ee00f62a2e2d1647744a80fdafb7524ac6736dcd`.
The base observer digest is unchanged. Both observer files were checked in
the actual retained manager and service locations against their respective
B104/B105 inventories. The fixed gate, Node executable, both source rows,
and eight distinct loader paths were read from their B105 staging locations
and checked by exact length, mode and digest. The two loader aliases by
content remain distinct paths. The broader layout pin also covers the
launcher support `env`, which is not part of the Node loader inventory.

The existing installed-inventory **parser** accepted the exact canonical
plan. It did not open installed views. The preparer retained the following
files once under `~/Library/Application Support/Aragorn-B106-Offline/` and
verified readback. The plan is 1,832 bytes without a trailing newline.

| File | SHA-256 |
|---|---|
| `worker-source-plan.json` | `a97e19440e7576edd52039334e9969e3681d8b9280f4eabd1f03aa9da1876e0f` |
| `outcome.json` | `3fd1eb46026a629d065d0aeeb73c5a2940099f4cef77f2468997a6100ba9b06e` |

For later use, nominate that plan by its digest in the existing protected
installed-inventory path. The actual worker and observer root identities
and the installed source and loader inventory digests have not been acquired;
do not derive them from B106's developer filesystem. The old B63 source plan
and all existing release records remain unchanged. Socket listing remains denied and no
worker-side lookup or process-relative link result was observed.

Only `pi-core-b106-worker-observer-binding-offline` ran. Three checks
passed at `8844a765e214059f8af0a09e567d74c008c1e079dfdff54c43b1b55994e85998`:
exact one-pin projection, refusal of same-length substituted bytes, and
refusal to overwrite. The one local preparation then checked the selected
real files and published the offline outputs. No historical tests reran.

1. **D2:** Offline worker/observer binding retained. Media preparation is
   outside this batch. Actual installed identities, consumed-source and
   approved exceptions evidence, installed health, independent output,
   timing/recovery and the separately authorized pilot remain open.
2. **D3:** Finish connected admission, RUN/health and workload coverage.
3. **D4:** Complete independent evidence coverage of all 29 requirements,
   then freeze the one deployment.
4. **D5:** Separately authorize fresh acceptance, 100 attempts and 100 task
   pairs, verify cleanup and independently replay the retained evidence.

B49 remains null. No media build, spending, boot, installation, worker,
service, capture or provider run. No qualification is claimed.
