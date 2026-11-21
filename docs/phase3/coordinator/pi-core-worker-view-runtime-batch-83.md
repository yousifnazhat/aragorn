# D2 B83 — stage the fixed-view gate with the retained worker runtime

This is a four-file **candidate**, not an approved launch profile. The
operator-approved socket directories remain non-listable. B82 supplies the
pre-exec component; the Node executable, entrypoint and package metadata
are the B36 bytes. No dependency installation, JavaScript build, gate
recompilation or guest execution is needed.

The assembler validates the predecessor inventory and the separate signed
gate checkpoint before preparing a new directory. The original runtime,
gate, build records and failed fingerprints are not replaced. A new runtime
digest describes the assembled bytes; it is **not** the old runtime's digest
and must not inherit the old profile's acceptance.

The [artifact checkpoint](../../../packaging/pi-core/worker-view-runtime-checkpoint-v1.json)
pins the original manifest, candidate receipt and tree
`sha256:dd724c97afcbfbcf2d3ecd24322d693099f066fd4ea6d5c81115ba9d8cc425dd`.
Six refusal/contract checks passed (`efa1189ecc59dcaf1f6ab26b60011e14892a89fbdeeccefa31e0124516f757a0`).
One fresh assembly/readback passed (`602042431b5906f01cdd2c613ad7d20dc1ad7085fc2d73b3d012110c09b722b5`).
Both were first runs. The existing launcher's receipt readers rejected
the candidate; no host service or VM was contacted.

The next worker-side integration must recognize this exact identity and
observe only the fixed B82 operations from the same confined task. Do not
enable launch until observation and independent replay reject unexpected
paths, missing or mixed samples, wrong mounts and unverified cleanup.
Neither operator custody nor permission to export a full private managed
result follows from staging.

1. D2: candidate staging only; actual worker lookup/link evidence, volume
   custody and a common installed deployment with measured health, timing
   and recovery remain open. The pilot still requires separate approval.
2. D3: finish connected admission, RUN/health and workload observations.
3. D4: independently cover the 29 requirements and then freeze.
4. D5: separately authorize fresh admission, 100 attempts and 100 pairs;
   verify cleanup and replay. No live evidence or Phase 3 qualification.
