# Batch 37: restricted host code pins and retained worker inventory

Base: signed and published `fb49c72f9381aee050cc51547fb4ff180db9f7c2`.
D2 requirement: bind the updated trusted host code to the worker's retained
source-plan intent. This is offline preparation only, not a host installation,
an installed inventory, a new build, a source read by the worker, or qualification.
All registry/scheduling and integrations belong to the coordinator.

- Host-source owner: `scripts/prepare_pi_core_restricted_host_sources.py`,
  `packaging/pi-core/restricted-host-sources-v1.json`,
  `tests/test_pi_core_restricted_host_sources.py`. Pin the wrapper, pinned-import
  bootstrap, package and complete relevant in-repo import closure of the
  wrapper's fixed entries using the approved base's tracked bytes. Provide
  the sorted absolute `{path,digest,size}` rows used by the existing host
  preparer. Refuse substitutions, omissions, extra rows and ambiguous trust.
  No discovery of trust from the installed machine, untracked files or ambient
  Python. Keep the full Linux host/stdlib/tools export as a separate prerequisite.
- Worker-inventory owner: `scripts/prepare_pi_core_restricted_worker_inventory.py`,
  `packaging/pi-core/restricted-worker-inventory-v1.json` and
  `tests/test_pi_core_restricted_worker_inventory.py`. Verify the retained
  four-file runtime and the existing pinned worker OS/loader inputs as data,
  join observer pins to the host projection, and produce the actual canonical
  source-plan/v2 bytes consumable by the existing installed-inventory path.
  Bind selected loader files to reviewed identities; distinguish static
  declarations from dynamic resolution, later required reads and measurements.
  Refuse missing/replaced artifacts, unsupported inputs, cross-runtime plans,
  or forged output. Never rebuild the bundle, gate, OS or image.
- Coordinator: own the combined real readback, optional separate focused
  `tests/test_pi_core_restricted_inventory_materialization.py`, output
  checkpoint, roadmap, this handoff, the pipeline registry and signed delivery.
  Preserve actual canonical bytes and their pins, and distinguish a checked-in
  plan from ephemeral evidence. Retained-assets reviewer is read-only.

Only new/affected inert refusal checks and one necessary offline preparation
using actual retained inputs may run, via the reviewed pipeline. Preserve all
prior results and drafts. Never sample or fabricate VM state, use a key, launch
Node, enter a VM, run a service, or start a capture. Handoff requires exact
pins, explicit prerequisites, verified signed merge, and remote readback.

## Prepared inputs and how to use them

Assignment `c0ab348` was signed and published in signed merge `ccefb0f` before
implementation. The [host manifest](../../../packaging/pi-core/restricted-host-sources-v1.json)
selects the wrapper and 103 in-repo Python sources (2,977,272 bytes total),
including the bootstrap loader and both observers. The 104 names were compared
to the wrapper's four dispatch roots, bootstrap and transitive local imports,
and their file bytes to Git blobs in the signed base tree
`342e75c58ae5386b4c4cbe9f16117159b8de4bd8`. This does not pin CPython,
stdlib, third-party Python, native libraries, or systemd tools.

The [reviewable worker plan](../../../packaging/pi-core/restricted-worker-inventory-v1.json)
names one required source (the exact 755,592-byte JS) and one optional data file
(`package.json`). The eight ELF loader paths come from comparing the actual
retained Node and OS bytes with the signed OS checkpoint's static dependency
graph. Both paths for the interpreter are preserved; the pre-gate env program
is not a module read by Node. Gate and Node executable pins are separate. No
loader-cache, process-map, inode, trace or sensor evidence is inferred.

The [checkpoint](../../../packaging/pi-core/restricted-inventory-checkpoint-v1.json)
binds the worker runtime tree, wrapper, host file rows and canonical plan.
Prepared files below are private developer artifacts relative to
`.aragorn/pi-core-build/restricted-inventory-b37/`.

| File | Raw SHA-256 | Intended use |
| --- | --- | --- |
| `host-source-files.json` | `505223fe3c2aa501fdeac925c64e874b6f1adf3b38f82ecd73a48f8c13e45808` | Code rows for the full Linux host profile; **not** the full profile. |
| `worker-source-plan.json` | `305679f5a4891465d0820e2f2adfb3402e60b9d50489c1ccd93bb6ea8bd66ac4` | Exact canonical source-plan/v2 input (no trailing newline). Do not substitute the pretty-printed repository JSON. |
| `outcome.json` | `54cec1c94d3bfb75a19af657f0f00e9c9987a45fe7743dc7cc570b4f5bd1a915` | Developer preparation record only. No trusted host or worker was started. |

The staging directory modes currently read `0700`, not the `0555` checked at
the previous assembly. No mode was changed. The selected runtime's file bytes,
file modes and namespace matched; this handoff makes **no** claim that the
historical directory modes or read-only installation are present.

For the next host-preparation step, supply independently approved canonical
full-profile bytes, their digest and the corresponding retained export to
`scripts.prepare_pi_core_restricted_host_sources.prepare_restricted_coordinator_host`.
It requires an exact match to the newly pinned code namespace, then passes
the **same** bytes and digest to the existing full host verifier. This profile
must describe the selected arm64 CPython 3.12, approved import/search paths and
stdlib/native files, as well as `/usr/bin/systemd-run`, `/usr/bin/systemctl`
and `/usr/bin/busctl`. The retained worker OS and the historical service image
are not that export. No credentials or provider traffic are needed for this step.

## Checks and remaining work

Only three newly registered stages ran; 14 checks passed on their first attempts.
No previous stage, build, service, VM or provider operation was run. The combined
stage retained its two inputs for the protected preparation flow after parsing
the plan with the existing reader. It did not call the installed-view acquisition.

| Stage | Checks | Fingerprint |
| --- | ---: | --- |
| `pi-core-restricted-host-sources-offline` | 7 | `abba851914e6afb5f5c2fa440f4eabe7ea21a5c28670cae02f90fefb824b63fb` |
| `pi-core-restricted-worker-inventory-offline` | 6 | `78e2b36ef8a9dcd6d924230b487696d1629be317185089e5023af77b4c5c89e1` |
| `pi-core-restricted-inventory-materialization-offline` | 1 | `aa4ca68f7945bfbb13631afe13d5498689cf6b9a2f5634e16653da4379293f28` |

1. **D2:** code pinned and worker plan prepared. Full host profile/export is
   missing. Once supplied and verified, actual installation and source/loader
   identities require separate authorization, a protected read-only worker
   view, and independently approved worker/observer roots. Then observe argv,
   source delivery and sensor progress/loss, collect recovery/full timing, and
   obtain approval for the bounded useful pilot.
2. **D3:** finish connected admission, RUN/response and sensor-health coverage,
   workload producers and independent observations on the common deployment.
3. **D4:** close all 29 requirement-to-verifier mappings and freeze the one
   deployment only after prerequisites close.
4. **D5:** separate execution approval; fresh admission surface, 100 attempts
   and 100 workload pairs; cleanup, restoration and independent evidence replay.
