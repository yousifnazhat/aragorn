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
