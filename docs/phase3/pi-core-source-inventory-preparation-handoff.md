# D2 installed source-inventory preparation

`prepare_pi_source_inventories` prepares the exact existing Node observer and
independent replay contracts from installed objects. It does not install files,
construct a worker root, launch Node, observe consumption, assert health or close
a Phase 3 requirement. This implementation batch performs no live operation.

## Caller contract

The callable is in `aragorn.pi_core_source_inventory_prepare`. Supply:

- `expected_manifest_raw` and its **independently approved**
  `expected_manifest_digest`. The canonical `aragorn/pi-core-source-plan/v1`
  document has exactly `schema`, `pins`, `sources`, `required_sources` and
  `loader_files`. `pins` contains only `gate_digest`, `node_digest`,
  `producer_digest` and `node_observer_digest`; source and loader rows contain
  exact worker-visible `path` and expected `digest`.
- Borrowed `worker_root_fd` and `observer_root_fd`, plus independently pinned
  `expected_worker_root_identity` and `expected_observer_root_identity`. These
  are already-held protected installed views, not arbitrary PIDs or paths. Root
  identities use the existing complete file-identity fields. Acquire authority
  for those identities through the existing protected provisioning/installation
  workflow; do not adopt an unknown root merely by hashing its present contents.
- A mandatory original monotonic `deadline` within the existing provisioning
  bound of 600 seconds. No operation extends that deadline.

The worker descriptor must expose the **actual completed read-only view** with
the exact absolute paths that the worker will see, including its runtime,
admitted source and loader objects. A source archive, host staging directory,
copied image or an unmounted future bind specification cannot supply installed
worker identities. Missing or writable views are prerequisites, not an invitation
for this helper to mount, repair or relabel them. Worker roots, ancestry and each
leaf independently prove read-only status through held descriptors.

The observer descriptor names the protected controller view containing the two
producer Python files at their fixed paths. Those sources retain the existing
stricter no-write-bit rule; an observer read-only mount does not excuse writable
producer modes. This distinction matches actual arming behavior.

The reviewed required-source subset is preserved, not auto-expanded or inferred
from discovered files. Gate/Node fixed paths can reappear in a declared role
only with the same pin; aliases under different paths/views are refused.

## Returned artifacts and follow-on steps

The frozen result contains four immutable canonical byte strings:

1. `source_inventory_raw`: `aragorn/pi-core-node-source-inventory/v2`, exact
   path-sorted `sources`, observed identities and genuine `readonly_view: true`.
2. `loader_inventory_raw`: `aragorn/pi-core-loader-inventory/v1`, path-sorted
   `loaders` using the separate existing executable-size bound.
3. `profile_raw`: the existing `aragorn/pi-core-node-source-profile/v1`, with all
   six pins, suitable for explicit approval/pinning in the protected launch
   configuration. Runtime and deployment pins are deliberately absent to avoid
   configuration self-reference.
4. `preparation_raw`: a nonqualifying receipt joining reviewed manifest, both
   selected roots, four code identities and output pins. Its authority is
   `INSTALLED_VIEW_PREPARATION_ONLY_NOT_SOURCE_CONSUMPTION_HEALTH_OR_LAUNCH`.

Only after protected output review should the coordinator retain these documents
in the existing evidence CAS and approve the profile for the changed successor.
The exact source/loader file bytes must already be retained under their approved
content pins for independent replay; this helper neither writes CAS blobs nor
promotes missing evidence into acceptance. Later arming revalidates installed
identities against the actual captured worker, and independent consumed-source,
health, timing and cleanup evidence remain mandatory.

Only owned descriptor duplicates are closed; borrowed descriptors remain with
the caller. Failed opens, substitutions, unsafe modes, aliases and expired
deadlines return no prepared profile. An ambiguous close is attempted once and
reported with `held_fds`/`ambiguous_fds`; the caller must preserve that ownership
hold, not automatically retry a possibly reused descriptor.

## Validation scope

The new focused tests use an inert descriptor/filesystem fixture to cover pinned
intent, both views, source versus producer protection, immutable identity and
named-object joins, aliases, forbidden links, deadline bounds, borrowed-handle
preservation and cleanup ambiguity. A narrow independent-consumer check verifies
the emitted inventory schema, bytes and digests; it is not acquisition proof.
No target processes, services, mounts, build, provider call or acceptance capture
are part of these checks. The coordinator owns registration and execution of the
new stage only; unchanged historical successes remain retained.
