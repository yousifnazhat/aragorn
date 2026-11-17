# Pi-core batch 24: protected host and installed-inventory preparation

Base: signed published `e03a8e106e73223d2a802588e09a2b17361d2dc3`.
Assignment: signed `80956a1`, published in signed merge
`b9dc9de211c6b424376f717d2e0fdfca4438b8f8` before implementation.
Status: implemented and independently reviewed offline; 93 new/affected checks
passed on first execution. No live operation released.

## Scope and nonoverlapping ownership

1. `inventory_dependency_review` owns new
   `scripts/prepare_pi_core_coordinator_host.py` and
   `tests/test_pi_core_coordinator_host_prepare.py`.
2. `handoff_gate_review` owns new
   `src/aragorn/pi_core_installed_inventory_entry.py` and
   `tests/test_pi_core_installed_inventory_entry.py`.
3. `timing_recovery_review` reviews both lanes and the fixed dispatch, read-only.
4. Coordinator owns the additive fixed preparation dispatch in
   `packaging/pi-core/coordinator.py`, new
   `tests/test_pi_core_inventory_dispatch.py`, shared documentation, registry,
   minimal capacity adjustment, focused execution and signed delivery.

Lanes do not run tests, builds, repository imports, target programs, Git writes
or live operations. Do not change the existing root execution path or historical
inventory helper except where explicitly owned above. Preserve all drafts,
frozen predecessors, failed fingerprints, deadlines and operational holds.

## Retained host export preparation

`prepare_pi_coordinator_host_profile(expected_profile_raw, *,
expected_profile_digest, retained_root)` returns immutable `profile_raw` and
`preparation_raw` byte strings. Reuse the exact batch-23 host schema/validator,
existing developer-input reading helper and static arm64 ELF parser. Check the
independent expected profile pin before reading the retained export; never
derive expected trust from discovered host files or ambient Python.

The caller supplies a retained export directory, never `/`. Its complete file
namespace must equal the declared absolute profile paths relative to that export.
Check regular files, no links/special files/aliases, exact bytes/sizes, absent
zip placeholders, source/stdlib bounds and stable readback. Do not claim that
developer input custody is installed root protection.

Python/control tools and ELF or shared-library candidates must pass the existing
arm64 parser. A declared interpreter must exist, and each direct dependency must
have one unambiguous declared ELF candidate with the matching name/SONAME.
Preserve the parser's narrow supported search-path policy. Record static edges,
not claims about actual VM loader/cache/dlopen resolution or ABI execution.
Return the unchanged approved profile and a
`PREPARED_RETAINED_EXPORT_NOT_INSTALLED_OR_EXECUTED` receipt with qualification
false. No downloads, package discovery, provisioning, target execution or output
filesystem writes belong in this function. The CLI emits bounded canonical JSON
for explicit caller retention; it does not auto-approve new pins.

## Installed-inventory entry and fixed dispatch

Add only the literal `--prepare-inventories` prefix to the existing root CLI:
`--prepare-inventories PROFILE_PATH PROFILE_DIGEST PLAN_PATH PLAN_DIGEST DEADLINE_NS`.
Without the prefix, the original managed-bootstrap call remains unchanged.
Both routes use the same pinned host custody and verified source loader before
any Aragorn import. No arbitrary module, command or callback selector is allowed.

The new fixed entry exports
`run(plan_path, expected_plan_digest, *, deadline_ns, source_loader, host_custody)`.
Its exact canonical plan fields are `schema`, `host_profile_digest`,
`source_plan`, `worker_view`, `observer_root_identity`; schema is
`aragorn/pi-core-installed-inventory-plan/v1`. `source_plan` is the existing
`{path,digest}` protected reference. `worker_view` is exactly `{path,identity}`;
the path names an already completed protected read-only view, not `/`, staging
trees or a future bind-mount specification. The observer root is fixed to `/`
in this pinned VM host. Both root identities must be independently approved in
the plan using the existing verifier identity schema, never self-pinned from
current `fstat` observations.

Reuse coordinator `_Inputs`/`_custody`, additionally require this new entry's
consumed-source record, and validate source intent before acquiring views.
Acquire protected no-follow worker ancestry and the fixed observer-root handle,
compare independently expected roots, and call the existing
`prepare_pi_source_inventories` exactly once. Recheck named/held roots and source/
host custody, then close only owned descriptors once. The existing helper still
requires actual `ST_RDONLY` throughout the worker view. Preserve its uncertain
descriptor evidence without adopting or retrying its owned closes.

Return the common root observation fields used by batch 23, with
`managed_call_attempted: false`, `managed_result: null`, `deployment_digest: null`,
and these additive fields: boolean `preparation_attempted`, boolean
`owned_views_closed`, `artifacts` and `artifact_digests`. The last two are null
on refusal or exact dictionaries with keys `source_inventory`,
`loader_inventory`, `profile`, `preparation`; artifact values are parsed canonical
documents from the existing helper. Success status is
`INVENTORIES_PREPARED_NOT_QUALIFIED`; failure remains refused/indeterminate or a
cleanup hold with the existing fixed failure phases plus `INVENTORY_PREPARATION`.
Keep host/source before/after snapshots and the plan pin. No original plan body,
credential or arbitrary exception text is emitted.

The wrapper emits bounded canonical preparation metadata/artifacts only after
checking fixed schemas/digests and successful owned cleanup; failures preserve
attempted/unknown status and cleanup holds. Neither route grants fresh health,
approval, activation or effect authority. Do not write CAS, mount views, install
files, start services or invoke a provider. Actual acquisition is a future
separately authorized VM operation, not performed by this implementation batch.

## Focused verification and remaining plan

Registered only the new host, installed-entry and fixed-dispatch stages, plus
four affected capacity checks. The registry now contains 200 stages, matching
the minimally increased capacity. Existing fixture helpers are reused without
discovering historical suites; dispatch selects 13 new cases and exactly nine
affected existing cases. The reviewed input closures contain 8, 96 and 99 paths
respectively, including statically reachable source and fixture dependencies.

The coordinator ran only these stages through `scripts/phase3_pipeline.py`:

| Stage | Checks | Result | Fingerprint |
|---|---:|---|---|
| `pi-core-coordinator-host-prepare-offline` | 33 new | PASS | `sha256:792904b3b9c7694127407be9de0d393f1d231050500040e6f52ac24aad98b7e4` |
| `pi-core-installed-inventory-entry-offline` | 34 new | PASS | `sha256:c80e4be438f0d9ae86891b09f9df4b49a2f2b33960ad6c67b53933fa8ff8ccfd` |
| `pi-core-inventory-dispatch-offline` | 13 new + 9 affected | PASS | `sha256:b9a8603638734e840332e538f613fbac8996f65c148572789f6d81edd3470ee0` |
| `pipeline-capacity` | 4 affected | PASS | `sha256:3f55e412704d41b6463e5b6e14c1367591a1cc538a3f18f587acfc73726a7cf3` |

All 93 checks (80 new, 13 affected) passed once; zero reruns. Logs and exact
result records remain in `.aragorn/phase3-pipeline/<stage>/<fingerprint>/`.
Local checks used Python 3.14.6, not the selected Linux arm64 Python 3.12 target.
The composed inert check runs the new installed entry, existing preparation
helper and public projection together; its artifacts are not installed evidence.
No full historical stage, broad suite, build, target program or live operation
was run. Existing successes and failure records remain unchanged.

Independent review closed schema/projection mismatches and ensured artifact
release is withheld on post-call custody or cleanup failure. Helper-owned
descriptor uncertainty is preserved without an automatic close retry. The
original managed-bootstrap dispatch remains selected when the fixed preparation
prefix is absent. Neither route derives fresh health or effect authority.

The strict no-symlink host profile can refuse merged-/usr layouts or interpreter
aliases. The concrete VM must satisfy the approved paths or require a material
profile decision; flattening an export cannot prove the actual host layout.
Static dependency edges do not establish loader/cache/dlopen resolution or ABI
execution. No concrete retained export or installed inventory was prepared here.

1. **D2:** offline host/export and installed-view preparation implemented; next real selected
   host/installed views, genuine observation/health, raw-effect retention,
   recovery/full timing and separately authorized useful pilot.
2. **D3:** remaining connected admission, RUN/health and workload coverage.
3. **D4:** complete real independent-consumer inventory and freeze.
4. **D5:** authorized fresh acceptance, measurements, cleanup and offline replay.

No concrete VM, host export, provider profile/model, credential setup or spending
bound is selected. Static export pins and mocked checks cannot close D2 or prove
the existing five-second approval/timing feasibility.
