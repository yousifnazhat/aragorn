# Batch 36: managed Node launcher restriction

Signed and published base: `063586ab9dbd2d74c530979931624b1d54626301`. The operator approved fixed Node argv `node --disallow-code-generation-from-strings entrypoint.js` for the bundled managed worker. Keep upstream sources, original worker receipt, v1 nonbundled gate, absolute deadlines, inventory/event caps, and every operational hold. Do not use NODE_OPTIONS or run the target, VM, provider, service, capture or acceptance. No new permissions.

Assignments in the coordinator checkout (no concurrent lane scheduling or Git writes):

* Gate owner: `packaging/pi-core/source-gate-noeval-v2.c`, `packaging/pi-core/source-gate-toolchain-v2.json`, `scripts/build_pi_core_source_gate.py`, and new `tests/test_pi_core_restricted_gate.py` / `tests/test_pi_core_restricted_gate_compile.py`. Retain v1 semantics. Fixed gate validates its complete input argv including its own fixed path, exact Node, flag and entry, closes inherited descriptors, stops once, then supplies only its own constants to execve and the original empty-by-default environment. Emit an independently checkable v2 receipt binding this restriction. Reuse existing host-only compile/link, validate static ELF and fresh output; compile just this successor once. No edits to either file in the retained JS build recipe.
* Launch/observation owner: `src/aragorn/pi_core_confined_launch.py`, `src/aragorn/pi_core_node_source_observer.py`, `src/aragorn/pi_core_node_source_observation_verify.py`, `src/aragorn/pi_core_source_inventory_prepare.py` if necessary, and new `tests/test_pi_core_restricted_launch.py`. Additive restricted bundled runtime receipt and restricted source profile; authenticate exact bundle, Node, gate, immutable files and argv across protected launch and observer/replay. Reuse existing install and inventory validation. Prevent a v1/raw/unobserved launch or claimed gate/argv substitution for this bundle. Retain original validators unchanged for actual predecessors. Never treat planned argv as observed runtime behavior.
* Independent bundle owner: `scripts/inspect_pi_core_worker_bundle.cjs`, `scripts/verify_pi_core_worker_bundle.py`, and new `tests/test_pi_core_restricted_bundle.py`. Keep ordinary verification refusing active string-code paths. For the exact retained JS digest and the reviewed restricted profile only, recognize the reviewed syntactic forms and TypeBox interpreter fallback; no blanket read or eval allowance. Bind externally pinned gate bytes/receipt and fixed argv before returning a conditional static report; no self-asserted runtime enforcement. Preserve raw provenance/metadata/export checks, compare to the independently emitted copy without re-running original emission. Include original-source and profile/argv downgrade, loader substitution and unrelated dynamic-code refusal tests.
* Coordinator owns `src/aragorn/pi_core_restricted_profile.py` (shared fixed identity/argv pins), `scripts/prepare_pi_core_restricted_runtime.py`, `tests/test_pi_core_restricted_runtime.py`, packaging checkpoints, registry, evidence review and release. Reuse the exact retained original, verify provenance, then perform only its as-yet-unperformed independent reproduction. Assemble the four-file runtime from the original JS, pinned predecessor Node and module package metadata, and new gate. No obsolete worker/provider/node_modules padding. Hold on disagreement, retain partial output and no automatic retry.

Handoff criterion: reviewed affected checks, exact unexecuted artifact readback, signed delivery and specific remaining gaps. Never promote local compilation or inspected argv to actual Node enforcement/behavior, pilot readiness, D3 closure, freeze or qualification.

During caller review the coordinator released three existing downstream consumers:
the installed-inventory entry and provider HELD-boundary checks to the gate owner
(`pi_core_installed_inventory_entry.py`, `pi_core_provider_observation.py`, and
`test_pi_core_restricted_consumers.py`), and the standalone public inventory report
in `packaging/pi-core/coordinator.py` plus `test_pi_core_restricted_public_inventory.py`
to the launch owner. The independent build lane also implements the coordinator's
preparation script and three separate runtime-unit, reproduction and assembly stages.
Only the coordinator schedules them. No ownership of frozen artifacts changes.

## Delivered offline

The exact original passed the restricted static audit, which binds 32 reviewed
syntax regions (including the TypeBox probe and fallback) to the full product
digest. The ordinary verifier still rejects string-based code generation. A
single fresh independent emission matched the original JavaScript, metadata
and receipt byte for byte. Neither path evaluated the worker. Original and
reproduction inspection reports both hash to
`b99d3bc74624b2575b8c66521c6ed2cb28ea6055a1bcbb8963e1e2c8a86576bb`.
The [reproduction checkpoint](../../../packaging/pi-core/worker-reproduction-b36.json)
pins the retained outcome; do not schedule the original batch-35 emission stage.

The four files are Node, the 2,152-byte static gate, the **original** entrypoint
and the module package metadata. The [artifact checkpoint](../../../packaging/pi-core/restricted-runtime-artifact-v1.json)
pins the manifest, assembly outcome and receipt. Runtime tree digest:
`sha256:5629ad71c1665dcf2da51fabae3969e4e9ed84db6a648dbdfebbdb52492a4e9e`.
Raw artifacts are retained under `.aragorn/pi-core-build/` in this checkout;
the Git delivery includes source and pins, not the binaries or an installed image.

On the new path the gate verifies its complete argv and calls Node with fixed
arguments and environment. The observer requires kernel cmdline bytes at the
stopped exec of the same process generation. Replay joins them to that stop,
and the provider boundary rejects a missing flag, unbound runtime, or incomplete
source read. Those branches were checked with inert inputs, **not** an observed
Linux startup, proven TypeBox fallback, or a healthy sensor.

### Focused pipeline results

55 methods passed across nine focused stages; the two gate results were reused
by reproduction, not executed twice. No historical build or failed stage was
repeated. Prefixes below identify immutable local pipeline records.

| Restricted stage (all offline) | Methods | Fingerprint prefix |
| --- | ---: | --- |
| gate | 10 | `42907a6548a6` |
| gate-compile | 1 | `c7d091318174` |
| bundle parser refusals | 6 | `6a04893dbec5` |
| runtime custody | 9 | `6bdf4ad67696` |
| reproduction | 1 | `58bdb3a204d3` |
| assembly | 1 | `df70684ec7fe` |
| launch and stopped-argv replay | 12 | `3fb2b69d39a7` |
| provider and installed-inventory consumers | 11 | `b1a356efe78c` |
| public inventory report | 4 | `4072754c2439` |

The parser-refusal methods ran before the shared profile gained the four-file
tree digest. That change did not touch the parser or its gate/argv checks.
Their earlier success is not a cache hit for the final file. The real
reproduction, assembly, launch and consumer checks used the final profile.

1. **D2:** restricted artifact prepared, not installed. Pin the successor host
   wrapper and trusted Python closure, prepare the exact worker-view inventory;
   independently acquire actual stopped argv, source reads and sensor progress/loss,
   then recovery and full timing. The bounded useful pilot requires separate approval.
2. **D3:** connect the remaining admission, RUN/health responses and workload
   paths on that same deployment. Static bundle inspection proves none of them.
3. **D4:** complete the 29-requirement evidence-to-verifier inventory and freeze
   one deployment only after prerequisites close.
4. **D5:** separately authorize the fresh admission inventory, 100 attempts
   and 100 workload pairs, verify cleanup and independently replay retained evidence.
