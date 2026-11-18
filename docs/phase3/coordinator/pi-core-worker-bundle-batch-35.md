# Batch 35: build and independently inspect the managed worker bundle

Signed integration base `ceff4990e4b503d95ffdb674a58fcbc9e6f14669`. The operator selected reproducible bundle consumption, not literal per-npm-module runtime observation. This assignment releases a build-only successor from current tracked adapter sources. The v3 entrypoint and worker source hashes are stale; reuse its verified dependency custody, never its old emitted adapter bytes. Preserve all signed predecessors, drafts, cache outcomes and runtime bounds.

- Build owner (admission agent, coordinator checkout only): new `scripts/build_pi_core_worker_bundle.py` and `packaging/pi-core/worker-bundle-toolchain-v1.json`. Reuse the existing build reader/inventory, fixed tracked source names and pinned inputs. Use a verified build-only standalone esbuild from the local npm archive, never ambient executable resolution, npm acquisition or target execution. Pin its archive/binary, build options, actual current adapter and legacy bytes, and the dependency tree. Produce one deterministic Node ESM entrypoint from the actual current provider-capable caller; handle the fixed legacy CommonJS import explicitly, no broad exclusion or untracked inputs. Build in fresh private scratch, strip environment, confine the compiler to reviewed inputs/no network. Emit raw metadata and a receipt with source/tool/output hashes. Leave failed outcomes unqualified; never publish an unchecked artifact as runtime ready. Provide a callable build entry with fixed defaults and output path for the independent verifier.
- Independent evidence owner (RUN/health agent): new `scripts/verify_pi_core_worker_bundle.py` and, if needed, `scripts/inspect_pi_core_worker_bundle.cjs`. Verify emitted bytes and their source/tool provenance, not just producer PASS; audit the emitted ESM static/dynamic imports and CJS/loader access against an explicit reviewed allowlist using syntax-aware checks that never execute the worker. Reject undeclared or computed external loads, unexpected outputs and unbound files. Provide a verifier entry accepting build outputs; compare independent fresh builds. A failure is not a usable successor.
- Checks owner (workloads agent): new `tests/test_pi_core_worker_bundle.py` and `tests/test_pi_core_worker_bundle_build.py`. Cover changed source/tool/output, undeclared static/dynamic/CJS loads and same-result reproducibility as applicable. Keep local negative fixtures separate from the real build stage. Coordinate function signatures before writing; no agent schedules checks. Only two fresh isolated emissions in the real stage: original and required independent reproduction; not a historical compiler rerun.
- Coordinator: approved claim/roadmap, signed assignments, shared pipeline registration, full input closure, source review and delivery. No legacy installation layout change until artifact output and verified residual loads are known. No service, worker, VM, provider, capture or qualification run. No release of existing worktree drafts.

Handoff: pass only reviewed affected stages, retain exact build output or refusal and name residual prerequisites. D2 remains open through actual consumption/health, timing and the separately authorized pilot. D3 lanes use distinct signed releases for common-deployment producers and consumers; D4 requires full independent inventory and freeze; D5 requires separate fresh execution approval.

## Retained first emission — not accepted, reproduced, installed or run

The 12 new local build-custody and syntax/evidence checks passed once (`2bddbb549e561ccde1dca3ec6c1f3f51feb47af671a83252b86208ef2c1c5ee6`). They did not test a real emitted bundle. The original real build stopped in Darwin dyld/libignition before compiler main (`cb3c366e50c1c0b49b13b3522b2e101b480dae24880d8a8e44e90887997c0a80`). Pinning and admitting the host's read-only dyld bootstrap rules exposed a different failure resolving the staged entrypoint (`4d65a532111fe97407be6e9999c66db32ed9c9b3bd1115ba333208fd366d5ffe`). Allowing the compiler to enumerate only its private working directory fixed that. No failed fingerprint was repeated, no historical stage reran and no provider or target executed.

The resulting original is retained in `.aragorn/pi-core-build/d2-worker-bundle-qyr6cefv/`. Raw records:

| Record | SHA-256 |
|---|---|
| original/entrypoint.js (755,592 bytes) | `0806d07ae9110eaa1d98d97b49d4ee305deaf95b82c0c0b61ca905f24bf73c44` |
| original/meta.json | `aaeac376685027df4780ad5e8c5f8628e6d76134e61a9ebaab347b759ca73bac` |
| original/receipt.json | `c6eb0f9483aacdfc1c5cb3a726bd51026014342f37a303c0b65c06f7ae3d3d65` |
| inspection-refusal.json | `6a208564c60774f9edc9996f0758a8e9971f76666c3d87c16a749f970da78230` |

**Actual outcome:** `original-inspection` refused (stage fingerprint `80b837b5d6b659fc8c31dc3eb5a303d0e474ec156f2dc85d8ab21b812ab33184`); no second emission. The compiler reports 712 build inputs, one JS output and seven static external Node builtins. The output fits the per-source size bound on disk; this is not a Linux file-read witness or proof it fits the event/time budget.

Two static reviews distinguish false positives (the lexical CommonJS initializer, local provider parameter named `binding`, and hoisted destructuring of exact builtins) from the unresolved TypeBox path. At lines 1866–1880 it probes and constructs JavaScript from strings. Lines 13701–13711 contain both the generated validator and its existing interpreted alternative. The Pi tool-argument validation path can select the generated validator. Model arguments are data and the tool schema is pinned: this is **not** evidence of an external load, an exploit or an executed effect. Static imports alone do not constrain the generated body. Simply setting `useAcceleration=false` still performs the initial probe. The native gate fixes argv to Node plus the entrypoint; its environment contains no Node option override.

**Material profile decision before release.** Recommended: keep upstream bytes unchanged; add a versioned native gate/launcher for this managed worker that enforces Node's fixed `--disallow-code-generation-from-strings` argument. Bind the exact gate and argv, require the upstream interpreted fallback, and verify refusal of substituted launch profiles. The flag string is present in the pinned Node binary; effective target enforcement, supported-task behavior and timing remain unproven. Alternative: leave the native gate unchanged and approve a narrowly pinned build-time change to TypeBox's evaluation module that selects its interpreter without probing; independently reconstruct that change and verify the emitted closure. Neither choice licenses a generic eval allowance or waives the undeclared-load rule. First replay the retained bytes for verifier-only changes; produce a new JS original only when actual build inputs change. Preserve the failed stage and prior observations. Batch 35 implementation files remain local pending the applicable passing stage and independent reproduction.

1. D2: original emitted, static inspection refused; select policy, verify/reproduce, connect installed identity and health, time recovery, then separately authorize the useful pilot.
2. D3: admission post-publication readback integrated in `bf1385c`; boundary-health and real confined workload producers remain open.
3. D4: finish independent evidence and surface inventory; no freeze.
4. D5: no final authorization, capture or qualification.

**Later disposition:** the operator selected the managed launcher restriction.
[Batch 36](pi-core-restricted-launch-batch-36.md) records the conditional review,
one independent reproduction, and offline assembly from this retained original.
The original refusal and the predecessor gate remain unchanged.
