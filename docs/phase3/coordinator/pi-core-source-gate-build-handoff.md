# D2 batch 19: fixed source-gate build handoff

Lane status: helper and **21 new focused inert checks** authored; no tests,
compiler, linker, target executable, VM/service or Git action run by this lane.
The coordinator owns tool acquisition/pinning, reviewed stage execution, the
single actual compile/link, artifact retention and release.

## Fixed interface and reused consumer

`scripts/build_pi_core_source_gate.py` exposes:

```python
build(root, output, toolchain_manifest, toolchain_digest, timeout_seconds=30)
```

The exact canonical manifest uses
`aragorn/pi-core-source-gate-toolchain/v1`, target `linux-arm64-static`,
command profile `clang-rust-lld-gnu/v1`, `source_sha256`, and three exact
`{path, sha256}` records: `compiler`, `linker`, `linker_library`. The independent
manifest digest is mandatory. Paths must already resolve to their regular files;
tools require executable mode. The library must be the reviewed adjacent
`rustc/lib/libLLVM.dylib` for the selected macOS arm64 rust-lld layout.

The helper reuses `regular_bytes`, canonical hashing, errors and the existing
`source_gate_input` ELF/receipt consumer from `scripts/build_pi_core_linux.py`.
`packaging/pi-core/source-gate.c` and the existing builder are unchanged.

## What executes and what never executes

One fixed host clang command compiles the staged source with the Linux arm64
target, freestanding/no-header/no-builtin/no-stack-protector/no-PIC settings and
the integrated compiler/assembler. A second fixed command invokes pinned
rust-lld in GNU flavor for a static arm64 `_start` executable. There are no
manifest-supplied options, headers, libraries, shell commands or automatic
retries. The environment contains only fixed PATH/LANG/LC_ALL; inherited
credentials, SDK paths and compiler/linker overrides are not forwarded.

The output gate, Node, entrypoint and any other target code are **never invoked**.
No `ldd`, loader probe, service, container, network, dependency installation or
VM operation is part of this helper.

## Custody and retained outputs

Output must be an absent named directory within the existing
`.aragorn/pi-core-build` root. Existing outputs are never overwritten. Source,
tool, library and manifest bytes/identities are checked before and after the
build. The recipe, exact argv/environment, compiler/linker logs, object/ELF
digests and input identities are retained.

One original 5–60 second budget (default 30) covers preparation and both commands,
with its final two seconds reserved for terminating/reaping only the captured
host-tool child if necessary. File-backed output is limited to 1 MiB per
command; oversize logs remain retained and no retry is scheduled. Exit races
during termination still require bounded reaping; uncertain cleanup is recorded
as `CLEANUP_HOLD`.

The existing static ELF validator consumes `candidate-receipt.json` before the
helper publishes `build-receipt.json`. A separate `provenance.json` records both
tools, the selected LLVM library and the full recipe. `failure.json` retains
failures, child cleanup state and log paths/hashes; no final receipt is emitted
for failed compilation, linking or validation.

Receipt schema remains `aragorn/pi-core-source-gate-build/v1`, including
`runtime_executed: false`. The command hash binds the complete fixed two-phase
recipe and toolchain manifest pin. This is developer build custody, **not full
transitive host compiler/dyld attestation**, installed process identity, gate
behavior proof, healthy Node observation or Phase 3 qualification.

## Focused input closure

- `scripts/build_pi_core_source_gate.py`
- `scripts/build_pi_core_linux.py` (reused consumer; unchanged)
- `packaging/pi-core/source-gate.c` (unchanged)
- `packaging/pi-core/source-gate-toolchain-v1.json` (coordinator-owned pins)
- `tests/test_pi_core_source_gate_build.py` (21 new methods)

Tests mock every subprocess and use authored ELF bytes only for rejection and
receipt-contract checks. They cover fixed commands/environment, manifest and
source/tool/library substitution, canonical tool paths/library location, fresh
outputs, retained failures, existing ELF rejection, source/identity mutation,
original deadlines and owned child cleanup. They do not constitute a build.
