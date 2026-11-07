# Pi-core batch 19: compiled gate and protected inventory preparation

Base: verified signed integration `6c4f43bb4824753f4ce8200d54b99a14d1d84804`.
Scope: one host-side cross-build, offline preparation implementation and only
new/affected checks. No Linux target execution, VM startup, installed-view
creation, tracing, service activation, provider request or qualification.

## Connected scope

The gate-build lane adds a fixed clang/rust-lld recipe, not another runtime or
package resolver. It reuses `build_pi_core_linux.py` for bounded input custody,
canonical receipts and static arm64 ELF validation. It never executes its output.
The original gate source, existing receipt consumer and predecessor artifacts
remain unchanged. Fresh output retains source, object, ELF, commands, toolchain,
logs and provenance; errors retain a failure record without automatic retries.

The independently pinned toolchain manifest is
`packaging/pi-core/source-gate-toolchain-v1.json`, SHA-256
`0c777bdc822ed59eafbb0ca5a0196295659d303fcbe7b833147f2b9a974f57a3`.
It binds the existing Apple clang 21.0.0 binary, reviewed gate source, explicit
rust-lld and its adjacent LLVM library. No host package installation occurred.

The linker and LLVM library were extracted from the official
[Rust 1.99.1 macOS arm64 compiler archive](https://static.rust-lang.org/dist/2026-10-15/rustc-1.99.1-aarch64-apple-darwin.tar.xz).
The archive SHA-256 matched the published Rust distribution manifest:
`23948a0a9c162fd2952defb3fb0462c44e8fcfd1a4ab8a274a1e1bdb2cf810a3`.
The archive and selected tools are retained under the ignored
`.aragorn/pi-core-gate-toolchain/`; no Rust installation or target process ran.
The exact tools and library are byte-pinned, but macOS dynamic system-library
dependencies and the build host are not independently attested. This is local
artifact provenance, not a hermetic-build or vendor-signature-chain claim.

The inventory lane adds a read-only preparation call for two independently
identified, already-held installed filesystem views. A separately pinned plan
selects expected source/loader bytes and gate/Node/observer code pins before any
filesystem access. Worker files require actual read-only views; observer sources
retain the existing stricter immutable-file check. Root ownership, no-follow
ancestry, original deadline, object identities, aliases, named/held rechecks and
ownership-safe descriptor cleanup precede any returned profile.

Canonical source inventory, loader inventory and profile bytes are compatible
with the existing launch/observer/replay consumers. Runtime/deployment identity
is still joined by the existing held launch plan, not included in a circular
profile pin. The helper does not mount a view, copy files, discover trust, start
a worker, create CAS evidence or manufacture future installed identities.

No real installed-view preparation is performed in this batch: the fresh owned
Linux deployment and its exact read-only view are not authorized here. A writable
checkout or staging tree cannot produce a launch-ready installed profile. After
installation, preparation must precede config/deployment pinning; moving,
reinstalling or replacing selected files invalidates their metadata-bound pins.

## Verification and delivery

**58 selected checks passed once:** 21 new gate-builder checks, 33 new installed
inventory-preparation checks and four affected pipeline-capacity checks. No
failed case, rerun, broad suite or historical recapture occurred. The registry
adds only two stages and raises its bound from 185 to 187.

| Selection | Result | SHA-256 fingerprint |
| --- | --- | --- |
| `pi-core-source-gate-build-offline` | 21 PASS | `ad8437675cfa079743efdc236b9fab47b977a56796014aa9c8f1b5cb5ae40cc4` |
| `pi-core-source-inventory-prepare-offline` | 33 PASS | `ef40baf9d6aff513e5f6401aa5dd36871eeecfd09f80483e55cd09adf68ce997` |
| `pipeline-capacity` | 4 PASS | `da87c9cf78dd266ae5bd01e752a1c1b10dc91f4b6dd2277179008b6dc0f390b5` |

Only this reviewed selection executed:

```sh
/opt/homebrew/bin/python3 -B scripts/phase3_pipeline.py run pi-core-source-gate-build-offline pi-core-source-inventory-prepare-offline pipeline-capacity
```

The actual cross-build then ran **one compile and one link**, both exit 0 with
their captured child reaped and empty output/error logs. The existing receipt
consumer accepted the 1,856-byte static arm64 ELF. Static header/disassembly
inspection showed separate read-only and executable segments, no dynamic
interpreter/segment, a non-executable stack, the fixed entrypoint and only the
expected close-range, get-PID, stop, exec and refusal-exit syscall sites. This is
an artifact inspection, not an execution or behavioral qualification.

- Retained output: `.aragorn/pi-core-build/gate-batch-19/`.
- ELF SHA-256: `365cc585f782b65d9a6c63cf2a635725e7f0804b48ff1956e05a3413f54dc376`.
- Existing-schema receipt: `packaging/pi-core/source-gate-build-receipt-v1.json`.
- Receipt SHA-256: `08786bf6c40bc2b3395790dc5989c9c530962b2e32f9ecb7fb97a4a0f5a02290`.
- Command/manifest binding: `34020cd315a11eac6e0f10989f881fb6fe73ff71cf7694a5548c6d8eed7f32c5`.

The receipt is committed; the compiler archive, build tools and actual ELF/logs
remain locally retained ignored artifacts, not a published binary release. The
existing Linux builder can consume that exact ELF plus the committed receipt
and independent receipt pin. Do not rebuild the unchanged gate to repeat this
result or describe these offline checks as installed identity/health evidence.

```sh
/opt/homebrew/bin/python3 -B scripts/build_pi_core_source_gate.py --toolchain-manifest packaging/pi-core/source-gate-toolchain-v1.json --toolchain-digest sha256:0c777bdc822ed59eafbb0ca5a0196295659d303fcbe7b833147f2b9a974f57a3 --output .aragorn/pi-core-build/gate-batch-19
```

The coordinator owns registry changes, review, scheduling and signed release;
parallel lanes do not execute tests, builds or Git mutations.

The code-review skill guides trust-boundary and cross-consumer review. The
commit-work skill limits staging to this batch and requires staged-diff review.
Unrelated drafts and every retained failed or interrupted result remain intact.
Signed source/merge hashes and exact remote readback will be retained in
`.aragorn/pi-core-gate-inventory-batch-19-release.json` and the chat checkpoint.

## Remaining plan

1. **D2:** assemble/install the common successor and prepare its exact protected
   inventories under separate authority; establish actual Node route/kernel
   feasibility, connect the owned provider listener/native dispatcher and
   enabled START, complete approved provider setup, recovery and full timing.
   Then perform the separately authorized useful calculate-and-save pilot.
2. **D3:** complete remaining managed admission, seven RUN event classes/six
   responses, HTTP/DNS/truncate/unlink and real paired-task contexts.
3. **D4:** close the 29-requirement managed producer/evidence/independent-verifier
   inventory and all prerequisites; freeze one complete deployment.
4. **D5:** separately authorized fresh managed acceptance, 100 actual attempts,
   100 actual pairs, unchanged thresholds, retained failures, verified cleanup
   and prior-state restoration, then independent offline replay.
