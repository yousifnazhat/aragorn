# Pi-core D2 batch 4: protected OS provisioning and native supervisor

Date: 2026-11-03. Base: `272232a8d8d99be14ecc2fc7ddcb1514fb5cf2fd`.
Release: parallel implementation, only new/affected checks, verified signed
commit and ordinary push. No live installation, worker, service, provider,
effect, capture, VM lifecycle change or qualification is authorized.

## Implemented and reused

Three nonoverlapping owners supplied static OS assembly, protected provisioning
and native lifecycle code. The coordinator owns shared plan/registry changes,
integration review, focused scheduling and release. Existing Admission/RUN/
Workload worktrees and unrelated drafts were not changed.

`scripts/prepare_pi_core_os_root.py` treats an already-cached Docker image as
data. It verifies the pinned OCI index, selected arm64/v8 manifest, config,
compressed layer digests and uncompressed diff IDs, then resolves the retained
Node executable and `/usr/bin/env` ELF interpreter/dependency closure. It never
executes `ldd`, Node, a shell, a container or target code. Bounded virtual overlay
processing handles links and whiteouts; emitted aliases are regular files.
Debian package ownership and license texts are retained beside the OS root.
No package installation, image pull or source replacement is performed.

`src/aragorn/pi_core_os_provision.py` composes the existing directory inventory,
compiled-receipt validator and protected-tree reader. It exclusively creates one
new root-owned deployment containing `os/`, `runtime/` and a bound receipt.
Descriptor-relative no-follow copying refuses changed bytes, links, special
files, unbound directories and overwrites. Only `node/bin/node` remains executable
in the compiled runtime. Roots are protected 0755; descendants are immutable
0555/0444. Errors preserve partial output and never authorize repair or retry.
The real protected installer was **not invoked**; its checks use owned temporary
files with explicit mocked root custody.

`src/aragorn/pi_core_native_supervisor.py` is an implemented operational caller,
not just an argument renderer. It holds the existing prepared admission/launch
lease, exclusively binds the bootstrap endpoint, attempts one exact transient
unit start, retains MainPID/InvocationID/PIDFD/cgroup identity, validates fixed
unit settings and calls the existing authenticated post-exec activation binder.
A local callback records the newly published activation before START. Native
bootstrap still returns `PROVIDER_UNAVAILABLE`; there is no effect/provider path.

Cleanup reserves time inside the original maximum 30-second caller budget.
It verifies exact unit/process/cgroup ownership, observes exit and absence or
empty retained cgroup, then withdraws only the retained activation/socket and
newly created empty bootstrap directory. Partial start, changed ownership,
uncertain exit or cleanup failure returns `CLEANUP_HOLD`; no broad kills,
deletions, automatic retries or repair are permitted. Every owned handle gets a
close attempt. Native operations were **all mocked** in this batch's checks.

## Review-driven confinement changes

- The selected admitted version is mounted under a private read-only tmpfs
  parent, avoiding per-context directory writes to the pinned OS tree.
- All fixed mountpoints, including both `/tmp` and `/var/tmp`, must be empty.
- Standard streams are disconnected. `BindLogSockets=no` and empty
  `LogNamespace` are explicit and read back; manager and client must support
  systemd **257+** before any resources or service are created. This is a native
  API compatibility prerequisite, **not an upgrade or validation of this host**.
- The legacy relay socket and ambient `/dev/shm`, `/dev/hugepages` and `/dev/pts`
  paths are masked. Worker-supplied shell/path expansions are not accepted.
- Runtime/stop limits, execution hooks, credentials, environment files, mounts,
  executable arguments and confinement properties are checked, not inferred
  from a successful start command. The root system manager and its configuration
  remain trusted host inputs; this is not an adversarial-root boundary.

Design references: [systemd mount and execution semantics](https://www.freedesktop.org/software/systemd/man/257/systemd.exec.html),
[257 D-Bus/property compatibility](https://www.freedesktop.org/software/systemd/man/257/org.freedesktop.systemd1.html),
[private-device namespace implementation](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/namespace.c).
These source reviews are not observed Linux confinement proof.

## Retained real artifacts

The previous compiled artifact is reused without rebuilding or executing it:
`packaging/pi-core/compiled-artifact-v1.json`.

The cached `python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b`
image was exported once as data using the existing `colima` daemon. No container
was created or started. Its outer archive SHA-256 is
`e0f568085ac82e4ed8aa84f7550859ae57af5c27f6142b751889cfbd257d5548`.
The approved source-chain/local-input pins are `os-source-v1.json` and
`os-assembly-inputs-v1.json` under `packaging/pi-core/`.

The current static closure is **9 files, 18 directories, 5,160,984 file bytes**.
Its digest is `sha256:a6d0cce8629274d940f9ca0be9242c0ba76badc2210ae4c121bb2e1c5a95e9eb`.
The full local receipt is
`.aragorn/pi-core-os-inputs/assembled-9c2603fbc1c14646bb42aa828ac3ae5a/os-root-receipt.json`,
SHA-256 `99cdd3ed224d02f2b57530b90eb004292a38fb0d823609781d5f4e441a6c9752`.
`packaging/pi-core/os-artifact-v1.json` records the source, file inventory,
package/license provenance and evidence ceiling. Binary/license artifacts stay
local. Static ELF dependency closure is not ABI, dynamic module loading, kernel,
confinement, useful-task or installed-deployment proof.

## Focused checks and retained failures

Only five new stages and the four affected capacity cases were registered; the
finite registry increased from 134 to 139. No earlier Pi worker, compiler,
identity or complete confined-launch suite was rerun. No historical acceptance,
whole-schema sweep, live capture or performance measurement ran.

| Selected slice | Evidence |
| --- | --- |
| OS archive/ELF behavior | 24 original methods passed; only the positive mountpoint method reran after adding `/var/tmp`; other 23 not rerun |
| Real static assembly | One initial 17-directory assembly, then one necessary 18-directory successor; both retained, neither executed target code |
| Protected provisioner | 14 passed initially; 20 cases failed at the temporary fixture's inherited macOS group. Fixture-only group normalization fixed the cause; only those 20 reran and passed |
| Native supervisor | 55 passed initially; one mocked socket case lacked Linux's `SOCK_CLOEXEC` constant on macOS. Supplying that fixture constant fixed it; only that case reran and passed |
| Affected confinement guards | 10 new guards passed; one existing argv assertion was updated for the masks and ran alone afterward |
| Registry capacity | Four affected checks passed once; no behavioral child execution in those checks |

This gives **130 distinct selected checks with passing evidence** (including one
real static-assembly case), not 130 qualification requirements. There were 153
method executions across the necessary changed-input attempts: 132 passes and
21 retained fixture failures. No unchanged failed fingerprint was retried.
An invalid dotted-method registry selection was refused before any test ran;
the existing module-only selector pattern was used instead, without changing the
pipeline runner's selection contract.

Retained fingerprints (all prefixed `sha256:`):

| Stage / attempt | Fingerprint | Result |
| --- | --- | --- |
| OS behavior, original 24 | `4c73c17eaafb4216a0493ac0859cc2cde692ba0d6443eaba761ff24846be6085` | PASS |
| OS mountpoint, affected 1 | `eaf64a550b77dfeedc5a01d48cfb1de2fa1ff67c0fab9dd7420b29ec89c909cb` | PASS |
| Static assembly, original | `786e0613417410d34292669f544a01dedd69c730518bad85f76ffc3b12b08166` | PASS, superseded topology retained |
| Static assembly, current | `5da3549aa4e176e04e23236872c34f4484e987c0023255a1372989f562540823` | PASS |
| Provisioner, original 34 | `e977b3c0df8d0786d7917825f038eaa46c10905f475555c625a83caddf8c8c00` | FAIL: 14 pass / 20 fixture failures |
| Provisioner, repaired 20 | `96d57e3884eca3fcf20537e33af411b5ef6fb0701ca4604679b26cc93be9b5e4` | PASS |
| Native supervisor, original 56 | `0b826e648639f6fcfc818d8868664fa9af38fcad65fe4ea04815de9dae34225e` | FAIL: 55 pass / 1 fixture error |
| Native supervisor, repaired 1 | `604f430ab10bd5671fe5eb3bf78d364671601069e8a46d5cbe5bd3dfa5871773` | PASS |
| Native-plan guards, 10 | `328c8db4c38686ba9610b6a69fce302fde1c99a711c4d01a7265dbead5e170a2` | PASS |
| Existing mask assertion, 1 | `ba0ab66dc59a5fd878f705d2c6e0360783ca372bf83048247c20bc107de2757b` | PASS |
| Capacity, 4 | `fc49f56a839eabcb6c16809331652b9a5bde6ac41ce15d67b76acaebff1867ba` | PASS |

The native stage's explicit closure also lists `test_pi_core_confined_launch.py`,
although the native tests do not import it. Updating the old argv assertion last
changes its current declared fingerprint to
`sha256:c88fe50666708e7d4b0e1d1056813afede5a3b2bee8713932ead278fb88a65c6`.
A read-only fingerprint reconstruction confirms that this unused assertion is
the **only** difference from the retained one-case PASS: native production and
native fixture bytes remain unchanged. Do not label this new fingerprint PASS,
copy/erase records or rerun the native case merely for that unrelated assertion.
The changed assertion has its own pipeline evidence above. These are reviewed
component results, not a current aggregate cache or deployment qualification.

## Remaining plan

1. **D2 next:** protected action-identity handoff to the existing unprivileged
   relay, then credential-isolated provider/data mediation. Keep the same Pi
   runtime and reuse existing broker/receipts; do not weaken process protections.
2. **D2 pilot, separately authorized:** provision the pinned roots on a compatible
   controlled Linux host, demonstrate useful allowed/blocked work, independently
   observe effect/health, and verify process/mount/activation cleanup. No live
   authority is granted by this implementation checkpoint.
3. **D3:** complete lifecycle/update/revocation, RUN and meaningful sensor-health
   coverage, then actual workload and timing adapters on the common deployment.
4. **D4:** implement the approved 29-requirement successor contract, finish the
   independent verifier inventory and freeze the complete deployment once.
5. **D5:** separately authorized fresh acceptance, retained cleanup evidence and
   offline replay. Phase 3 completion and Phase 4 remain blocked until those pass.

The original 48-ID manifest, historical qualifications and operational holds are
unchanged. Commit identity is the containing verified signed Git commit; the
post-push local release checkpoint and user handoff record its exact SHA.
