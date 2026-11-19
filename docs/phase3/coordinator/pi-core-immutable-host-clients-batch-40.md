# D2 batch 40 — immutable guest client build

Base: signed merge `74c6a06`. The three requested programs are Ubuntu's
`systemd-run`, `systemctl` and `busctl` (259.5-0ubuntu3, ARM64). The
batch-38 patch changes how these three link and stage, not their security
features. Ubuntu's reduced `stage1` profile is not an equivalent candidate.

## Build inputs

- The cross sysroot locks 196 Ubuntu packages to the signed Resolute release's
  ARM64 main and universe indexes. No package scripts run. The selected
  files are headers, compiler startup objects, libraries and pkg-config data,
  not a bootable root or package installation.
- The private materialization under `.aragorn/host-preflight/build-b40/sysroot-work/root`
  has 2,632 regular files, 330 internal symlinks and 160 directories. Its
  path/mode/content/link inventory digest is
  `6d3f075ecf34e8b479d413da95cd00aae649eb6be5d78571170e636b2fb07c1f`.
  Both spellings of eight case-colliding legacy netfilter header pairs are
  excluded on Darwin. Neither a wrong-case header nor a host path is used
  as a substitute. The guest's real-directory and early-bind policy is
  unchanged; the sysroot's development aliases are **not** that policy.
- The reference feature advertisement comes from
  `libsystemd-shared_259.5-0ubuntu3_arm64.deb`, SHA-256
  `754ac748a6525d153f0edffb419a5b84b5c2b992812219dbe31fa705203a2bdc`.
  Its shared library is used only as a reference; it is forbidden in the
  staged client dependency closure. Both BPF and BTF are enabled. The
  matching `vmlinux.h` comes from the authenticated `linux-bpf-dev`
  package, not a running kernel.
- The build uses Clang 23.1.5, the retained GNU-flavor ELF linker, Meson
  1.9.1 and Ninja 1.13.2. Darwin and its system frameworks remain trusted;
  this is not an attestation of the build host. The Linux-only BPF generator
  is **not** an ARM64 target: the pinned Alpine x86-64 helper actually
  reported `bpftool v7.3.0` under Darwin user-mode instruction translation.
  The nine-file, six-alias Alpine library/program projection has digest
  `a7396d37e1eb0386aad27c6eb56b5088154105dd6fb48584604df477c4398cd4`.
  None of those inputs belongs in the guest. The upstream static glibc helper
  did not initialize in this environment and is not a fallback.
- The initial host preflight refused a Python cache directory whose observed
  mode was `0700`, not read-only. It did not invoke Meson. The corrected
  Python launcher redirects bytecode lookup below a pinned **regular file**;
  that path cannot contain an importable cache regardless of directory modes.
  The refusal and superseded private inputs were retained.
- The first Meson configuration (`b84f0a09…`) stopped when Darwin refused a
  nested sandbox. The replacement (`ec81aebb…`) configured successfully:
  the parent executed the real, separately sandboxed, version-only query in
  response to the build's one-shot request. The retained stdout was
  `bpftool v7.3.0 / using libbpf v1.3 / features: libbfd`. Its first
  compile selection was ambiguous (the executable and Bash completion are
  both named `systemctl`); Meson stopped **before** invoking Ninja.

## Result: all three built and verified offline

The corrected selector used only the three `:executable` targets. The builder
checked and retained the original configuration and reused it without another
configure or version query. Ninja completed 525 actions once. The tagged,
no-rebuild install produced exactly three regular files under `stage/usr/bin`.
The [artifact pins](../../../packaging/pi-core/host-tools-b40/clients.json)
identify attempt `d6904d891442f7a667d324507b2e79256092a74e8ae4d4b0d1bf3858754f2f37`.
Its private directory is `.aragorn/host-preflight/build-b40/client-work/<fingerprint>/`.
No guest executable, systemd manager or kernel BPF program was started.

The [independent static ELF report](pi-core-immutable-host-clients-batch-40.static-elf.json)
is byte-identical to the focused pipeline's stdout (SHA-256
`fb7c5fffeb2cb351ef4017e3cce5c35a8585808eaa9ec100667819150f856249`).
All three declare `/lib/ld-linux-aarch64.so.1`; none carries a private
systemd shared-library dependency or embedded runtime search path. The report
binds nine actual ELF objects (three clients and six providers), 20 versioned
dependency edges, and the release's advertised feature string in read-only
loadable client bytes. Carry these provider hashes into the full host profile;
do **not** copy the build sysroot or Alpine tools into the image.

Only `pi-core-immutable-host-clients-offline` ran: **29 new checks passed**
on its first run, fingerprint `82e52ce95da2ff3fc2830c55fd503be9d7a4b834f182e56e874d279e2f2c420c`.
These are developer checks, not the 29 managed-profile acceptance requirements.

## Evidence boundary

An ARM64 cross-link and offline ELF comparison do not execute these clients
or demonstrate a systemd unit, D-Bus call, runtime loader choice, health,
recovery, or a useful pilot. Even a verified static dependency graph does
not cover unversioned relocations or runtime `dlopen`. The full guest image,
independent host inventory, verified boot and D2 pilot are separate gates.

1. **D2:** assemble the full immutable host image and inventory with the
   pinned clients, libraries and CPython. Pin the kernel/initramfs and verify
   early read-only mounts, real PID 1, loaded identities and restore in a
   separately approved boot. Then close observed health, recovery/full timing
   and the separately authorized useful pilot.
2. **D3:** connect the remaining admission, RUN/health and workload paths to
   that same deployment and retain independent evidence.
3. **D4:** close all 29 managed requirements and their concrete verifier
   inventory; freeze only when prerequisites are complete.
4. **D5:** with separate authorization, run fresh admission, 100 attempts and
   100 baseline/instrumented pairs; verify thresholds, cleanup and offline replay.
