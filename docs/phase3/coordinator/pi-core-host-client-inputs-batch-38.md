# D2 batch 38 — coordinator host build inputs, not a bootable host

Base: signed merge `dd7bf9c0a1ec7f423b7623a3e904b43e9fd0c95f`. This
checkpoint does not authorize a pilot. No target program ran. No VM was
created, started, stopped or modified. The worker and host verifier are unchanged.

## Reusable output

- **Client sources.** The [Ubuntu release](https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease)
  verified under archive key `F6ECB3762474EDA9D21B7022871920D1991BC93C`.
  The signed release pins the main Sources.xz and ARM64 Packages.xz indexes;
  these authenticate the inputs below. The shipped systemctl, systemd-run and
  busctl bytes in systemd 259.5-0ubuntu3 match the retained ISO copies. All
  three have the forbidden installed RUNPATH. The matching package's standalone
  alternatives are for other commands, not these three.
- The [source preparer](../../../scripts/prepare_pi_core_host_tool_targets.py)
  applied the 19 Ubuntu patches in order, then a narrowly scoped Meson overlay
  for the three clients. It selects upstream internal static archives, an empty
  installed RPATH and a dedicated install tag. Retained source directory:
  `.aragorn/host-preflight/build-b38/client-source/systemd-259.5/`. The patched
  Meson file hashes to `19c3cc650bd3e2d856a172db57a359d04392adbb0e6a53226952998a3d9a5428`.
  Source preparation is **not** a signed toolchain, complete source-tree
  attestation, successful configure/link, or proof of installed ELF metadata.
- **CPython.** Retained **658 files**, 24,302,223 bytes, including 69 native
  extensions, under `/opt/aragorn-cpython` relative to the input export.
  The interpreter and libpython keep their required relative layout without
  replacing Ubuntu's system Python or copying the Bookworm loader/libc.
  The content-addressed private result is under `.aragorn/pi-core-build/host-python-c03a2cacf42161b94c730948e4d1c1dcfd58aede8d003a16312fef0663f3a46e/`.
  It contains exact host file rows, original source/mode rows, bytes and receipt.
- **Library evidence.** Using bytes from the release-index-authenticated Ubuntu
  libc6 2.43-2ubuntu2 package, the static reader matched 56 versioned undefined
  symbols from stock systemctl and 3 from retained Python to that libc.
  Retained Bookworm libc failed the stock-client edge at
  `__isoc23_strtol@GLIBC_2.38`. The check concerns only explicitly nominated
  edges; it does not prove copy relocations, unversioned imports, the 69
  extension modules, runtime loading, or the new **unbuilt** clients.

| Reviewed artifact | SHA-256 |
| --- | --- |
| Signed GA InRelease | `45f95ce276cdba3e41870516a130e03c58b8b7a79e9546b0efe9e526d255740c` |
| main/source/Sources.xz | `dce0fc8e2a473b26f729b1204fd4c12ae068428f743f96761392a059ab7bbfcd` |
| main/binary-arm64/Packages.xz | `537715817d9ed77cc919f5123edb91a48d9ae97abf05588a8f18208cc7227e08` |
| base-files 14ubuntu6 ARM64 deb | `7b2e953decc47b3c325477bbf15f045149a4fff36298a8cd0374d0d00efce2d8` |
| systemd 259.5-0ubuntu3 ARM64 deb | `c66b96c73f929f46e58def60f4a9198830d8ad2b10148fe925ac55064032675f` |
| libc6 2.43-2ubuntu2 ARM64 deb | `6be782d90425acbdf9b7523f791a69a0d3f8770be0750b5cce71d4cdc18397c0` |

## Validation and retained refusal

Final six stage fingerprints below cover 17 focused checks. No historic stage
was scheduled. The first real Python preparation correctly stopped when the
new adapter compared raw JSON bytes to the prior manifest's **canonical JSON**
pin. Retained failed fingerprint:
`058f8084f71c51f34eb2976e37d6b13d2cdb8b1f4897d1c6f746ffd40a806fba`.
The fix checks both the Git-pinned raw file and the original canonical hash
before parsing the archive. The failed result and partial directory remain;
the corrected preparation publishes only after authenticating the inputs.
Only the two affected Python stages and the previously blocked libc check
ran afterward. The three unaffected stages did not rerun.

| Stage (pi-core-host-…-offline) | Checks | Successful fingerprint |
| --- | ---: | --- |
| python-inputs | 6 | `2ba8e9686eadd7461aa82d2571386dcd10bb05029a32c1638aa36ea71c79e78f` |
| python-materialization | 1 | `bfc89cf45ccd1755192b7033d8bdd8ab39d40acae61c52deca249c72888d9732` |
| tool-targets | 3 | `0e620ea0493c07c1de388eaa2f89004cc070beabe9f4f71ac2b0cfb64a6c98fe` |
| tool-source-prep | 1 | `8875cf804649ba76f1c8d604e539d8519ce676302ba065794aff49cd08f91a4a` |
| versioned-symbols | 5 | `371501472467d3ac4481bedcffd04c393b3fb85b94e67bb7632a146fd8419cb6` |
| real-libc-edges | 1 | `9b878f54bb2ae54a70bd4950098240ede91272a68993199dbf3e0662fea69e92` |

## Host lifecycle decision before VM creation

The actual Ubuntu base-files 14ubuntu6 ARM64 control archive's `preinst`
checks `/lib` on install **and upgrade**, rejects a real directory and exits 1.
It expects the symlink `/lib -> usr/lib`. The approved coordinator contract
requires a real directory; not only the three clients but also Ubuntu libc
itself declares `/lib/ld-linux-aarch64.so.1` as PT_INTERP. Rebuilding just the
clients cannot settle this. Upstream systemd 259.5 README also rules out two
independent library hierarchies. A normal package-managed install and a
whole-image-updated appliance are different maintenance contracts.

Do not remove or bypass the vendor check, change the Aragorn verifier, fake a
root with a staging chroot, or silently make in-guest upgrades unsupported.
For a whole-image-updated appliance, keep one library hierarchy and validate
the actual early-boot mount layout, protected loader/paths and kernel-reported
file identities; a bind-mount design is a candidate, not established evidence.
If ordinary in-guest package updates are mandatory, review the precise
vendor-layout custody design separately before creating a guest.

1. **D2:** select the host lifecycle; pin the compiler, native build tools and
   Linux ARM64 development sysroot; compile only the three clients and verify
   their installed-form metadata and complete dependency closure. Prepare the
   independently pinned full host export before VM setup. Installed identity,
   observer health, recovery/timing, restore proof and the authorized pilot remain.
2. **D3:** complete admission, RUN/health and workload paths on one deployment.
3. **D4:** close all 29 independent requirement mappings and freeze.
4. **D5:** separate authorization for fresh acceptance, measurements, cleanup and replay.
