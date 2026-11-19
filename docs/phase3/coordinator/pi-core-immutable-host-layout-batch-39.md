# D2 batch 39: immutable host lifecycle selected; boot not verified

Starting point: signed local main merge `059f11440277cd9ad901fe859211b5d38210f779`.
The operator selected an **immutable, whole-image-updated VM guest**. Assemble
the image from authenticated inputs, preserve the existing host verifier,
and verify its actual boot layout before claiming readiness. Do not support
`apt upgrade` inside the guest or suppress Ubuntu's package checks: apply
updates when assembling a new image, pin it, validate it and retain the prior
image for rollback. This choice grants neither permission to publish to a
public Git remote nor permission to run the provider pilot or D5.

## What exists

The [preparer](../../../scripts/prepare_pi_core_immutable_host_layout.py)
created a fresh, private **fragment**, not a disk image or full verifier
export. Its only two files are regular, singly linked, mode 0555, and
matched on readback the bytes previously authenticated from Ubuntu's
`libc6_2.43-2ubuntu2_arm64.deb`. The developer staging directories (0700)
are not evidence of guest ownership, permissions, or mounts.

| Physical location in fragment | Purpose |
| --- | --- |
| `/usr/lib/ld-linux-aarch64.so.1` | Single real loader; no duplicate at another path |
| `/usr/lib/aarch64-linux-gnu/libc.so.6` | Matching Ubuntu libc |
| `/lib/` | Empty real directory; **not** a second populated library tree |

Keep the layout when assembling the guest. In the future authenticated early
boot path, make `/usr/lib` visible at `/lib` with a read-only bind, before the
first real-root ELF execution. Do not replace the empty directory by a symlink
or claim that a directory in the fragment is already mounted. The full
canonical coordinator-host export is a separate interface using the actual
literal paths the verifier expects.

The private output is `.aragorn/host-preflight/immutable-layout-b39/`; its
adjacent `immutable-layout-b39.receipt.json` has SHA-256
`b9b18dbe5a59d12d379e8fd634f747b9109db42dfda6c06b80c9da6b22fcb7cd`.
Only `pi-core-immutable-host-layout-offline` ran: 4 new checks passed
on the first attempt (fingerprint
`665cba6ad8fbf591db4dfa7809e52fa00224f422d53a1db4244de677ada8499f`).
No prior stage ran. No target code, mount, service, VM or provider was used.

## Boot boundary and next work

Ubuntu's `initramfs-tools-core_0.151ubuntu1_all.deb` (SHA-256
`09a2413b6d4e5719c795ed9fd3b6b6e3396274513d6d8b232ca79dc6d9ebc46c`
from the batch-38 signed release's main ARM64 index) contains
`/usr/share/initramfs-tools/init`, SHA-256
`eca0482dafc96e4221ecc67b0c65cb3f7a86e4ed142419b90df741017221570c`.
The unmodified script mounts the real root, runs init-bottom, then invokes
`run-init -n`. If validation fails, it also tries other init programs,
including `/bin/sh`. A hook that merely logs failure, a shell prompt, or a
snapshot name does not establish that the pinned systemd manager booted.
The inspected package is **not** an assembled initramfs.

1. **D2:** pin the build tools and Linux development sysroot; build the three
   batch-38 clients. Verify the installed-form ELFs, Python and full native
   closure. Assemble and independently pin the full host profile, read-only
   root image, kernel and initramfs. Integrate the bind and gate the handoff
   to the exact manager; on failure do not fall through to an alternate init.
   Do not start the guest on a partial candidate.
2. When prerequisites and Mac memory headroom permit isolated Fusion setup,
   check **from the real boot**: systemd as PID 1, intended immutable root,
   no writable overmount, both library paths reaching the same directory and
   regular loader inode, and the unchanged host verifier's interpreter,
   search-path and mapping checks. Demonstrate an owned snapshot restore,
   then power off. Host readiness still does not prove the D2 pilot.
3. **D3 / D4 / D5:** common-deployment coverage; all 29 verifier mappings and
   freeze; separately authorized fresh acceptance and cleanup evidence.
