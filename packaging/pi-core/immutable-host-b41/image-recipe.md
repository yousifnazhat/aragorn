# Offline root filesystem

The base is the **signed Ubuntu 26.04 ARM64 desktop ISO's `casper/minimal.squashfs`**, not a running guest, a host directory tree, or the full desktop live session. The exact ISO, embedded member, exported pseudo file, host-only SquashFS executables and non-system decoder libraries are pinned in `image-inputs.json`. The guest manager, service units and their original Linux ownership come from that authenticated base; no host package, package postinst or chroot supplies guest system files.

To prepare the retained inputs in a fresh private build directory, verify the ISO against the authenticated distribution checksum and the recorded digest. Extract only the raw member using `/usr/bin/bsdtar -xOf "$ISO" casper/minimal.squashfs`; check its digest. With the pinned SquashFS 4.7.5 tools and private decoder library directory, export the member as data with `unsquashfs -processors 5 -no-progress -pf base.pseudo base.squashfs`. Check the recorded pseudo-file digest. Do not extract this guest onto a Darwin filesystem; that would not preserve arbitrary Linux metadata.

Starting from that prepared private directory (`.aragorn/host-preflight/build-b41/image`) and the B41 protected payload, the assembly command is:

```sh
python3.12 -B -m scripts.prepare_pi_core_immutable_image \
  .aragorn/host-preflight/build-b41/payload \
  3cd63c0accffb9c42eb99f89056e19e3f65bbeb36ff7b17f62c5592a8335e8ce
```

The assembler reserves a new transaction; it does not overwrite or automatically rerun an existing one. The checked-out output record in `image-output.json` identifies the retained transaction. It contains the physical unpadded `root.squashfs`, `inventory.jsonl` derived from a full readback, `receipt.json`, build logs and the intermediate pseudo streams. The inventory covers the complete guest namespace including numeric ownership, mode, mtime, device numbers, logical content hashes, hardlink targets, symlink destinations, sparse flags and Linux xattrs. Every inventory row matched the separately derived expected projection. Published pins need not duplicate these multi-gigabyte local artifacts in Git.

The image has a physically empty `/lib`, real `/usr/lib` and a single regular canonical loader at `/usr/lib/ld-linux-aarch64.so.1`. When an incoming library pathname was an alias, the old equal-content target became a relative alias to the newly pinned regular path; a differing library build is rejected. The boot handoff owns the eventual read-only bind of `/usr/lib` at `/lib`; no such mount was performed on the build host. The base has an empty `/etc/machine-id`. A booted writable state policy, actual PID 1, system bus and operation of guest services have **not** been demonstrated. No guest provisioning, pilot or Phase 3 qualification is implied.
