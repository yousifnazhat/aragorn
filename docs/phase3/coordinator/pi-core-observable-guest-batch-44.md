# D2 batch 44 — observable ARM64 guest, built but not booted

Base: signed merge `af4e9f31dde43ae048fe399e069780ab47398ef6`. The B44 raw
disk exists and has been independently read as an ordinary file. No allocation,
transfer, firmware-store creation, enrollment, boot or pilot occurred. The
[successor boot request](../../../packaging/pi-core/immutable-host-b44/boot-request.json)
keeps every B43 hold; it substitutes the new disk, UKI and firmware pins.
Never apply the B42 allow entry to this image.

## Sealed outputs

| Object | SHA-256 |
|---|---|
| Raw GPT disk, 3,542,227,456 bytes | `c87cf6ef3a6f728958256bd278a748f5f71fae78b3f0de91c02ee1dba1a4837c` |
| Unsigned outer UKI, 25,274,880 bytes | `bc5ce331a61b4a35350adfbf4d6a4acb4061754d94078a94f558a009449f6a27` |
| PE/COFF image digest for firmware db | `fa2ccca39b781d7e20baad88944bf0a52c5b578034d49b6839dd79f4040a22fa` |
| Detached proposed EFI signature list, 76 bytes | `ef48fe74972ba8f7343ea74fcd44544bcf8c467521c750031f02cfe11b5fbb30` |
| Root-bound initramfs | `cee1fd866eb661b18270748cacb0e1083b346c7334dcca071e2d8fb9665fe307` |

The [full pins](../../../packaging/pi-core/immutable-host-b44/media-output.json)
name the private build directory beneath `.aragorn/host-preflight/build-b44/`.
It contains `aragorn-arm64.raw`, `BOOTAA64.EFI`, `initramfs.cpio`,
`b44-uki-sha256.esl`, inputs and receipt. Git carries sources and pins,
not gigabytes of media. The [builder](../../../scripts/prepare_pi_core_observable_guest.py)
made one fresh build. It preserved B41's kernel, modules, root filesystem,
policy, manager and loader. The previous archive was reconstructed byte-for-byte
before substituting only its static `/init`; the UKI pins a new command line
adding only `console=hvc0`. The retained kernel configuration includes built-in
HVC, VirtIO console and PCI support.

## What a future guest record can establish

The [early init and witness](../../../packaging/pi-core/immutable-host-b44/boot-init.c)
never uses a disk write as a probe:

1. PID 1 reads `BLKROGET` separately on the whole NVMe disk and partition 2,
   checks the logical sector is 512 bytes and reads the partition byte length.
   It verifies root contents and padding before mounting. It joins the mounted
   SquashFS to the checked partition and records the read-only root and distinct
   read-only library bind identities.
2. After the root handoff, a child gets the already-verified manager file
   descriptor. The parent executes that descriptor. The child compares the
   kernel's `/proc/1/exe` file identity with it, checks the mount IDs and
   directory identities through **PID 1's** root and verifies the executable
   again before reporting. A pre-exec announcement is not sufficient.
3. Only then can the child emit one bounded record to the verified, write-only
   [hvc0 character device](https://github.com/torvalds/linux/blob/v7.0/drivers/tty/hvc/hvc_console.c).
   It includes the kernel boot UUID, geometry, read-only flags, PID and digest
   joins. At most 500 observation polls of 10 ms each; no repeated effects,
   console input or second write. A refusal, pressure on the serial port, or a
   witness that never sees the manager may yield no usable record.

The [offline reader](../../../scripts/inspect_pi_core_observable_serial.py)
requires the retained file and its independently supplied capture digest;
it preserves raw record offset and length. It refuses missing, mixed, duplicate,
malformed, truncated, over-limit or conflicting records and captures containing
a refusal or kernel panic. It checks expected manager, root, aligned partition
length and an external boot UUID when known. A match means **guest reported
the specified facts**. It is neither a host attestation nor proof that systemd
became ready. It cannot establish capture completeness, guest integrity, later
mount state, or worker/source identity by itself.

## Affected checks only

| Stage | Checks | Passed fingerprint |
|---|---:|---|
| Final raw media, archive, inputs/build and approval pins, independent LIEF PE hash and ESL | 5 | `e53e7f2838247b575b32c9f98947c557304886c55913c89320d7f9f8ceadcaf0` |
| Serial reader and negative cases (inert byte fixtures only) | 6 | `db0bc67a152b64756b2d470eb547d0b18743fcce9059841d59d4d83ddcb1245d` |
| Registry capacity and guards, 263 → 265 | 4 | `45a3c756a11d9f52c85bf915d54ced9fa600192f0fa56b9027da49fa8fdfb2d5` |

All 15 passed on their first run. No historical stage, live capture or
qualification sample was run.

## Next authorization boundary

1. **D2 open.** Bind the signed host runner and independent, bounded raw-capture
   recorder to this exact B44 disk/store/configuration and one exclusive
   attempt. B43's local preview opens **B41 only**; it is not a B44 runner.
   Retain host timing, candidate hashes, fixture/store identity, stream
   completeness, exit and cleanup. Follow the [separate custody, funding,
   enrollment and boot approvals](pi-core-isolated-boot-approval-batch-43.md)
   using B44's pins, approved revocations and store readback. Boot is not the
   useful pilot: worker/source identity, sensor health, recovery/timing and
   that separately authorized pilot remain.
2. **D3 open:** complete admission, RUN/health and workload paths on the same deployment.
3. **D4 not frozen:** finish independent evidence coverage of all concrete
   surfaces for the 29 managed requirements, then freeze.
4. **D5 not authorized:** after freeze and separate approval, fresh admission,
   100 actual attempts, 100 task pairs, thresholds, cleanup and independent replay.
