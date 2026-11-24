# B112 — B111 host, services and worker on one offline ARM64 disk

This is a media-preparation checkpoint for the Pi-core managed profile, not a
boot, installation, firmware enrollment, or pilot release.

### Inputs and readback

The root adds the [B111 staged files](pi-core-host-retention-successor-batch-111.md)
to the authenticated Ubuntu filesystem used for B41. It preserves the original
real `/lib` layout and library aliases. B111 supplies the protected host wrapper
and both retention modules; the worker and protected service files are copied
from that layout, not rebuilt. Adding these bytes installs no service state,
credential, retention release, operator approval or populated evidence store.

Before packing, the B41 whole-root inventory and signed B111 inputs gave an
expected **182,229 paths and eight extended-attribute records**, inventory
SHA-256 `6ee50fe7b8cb234b9e8a8439735f736b677bf5ee133d14851a91822cb588160c`.
Compared with the 181,293 B41 paths, 936 names are new and 18 existing rows
change. This comparison covers the stock system as well as the 1,791 B111
entries; merely finding the host profile on disk would not be enough.

To reproduce that expectation independently, start with B41's authenticated
`inventory.jsonl` (SHA-256 `421801ead2c04324f04ab7c7d4d0d7e8f093cfc7fedf82b96d769558e6bf1208`;
location fingerprint in the [B41 catalog](../../../packaging/pi-core/immutable-host-b41/image-output.json)).
Index by absolute path and overlay B111 `payload.json` (pin below in the media
catalog): preserve its mode, use `D`/`R`, uid/gid 0, mtime 1776907354 and empty
xattrs. For files include B111 size and SHA-256, `sparse=0`. Keep every other
row unchanged. Hash the concatenation in path order (root first), one compact
ASCII JSON object with sorted keys and a trailing LF per row. This expectation
does not depend on the compressor or its output.

The B44 ARM64 kernel, modules and static early-boot observer are reused. The
old initramfs itself cannot be reused byte-for-byte: its 112-byte policy pins
the **old** root. The successor replaces that member with the new root length
and digest while keeping the expected manager and loader. The new EFI image
therefore needs its own whole-file digest, firmware image digest and detached
candidate signature list. No EFI variable was written. The early observer's
`ARAGORN_B44_V1` message format identifies its protocol, not the disk it ran on.

The [media catalog](../../../packaging/pi-core/immutable-host-b112/media-output.json)
names the exact private candidate produced by the [offline builder](../../../scripts/prepare_pi_core_b112_media.py).
The raw media and intermediate files stay in `~/Library/Application Support/Aragorn-B112-Offline/`;
Git carries the pins, not the multi-gigabyte disk. The EFI image is unsigned;
the detached 76-byte hash list is a proposed firmware input, not a trust decision.

| Retained artifact | Bytes | SHA-256 |
|---|---:|---|
| Raw ARM64 disk, 512-byte sectors | 3,595,017,728 | `aae016bd1b7ef412e619bd82adc6cb9b436349fe9bfe48a0a0ba091e8b646cec` |
| Root SquashFS | 3,459,734,201 | `5c54018c1d9fa506933235aded1d2aad551929b5d8f76112ef9125e7c5941441` |
| Removable `BOOTAA64.EFI` | 25,274,880 | `7c5d6d5ed501780c352416c0b71f07d0a6d57aa0aa30d0f4fdb3ed6680d766f8` |
| Detached trust proposal | 76 | `517294dfd51f6788a7bdc63e3afd2eecdbe918fe12e8ab4cd6d68be273bc5aa4` |

The [independent reader](../../../scripts/verify_pi_core_b112_media.py) checked
both partition tables, the EFI path and embedded startup code, the kernel and
the exact policy-only initramfs change. It decoded the root directly from the
same open raw disk and matched all 182,229 entries and eight xattrs to the
precomputed inventory. Two **new** pipeline stages ran once each:

| Stage | Result | Fingerprint |
|---|---|---|
| `pi-core-b112-media-guards-offline` | 4/4 refusal checks passed | `94d29518af3a087a5930506f4bd3364877fd4ffab9baa48b6ee4c10713767bed` |
| `pi-core-b112-media-readback-offline` | 1/1 actual disk readback passed | `9459710a71752fc83b0aee041ab390f71f8cfaac12625fce4d9a050a48d0fabc` |

No previous stage ran. The finding covers media identity and contents, not
firmware behavior, bootability on an actual VM, installed service identity or
the calculate-and-save pilot. B49 was not edited.

### Next authorization boundary

1. **D2 open:** Bind the host runner, its firmware-store baseline, bounded serial
   recorder and offline replay to the exact successor disk and EFI pins. A B44
   request or B49 compatibility packet cannot authorize B112. Before boot, the
   dedicated host, budget/window, private evidence destination and cleanup owner
   need approval. A useful task also needs separately bounded provider and effect
   authority, actual installed identity and sensor health, timing, recovery,
   refusal and cleanup evidence.
2. **D3 open:** Finish remaining connected admission, RUN/health and workload
   coverage on the same deployment.
3. **D4 not frozen:** Close the independent evidence mapping for all 29 managed
   requirements before freezing the deployment.
4. **D5 gated:** Separately authorize fresh acceptance, 100 attempts and
   100 baseline/instrumented pairs, verified cleanup and independent replay.
