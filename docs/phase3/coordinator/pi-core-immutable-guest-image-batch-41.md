# D2 batch 41 — immutable ARM64 host disk, offline

From signed merge `879dadbf57a106e9aec74435451fa6e717a13ab0`. This batch produced
a **real raw disk file**, not just a recipe. It is a developer candidate; it
is neither boot-tested nor a live-environment approval. Only sources, small
pins, tests and this handoff belong in Git. Do not publish or rebuild the local
disk for a status check.

| Retained object | Bytes | SHA-256 |
|---|---:|---|
| Raw disk, both GPTs and EFI System Partition | 3,542,227,456 | `4ab772f03800e430eed9aba1bc690508413072d41fdba009b0b6e492c7510288` |
| Unpadded immutable SquashFS | 3,406,943,909 | `42f38fc97f01248623fb69f2720d24a42b7e6a405a50124bc7cbe9542601409a` |
| Ubuntu ARM64 kernel, 7.0.0-14-generic (7.0.0-14.14) | 23,831,944 | `9a3baf125237a503fe47e8d36429e328307340e85ba371aa52e64b1b7d1c8d1e` |
| Root-bound initramfs, uncompressed newc | 1,312,768 | `e59ae34a7437dc04671ca6c2e879b03c4cd082c91c41a142e2b70d6df724aa34` |

Under `.aragorn/host-preflight/build-b41/`, the disk is
`media-v1/aragorn-arm64.raw`. Boot files are in `boot/`; the full Linux
inventory is `image/59122196cb507ab4182468b525cde753482c3429407ca457585fed6c832af806/inventory.jsonl`.
Its SHA-256 is `421801ead2c04324f04ab7c7d4d0d7e8f093cfc7fedf82b96d769558e6bf1208`.
The approved expected projection was compared with a full readback of the
repacked root: **181,293 paths**, including link targets, file digests, numeric
ownership, modes and eight extended-attribute records. All 21 relocated Ubuntu
library aliases resolved to equal-content targets before substitution.
See the [image recipe](../../../packaging/pi-core/immutable-host-b41/image-recipe.md)
and [media pins](../../../packaging/pi-core/immutable-host-b41/media-output.json).

## What was reused

The base is the authenticated Ubuntu 26.04 ARM64 ISO's minimal SquashFS.
The protected coordinator projection includes the retained wrapper and trusted
sources, B38's 658 CPython files (including 69 native extensions), B39's loader
layout, and B40's three clients and six ELF providers. Seven additional pinned
Ubuntu runtime packages complete the selected dependency graph. No client,
interpreter or historical workload was rebuilt, and neither the build sysroot
nor the Alpine host toolchain was installed into the guest.

The unchanged host custody checker accepted the candidate host profile/export:
**793 files, 54,401,615 bytes, 102 native files, 249 declared dependency
edges**. The physical projection also contains the host profile itself.
The ABI receipt covers 213 new versioned edges (3,831 edge-symbol
observations); 20 B40 edges and one B38 edge were reused. Those are static
symbol/version checks, not runtime resolution, unversioned relocation proof,
installed identity or proof of source consumption. The
[host profile pins](../../../packaging/pi-core/immutable-host-b41/payload-pins.json)
are reviewable proposals, not operator grants.

## Boot chain and limits

The ARM64 fallback path on the 128 MiB FAT32 ESP is
`/EFI/BOOT/BOOTAA64.EFI`. It holds the Ubuntu EFI stub, kernel, initramfs and
fixed command line. GPT partition two is the ARM64 root type, read-only
attribute set, with zero sector padding. Kernel, modules and stub derive from
Ubuntu release inputs; the initramfs embeds a cross-compiled static PID 1,
five matching signed NVMe module payloads and a policy binding the root,
loader and systemd manager. No package maintainer scripts ran.

Early init is designed to refuse a writable whole disk **or** root partition,
a changed root digest, a nonempty or linked physical `/lib`, the wrong bind or
substituted manager/loader. It verifies the manager through the file descriptor
it passes to exec. This is code and artifact evidence only. SquashFS, an
ordinary file's permissions and GPT attributes do not prove a hypervisor
presented read-only media. The **outer UKI is unsigned**; the inner kernel's
certificate is not outer-image authentication. No key generation, enrollment,
Secure Boot change or live operation occurred.

The producer retained its initial host-profile order refusal, a transient
metadata-read refusal and the original compiler refusal. Corrections preserve
component-wise path ordering, separate durable writes from independent
readback, and initialize the ioctl result without suppressing warnings.
The GNU readelf adapter normalizes hexadecimal symbol sizes without dropping
rows. No historical check or live effect was retried.

## Reviewed checks

The raw-media verifier read the finished ordinary file, validated its protective
MBR, primary and backup GPTs, mirrored FAT32 tables, single removable EFI path,
stock EFI entry code, kernel, command line, initramfs, embedded root and complete
disk digest. The initramfs was independently decoded with libarchive; the root
inventory and boot policy join to the same root SHA-256 and length.

| Stage | Passing checks | Pipeline fingerprint |
|---|---:|---|
| Pipeline registry capacity (256 to 260 for these four entries) | 4 | `f5851afc66139bda4dc1888b12fc382b8a6d9aa6a1df35c6aab3ec017f4963a0` |
| Immutable payload | 6 | `ef5175f252415f59016b5ec5afd4a18fc9c936917338673b9fb1a48f19d94fb3` |
| Root inventory | 4 | `f144323e40f13e14a40e4b9c08aeeea536d3f692ba3dcca52ea99f42917b13ce` |
| Boot artifacts | 4 | `0e2fdd153faba457d61508df8223b93f0c8ffadc403fce854ac2e5e7a4e3a1b8` |
| Raw disk and firmware | 9 | `d6b9aad3fc74539ce64664bbe7fed118e4b084eb3cdca04b258fca1106626add` |

**27 passing checks across the final five stage results.** The first disk-stage
fingerprint (`d13bdc4e79a41d713ddd393aac2d7c23205955f0a69dab978b7595a8ce3b7894`)
is retained as a failure: the parser mistook mtools' redundant VFAT spelling of
the volume label and EFI file for extra entries. The corrected reader checks
the exact short/long spelling, slot identity and short-name checksum; an added
mutation test rejects alternate spellings or a wrong checksum. Only this
changed stage ran again. No media rebuild, old regression suite, capture,
mount, target-code execution, or performance measurement occurred.

## Next gates

1. **D2 — open.** Approve a firmware trust path for these exact boot bytes (or
   sign and pin a successor) and confirm a candidate VM can expose a genuinely
   read-only, 512-byte-sector NVMe disk. No automatic downgrade if it cannot.
   A separately authorized, isolated boot must observe PID 1, the read-only
   mounts, installed identities and prior-state restoration. The root has an
   empty machine ID and does not provision the protected worker image or writable
   Aragorn state; prepare their independent custody, mounts and cleanup before
   the useful pilot. Still needed: actual source observations, health/loss
   accounting, protected effect, recovery and full timings. Boot authorization
   is not provider or pilot authorization.
2. **D3 — open.** Connect remaining admission, RUN/health and workload paths
   and independent consumers on that same deployment.
3. **D4 — not frozen.** Close all 29 managed requirements, their concrete
   surfaces and independent verifier bindings before freezing once.
4. **D5 — not authorized.** On the frozen deployment perform fresh admission,
   100 actual attempts and 100 paired tasks; retain failures, verify thresholds,
   cleanup and independent offline replay. No D5 sample was collected here.
