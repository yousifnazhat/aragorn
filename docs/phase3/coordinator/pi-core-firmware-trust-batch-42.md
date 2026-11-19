# D2 batch 42 — firmware trust preparation and storage compatibility

Base: signed B41 merge `633e3f567b3c07b76bae232d3aa5fd80a4a75533`. **Prepared,
not enrolled or boot-tested.** This batch leaves the existing raw disk, unsigned
outer EFI image, root, kernel, initramfs and its refusal conditions unchanged.

## What can be handed to the firmware owner

| Object | SHA-256 |
|---|---|
| Complete 25,254,400-byte B41 EFI file | `233069bd7b0e4b74287f96557622c08d1995d0544059709557c938020f90c6d8` |
| Firmware's PE/COFF (Authenticode) image digest | `76c2fe6d0dca7a7345c47d7409eca573ad2598d147b60caf0136fb6a9461de62` |
| Proposed 76-byte EFI signature list, one SHA-256 entry | `4b731d896c635fb5fdccbd89a5202b16e1598c64b91749d164b8772c22845acd` |

The first digest binds exact bytes, including the PE checksum. The second is
the digest the UEFI image-hash policy uses: it excludes the checksum and
certificate-directory entry. A checksum-only mutation produced the same PE
digest **and was refused by the separate whole-file pin**. The owner GUID is a
label, not a signing key. The proposal is an ordinary file, not an authenticated
variable update. No keys, signatures, enrollment or permission to boot were
created. A match in a forbidden database must not be overridden.
See the [UEFI image validation specification](https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html).

The small [tracked proposal](../../../packaging/pi-core/immutable-host-b42/firmware-trust.json)
and [preparer](../../../scripts/prepare_pi_core_guest_firmware_trust.py) reproduce
the exact record from the pinned B41 EFI file. The local record is
`.aragorn/host-preflight/build-b42/firmware-trust/b41-uki-sha256.esl` (0400).
The B41 disk-to-EFI readback was retained, not rerun. The new independent
reader used [LIEF 1.0.0](https://pypi.org/project/lief/1.0.0/) to compute
the digest of the actual complete EFI bytes, not the 76-byte result. Its one
reviewed Darwin CPython 3.12 ARM64 wheel is retained under
`.aragorn/host-preflight/build-b42/reference/`, SHA-256
`92bf3b06c19a1ebd9e7978de47cc61040752ec452f7906bc3aac8d57abb23a8b`.
No pip installation or target code execution was involved.

## Where the backend decision stands

The [NVMe assessment](pi-core-b42-vm-readonly.md) records actual Mac host
descriptor acceptance on the retained B41 disk, not just an API lookup.
The Apple raw attachment uses 512-byte blocks and reported read-only, and an
NVMe configuration retained it. An actual Ubuntu kernel must still observe
`BLKROGET=1` on the whole disk **and** partition 2, and `BLKSSZGET=512` on the
disk. Fusion 26.0.0 supports virtual NVMe but the exact guest guarantee was
not established; the installed Lima/Colima VZ startup path uses VirtIO.

There is a second, independent gap on this Mac: it runs macOS **26.6.2**.
Apple's public [Secure Boot enrollment](https://developer.apple.com/documentation/virtualization/vzefivariablestore/enrollsecurebootsignatures%28_%3A%29)
and [enabled-state readback](https://developer.apple.com/documentation/virtualization/vzefivariablestore/issecurebootenabled)
APIs require **macOS 27**. They are absent from the installed 26.5 SDK.
Creating an ordinary EFI variable store does not demonstrate enrollment or
enforcement. Broadcom's [custom image-hash preconfiguration article](https://knowledge.broadcom.com/external/article/377306/)
covers ESXi/ESX; it is not proof of that interface on the installed Fusion Arm
backend. No supported combined route was established **on this host**. This is
not proof that a guest boot failed or that all backends lack the capability.

**Next operator decision:** nominate a dedicated ARM64 host/backend with a
documented method to enroll and read back this exact image hash. One candidate
is Apple VZ on macOS 27+; check its guest storage behavior separately. Do not
upgrade this Mac, replace trust databases, modify template/host NVRAM, disable
Secure Boot, or switch controllers as an implicit part of this batch.

Before any compatibility boot, record the exact owned VM/firmware and isolated
variable store; separately approve the target, trust policy, enrollment and
bounded boot/cleanup procedure. Verify the raw EFI and disk pins; preserve
revocations and read back effective enforcement, expected trust anchors and
the candidate digest in db and absent from dbx. Exclude alternate boot media,
EFI add-ons, shares, network and writable overlays. A refusal or ambiguous
result is retained and stops the attempt. Observations must cover the guest
disk and partition, PID 1, mounts and restoration; no write probe is needed.
Enrollment and compatibility boot are not permission to run the provider/pilot.

## Affected results

| Stage | Checks | Result fingerprint |
|---|---:|---|
| Firmware proposal, refusals and independent digest | 5 | `357192b24cfcdefb9c01196bac73b04f137b3cb3d40e191866f9c540d5e5c6fd` |
| Darwin NVMe attachment descriptors | 1 | `eb88cdc646c1e35b9da01db02889c6629f0ba9cba5e395148c43f80e08e89639` |
| Pipeline registry capacity (260 → 262 for the two new stages) | 4 | `1422bb6443c144ec09ad981b5b1f938a16f0cbea26293f3664c74ad5e5f384fe` |

All ten passed on their first run. No unchanged stage, B41 disk build,
regression suite, guest, service, pilot or qualification campaign was run.

1. **D2 open.** Resolve the backend decision above, then independently verify
   authorized boot and installed identities. Protected worker/state, consumed
   source, sensor health, recovery/timing and the separately authorized pilot remain.
2. **D3 open.** Connect remaining admission, RUN/health and workload evidence
   on the same deployment.
3. **D4 not frozen.** Complete independent verifier coverage for all 29 managed
   requirements and their concrete surfaces, then freeze once.
4. **D5 not authorized.** After freeze and separate approval, run fresh
   admission, 100 attempts and 100 paired tasks, verify thresholds, cleanup and
   independent replay.
