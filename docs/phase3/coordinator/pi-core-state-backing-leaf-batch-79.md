# D2 batch 79 — tie the encrypted mapping to the kernel's whole-disk record

Parent: verified signed B78 merge `9d9b1687f3e6a9958709add9d1a2e35d126c4e78`.
This is source and offline verification, not installed observation. B49 remains
null. No resources were acquired, no disk or credential was read, no VM was
booted, and no unlock, effect or qualification case was executed.

The provider-unavailable protected sensor plan may add `observe_backing_leaf: true`
to B78's direct-layout, single-backing, filesystem-UUID contract. It requires
the new reader's own verified-loader source row. Older plans remain on their
existing paths. The protected manager takes two sysfs observations **inside**
the original dm-crypt bracket, using the decoded dependency, not a device name
or guessed bus. The reader checks:

- The manager and calling thread share the held root and genuine sysfs mount.
  The kernel's numeric device index must resolve beneath its devices tree.
  Each component is held and checked; a different mount, object or generation
  refuses. The guard opens no block device and cannot issue an unlock.
- The kernel calls this a disk, both device numbers and both disk sequences
  agree, there is no partition attribute (only ENOENT counts), and the list of
  lower block devices is actually readable and empty. Neither missing evidence
  nor an access denial counts as a successful observation.
- The v4 record retains the checked public registration fields and inode chain,
  not arbitrary uevent fields, serials or the device path. Independent replay
  joins both samples to the saved manager mount table and B78 dependencies.
  `--require-backing-leaf` rejects earlier archives; it is not admission or
  an authorization. Publication does not requery the target.

This rules out a partition or a reported block stack. It does **not** identify a
physical disk, distinguish a clone, prove direct host attachment, or prove that
a LUKS2 header on it was used at unlock. Some virtual devices have no reported
lower block device. The separate authenticated attachment, fence and current
external recovery head are still required.

**Checks run:** `pi-core-backing-leaf-offline` — 15 new checks, fingerprint
`f74aa1104f33c74ce26b55d689eb2b352b94572d62f075e7530f894a8add98c3`.
Adding stage 321 required raising the scheduling limit from 320 to 384;
`pipeline-capacity` passed its four affected boundary checks, fingerprint
`9ebadcb39f517e529511d345f18ce0de2cd8db6217d046ef39f09c2d25676c13`.
Both passed on first execution. The scheduler source is a fingerprint input;
this capacity change is not grounds to rerun earlier stages. No result was
cleared, promoted, or used as qualification evidence.

1. **D2:** bind header bytes to the observed disk and independently approved
   volume. Distinguish the current on-device header from evidence of the
   original unlock. Then establish external attachment/fencing and current head,
   full worker view, installed health and recovery/timing; useful pilot needs
   separate authority.
2. **D3:** connect remaining admission, RUN responses and sensor health, and
   workload/sink evidence to the common deployment.
3. **D4:** independently verify all 29 managed requirements and seven shared
   deployment bindings before freeze.
4. **D5:** after separate authorization, run fresh managed admission, 100 actual
   attempts, 100 baseline/instrumented pairs, cleanup and offline replay.
