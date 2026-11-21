# D2 batch 74 — read the mounted state filesystem's own UUID

Parent: signed B73 merge `ffb89526a275e7c6515cf30f7f68226d5649a3fa`.
This connects a guest measurement to the protected caller and independent
reader; no installed measurement or activation is claimed. B49 remains null.

For a future explicitly approved, provider-unavailable B70 plan, add the
canonical, nonzero `filesystem_uuid` to `sensor_state_observation`.
The digest of the entire protected plan binds the opt-in and expected value.
Old plans do not request this operation. B59/B71 releases are unchanged.

At both observation boundaries the manager checks the state mount table and
held private anchor, filesystem magic, owner/mode, device, inode and mount ID.
The observer opens only `.` read-only relative to that held anchor; it never
opens a block device. The read-only Linux `FS_IOC_GETFSUUID` request returns
a one-byte length and 16 UUID bytes. A v2 sensor view stores both original
17-byte replies as hex in the normal receipt. The expected UUID isn't passed to
the observation routine. Unsupported, partial or unstable reads cannot produce
a successful finding; there's no fallback to another device or identity.
A complete stable mismatch is retained as inconsistent and cannot pass the
pre-dispatch check. Publication does not reissue the UUID operation.

The ARM64 request `0x80111500` is present in the **retained** B44 kernel, not
just the sysroot headers: the decoded Image's `do_vfs_ioctl` dispatch at
offset `0x6b5d6c` leads to the 17-byte copy at `0x6b60d4`.
Decoded Image SHA-256: `94e37ccd7694d894e0d21f3f7c2e964046c77ce1c9208e11aa62fc98eb621696`.
This static inspection does not establish how any particular mounted filesystem responds.

The [joined reader](../../../scripts/verify_pi_core_joined_sensor_state.py)
accepts `--require-filesystem-uuid`: both replies must match the plan **and**
the distinct filesystem UUID in the independently pinned B58 volume profile.
Historical results can still describe the old observation but never satisfy
this flag. No filesystem UUID distinguishes a clone, proves encryption or
proves current exclusive attachment.

| New offline stage | Checks passed on first run | Retained fingerprint |
|---|---:|---|
| `pi-core-state-fsuuid-observer-offline` | 5 | `35091c49e9fe6cc7a8ca7b2c3a2838830fcd9c583cfbdac89c734531687f4460` |
| `pi-core-state-fsuuid-entry-offline` | 2 | `81f95cbe662e316f55d50f4b8623b19302ff5a9d206683d78b68f70807bd9cea` |
| `pi-core-state-fsuuid-replay-offline` | 6 | `1906d4a1d5482d257c4bceed123158584ca1a4cf40ff6d9083afdd4294e0a301` |

Only inert kernel/plan fixtures and private test receipts were used. No
real ioctl, storage attach, guest, service, provider, rebuild or spending.

1. **D2 open:** next, corroborate the active encrypted mapping and its backing
   devices. An encryption format and independently authenticated attachment,
   exclusive writer and current head are separate requirements. Finish the
   [worker view](pi-core-worker-visible-tree-decision.md), pin one updated
   deployment, then collect installed health, recovery and timing and run a
   separately authorized pilot.
2. **D3 open:** remaining connected admission, RUN/health and workload evidence.
3. **D4 not frozen:** independently review all 29 requirements and close the
   concrete producer/verifier inventory before freezing.
4. **D5 not authorized:** fresh admission, 100 attempts and 100 paired tasks,
   cleanup and independent replay only after freeze and separate approval.
