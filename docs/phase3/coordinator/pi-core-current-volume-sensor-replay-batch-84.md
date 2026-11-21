# D2 B84 — compare the same volume, manager and read-only sensor

Use `--require-current-volume-and-sensor` on the existing
[offline reader](../../../scripts/verify_pi_core_joined_sensor_state.py).
Supply the independently approved plan, original public wrapper bytes,
admission archive and separate private sensor export by their expected pins.
The host inventory must also be available in the read-only archive under
the plan's digest. No device or live process is opened.

Historical replay could correctly report that a read-only sensor saw the same
directory without establishing that it was the **same sensor** as in admission.
Strict replay refuses that result. It compares both the manager and sensor
process generations, mount-table bytes and target identities. It also requires
the full v5 chain: independently nominated filesystem and encryption IDs,
the active one-device mapping, whole-disk evidence, and matching checksummed
on-device LUKS2 metadata. The plan must have the provider disabled. The public
wrapper must bind the private receipt and closed cleanup, and its host record
and pre-capture loader records must match the pinned host inventory.

The positive field is `current_volume_and_sensor_records_matched`, not
“current deployment verified”: these are comparisons of originals from
recorded observations, not proof of a simultaneous capture, physical host
attachment, original unlock, exclusive writer, worker isolation or sensor
health. In particular, the manager's ability to list a socket directory
is not evidence that Pi can list it, nor that Pi can resolve its own links.

| Affected offline stage | Result | Retained fingerprint |
|---|---|---|
| Current volume/sensor replay | 9 passed | `6c4c3c06f4a22e1731f774e35ecb58bd778b5c57ab0a02bce55fa7d77e4605be` |
| Existing socket reader, shared custody path only | 2 passed | `2988ecb103927177c545d817f95abce53a04e5eebed820acaf23f3a4bc9d463a` |

1. D2: wire actual-worker evidence for the two sockets and process-relative
   links; complete protected state custody, health, recovery and timing.
   B49 is unchanged. No worker start or useful pilot is approved here.
2. D3: complete connected admission, RUN/health and workload evidence.
3. D4: close the independent inventory for the 29 requirements, then freeze.
4. D5: obtain separate authorization for fresh admission, 100 attempts and
   100 pairs on the frozen deployment; verify cleanup and replay the evidence.
