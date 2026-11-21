# B96 — distinguish an inherited null handle from an unrelated filesystem link

The worker's three standard descriptors can legitimately refer to an inherited
`/dev/null` outside its own mount table. That exception does not extend to
every link that reports the device number for null. Both strict replay paths
(current volume and sensor; owned stopped worker) now use the same comparison:

- For a recorded `/dev/stdin`, `/dev/stdout` or `/dev/stderr`, require a
  symlink whose resolved type/mode, inode, filesystem device, special-device
  number and mount ID equal the record for descriptor 0, 1 or 2 respectively.
  A mount ID present in the worker's table must still match its filesystem.
- Every other resolved link subject to this comparison must name a listed mount
  with the matching filesystem. Independently proved masks use their existing
  rules. A filesystem device of `0:0` cannot exclude state; an ordinary
  object's special-device number of `0:0` remains valid.

The finding `worker_device_records_consistent` is emitted only after strict
archive replay succeeds. It does not prove that a link exists on the guest,
that its link text was read by Pi, that equal metadata identifies the same open
file description, or that the two socket directories were enumerated or opened
by Pi. It grants no access or recovery authority. Historical archive replay
keeps its original rules; no old evidence was recaptured or rewritten.

**Verification:** four focused offline tests passed on the first run of
`pi-core-strict-worker-devices-offline`, fingerprint
`sha256:c1126d30e410e782c32cb11f65ac95a20a3fcfeb20427f226153af26b694859e`.
The fixtures include a sealed archive with a valid inherited standard link
and an independently resealed version with an unrelated link to exactly the
same target. Strict replay rejects the latter; historical replay accepts it.
No actual descriptor, disk, guest or protected effect was inspected.

1. **D2:** Keep both socket directories non-listable. Connect the actual
   worker's fixed lookup/denial/link results to independent observation and
   replay. B94 inventories still name the B93 source; do not install changed
   sources under those pins. Current deployment, health, recovery, full timing
   and the useful pilot remain outstanding. B49 stays null.
2. **D3:** Finish connected admission, RUN/health and real workload coverage.
3. **D4:** Complete the 29-requirement evidence and verifier inventory, then freeze.
4. **D5:** Obtain separate authorization for fresh acceptance, 100 attempts,
   100 task pairs, cleanup and independent replay.
