# D2 batch 78 — check the mounted filesystem's active encryption mapping

Parent: signed B77 merge `78a008b2d0247d1dc800de29607481d59907101f`.
V1 supports one directly attached LUKS2 state volume with its header on that
device. Other layouts are not eligible. The choice is not a disk nomination,
spending authorization or permission to unlock or run anything. B49 remains null.

In the provider-unavailable B70 plan, select
`state_volume_layout: DIRECT_LUKS2_INLINE_HEADER_V1` with the existing
filesystem UUID and one distinct backing device. A protected-loader receipt
for the mapping reader is mandatory. The B74 observation obtains the state
directory's filesystem identity from its held descriptor. At both ends, a new
reader checks the manager's mount view, reopens only the checked device-mapper
control inode read-only, and asks for live status, dependencies and status
again. It checks the original deadline and refuses partial, mismatched or
changed results. It never requests table parameters or opens the backing disk.

The v3 sensor receipt contains only checked numeric header/target/dependency
bytes, not mapper names, mapper UUIDs, keys or arbitrary returned strings.
Existing custody retains the original projected records and mount streams.
Publication verifies the measured anchor and does not requery the mapper.
The [joined reader](../../../scripts/verify_pi_core_joined_sensor_state.py)
can require `--require-direct-crypt-mapping`; it compares the two edges to
the mounted filesystem, approved protected plan and independent B58 archive.
Historical records can be read under their old contract; they cannot satisfy
the new one. Do not treat two matching observations as continuous monitoring.

The pinned guest has device-mapper built in and dm-crypt packaged as a module.
That does not show a module was loaded or a root service used this source.
This batch does not rebuild or modify the B75 payload or a frozen guest image.

**Affected verification only:** 16 mock-device and private-archive checks passed
in `pi-core-direct-state-mapping-offline`, fingerprint
`63a59a110a2da97f061e5c4aa66a80e92eebd2e7726e2b438acdb0b269fb0bc1`.
The retained first run `62412354a74315e111712680337d9dad527fb3da8d05f1342865cc222ca3c558`
refused a test mount table with parent ID zero. Both fixtures now use the
same valid positive outside-root parent; the production parser is unchanged.
No prior stages, live device operations or qualification cases ran here.

1. **D2:** still need actual same-device LUKS2 metadata and authenticated unlock
   provenance, independent physical attachment and sole writer/current recovery
   head, full worker view, installed health, recovery/timing and a separately
   authorized useful pilot. A matching dm-crypt table cannot distinguish
   a detached header, an underlying stack or a cloned volume.
2. **D3:** complete connected admission, seven RUN classes/six responses,
   sensor loss accounting and workload/sink evidence on one deployment.
3. **D4:** close the independent inventory for 29 managed requirements and
   seven deployment bindings before freezing that deployment.
4. **D5:** separately authorize fresh managed admission, 100 actual attempts
   and 100 paired executions, cleanup and independent replay. No gate closed.
