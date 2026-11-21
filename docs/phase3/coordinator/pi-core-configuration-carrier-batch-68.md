# D2 batch 68 — check the configuration disk before using it

Signed parent: `565af93`. The stopped-worker observer, coordinator bootstrap
and broker preparation now use the same check for service configuration at
`/run/aragorn-pi-config/installed`. This is offline implementation; there
is no installed guest observation. B49 stays null.

The [host producer](../../../scripts/prepare_pi_core_configuration_delivery.py)
keeps the original unpadded SquashFS and also publishes a read-back-verified
standalone data disk. The disk has a zero-only tail to the next whole 1 KiB
SquashFS device block and presents 512-byte logical sectors. Its outcome gives
the separate hashes and sizes. It neither nominates the device nor issues a
grant. Do not attach it using B44's single-boot-disk configuration.

For a future protected plan, preserve the original manifest, configurations
and receipt pins and add `service_configuration.carrier`: the approved guest
device number (`major:minor`), `image_bytes` and the unprefixed lowercase
`image_sha256` of the **logical image**, not the padded disk. Those values
must come from authenticated inputs outside the disk. The reserved path
cannot silently fall back to legacy file-only checks. A legacy plan elsewhere
can still read its pinned files but provides no disk claim.

The [guest reader](../../../src/aragorn/pi_core_configuration_carrier.py)
compares the caller and manager namespaces, pins the mounted root and block
node, checks the mount flags, kernel read-only setting and device geometry,
and hashes the logical bytes plus verifies the zero tail before yielding.
It rechecks the held and named objects across the read. The service holder
opens the fixed references from the held mount and checks the installed role
files, their modes, the receipt and each descriptor's mount membership.
Capture plans cannot reuse the nominated state device or backing number as
the configuration carrier.

This is a manager-side check, not proof of the physical asset or absence of
other guests, loop mappings, prior exposure or handles in Pi. Actual private
attachment, independent role-view observation, storage provenance and freshness
remain required. Kernel reads can block: an external owner must enforce the
execution window; the reader's elapsed-time checks are not a watchdog.

| Affected stage | First-run passes | Retained fingerprint |
|---|---:|---|
| `pi-core-protected-configuration-carrier-offline` | 11 | `f10dbea6a352f622b0c65decdff9aeced19f465913cc31500e6bba9f8e547167` |
| `pi-core-configuration-carrier-delivery-offline` | 6 | `c5bd504369aca06d153280c5411949ed3e7ffbcbde007898bd1482982f3d63ba` |

One disposable data-only image was built and independently decoded. The guest
byte reader checked that same file with modeled device geometry. Other kernel
and service tests used inert models or temporary files. No earlier stage ran,
no boot media was rebuilt, and no device, service, grant or spending was activated.

1. **D2 open:** pin the changed trusted sources for the common deployment;
   connect the private attachment and independently observe sensor/Pi exposure,
   source consumption, loss accounting, recovery, and timings before the pilot.
2. **D3 open:** complete admission, RUN/health and workload coverage there.
3. **D4 not frozen:** close independent executable evidence for the 29 requirements.
4. **D5 not authorized:** after freeze and separate authorization, run fresh
   admission, 100 attempts and 100 task pairs; verify cleanup and replay.
