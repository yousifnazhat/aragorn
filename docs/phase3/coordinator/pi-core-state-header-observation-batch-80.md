# D2 batch 80 — corroborate current inline LUKS2 headers

Parent: signed B79 merge `9b478017dc9a598eef4db70aed9c6e6af1a17a9e`.
No guest, disk, credential, actual metadata or service was accessed. B49 remains null.

Only a provider-unavailable protected plan explicitly selecting the B79 leaf
check may also select `luks_header_profile`. The operator pins a single
devtmpfs basename, encryption UUID, size of each metadata area and distinct
SHA-256 digests of both full areas. Select these from separately approved
provisioning evidence, never from the disk being evaluated. The new reader's
source must have been consumed by the protected loader. Historical plans and
receipts neither trigger nor satisfy this operation.

The single acquisition is inside the two existing disk/mapper observations.
It pins and rechecks the manager's devtmpfs block inode, opens only that
inode read-only, and checks the opened disk's sequence and geometry before
and after. Only the two preapproved metadata ranges may be read; on a valid
approved layout this excludes binary keyslot material. It verifies the binary
headers, offsets, UUID, matching sequence and padded JSON-region digest, and
each full-area commitment and self-checksum (SHA-256/384/512). Unsupported
or inconsistent copies refuse, including when one copy would be recoverable.
The checksum covers the binary header with its checksum field zeroed and the
whole padded JSON area, following [cryptsetup 2.8.4](https://github.com/mbroz/cryptsetup/blob/v2.8.4/lib/luks2/luks2_disk_metadata.c).
No unlock, JSON interpretation, key handling, header repair or repeat read is performed.

Private evidence retains validated projections and digests rather than the
metadata bytes. `--require-inline-luks-headers` verifies the protected
measurement, both operator pins, the manager's devtmpfs and the B58 volume's
encryption UUID. Replay does not rehash the withheld bytes. A matching pair
means each copy was sampled during the bracket, not an atomic snapshot, a
valid unlock, semantic validation of every JSON field, or proof against a
cloned disk. Checks before/after synchronous I/O enforce refusal on a late
return but cannot interrupt a stuck device; separately verified outer
supervision and safe cleanup remain prerequisites before any pilot.

**Affected stage only:** 15 offline checks passed, fingerprint
`9972f54ed90963ea2e394b1796768b5b5dbc4682a44fee091206bea230582910`.
Retained failed fingerprint `940ba47f1d8aacff461b7a1cffd9f11e2dcbf1f4ecee5cd354939a9f02b8e542`
rejected a hand-built mount fixture with an invalid root parent. The changed
fixture now uses the shared manager mount fixture. Production validation was
not loosened; no other stages ran.

1. D2: still need original-unlock authority and independent custody,
   attachment/single writer and current recovery head; full worker exposure,
   installed health, recovery/timing, and a separately authorized useful pilot.
2. D3: remaining admission, RUN/health, managed workloads and sink evidence.
3. D4: complete the independent inventory and freeze one common deployment.
4. D5: separately authorized fresh admission, 100 attempts and 100 pairs,
   cleanup and independent replay; no qualification now.
