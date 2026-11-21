# D2 batch 66 — deliver the late service configuration outside the boot image

Parent: signed B65 merge `a7c84c9`. The B65 host, worker, service payload and
coordinator remain unchanged. A protected operator can now prepare the exact
configuration layout the coordinator already reads, without rebuilding the guest.

The [offline producer](../../../scripts/prepare_pi_core_configuration_delivery.py)
accepts one private, canonical, three-role configuration file and a SHA-256
digest supplied independently of that file. It does not issue or renew a grant.
Action and sensor must agree on the grant. The restricted Node executable and
runtime, worker unit shape and source-manifest suffix of the admitted version
must all match. The grant must still be current before publication. An expired
input or occupied output is refused, not repaired or retried.

The result is a read-only SquashFS and a separate outcome containing its digest
and the coordinator's four-field `service_configuration` section. The pinned
writer and reader work on ordinary files: no mount, boot or root access. Before
publication the reader opens the held image, checks every name, type, mode,
Linux owner and byte, and the producer rechecks the original image. An interrupted
directory is not an approved delivery. The final bytes and section require
independently authenticated transfer and approval; the outcome cannot provide
its own provenance.

For a **future, separately authorized** installation, the private manager must
expose only that approved image at `/run/aragorn-pi-config`, with a private
read-only mount, outside Pi's view. It must prove the exact source, mount flags,
namespace isolation and guest-side readback. Do not mount over an occupied
target, persist the grant in B65, expose the entire directory to services, or
use an old image to refresh a grant. Released plans still bind their original
deployment, launch, configuration, deadlines and separate authorities. Nothing
here establishes actual admission, freshness of a unit, sensor health, or
authority to use the provider.

Only `pi-core-private-configuration-delivery-offline` ran: **9 passed** on the
first run, fingerprint `ccbfcf664e5b7f676e630d52c7608b1254a832df280716bc491728a67629b25d`.
One check built and independently decoded a disposable configuration-only image
using deliberately expired fixture data and a fixed test clock. No operational
configuration, provider credential, B49 entry, or qualification sample was created.

1. **D2 open:** next connect manager-only storage and configuration attachment
   and independent device/mount readback. Then installed observation, health,
   recovery, full timings and the separately authorized useful pilot.
2. **D3 open:** remaining admission, RUN/health and workload paths on the same deployment.
3. **D4 not frozen:** complete the executable independent inventory for all 29 requirements.
4. **D5 not authorized:** fresh admission, 100 attempts, 100 pairs, restoration
   and independent replay only after freeze and separate authorization.
