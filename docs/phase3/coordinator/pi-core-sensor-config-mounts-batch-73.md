# D2 batch 73 — corroborate the sensor's configuration before dispatch

Signed parent: `7ff5adb5c39fd91ae4b730aca1798f25196dc6a0`. Applies to the
explicit [B70 sensor-state observation](pi-core-sensor-state-observation-batch-70.md),
not to general sensor health or the ordinary bootstrap route.

The protected plan already names a configuration disk. A valid plan and an
owner receipt alone did not show the manager mounted that disk, or that the
sensor saw the intended file. Before returning a positive observation, the
request now checks both original mount streams under its original deadline.
The independent reader applies the same rules to exported bytes:

- The manager must have the [B68](pi-core-configuration-carrier-batch-68.md)
  read-only SquashFS carrier at its fixed mountpoint and device number.
- The sensor must show the read-only file `/etc/aragorn/pi-sensor-service.json`
  from the exact installed path on that device and block source, without an
  additional alias. Mount IDs need not agree across namespaces.
- A stable mismatch may be retained as inconsistent under the existing custody
  checks. It cannot return a positive status permitting worker dispatch on this
  route. Missing or unsafe custody cannot create a successful observation.

Only the two existing affected stages ran. Their input lists now include the
two worker-evidence modules imported since B71. Neither stage required a retry.

| Stage | Checks passed | Retained fingerprint |
|---|---:|---|
| `pi-core-owned-sensor-entry-offline` | 8 | `72938759252c17d950dcff1fe5308ff49378de0c07265720c8e1b36b96fb4414` |
| `pi-core-owned-sensor-replay-offline` | 11 | `1818a7a7f71d6659fb1795ea5c702aa635df8d6f1a4b0dc3736445e405338cfd` |

All examples were inert. No live capture, storage access, image rebuild,
spending or B49 change. Mount records establish neither image bytes nor
ownership of the physical asset.

1. **D2 open:** corroborate the state filesystem and its backing independently;
   finish the [worker-view decision](pi-core-worker-visible-tree-decision.md),
   installed health, recovery and timing before the separately authorized pilot.
2. **D3 open:** remaining connected admission, RUN/health and workload evidence.
3. **D4 not frozen:** complete and review all 29 managed requirement mappings.
4. **D5 not authorized:** after freeze and approval, fresh admission, 100 attempts,
   100 task pairs, cleanup and independent replay.
