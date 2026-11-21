# B91 — verify who was assigned the read-only state view

The two B84 archives could agree on a process and its read-only mount without
showing that the protected configuration assigned that process's UID and GID
to the sensor. Strict replay now reads the canonical configuration bytes at
the digest already shared by the protected plan, sensor record and independent
admission archive. It rejects a missing original, a different action, sensor,
provider or worker principal, or grants for another installation context.
The root manager still has its separate custody checks. Historical replay
does not assert the new `configured_role_principals_matched` finding.

Only `pi-core-current-volume-sensor-replay-offline` ran. All 12 affected
checks passed on the first run, including independently resealed wrong roles
and the previously refused writable mount. Fingerprint:
`ab7f4da6a6a8eed7f9c1bed710295f418343657c80d67f77ea601dd46b0574a9`.
No original captures were repeated and B49 remains null.

1. D2: the identity assignment now joins to the recorded sensor view. This
   does not prove file consumption, exclusive attachment, worker permissions,
   runtime health or pilot readiness. Recovery and timing still need evidence.
2. D3: finish common-deployment admission and RUN/health coverage; select
   the real workload carrier and copy fixture before measuring.
3. D4: complete independent coverage for the 29 requirements before freeze.
4. D5: separately authorize fresh acceptance, 100 attempts and 100 pairs,
   cleanup and independent replay. No live samples or qualification here.
