# B92 — check the bootstrap socket before the worker resumes

The supervisor creates and owns `bootstrap.sock` before the worker starts.
B87 checked its parent mount and both role sockets but not this first
endpoint through the stopped worker's root. The pre-resume guard now checks
the named socket against the supervisor's original filesystem identity.
The listener handle has a different kernel identity; it is not a substitute
for the named object. This check neither connects to the socket nor creates
a third directory-permission exception.

The existing private result format and prior guest artifacts are unchanged.
This is a source change: a previously built guest does not acquire it.

Only `pi-core-stopped-worker-socket-mounts-offline` ran. Seven affected
checks passed on their first run (fingerprint
`1e92e7e2c40a89e4307f41a7ce6fdc0cfb4cd530ab1472ecf984e275603e5fa3`).
The checks used inert metadata and checked handle cleanup, including when
both a name and its purported owner pin changed between the two samples.

1. D2: the protected startup now checks which bootstrap endpoint the worker
   sees. It does not prove Pi's own permissions or process-relative lookups.
   Actual observation, sensor loss accounting, recovery, timing and pilot
   evidence remain open. B49 stays null.
2. D3: finish connected admission, RUN/health and the workload carrier and
   copy-fixture decisions on the common deployment.
3. D4: finish the 29-requirement independent verifier inventory; no freeze.
4. D5: separate execution approval, fresh acceptance, measurements, cleanup
   and independent replay. No Phase 3 qualification.
