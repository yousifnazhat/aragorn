# D2 batch 70 — observe the owned sensor before dispatch

Signed parent: B69 merge `32147a4313a9ebcd5c36ce0405ec6e454e46f6f8`.
The [stopped-worker mask observer](pi-core-stopped-mask-observer-batch-59.md)
already retains the manager and worker views plus an independent probe witness.
This batch covers a different process: does the service lifecycle's sensor see
the manager's action directory on its own read-only mount?

The optional `sensor_state_observation` section is accepted only on the
provider-unavailable managed path with the protected B68 configuration carrier.
It pins one attempt, clock/boot/time namespace, and expected storage device,
filesystem and backing devices. It does not accept a PID or grant permission
to launch. The bootstrap reserves the original cleanup interval, authenticates
its existing service peer, and observes it before calling the worker.

The observer measures the source directories in the manager's namespace, the
sensor's action directory and both complete mount tables. It holds the process,
root and namespace identities across samples, checks the sensor's unit and
process generation, and checks again during publication. A consistent result
requires the expected device, directory identity, read-only bind and mount
flags; the sensor must not have another mount of the protected state.
If a stable observation is inconsistent, the original bytes can be retained
on a safe destination, but worker dispatch is refused. Missing inputs, an
unsafe evidence destination or a changing view do not produce a positive
result. Do not delete a partial record or retry an ambiguous attempt.

The manager needs an independently provisioned private ext4/xfs mount at
`/run/aragorn-sensor-state-evidence`, with root-owned mode-0700 `cas` and
`receipts` directories. The mount must not be the underlying `/run` tmpfs,
share the nominated state, backing or configuration device, or be visible in
the sampled sensor mount table. B70 does not provision it. The stored members
are the capture record and the original manager and sensor mount streams;
the external-to-CAS, no-replace attempt receipt pins all three. This is local
byte custody, not independent ownership of the physical disk.

From the repository root, use `PYTHONPATH=src python3 -m scripts.verify_pi_core_joined_sensor_state`
with the B58 archive, approved profile/current head/witness pins, protected
plan pin, original public wrapper stdout pin (including the final newline),
and the separate local capture and receipt pins/directories. The reader
validates owner generation, cleanup, clock, deployment/configuration and
directory identities. Directory agreement does not establish simultaneous
capture; `--require-same-manager` adds the manager identity and mount comparison.
The strict direct-filesystem reader treats unknown mount layouts as a refusal.
No data were removed from a mount stream to make it admissible.

| Affected stage | First-run passes | Retained fingerprint |
|---|---:|---|
| `pi-core-owned-sensor-read-offline` | 15 | `37d082b019ac2dab9e4c9c718521cc20f09f2abc6c5424083cbec62d845259fb` |
| `pi-core-owned-sensor-entry-offline` | 7 | `966a42e77dc5333854b421c1f1138808c43e486b3e31160bb0fc2d13615705e7` |
| `pi-core-owned-sensor-replay-offline` | 8 | `4abb20686a5189648a88311946887afaab88768bcaae491edd89daf275f17923` |

All 30 checks used inert process evidence or temporary files. No guest, service,
provider, historical capture, storage attachment or paid operation ran. B49 stays null.

1. **D2 open:** B69 predates these sources. Complete the other role/worker view
   acquisition and external volume identity/freshness, then pin the common
   successor. Installed observation, progress/loss, recovery, timings and the
   useful pilot still require an approved deployment.
2. **D3 open:** finish connected admission, RUN/health and workload evidence.
3. **D4 not frozen:** close the independent executable mapping for all 29 requirements.
4. **D5 not authorized:** after freeze and separate approval, acquire fresh admission
   evidence, 100 attempts and 100 paired tasks; verify cleanup and replay.
