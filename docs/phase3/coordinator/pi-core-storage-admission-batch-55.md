# D2 batch 55 — read-only storage and role-view check

Base: signed `170a4d7`. Implements the offline comparison in the
[B54 storage specification](pi-core-service-state-recovery-batch-54.md).
There is no attach, start, recovery, health publication, B49 nomination or
live observation in this batch. Neither the B44 disk nor the B50 release changed.

## Using retained evidence

With an existing private Aragorn CAS and **two independently obtained** SHA-256
pins, the reader is `PYTHONPATH=src python3 -m aragorn.pi_core_state_admission CAS PROFILE_PIN LATEST_PIN`.
It opens the CAS read-only. Every referenced blob is read with a byte limit
and verified against its digest. Missing inputs or conflicting records refuse.
No trusted pilot pins or production capture are shipped. Do not use the
sample identities, an arbitrary command line digest, or a value supplied by
the volume as a substitute for approval or for the latest off-volume witness.

| Input | Bindings used |
|---|---|
| Approved `pilot-state-profile/v1` | Deployment, image and configuration digests; per-role UID/GID; external backing identity, encryption and filesystem UUIDs and supported filesystem (ext4 or XFS). |
| Independent `pilot-state-independent-head/v1` | Profile and capture pins, boot ID, exclusive writer/fence, device-mapper and backing devices, latest generation and state digest, no unresolved attempts, process identities, worker root and admitted cwd. Its authenticity and currency must come from outside the state volume. |
| `pilot-state-role-capture/v1` and its blobs | Observed image/configuration/deployment and volume identities, source-directory stats, before/after process and namespace identities, original Linux mountinfo per role, statx at each target, and the stopped Pi gate's namespace walk and handle records. |

All control objects use the `aragorn/` schema prefix and canonical integer JSON
plus LF. See [the entrypoint](../../../src/aragorn/pi_core_state_admission.py)
for exact fields and [the inert composition fixture](../../../tests/test_pi_core_state_admission.py)
for the wire format. Directory `mode` is the full stat mode, not just permissions.
The three manager objects correspond to the private backing root and its
two source directories, not stats taken from unbound placeholders.

The [mount check](../../../src/aragorn/pi_core_state_mounts.py) requires the
exact state filesystem, bind roots, targets, access and private flags in all
five roles. A sensor view must be read-only even when the underlying filesystem
is writable. Extra aliases, shadowing mounts, exposed physical backing devices
and wrong source objects refuse. The [Pi check](../../../src/aragorn/pi_core_state_exposure.py)
joins worker-visible names to mount IDs/devices, resolves links, and checks
root, admitted cwd, task and descriptor sets while the single-threaded gate is
stopped. Only the three null standard descriptors are expected. Missing,
truncated or unclassifiable data is not a clean result.

**Evidence ceiling:** exit 0 means consistent supplied records, not proof the
observer reported every accessible object, that the latest witness is genuine,
or that isolation continues after the sample. This is not a launcher interlock.
A future trusted acquisition must hold the same subjects, collect in Pi's
visibility context, account for all changes/errors, and handle inaccessible or
oversized namespaces by refusing. No key is an input. No synthetic result can
substitute for a guest capture or become an MP1 PASS.

## Focused verification

| Stage | Passed once | Fingerprint |
|---|---:|---|
| `pi-core-pilot-state-admission-offline` | 19 | `b7df13cc0c9c63e6c8bc3629957113012c799d27498dc0be664aedb97aafa280` |
| `pipeline-capacity` (284 registered slots) | 4 | `4285e9f65989674eafba9177b0203a9098669704dfcf8ce6e8e37b107193dadb` |

1. **D2 open:** offline consumer delivered. Matching acquisition, independent witness,
   installed view/health, recovery/timing and a separately authorized pilot remain.
2. **D3 open:** connect remaining common-deployment admission, RUN/health and workloads.
3. **D4 not frozen:** complete the 29-requirement independent-verifier inventory.
4. **D5 not authorized:** only after freeze and approval acquire fresh admission
   evidence, 100 attempts and 100 task pairs; verify thresholds, cleanup and replay.
