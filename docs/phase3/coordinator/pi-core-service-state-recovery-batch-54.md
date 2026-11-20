# D2 batch 54 — service-owned state placement and recovery

**Design specification, not an installation or recovery receipt.** Base:
`fcb09b7`. This is for a future useful-pilot successor. The B44 compatibility
guest still has exactly one read-only disk; the B50 runner still has zero boot
slots. B49 stays on hold. No device, customer data, destination, key, operator
or budget is nominated here.

## Where the bytes live

Specify **one separately identified, encrypted writable data volume per pilot
deployment**, with a local Linux filesystem supporting POSIX ownership, locking,
atomic same-filesystem rename, and durable file **and directory** sync. No
host-folder share, network filesystem, writable boot-disk overlay or fallback to
temporary storage. The trusted guest exposes it privately at
`/run/aragorn-pilot-state` (root-only, private mount propagation,
`nodev,nosuid,noexec`). The mountpoint is volatile; its contents are on the
data volume. The deployment manifest must pin the backing device identity,
filesystem type/UUID, boot-image digest, service identities and configuration.
A UUID or path alone cannot distinguish an authorized volume from a clone.

| Backing path, relative to the volume root | Guest view and allowed consumer |
|---|---|
| `var/lib/aragorn-runtime-action/` | Same path under guest `/`. Action service: read/write. Sensor: read-only, subject to the existing file modes. Pi and the provider adapter: no mount. |
| `var/lib/aragorn-runtime-provider/` | Same path under guest `/`. Root-owned provider controls and protected evidence, used by the trusted coordinator/mediation path. **Not** a writable mount for the provider network adapter, sensor or Pi. |
| Neither subtree | Pi retains its separate OS root, read-only admitted/runtime binds, bootstrap channel and private disposable scratch. No data device, staging anchor, credential, state descriptor or host directory is inherited. |

Keep each service's `control`, `protected` and `staging` directories distinct,
with `protected` and `staging` on the same filesystem. Preserve existing modes,
UIDs, GIDs, lock files, grant/receipt archives, journals, targets and evidence
stores; do not infer write access from a directory's name. Provider credentials
stay in the separate service credential mechanism, not in this volume or its
backups. Raw evidence may still contain sensitive prompts or results.

**First install is different from reopening state.** In the successor, the
trusted guest manager needs two empty, immutable mountpoints at the final
service paths and a distinct private staging anchor. First verify an authorized
fresh volume and the [B53 seed](pi-core-worker-filesystem-batch-53.md). In a
non-propagating **provisioner-only** namespace present the seed's `var/lib` as
`/var/lib`, preserving access to the held configuration. Both final leaves must
be absent *in that namespace*. Run only the existing [fresh-only installers](../../../src/aragorn/pi_core_broker_base_provision.py)
under future provisioning authority. Reject an existing or partially created
leaf; never empty, adopt or repair it. After successful synced readback, bind
only the two **completed subtrees** onto their respective empty mountpoints in
the trusted guest manager's view. Never replace the manager's or VM host's
entire `/var/lib`. The [service lifecycle](../../../src/aragorn/pi_core_service_lifecycle.py)
can then select its existing per-role bindings; the [Pi launcher](../../../src/aragorn/pi_core_confined_launch.py)
does not bind either subtree. No launch if a placeholder is visible instead
of the authorized volume or if the service and manager resolve different objects.

## Recovery decision

**Recover evidence first, authority last.** Fence new requests and any old
writer. Establish exclusive ownership before writable reattachment; two
apparently healthy hosts are not proof of one writer. Preserve originals and
partial evidence. Start investigation read-only without journal replay or other
implicit repair; if the filesystem cannot be inspected that way, hold the
original and investigate a separately authorized copy. Never roll back in place.

| Condition | Required disposition |
|---|---|
| Service restarts on the same, verified volume | Do **not** run the base installers again. Recheck deployment/volume identity, named-to-open directories, owners, modes, same-device constraints and the effective role mounts. Recreate volatile sockets/listeners through the owned lifecycle; never treat a socket node, PID or lock file as a live owner. |
| Broker journal clear, original claim/receipt available | Use the existing [Pi grant reconciler](../../../src/aragorn/pi_core_request_recovery.py) under its role lock and original bounded deadline. An exact terminal receipt can finalize a matching claim; publish the consumed state durably before pending cleanup. Preserve a BLOCK. A restored AVAILABLE row must not override terminal history. This reconciles metadata; it never repeats the effect. |
| Outstanding effect journal, unmatched claim or missing receipt; cancellation, submission or cleanup uncertain | Hold the affected operation. Preserve pending bytes, archives, protected target and any actual sink/provider records. A connection attempt or cancellation does not prove non-submission. No automatic model call, filesystem effect, grant rotation, unlink or retry. |
| Lost host, missing volume, older copy, duplicate writer or incomplete backup | Keep the deployment held. A backup can recover bytes, **not** current authority or proof of no later effect. Reconcile outstanding attempts against independent observations and the [host-loss procedure](pi-core-owner-evidence-batch-48.md); no replacement attempt or cross-boot monotonic-clock comparison. |

For backups, require a quiesced, synced consistency point for both subtrees and
a private, encrypted off-host copy with separately controlled keys. Record the
deployment and volume identities, snapshot generation, predecessor digest,
manifest of bytes/metadata, and last accounted-for attempt in a signed record
**outside the volume's rollback domain**; the independent custodian must read
it back. On restore, compare against the *latest* independently held record,
not a digest supplied by the backup itself. Account for all attempts since
that point or keep them unresolved. Preserve the original and record any new
volume identity rather than passing off a restore as the original disk.
Without an approved custodian, current external record and matching evidence,
recovery is forensic only. The operator-owned destination remains unset in B49.

Even after reconciliation, historical grants, health, approval windows, process
identities and credentials do not reactivate services. Reestablish current
revocations, independent sensor progress/loss, fresh runtime identity and any
separately approved new authority before protected work. Record independent
ownership/cleanup and prior-state readback before release or disposal.

## Next engineering step and evidence still owed

Implement a **read-only admission check for the proposed backing volume and role
mounts** before adding any attach/start action. Reuse existing filesystem custody,
service plans and grant recovery. With inert inputs, reject wrong or cloned
identity, backing absent, writable sensor bind, Pi-visible device/path/descriptor,
split staging/target filesystem, rollback and ambiguous effects. Do not invent
mount IDs, health or off-host receipts to make this pass.

Later, a separately approved successor needs real mount/namespace and device
identity readback, actual worker-denial and service-access evidence, a bounded
restart/recovery exercise and independent sink/cleanup observations. This
document changes no runtime behavior, acceptance threshold or execution grant.
