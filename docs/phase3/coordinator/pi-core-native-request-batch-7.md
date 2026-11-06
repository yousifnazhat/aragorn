# Pi-core D2 batch 7: native request and independent sensor channels

Date: 2026-11-03. Base: `5225f51ae8d53e6688c4d12d1f31e43227dbdab8`.
Release: reviewed source, only new/affected offline checks, verified signed
commit and ordinary branch push. No live operation or deployment is authorized.

## What is connected

The native supervisor can now own a single request endpoint under its already
projected bootstrap directory: `/run/aragorn-pi-bootstrap/requests/request.sock`.
It creates only an absent directory/socket, pins their ownership and identity,
and retains the exact native launch plan, process handle, unit generation,
activation and immutable-launch custody while dispatching one accepted request.
The root reader remains the sole consumer of the actual Pi request stream.

A separate authenticated root-to-sensor packet channel transfers candidate
request bytes and one duplicate of that accepted stream. Root-supplied bytes and
identity are not promoted to sensor attribution. The sensor independently obtains
the actual socket peer and PIDFD, measures its process profile, holds existing
quarantine-aware installed lineage, hashes the protected action target and uses
the existing profiled capability issuer. No parallel observation framework or
new broker effect implementation is introduced.

The connected ordering is:

1. Root reads the actual bounded Pi frame and retains native worker custody.
2. Sensor receives the duplicated socket, independently measures Pi and holds
   lineage, then sends READY before submitting to the broker.
3. The existing broker joins protected root request provenance with independent
   sensor issuance; root services its guarded CHECK/CURRENT exchanges.
4. Broker returns the exact result and write-side EOF to the sensor before DONE
   to root. This prevents the old EOF-wait/result-acknowledgement deadlock.
5. Sensor releases lineage, extra process/file handles and, for the dedicated
   wrapper, restores its filesystem identity. The custody helper closes its
   duplicated worker socket and root PIDFD before sending exact-result DONE.
6. Root requires that terminal receipt before worker success. Native dispatch
   closes the accepted stream and verifies owned endpoint cleanup before
   identity revocation and bootstrap RELEASE.

READY/measurement/authorization require live peers. Terminal sensor DONE is
different: the dedicated sensor may exit immediately after sending it. Root
accepts only the original nonce/request/result/deadline-bound packet with exact
per-message credentials on the same authenticated connection, while retaining
the original peer handle through receipt. It does not require the sensor to
remain alive after its terminal cleanup receipt. This creates no new continuing
authority and never accepts a missing or mismatched acknowledgement.

## Failures, permissions and trust boundary

- A request is attempted once. An incomplete result, uncertain transfer or
  missing sensor cleanup receipt prevents RELEASE and retains `CLEANUP_HOLD`,
  even if local socket/directory cleanup succeeds. No automatic effect retry,
  remote kill, journal reset or promotion of NOT_SUBMITTED to cleanup proof.
- The operation deadline can only shorten. Exact owned endpoint cleanup uses
  the original supervisor cleanup reserve, never a renewed action deadline.
  Replaced names, unexpected residue or uncertain handle closure preserve a hold.
- The endpoint directory is root:Pi-GID `0711`; the socket is root:Pi-GID `0660`.
  Existing effect-root permissions remain broker:broker-GID `0710`. Pi, sensor
  and broker primary identities stay separate. Only the dedicated sensor gets
  supplementary broker-GID traversal (its own primary group is optionally
  present); unrelated groups refuse. Pi receives no broker-group membership.
- The dedicated sensor reuses existing bounded FS-identity adoption/restoration
  and capability-drop helpers. It needs no root sensor or added ptrace capability.
  Restoration is attempted once, before DONE; failure cannot report completion.
- The sensor is part of the approved trusted computing base. A duplicated Unix
  stream is inherently bidirectional, not a kernel-attenuated metadata handle.
  The implementation never reads, writes, shuts down or changes the timeout on
  the received Pi stream; this discipline does not claim protection against a
  malicious trusted sensor. The broker still controls actual effects.
- Supplied control connections remain caller-owned and one-shot. The later
  deployment caller must establish them under exact protected service identities,
  close them on every outcome and manage service lifetime. In particular, the
  existing root/broker CHECK/DONE protocol still requires its broker peer alive
  while root consumes its response; a fire-and-exit broker caller is insufficient.

## Evidence ceiling and remaining D2 work

This batch connects **native root-side dispatch to request/sensor/broker source
paths**, not the compiled Pi client to the new endpoint. Existing START still
describes the legacy relay; its endpoint is deliberately masked and its legacy
bootstrap validation expects a nonroot relay. Repointing that configuration alone
would mask the new endpoint or fail its ownership contract. The next batch must
bind a fixed root-authenticated native request client/START contract without
loosening the legacy profile or enabling bypass routes.

The current compiled bootstrap still returns `PROVIDER_UNAVAILABLE`. If it emits
no request, the dispatcher explicitly records `NO_REQUEST`: neither that nor
`BOOTSTRAP_COMPLETE` proves useful computation, a deployed sensor, actual effects,
confinement or native cleanup. Provider/data mediation, exact service/channel
provisioning and lifetime, and Pi-aware effective-receipt recovery/rotation remain
before the separately authorized useful D2 pilot. Batch 6's frozen recovery and
archive limitation remains intact.

Frozen predecessor sources, compiled Pi artifact, static OS closure, original
48-ID manifest, approved 29-requirement design mapping, historical evidence and
operational/private-retention cleanup holds are unchanged. No VM, listener,
service, target binary, provider call or live capture was run. No requirement is
marked qualified, and Phase 4 remains unreleased.

## Focused verification and parallel ownership

Two lanes implemented the independent sensor and native dispatch in disjoint
new files. A third lane authored custody checks and independently reviewed all
boundaries. The coordinator owns channel protocol, connected caller changes,
pipeline registration, affected checks and this release.

The code-review skill influenced concrete fixes: incomplete remote custody now
holds RELEASE, the sensor's exact traversal group is enforced, and terminal DONE
does not race expected sensor exit. Root source and all new checks were reviewed
before the pipeline ran. Registry capacity rose only from 145 to 149 to register
four new focused stages. Four older directly affected Pi stage input inventories
were expanded for new transitive imports; their tests were **not** scheduled and
historical success/failure records were not altered. Imported fixture helpers
do not cause historical TestCases to execute.

All **137 selected new/affected checks passed once**, with no failure or rerun:

| Selected stage | Checks | Exact successful fingerprint |
| --- | ---: | --- |
| `pi-core-sensor-channel-offline` | 39 | `sha256:1e343d633a1c64612928a9ea55a270b469d6988bca264c2bfd4a8d5de3a5153d` |
| `pi-core-request-sensor-offline` | 45 | `sha256:42e893c6479159ec2d219e9b61760d0ce101bdda2f7d6cc21f415b8f58c716c7` |
| `pi-core-native-request-offline` | 31 | `sha256:cb2891ea854f06d4ffb1e836d1682747610f463922c50d3b1a92639a06809f49` |
| `pi-core-request-wiring-offline` | 18 | `sha256:e597a2ec2f2da87e303fa10169cff753bf548babaf04c980ae9b23c49271a49e` |
| `pipeline-capacity` | 4 | `sha256:cab957d932c0125349d026241cb92ea129fe854fc53b99da7d062d1c68dfe867` |

All ran through `scripts/phase3_pipeline.py` with reviewed explicit transitive
inputs. Transport, kernel/process identity, native ownership and privileged
transitions are mocked; sensor action hashing uses disposable owned files. This
is developer evidence, not installed identity, sensor-health, timing or acceptance
evidence. Retained logs stay under the exact local pipeline fingerprint directories.
The ignored `.aragorn/pi-core-native-request-batch-7-release.json` records the
resulting commit, signature verification and remote readback after publication.

## Remaining plan

1. **D2 in progress:** bind the fixed native Pi request client/START endpoint;
   connect protected provider/data mediation, exact service/channel provisioning
   and lifetime, and effective-receipt recovery/rotation. Then, only with separate
   live authorization, demonstrate useful allowed/blocked work with independent
   health, outcome and cleanup evidence.
2. **D3:** connect the remaining managed lifecycle/admission, RUN/sensor-health,
   action/workload and paired-task coverage on that one deployment.
3. **D4:** complete the executable approved 29-requirement mapping and independent
   evidence inventory, then freeze the exact complete deployment once.
4. **D5:** separately authorize fresh final acceptance, retain real metrics and
   cleanup, and replay evidence offline. Phase 3 is not yet complete.
