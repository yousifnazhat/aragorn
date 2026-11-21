# B94 — manager and service inventories for the common guest

The B75 guest predates the direct LUKS2 header, mapping and whole-disk backing
checks. Its named-socket observer is also older than the stopped-worker guard.
The [signed-source catalog](../../../packaging/pi-core/managed-sources-b94.json)
and [preparation entrypoint](../../../scripts/prepare_pi_core_b94_sources.py)
now supply the actual four deployment documents to the next common guest. No
intermediate B80 guest, worker rebuild or private observation was necessary.

Donor: signed `0aa14e486199b33b84e03bf62ae46c6ca790feaf`, tree
`82435c0e59ed43d6170ebc6d891241e7c7bacee6`. Source review SHA-256:
`bb95c830adf7e4f33eb8c3d77c419146942d5552fa403053588b4eec6b2207c0`.
Four new modules are shared by the manager and services: owned socket
directories, device-mapper state, backing leaf and LUKS2 headers. The manager
set has 127 code files and the service set has 118 modules. B93's offline
replay readers are not included. Unchanged native binaries, service permissions
and worker contents were not repackaged or re-tested.

The preparation used the exact B75 host profile, service manifest and binding;
verified the donor's signature and source blobs; rendered the existing wrappers;
and checked the four resulting byte digests against an independent projection.
The following files were published once in `~/Library/Application Support/Aragorn-B94-Offline/`
and read back. Refuse partial or existing destinations; do not regenerate them
on the next run. `service-runtime-receipt.json` describes the intended layout,
not an installation. Together the inventories cover 816 host files and 806 service files.

| Retained file | SHA-256 |
|---|---|
| `coordinator-host.json` | `54c72bbecbc1144c95265c4a3760f7dd3932094837f3253f8b43e78ad631c0f8` |
| `manifest.json` | `344013ad935d60a5702d6f549fbdfca052b6eaa387b706f34299a78f6d1fe635` |
| `runtime-binding.json` | `1cb3df496a22751155be118d2eb3c82f96fb425ec873e0b28dbcd6aca5e01c58` |
| `service-runtime-receipt.json` | `5ea98d30d51c9c6d41c09a80962c2d203f46b75da7416bed8c720d05345fec8f` |

Only `pi-core-b94-managed-inventories` ran: two checks, first run passed,
fingerprint `8a83b199ed6fece512fb5f5989b8ea82f35fde1d3a0e3bcdbf5ad30aacf972e6`.
The checks staged the exact inventories and refused a genuine B69 runtime
binding mixed with B75 inputs. No device, guest, service or provider was contacted.

1. **D2:** The manager and service inventories are ready, not installed. The
   Node observer now has SHA-256 `82851dcea5299a9455574694ee00f62a2e2d1647744a80fdafb7524ac6736dcd`.
   Neither the old B63 producer pin nor the candidate B86 worker archive is
   launch authority. Resolve the private actual-worker lookup/link receipt
   before binding the observer and worker plan. Sensor loss, exclusive state
   custody, independently observed output, full timing, recovery and an
   authorized pilot remain open. B49 stays null.
2. **D3:** Connect remaining admission, RUN/health and workload paths; settle
   the real task carrier and copy fixture without weakening confinement.
3. **D4:** Close all 29 requirements against original evidence and independent
   verifiers on one deployment, then freeze.
4. **D5:** After separate authorization, perform fresh acceptance, 100 attempts
   and 100 pairs, verify cleanup and replay. No qualification is claimed.
