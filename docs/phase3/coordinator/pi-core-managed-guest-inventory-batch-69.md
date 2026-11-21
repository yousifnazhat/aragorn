# D2 batch 69 — one guest inventory for the observer and configuration reader

Signed source: B68 merge `0910f1d1c5710cb7730002ac5d974803e14e2431`.
The [source projection](../../../packaging/pi-core/managed-sources-b69.json)
uses this Git tree, not the current working files. On the manager side eight
paths changed, including two additions. On the service side five modules
changed, including the same two additions, and all three service wrappers
now pin the new module inventory. No Node, CPython, native library, gate or
worker bundle was rebuilt. The retained B63 worker-source plan still points
to the same two observer producers, gate and Node executable.

The change has two independent inputs: the retained B65 payload and the signed,
reviewed source update. A [separate projection](../../../scripts/derive_pi_core_b69_payload.py)
derives five expected identities before the [assembler](../../../scripts/prepare_pi_core_b69_payload.py)
can publish. See the [exact five hashes](../../../packaging/pi-core/managed-payload-b69.json).
The complete guest payload SHA-256 is
`efc1b36a0a033992805cb60cbca14e3bfe5d4f21fb5e58c9d3ee80c0b1bb3a24`.
The existing immutable-image assembler consumes the retained `payload.json`
and `root/` together; the coordinator uses the retained `service_runtime`
section. This does not supply a boot disk, short-lived configuration, device
nomination, state-encryption identity, current evidence head or pilot release.

One new staging directory, `~/Library/Application Support/Aragorn-B69-Offline/`,
was published after full byte and mode readback. It contains 1,764 entries,
20 changed files (four additions); the host profile has 806 files and the
service manifest has 793. Local `outcome.json` SHA-256:
`fa8ed1160ef21e6a0233a85e534b991f47c731c914d40d49306efdf309419430`.

| Affected stage | First-run passes | Retained fingerprint |
|---|---:|---|
| `pi-core-managed-guest-source-inputs` | 8 | `e80288a0c5e21715c5c3b1e9f6ae6b4c703b476247e8cd28d91cf3da70cebba0` |
| `pi-core-managed-guest-preparation` | 1 | `53511f4c3ff3bba3790a91ccbadc321e2a6bed5f8292de6e9b310576d0deb64d` |

No historical stage, production workload, boot, attach, service operation
or spending. B49 remains null. Do not run the preparation again on the same
destination or adopt a partial directory; use the retained result.

1. **D2 open.** Connect the sensor's actual process and read-only service-state
   mount to the manager's stopped-gate record. Independently verify Pi's view,
   the backing volume and freshness. Installed observation, health, recovery,
   timing and the useful pilot still require an authorized deployment.
2. **D3 open.** Complete admission, RUN/health responses and workload evidence
   on the same deployment.
3. **D4 not frozen.** Complete the independent executable mapping for 29
   requirements and close the prerequisites before freezing.
4. **D5 not authorized.** After freeze and separate approval, collect fresh
   admission, 100 attempts and 100 pairs; verify cleanup and replay the evidence.
