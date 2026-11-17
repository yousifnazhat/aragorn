# Pi-core batch 22: preserve the pinned pre-execution gate at installation

Base: signed published `cf6aa2c9fb5435c78f1291f2a17c056937f4e339`.
Status: bounded offline implementation assignment; no live operation released.

## Concrete dependency and ownership

The current installer makes only `node/bin/node` executable, but the protected
launcher requires the compiled, independently pinned `observer/source-gate` to
be executable. The installed successor therefore cannot satisfy its own launch
contract. Close this existing D2/MC-02 dependency without changing authority,
deadlines, OS policy, runtime pins or frozen deployment artifacts.

Lane `inventory_dependency_review` owns exactly:

- `src/aragorn/pi_core_os_provision.py`
- `src/aragorn/pi_core_confined_launch.py`
- new `tests/test_pi_core_gate_provisioning.py`

Reuse the launcher's existing gate provenance validation through one private
shared helper. Before creating an installation, require a present gate and its
compiled provenance to agree, with executable source bytes and the exact pinned
digest. Only Node and the validated fixed gate may retain execution permission;
other runtime files remain mode 0444. Preserve the legacy no-gate policy and
absent-only installation/failure retention. The held launch plan must retain all
existing gate, Node and observation-profile joins.

The focused module should reuse existing inert owned-temp provisioning and held
launch fixtures, cover the new gate-enabled installation plus its refusals, and
select only affected legacy mode/held-gate cases. Do not run whole legacy stages.
No Linux target execution, real root installation or live service is authorized.

Coordinator owns this checkpoint, registry/input closure, necessary bounded
pipeline-capacity adjustment, independent review, focused execution and signed
integration/publication. Lane does not execute checks or change Git. Read-only
observation/health and timing audits have no write ownership in this batch.

## Evidence ceiling and remaining plan

Passing inert file/mode checks proves installer/launcher compatibility only, not
an installed protected view, consumed source or a qualified deployment. Keep all
qualification flags false and preserve every earlier result and draft.

1. **D2:** fix gate installation; connect genuine observation/health and exact
   installed inventories; establish authorized credential/Node/kernel feasibility,
   recovery/full timing and a separately approved useful pilot.
2. **D3:** remaining connected admission, RUN/health and workload paths.
3. **D4:** real independent-consumer/surface inventory and freeze.
4. **D5:** authorized fresh acceptance, measurements, cleanup and offline replay.
