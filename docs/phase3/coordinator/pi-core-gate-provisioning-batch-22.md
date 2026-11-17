# Pi-core batch 22: preserve the pinned pre-execution gate at installation

Base: signed published `cf6aa2c9fb5435c78f1291f2a17c056937f4e339`.
Status: implemented and reviewed offline; 28 new/affected checks passed once.
No live operation released. Assignment source `f3548d5` was signed and published
in signed merge `6db58ab` before lane writes began.

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

## Delivered and verified

The installer now invokes the same strict gate validator used by the held launch
plan before creating a destination. Exactly Node plus the pinned optional gate
retain executable mode; the legacy Node-only policy remains unchanged. The
receipt distinguishes these policies. Gate absence, malformed provenance,
changed bytes and nonexecutable source refuse before installation. Existing
partial-write retention and no-adoption behavior remain intact.

Independent review found no blocker. The coordinator reviewed the 94-file static
Python/import closure, including the newly reachable provider modules; no target
resource or source-gate build was scheduled. Explicit `load_tests` selects 15 new
cases, one affected legacy mode case and eight affected held-gate cases. Four
bounded registry checks cover capacity 194 to 195.

| Stage | Checks | PASS fingerprint |
| --- | ---: | --- |
| `pi-core-gate-provisioning-offline` | 24 | `37b5c2ca6bbd6af4df86f121cd69c78017afc3e564e181371de62099b77b22bf` |
| `pipeline-capacity` | 4 | `d28c2d7f85e53c647a28b3b833496a96dc4f97e31e7771b0a213bb3fbdb424a4` |

Only this behavioral command ran; both stages passed on their first execution:

```sh
/opt/homebrew/bin/python3 -B scripts/phase3_pipeline.py run pi-core-gate-provisioning-offline pipeline-capacity
```

Results and logs remain under each exact stage/fingerprint in
`.aragorn/phase3-pipeline/`. No broad suite, old stage, build, VM, service, provider
request or live installation ran. Temporary fixture root ownership/installed
custody is mocked and does not qualify a real deployment.

Dependency review identified the next missing caller: the managed bootstrap API
has no operational root entrypoint outside tests. Existing verified-source loader
logic must run before any Aragorn import at that entrypoint. A later file hash or
the child-service/source-observer pin cannot attest the root mediator's consumed
code. Fresh provider observations therefore require this root source custody and
an independently selected producer binding first. Keep all existing health
checks intact: narrow source challenges cannot refresh global health.

## Remaining plan

1. **D2:** gate installation repaired offline; connect the protected root caller,
   genuine observation/health and exact
   installed inventories; establish authorized credential/Node/kernel feasibility,
   recovery/full timing and a separately approved useful pilot.
2. **D3:** remaining connected admission, RUN/health and workload paths.
3. **D4:** real independent-consumer/surface inventory and freeze.
4. **D5:** authorized fresh acceptance, measurements, cleanup and offline replay.
