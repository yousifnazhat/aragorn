# D4 source handoff: managed-profile qualification composition

Status: implementation prepared for coordinator review and the new focused stage.
No check, build, live operation, freeze, qualification, or Git operation was run by
this lane. D2/D3 evidence prerequisites and the real independent-verifier inventory
remain open. The test callbacks are explicitly synthetic and cannot qualify a
deployment.

## Interface and scope

`aragorn.pi_core_phase3_qualification.qualify_pi_core_phase3_exit` is the narrow,
additive `pi-core-managed-phase3/v1` entrypoint. Its fixed manifest is
`benchmark/pi-core-managed-phase3-v1.json`, pinned in source to
`sha256:1c765fb473f25103fc094b0b379d549af726f4608a90672fd1c211cec2a9e5c5`.
It requires exactly the approved 29 `MP1/` logical IDs; those are not a case-count
budget. All 12 designed surface groups must be represented, and both supported
and denied paths must be covered. Native-plugin/ambient-loader groups do not need
invented supported paths just because other groups have supported paths.

The existing public `qualify_phase3_exit` still pins its original 48-ID manifest.
Only its composition body was mechanically extracted into a private shared
helper. The managed entrypoint reuses the strict duplicate/integer JSON parser,
CAS, seven deployment bindings, callable source custody, semantic-result binding,
measurement schedule builder and quantitative arithmetic. Core evidence joins
cannot be overwritten by additional managed context.

## Operator-held inputs and independent consumers

All expected pins and semantic callables must come from an independently reviewed
operator freeze, not from the evidence being judged. Alongside the existing
deployment, campaign, schedule, metrics and 29 requirement inputs, the API takes:

- `surface_inventory_raw` and `expected_surface_inventory_digest`: canonical
  no-LF JSON retained in CAS, schema `aragorn/pi-core-managed-surface-inventory/v1`.
  Fields are `schema`, `profile`, `deployment_identity_digest`, `sources` and
  `surfaces`. Sources map normalized relative identities to retained raw source
  digests. Each surface has `surface_id`, `group`, `disposition` (`SUPPORTED` or
  `DENIED`), `entrypoint`, `source_paths` and `requirements`.
- `surface_evidence_digest`: a canonical CAS document using schema
  `aragorn/pi-core-managed-surface-evidence/v1`, the inventory/deployment pins and
  an exact `evidence_by_surface` map to nonempty retained raw evidence blobs.
  The frozen inventory does not contain later observation hashes, avoiding a
  freeze/evidence dependency cycle.
- `surface_verifier`: an explicitly chosen `Phase3SemanticVerifier`, bound by
  source pin. It must independently discover/compare supported and denied source
  surfaces and semantically validate all raw surface observations. Shape checks,
  filenames, source hashes and a supplied PASS record are not that proof.
- `expected_reference_task_source_digest`: a separately reviewed source pin for
  the existing four-task implementation. Every retained task descriptor must
  bind those exact bytes. A descriptor's self-selected source hash is not enough.

Every requirement consumer also receives the exact profile, inventory, surface
evidence and reference-task source pins in its authenticated verification context.
The surface result is a prerequisite under the existing boundary requirement,
not an invented 30th requirement. FAIL/NOT_TESTED cannot be upgraded by passing
arithmetic; N/A and unbound results are rejected. There is no default verifier,
PASS importer, producer/verifier import requirement, or current freeze manifest.

The explicitly trusted semantic consumers still bear responsibility for actual
consumed-source identity, complete source closure/surface discovery, meaningful
health/loss accounting, raw attempt and sink evidence, clock-domain validity,
real task boundaries, cleanup and all approved mapping semantics. Pinning a
callable's source file is not proof of its correctness, independence or transitive
dependency closure; the retained legacy limitations say so explicitly.

## Campaign shape and measurements

The pinned campaign uses schema `aragorn/pi-core-managed-campaign/v1` with exact
fields: `schema`, `profile`, `deployment_identity_digest`,
`surface_inventory_digest`, `attempt_operations`, `pair_tasks`,
`task_descriptors`, `pair_ordering`.

- `attempt_operations` maps the frozen 100 attempt IDs to exactly 25 each of
  `HTTP`, `DNS`, `TRUNCATE`, `UNLINK`. HTTP/DNS must be exfiltration; truncate/unlink
  must be destructive. The declared unattributed control must be destructive.
- `pair_tasks` maps the frozen 100 pair IDs to exactly 25 each of
  `BENIGN_JSON_SUM`, `BENIGN_LINE_COUNT`, `BENIGN_SHA256`, `BENIGN_COPY_READBACK`.
  `task_descriptors` pins the existing `describe_tasks` outputs, bound to the
  independently held source pin and retained exact inputs. Each pair binds its
  matching descriptor/input; paired host equivalence remains in existing metrics
  and the semantic consumer contract.
- `pair_ordering` is `BASELINE_FIRST`. Actual baseline completion must precede or
  equal its instrumented start; overlap is rejected after strict numeric parsing.
- The existing arithmetic remains unchanged: attribution at least 99%; 100%
  residue-free pre-effect blocking separately per family; nearest-rank p95 below
  500 ms; aggregate overhead below 10%; one actual unattributed control; exact
  complete 100-attempt/100-pair inventories.

Inventory, campaign, descriptor and surface-index documents use the existing
64-KiB strict parser bound (canonical no-LF payload plus parser LF). Individual
source artifacts are bounded at 1 MiB and raw evidence at 16 MiB. Exceeding these
bounds requires a reviewed contract change, not truncation of coverage.

## Proposed focused stage

- ID: `pi-core-managed-qualification-offline`
- Test module: `test_pi_core_phase3_qualification`
- Static test count: 43 (40 new methods plus three explicitly selected affected
  legacy composition methods via `load_tests`); timeout suggestion: 120 seconds.
- No suite, import, build or check was executed by this lane. Coordinator should
  register the reviewed closure and run once through the existing pipeline.

Selected affected legacy methods only:

1. `test_complete_inventory_composes_only_explicit_synthetic_verifiers`
2. `test_semantic_callbacks_receive_read_only_cas_for_raw_evidence`
3. `test_any_mandatory_failure_or_not_tested_remains_ineligible`

Reviewed source/test/artifact closure (plus pipeline-owned common inputs):

```text
benchmark/pi-core-managed-phase3-v1.json
benchmark/phase3-exit-gate-manifest-v1.json
src/aragorn/__init__.py
src/aragorn/cas.py
src/aragorn/oci_worker_protocol.py
src/aragorn/phase3_deployment.py
src/aragorn/phase3_exit_gate_manifest.py
src/aragorn/phase3_exit_qualification.py
src/aragorn/phase3_quantitative_metrics.py
src/aragorn/phase3_reference_tasks.py
src/aragorn/pi_core_phase3_qualification.py
src/aragorn/native_phase3_http_fixture.py
src/aragorn/native_phase3_http_canary_contract.py
src/aragorn/runtime_process_profile.py
src/aragorn/runtime_action_broker.py
src/aragorn/runtime_action_decision.py
src/aragorn/runtime_action_observation_publisher.py
tests/test_pi_core_phase3_qualification.py
tests/test_phase3_exit_qualification.py
tests/test_phase3_quantitative_metrics.py
```

The approved mapping document may be retained as an additional reviewed contract
input: `docs/design/pi-core-phase3-acceptance-mapping-v1.md`. No legacy test module
or legacy manifest was changed; no other fixture files are read by this stage.

## Remaining gates

1. D2: connected provider/worker path, independent consumed-source observation,
   required healthy telemetry, recovery/timing and separately authorized pilot.
2. D3: complete producers/raw observations/independent consumers for all admission,
   RUN/health and workload surfaces on the common deployment.
3. D4: review concrete surface inventory and all executable independent consumers;
   close prerequisites and freeze exact deployment/source/campaign pins once.
4. D5: separately authorize and serialize fresh acceptance and measurements,
   retain all failures/indeterminate outcomes, verify cleanup and replay offline.

Only that final complete pass can claim Pi-core managed-profile Phase 3
qualification. This source batch does not claim OpenClaw compatibility, universal
EDR coverage, production release readiness or completion of D4.
