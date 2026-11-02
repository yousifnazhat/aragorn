# HTTP94 protected credential successor

This is an offline source change. The frozen HTTP93/HTTP94 implementations and
reports remain inputs. No service, fixture, readiness probe or qualification is
created by these renderers.

`scripts/materialize_runtime_http_credentials.py` consumes the HTTP94 payload
map verified by `scripts/stage_runtime_phase3_http_ready_profile.py`. The new
`scripts/stage_runtime_phase3_http_credential_profile.py` preserves its 94 paths
and 21 directories, changing nine existing payloads and two activators:

- HTTP action: separate root provisioning and service credential APIs, deferred
  process-profile import, and guarded service credential descriptor custody.
- HTTP readiness and provisioning: root writers/preactivation guards use
  `load_provisioned_fixture_binding`; broker startup reads the loaded readiness
  credential through `read_service_credential`.
- Sensor service: hold the fixture credential before entering `_run`, retain it
  through the filesystem identity drop, and close it when `_run` exits.
- Worker, sensor and broker units: copy the fixture with
  `LoadCredential=http-fixture:/etc/aragorn/runtime-http-fixture.json`. The broker
  also loads `http-readiness`. Service code accepts only the exact corresponding
  `/run/credentials/<unit>/<name>` view; it has no direct-path fallback.
- All three services read fixture boot identity through the existing protected
  `/run/aragorn-broker-boot-id` path. Preserve the broker's read-only bind and add
  matching worker/sensor binds; `ProcSubset=pid` hides the direct `/proc/sys` path.
- Gateway unit and existing HTTP config template: `OPENCLAW_NO_RESPAWN=1` and
  `logging={"level":"info","file":"/var/lib/aragorn-agent-gateway/gateway-lifecycle.log"}`.
- Both activators: current hashes for all changed dependencies, before the
  read-only readiness guard; the worker also pins the completed subordinate
  activator and updated gateway template. The measurement inventory remains 22
  names; its report pins are regenerated from the successor payloads.

The three service identities are worker `aragorn-runtime:aragorn-runtime`,
sensor `aragorn-sensor:aragorn-sensor`, and broker
`aragorn-broker:aragorn-runtime`. Real/effective/saved IDs must match; filesystem
IDs must match too. Only the sensor's already held context may use the configured
runtime filesystem IDs after its irreversible drop. Each operation checks the
main thread, PID/start epoch, fixed cgroup and fixture boot. Fork reuse refuses.

Credential acquisition owns descriptors for `/`, each ancestor and the file.
Directories retain device/inode/mode/UID/GID; unrelated directory timestamps,
sizes and link counts do not invalidate custody. The regular single-link file
retains its full metadata identity, bounded exact pread length, and read-only
file/unit-directory mounts. Normal worker/broker reads recheck named nofollow
ancestry. Sensor reads after the drop use only held descriptors, with no named
stat or reopen. Final guard failure preserves a primary body exception; the
global sensor context clears before descriptor cleanup, and cleanup failure is
attached to an existing exception rather than replacing it.
Nested or direct sensor credential acquisition while a context is held refuses
before any pathname open, including after filesystem-ID adoption. Initial
directory stat/open joins use stable metadata too; regular-file metadata remains
fully pinned. Accepted root/service ownership and mode/group combinations are
explicitly covered by inert mocks; actual unreadable credential projections
still fail at open rather than using a fallback.

## Reviewed first-stage registration

`runtime-http-credential-profile` owns the 14 new test methods in
`tests/test_runtime_phase3_http_credential_profile.py`. The reviewed 126-input
closure is the existing ready-profile behavioral inventory excluding its two
historical test modules, plus the new renderer, stager and test. Static import
review includes generated HTTP credential code and the three cold entrypoints;
it found no additional local dependency outside this union. `needs` is empty.
The public report is an output, and this mutable handoff is outside the fingerprint.
Only this newly registered stage is scheduled in the coordinator worktree.

Two reviewed, nonredundant focused stages are required:

1. Run only the new credential/cold-import/source-join module. Produce one actual
   canonical public inert staging report, retain its exact bytes as a source
   artifact, and record its size/digest and inventory counts. The new stager
   necessarily writes its absent DESTDIR once; no historical test module is run.
2. Use that retained report's actual pin in new helper/capture composition.
   Review and check new source-only assembly joins in memory, including the
   generated writer's explicit root API, loaded credential identity and
   independent consumer limits, fresh config digest/readback, and the gateway
   environment witness. Inspect the retained report bytes directly; do not
   restage the unchanged 94-file tree to rediscover its pin.

The second stage must not use a predicted report pin or a private fixture cache.
The outer signed-source launcher will bind both successor sources and generated
outputs. Log acquisition and restart evidence are coordinator-owned contracts;
this change only selects the fixed native logging file and environment. Neither
focused stage establishes live deployment, restart denial or Phase 3 qualification.

## Retained first-stage outcome, 2026-10-12

Selected command: `/opt/homebrew/bin/python3.12 scripts/phase3_pipeline.py run
runtime-http-credential-profile`. PASS: all 14 new methods, including three
isolated assembled entrypoint imports. Fingerprint:
`sha256:0d119c82b5671c45d08a1a1705a15ea092b601ff60caa32639b4ed4e4e1032a2`.

Actual public output: `benchmark/evidence/phase3-http-credential-staged-profile-v1.json`,
68263 bytes, `sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9`.
Counts: 94 files, 124 source inputs, 50 new dependencies, 21 directories and 22
measurement source names. Fresh rendered config digest:
`sha256:7166a9634f1157853e3db16bc5d04ab8cdcbf6a218fdbada933bb430551423cd`.
This is an actual inert staging report, not a prediction or a deployed observation.

Two diagnosed failures remain retained in `.aragorn/phase3-pipeline/`:

- `18349b471018734c8adfdaff0768564b1051798c0a8fa8271560a998ba1ed5bf`:
  default Apple Python 3.9 failed importing existing dataclass slots before tests.
  Corrected to the repository-required installed Python 3.12; environment changed.
- `f22e6f9afba6075c768df783236e80eb77fe1f76b273dd8716b991e4a767379c`:
  both class setups refused the draft's one-occurrence readiness replacement;
  source inspection confirmed two retained revalidation sites. Fixed exact count
  and regenerated the renderer pin; source changed. Zero methods/staging ran.

There was no unchanged retry, overwritten report, historical suite, live operation
or private retention. The successful run performed the only staging call.
The separate helper/capture/identity composition stage follows below.

## Reviewed composition registration

Coordinator-owned new paths are
`scripts/materialize_native_phase3_http_credential_helpers.py`,
`scripts/materialize_native_phase3_http_credential_capture.py`,
`scripts/capture_native_phase3_http_credential_attempt.py` and
`tests/test_native_phase3_http_credential_composition.py`.
Frozen predecessors and active lane worktrees are unchanged.

`native-http-credential-composition` selects only seven new test methods, with
`needs: []`. Its 277-input closure combines the existing attempt-assembly and
credential-profile source inventories, excludes every historical test module,
and includes these four files and the retained public report. Recursive static
local-import review adds no missing source; all 124 report source inputs are
included. Two installed gateway credential source names are generated outputs
of the included gateway credential materializer, not missing disk inputs.

The helper binds the actual report, root provisioning API and template/config
pins. A dedicated observer reads only the fixed loaded HTTP credentials with
held nofollow ancestry, exact ownership/modes, read-only mounts and a final
readback; the independent consumer joins their byte counts and digests to the
protected sources. Gateway environment bytes stay internal: only the selected
`OPENCLAW_NO_RESPAWN=1` witness is exported, with an explicit attestation limit.
Preparation v5, identity/process v3 and setup v3 reach their callers.

Nested preparation consumes the retained report. The outer launcher privately
loads the matching generated helpers and nine staged modules; pure in-memory
payload rendering joins all 94 installed rows to the actual report. The focused
check prohibits both full staging entrypoints and invokes no controller command.
Behavioral cases cover custody/metadata mutation, incomplete reads, independent
source disagreement and environment/config disagreement. Source is frozen and
reviewed before this selected stage is scheduled.

Composition PASS on its first run: all seven methods, fingerprint
`sha256:fc5ec4385aef9eb1263089fcd9aaa53be2c464d77d48c64efe9fad0b5c158a19`.
Command: `/opt/homebrew/bin/python3.12 scripts/phase3_pipeline.py run
native-http-credential-composition`. The actual result and logs are retained in
the matching `.aragorn/phase3-pipeline/native-http-credential-composition/`
fingerprint directory. All 277 reviewed input hashes remained unchanged and all
108 prior registry rows were preserved. No full staging entrypoint, controller
command, live operation or historical test method ran. The first-stage success
is reused without another run.
