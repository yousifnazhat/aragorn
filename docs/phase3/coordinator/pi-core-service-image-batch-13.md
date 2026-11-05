# Pi-core D2 batch 13: concrete service image and executable wrappers

Date: 2026-11-05. Base: `ce5345c71717595abbc36eeeba5881691088c1db`.
Scope: connected source implementation, static retained-archive assembly,
reviewed new/affected checks, verified signed commit and normal branch push.
No target execution, protected installation, service activation, credential
setup, provider call, live workload, pilot or Phase 3 qualification.

## Reuse and delivered behavior

Parallel lanes owned image assembly and fixed service entrypoints; an independent
lane reviewed both. Root owned the additive provisioning contract, input pins,
pipeline registration, integration checks, artifact record and release. Existing
ELF/license inspection, protected installer, configuration parsers, role/process
identity, authenticated peers and provider/action/sensor handlers are reused.
No replacement broker, package resolver, service protocol or dependency was added.

`prepare_pi_core_service_image.py` reads the already retained digest-pinned
Python3.12.13-slim-bookworm arm64 archive. It statically selects Python/stdlib,
native extensions, transitive ELF dependencies, licenses and the independently
pinned source/wrapper inventory. It never loads target ELF or executes Python,
OpenSSL, a container or package installation. Only Python's exact
`$ORIGIN/../lib` search is allowed by a narrow opt-in to the existing parser;
its default still rejects RPATH/RUNPATH/audit/filter loading.

The additive v2 runtime binding pins libpython and exactly three fixed wrappers
invoked through `/usr/bin/python3 -I -S -B`. The existing provisioner validates
their paths, digests and fixed commands; v1 remains unchanged. There is no host
interpreter fallback, site-packages, bytecode cache or arbitrary entry module.

`pi_core_service_entry.py` reads fixed root-owned canonical configuration,
requires exact real/effective/saved role IDs and cgroup identity, and connects
after exec to root-created supervisor listeners. The action wrapper creates one
absent-only listener; the sensor connects directly to it. Exact endpoint and
kernel peer identity are checked before existing handlers run once. Original
deadlines persist through cleanup; failures cannot initialize fresh authority,
refresh a timeout, retry effects or remove another owner's replaced endpoint.
Action/provider require the existing capability-free process profile; the sensor
retains its existing bounded filesystem-identity adoption/drop/restore contract.

Future lifecycle integration must supply protected config and endpoint parents,
start the sensor only after action-listener readiness, acquire post-exec
supervisor channels, and observe exact wrapper/unit exit and cleanup separately
from handler completion. Early environment refusal precedes service imports but
cannot undo native loader behavior before Python starts. Protected units must
provide a clean environment and isolate OpenSSL configuration/provider loading.

## Concrete retained artifact

The portable metadata checkpoint is
[`service-artifact-v1.json`](../../../packaging/pi-core/service-artifact-v1.json).
The exact reviewed inputs are
[`service-assembly-inputs-v1.json`](../../../packaging/pi-core/service-assembly-inputs-v1.json).
Large image bytes and full inventories remain local, not published.

- Output: `.aragorn/pi-core-service-image/assembled-13fb778b442d452f9c19e8b31348153b/`.
- 767 files, 54 directories, 41,391,812 root bytes; 79 source modules, three
  wrappers, 69 native extensions and 27 shared-library entries; 34 provenance files.
- Manifest: `sha256:1281530ef64d8b3f985b1fb4080151b3dae0f79e9473430ee848714f4b0346d0`.
- Runtime binding: `sha256:e906fdba77ec05af636c70fd47efce01bb11c84b653d45152e1743673c3549ac`.
- Receipt: `sha256:a2d744555244da3fa0c3a92713227caf4f8b2c52ed61f99037a33cf0633638e4`.
- Status: `PREPARED_NOT_INSTALLED_OR_EXECUTED`.

Every selected file and license was read back against exact size/hash/mode and
the canonical manifests. Inputs were rechecked after assembly. Static AST
inspection includes function-local imports but is not Python ABI or dynamic-load
proof. Four exact optional `cryptography` import sites in two benchmark DSSE
helpers are explicitly unsupported and recorded, not silently satisfied. These
helpers are not called by the three fixed service handlers. Supporting every API
in all copied modules is not claimed; no blanket external-import waiver exists.

## Review and focused verification

The code-review skill and independent review drove pre-execution fixes to
directory traversal modes, nonblocking config opens, saved role IDs, process
security checks, early environment refusal, established-channel/listener
lifetime handling, exact ELF search policy and license readback. The resulting
source and test corrections were reviewed before their affected stages ran.

**101 distinct selected checks pass:** 94 new checks and seven selected affected
compatibility/capacity checks. Only these stages were scheduled through
`scripts/phase3_pipeline.py` and the reviewed registry:

| Stage | Checks | Current successful fingerprint |
| --- | ---: | --- |
| `pi-core-service-image-offline` | 39 | `sha256:20f1baec6b68d96c051e80b4cb9a1d653dfb1141f2ed01826fd6467657523ecd` |
| `pi-core-service-entry-offline` | 45 | `sha256:66552a29d6a2d0ac053ba6f850e271f4c85c0a5c5cc1a87c722ebc3ec76d18ba` |
| `pi-core-service-image-contract-offline` | 12 | `sha256:2c352b5579c5736363634d822a2f9087b830f4be3954b18100f870151d487e8b` |
| `pi-core-service-image-assemble` | 1 | `sha256:87b79b9d765675d03451d2519b4e1a4643c795b1e50cc65654b339f257b189f2` |
| `pipeline-capacity` | 4 | `sha256:bce72ac903fe6cff867947eb00cd03f62ea4c1744848c55544bdf37c5f0c8ccb` |

Two failed fingerprints are retained, never rerun unchanged:

1. Wrapper stage `c85ca771bf665e86919743551c4d6066c8c0e689c4dec3ee8aab8968b7a9ebc1`
   stopped when `ast.unparse` lazily imported under globally mocked `sys.flags`,
   breaking importlib and traceback reporting. The test now inspects AST nodes
   directly and scopes simulated interpreter settings to the subject module.
   Only that changed 45-check stage reran; production wrapper bytes did not change.
2. Assembly `5de4841e9ef1ef2f9997af111669d5c00f5b18b317d50150051eedd0aee2f7d6`
   refused `pwd`, missing from the static builtin inventory. The retained target
   generated `config.c` explicitly registers `pwd -> PyInit_pwd`; its SHA256 is
   `30d353782cbaf8de2fed2ba82b1040940386e316b7f41604c49f8f3d6f16bb31`.
   The target libpython also contains the initializer symbol. AST-only comparison
   of all 79 sources found no other missing required builtin. The fix adds only
   `pwd` and one focused inert check. Only the affected image stage (now 39 checks)
   and assembly ran again; unchanged wrapper/contract results were `SKIP_PASS`.

The earlier 38-check image PASS remains retained at
`b4afb2c4b6f3579c3928cf1afd90100d6cfe4ebdc0692f004886d8dc42e39c62`;
it was not sufficient for the changed builtin policy. No record was erased,
irrelevant pin changed, timeout extended or retry added. There is one successful
real static assembly, not a target-code execution. Unit kernel/socket/process
edges were inert and filesystem fixtures were owned temporary data.

New stage closures contain 5/84/58/88 explicit inputs; capacity increases from
164 to 168. Three selected v1 provisioning compatibility checks run with the nine
new v2 checks; imported historical fixtures do not schedule their full suites.
Frozen artifacts and old qualification evidence were not recaptured or rebuilt.
This cache remains developer scheduling evidence, not deployment qualification.

The signed commit containing this checkpoint and exact remote SHA readback are
recorded in ignored `.aragorn/pi-core-service-image-batch-13-release.json` and
the chat milestone. Only batch-owned files are committed; unrelated drafts stay
untouched. The existing GitHub repository is public; the authorized push publishes
source and checkpoint metadata, not local image bytes or credentials.

## Remaining plan and evidence ceiling

Native START remains `provider_status: UNAVAILABLE`. Historical exit gates,
the approved 29-requirement mapping, frozen predecessors and operational holds
remain unchanged. No service readiness, admission, RUN or Phase 3 gate is closed.

1. **D2:** connect this image and wrappers to protected configuration/installation,
   unit startup and listener readiness, authenticated channel acquisition, exact
   process/unit stop and cleanup. Establish actual consumed-code identity,
   native recovery and bounded timing. Select the model/trust/key deployment
   profile; then run a separately authorized useful controlled-environment pilot.
2. **D3:** finish admission, RUN/sensor-health and workload/paired-task coverage
   on that same common deployment.
3. **D4:** complete the executable 29-requirement mapping and independent verifier
   inventory, close prerequisites and freeze once.
4. **D5:** perform the required fresh acceptance, measurements and verified cleanup;
   retain evidence for offline replay. Only then assess Phase 3 completion.
