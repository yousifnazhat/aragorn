# Native policy tamper handoff — reviewed focused mocked PASS

Base: verified signed published `d87572182584f9c106393a2ca952c69703b6da6d`.
The admission owner fast-forwarded the existing `codex/phase3-admission` branch
without conflicts, preserving `.lavish/` and the local `ADM03_NATIVE_MAP.md` draft.
Accepted `ownership-and-release-v2.md` and the final decisions in
`admission-policy-tamper-contract-v1.md`. Only the four assigned files are changed.
The owner subsequently verified the signed published corrected-runner checkpoint
`4ec18f80164c0cc11e387c2f292e0716f54df208`, fast-forwarded without conflicts and
acknowledged `lane-review-and-scheduling-v3.md` and the provider-review checkpoint.
All five reviewed source hashes below matched before the one scheduled run.

## Stable implementation and complete behavioral closure

Hashes below are SHA-256. These five files are the actual complete repository
import/test closure, not a prospective inventory. No file is generated or loaded
at test runtime; all inert fixture bytes are authored in the test module.

| Path | Bytes | SHA-256 |
| --- | ---: | --- |
| `src/aragorn/native_phase3_admission_policy_tamper.py` | 4249 | `2e44450c778921381d91267ddae3d8c9b36d172921608fe4c0c7152777ad347c` |
| `src/aragorn/native_phase3_admission_policy_tamper_verify.py` | 13552 | `9b56ebb59e1139c749c6df8a7d9c4b5770a24b1bd1b5829625a0f25d3fbea333` |
| `tests/test_native_phase3_admission_policy_tamper.py` | 21832 | `92f96cac9df0314b9f2b85b041fd61a451858e74f3ddc5fafd2214ade18f4c8d` |
| `src/aragorn/oci_worker_protocol.py` | 22775 | `0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b` |
| `src/aragorn/__init__.py` | 78 | `4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01` |

Producer imports the independent consumer's public incremental guards and the
existing canonical JSON function. Consumer imports no producer or producer
parser: it independently parses the complete retained envelope and replays all
joins, bounds and counts. Tests independently author complete envelopes and
callback bytes rather than trusting producer output as the only oracle.
Other imports are Python stdlib (`base64`, `hashlib`, `json`, `pathlib`, `re`,
`stat`, `copy`, `unittest`, and existing canonical-support stdlib imports).

The pipeline automatically adds `scripts/phase3_pipeline.py` and
`requirements-worker.lock`, binds interpreter/toolchain/environment and stage
metadata, and resolves the reviewed `benchmark/phase3-pipeline-v1.json` registry.
The handoff, contract, source map and public OpenClaw archive are review references,
not runtime behavioral inputs to these mocked tests. No historical fixture,
deployed config or historical suite is imported. No cache is copied.

The coordinator registered and scheduled this exact focused stage:

```json
{
  "id": "native-admission-policy-tamper",
  "description": "26 inert callback and independent retained-byte policy tamper tests; no native effects or qualification",
  "tests": ["test_native_phase3_admission_policy_tamper"],
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_admission_policy_tamper.py",
    "src/aragorn/native_phase3_admission_policy_tamper_verify.py",
    "src/aragorn/oci_worker_protocol.py",
    "tests/test_native_phase3_admission_policy_tamper.py"
  ],
  "needs": [],
  "timeout_seconds": 120
}
```

The owner inspected both worktree and integration cache locations: neither held
a prior actual result for this stage. Selected status was `NEW`, with no dependency
stages. The one scheduled owning-worktree command was:
`/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-admission-policy-tamper`.
No historical stage was run or reused as this result.

## Actual retained check result

PASS: 26 inert tests in 0.091 seconds, exit 0. The complete `stderr.log` has
26 individual `ok` outcomes and the unittest `OK` summary. Equal pre/post fingerprint:
`sha256:c08b47026e885e68bab6482ca5d858863ef442774f40db55eedea486b3e9ce46`.
Original artifacts remain in this worktree at
`.aragorn/phase3-pipeline/native-admission-policy-tamper/c08b47026e885e68bab6482ca5d858863ef442774f40db55eedea486b3e9ce46/`.

| Actual artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `result.json` | 812 | `529658a38ebf01bd742956df694fab531b66c17a1cc1b019a433042717804cdb` |
| `stderr.log` | 4335 | `834dab28a9cd919e43c0242a7a2db0d2f348cc91c9a606472d7d6e69c89ef050` |
| `stdout.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The result's log lengths/digests were checked against actual retained bytes, and
its status, exit code, stage ID and unchanged fingerprint were reviewed. No failure,
retry, cache copying, historical-suite rerun or native operation occurred. This
PASS validates finite callback/retained-byte consistency only.

## Implemented finite behavior

`record_policy_tamper` uses exactly the three required callbacks. Before any
callback it checks availability and the independently held context/bindings.
The fixed config-then-printf order has six operations each. Every accepted action
is bracketed by unchanged protected resource bytes/metadata/ancestry readbacks,
baseline digest and catalog digest. Only EACCES/EPERM/EROFS count as protective;
EXDEV/EBUSY count as structural solely for replacement rename/parent retarget.
The single subsequent invocation requires the six fixed arguments, exit 1 and
both exact source-confirmed CLI byte streams. It then requires a final snapshot.

`verify_policy_tamper` accepts only canonical bounded JSON/base64 with exact field
sets, strict integers and independently supplied record/context/binding pins.
It hashes retained config/printf bytes and reconstructs counts, ordering and
time brackets. It compares the invocation's observation pin with the separate
post-retention `expected_policy_observation_digest`; it never predicts that pin
inside context. All three authenticity/qualification flags must remain false.

Failure stops immediately: no retry, next mutation, repair or cleanup follows.
`PolicyTamperRecordingError.partial` is canonical bounded partial evidence with
phase, failure type and captured callback bytes. A callback exception can supply
`partial_bytes: bytes`; those fragments are retained as failure evidence only.
The partial byte budget is 2 MiB plus bounded envelope overhead; per-event caps,
full returned length/digest and explicit truncation prevent truncated success.
Arbitrary exception messages are omitted. Missing transport fragments remain an
outer provider/retention responsibility. Callback timeouts/cancellation supervision
belong to root; this synchronous leaf cannot preempt a callback that never returns.

The present disabled baseline is preserved; no target-absence flag is manufactured.
Baseline/catalog digests remain protected-observer assertions, not independent
tree/catalog decoding. Endpoint equality is not continuous custody. The current
printf hook does not retain its request; exact CLI text plus the observation pin
does not authenticate native policy execution. No native deployment, ADM-03 closure
or admission/Phase 3 qualification is claimed.

## Focused mocked cases

The test module contains 26 methods covering independently authored success,
producer order/replay, all protective errno values, structural EBUSY/EXDEV,
substituted external pins and held context identities, wrong record/observation
pins, bytes/metadata/ancestry changes, baseline/catalog/candidate changes, operation
inventory/order, unknown fields, structural misclassification/success, chronology
and bool/float/overflow integers, exact CLI channels/exit, claim promotion,
context/nonce/schema substitutions, duplicate/nonfinite/noncanonical/oversized JSON,
base64 bounds, invalid preconditions, missing callbacks, immediate stop and partial
retention, oversized returned prefixes, mutable caller bindings, provider partial
fragments and the contract's exact CLI lengths/hashes.

## Exact missing root provider fields and evidence

- Independent `bindings`: context, deployment, config, policy_executable, node,
  runtime_tree, candidate, baseline and observer_source. Supply protected installed
  readbacks and source/config-credential derivation; archive/member pins alone do
  not establish installed bytes or full runtime import custody.
- Context `fixture` (container/boot/netns), `gateway` (PID/start/UID/GID), `clock`
  (boot/CLOCK_BOOTTIME/time namespace), nonce, fixed subject, argv and reviewed
  public cwd/environment. Hold gateway/process/namespace identity through actual
  operations. Reject unreviewed environment keys or secrets before acquisition.
- Each `resources` entry: exact native path, digest, device/inode/mode/UID/GID/
  nlink/size/mtime/ctime and root-to-parent ancestry. Root must hold descriptors,
  verify nofollow named joins, and retain raw bytes under the selected namespace.
- Each snapshot: context/nonce/observed_ns, those resources plus raw_base64,
  baseline_digest, catalog_digest and candidate_installed=false. Root must acquire
  actual unchanged baseline bytes, disabled plugin inspection and gateway/skills
  catalogs; assertion equality here does not verify those full underlying records.
- Mutation callback: context/nonce/resource/operation/start/finish/result/errno,
  actual dropped-privilege syscall evidence, and fixed scratch/adjacent-name
  provisioning from the contract. No native mutation adapter is supplied here.
- Invocation callback: context/nonce/start/finish/argv/exit/stdout/stderr and
  policy_observation_digest. The protected observation must join the actual
  subsequent policy request/decision to the fixed subject and source identities,
  excluding earlier source/config/dependency failures. Its schema, acquisition
  provider, retained bytes and independent custody verifier are still missing.
  Supply the expected digest only after protected retention; never hash CLI text
  as a substitute or infer invocation from exit status.
- A separate absent-target adapter/parent custody and ordered lifecycle provider
  remain explicit root obligations for cases requiring them. This present-target
  tamper leaf supplies neither. Root owns deadlines, cancellation and retention.

## Checkpoint state

Source AST/import review preceded the coordinator's source/closure approval and
explicit selected-stage schedule. The actual focused PASS above completes the
released offline finite tamper recorder/independent-consumer batch, with all
native authenticity and qualification flags still false. The signed batch contains
only the three assigned source/test files and this handoff. Its original commit
hash and signature verification are reported separately to avoid a self-referential
commit claim. Existing passes, drafts and the fixture-cleanup hold remain intact.

Later assignments require concrete coordinator contract/path release: exact-byte
and activation-path ports, policy-failure, six reload groups (config,
filesystem-watch, plugin-skill-directory, manual-plugin, remote eligibility,
sandbox-per-run), then distinct ClawHub tracked replacement. Inventory each gap
against existing adapters/consumers before choosing implementation. All 31 cases
must eventually have real execution and independent semantics on one deployment;
this leaf is only one finite consistency component of that objective.

1. Shared startup/capture/listener integration: unresolved.
2. Admission and RUN/measurement implementation: current work.
3. Independent verifier inventory, then freeze: pending.
4. Final acceptance: blocked until prerequisites close.
