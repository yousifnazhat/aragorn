# Native admission policy tamper contract v1

Base: `27e9844e6d5f0924b79382a8a084099ee06e2ed6`.
Release is one offline callback-only recorder and independent retained-byte
consumer. This finite slice records protection of the actual native policy
resources and consistency of a subsequent native denial. It does not close
ADM-03, prove protected provider authenticity, or supply an absent-target route.
No live mutation, policy process, test or cleanup is scheduled by this document.

## Confirmed native policy and scope decision

The native config selects `security.installPolicy.enabled=true`, targets exactly
`["plugin"]`, `exec.source="exec"`, command `/usr/bin/printf`, trustedDirs
`["/usr/bin"]`, and args `%s` followed by the exact JSON string:

```json
{"protocolVersion":1,"decision":"block","reason":"plugin installs disabled by Aragorn protected profile"}
```

There is no separate policy script or interpreter. `/usr/local/bin/node` is the
OpenClaw runtime interpreter. Do not transplant historical Python or `/profile`
policy resources. The config source is `/etc/aragorn/agent-gateway/openclaw.json`;
the gateway consumes `/run/credentials/aragorn-agent-gateway.service/openclaw-config`.
Root owns its actual source-to-credential derivation and fresh complete config pin,
including HTTP tools and the successor logging settings. Historical config pins
must not silently substitute for this new complete config.

Confirmed package: `.aragorn/artifacts/native-cache-build-79ed6eb/openclaw-2026.7.1.tgz`,
19921213 bytes, SHA-256 `9923017c01a2905a4cc953f817e5ea2dfb75ece462f6376d589a664bfdbb4df2`.
Selected members (under `package/`) have exact SHA-256 values:

| Member | SHA-256 |
| --- | --- |
| `dist/install-policy-yA6T1vUH.js` | `fe85c45bb33191131662b161be2daf66270fa4f538cefbc807b16661cd9884e1` |
| `dist/install-security-scan.runtime-CMin9jbx.js` | `49efcd394780b9b65338e41121b1e14be6c4297aa3af232eb64d947364122f35` |
| `dist/install-BzCFXkWy.js` | `c0418807ee6a26e09b1cd878e5d68f87cdfe882786903449bde4ec1ec9c1da45` |
| `dist/plugins-install-command-BgpmND25.js` | `5e4af650bbdf8eda2d57fc2d80f0a09e6622e223cd95b6557e4c22ef30470c88` |

The reviewed policy code receives request JSON on stdin, spawns without a shell,
and parses the child's protocol-1 output. Config, source and dependency failures
can occur before this point. `printf` does not validate or retain the request.
An exit code or block string alone therefore cannot establish policy invocation.
The source names `security_scan_blocked` and `security_scan_failed` are internal
results, not CLI JSON fields or public emitted codes.

Use the existing fixed plugin replacement subject for this first finite slice:

```text
plugin ID: aragorn-plugin-skill-replacement-fixture
argv: ["/usr/local/bin/node", "/runtime/lib/node_modules/openclaw/openclaw.mjs",
       "plugins", "install",
       "/route-input/plugin-package-skill-replacement/candidate-source", "--force"]
expected exit: 1
expected stderr: blocked by install policy: plugin installs disabled by Aragorn protected profile\n
```

Root reuses the existing source-reviewed native plugin-package fixture builder
and namespace/privilege conventions, with fresh pins. Baseline target starts
present and must remain the same original bytes and catalog entry; candidate
must not replace it. This is explicitly distinct from fresh-target absence.
The latter remains a subsequent root adapter and evidence obligation wherever
the exit gate requires it. Never relabel baseline preservation as target absence.
Require the clean branch's exact CLI stdout (including final newline):

```text
Install policy target=plugin:aragorn-plugin-skill-replacement-fixture request=plugin-dir/update origin=plugin-package pathKind=directory source=local-path/user: blocked by install policy: plugin installs disabled by Aragorn protected profile
```

Its length is 242 bytes and SHA-256 is
`8c0265e48856ba50083bb6f92bc0e12f54fe99940af3b62aed289f39d5701e11`;
stderr is 81 bytes and SHA-256
`a149f38f8d60b58e495961982b80d56c9ac4cac151e0a7698945b3e45dd2eb32`.
Additional diagnostics refuse. These are source-derived expected bytes, not
observed native results. Do not treat printf's internal JSON as CLI stdout or
accept earlier config/source failure as policy denial.

## Exact ownership and interfaces

Admission owns only these new files:

- `src/aragorn/native_phase3_admission_policy_tamper.py`
- `src/aragorn/native_phase3_admission_policy_tamper_verify.py`
- `tests/test_native_phase3_admission_policy_tamper.py`
- `docs/phase3/admission/POLICY_TAMPER_HANDOFF.md`

The existing source-map draft may stay local. Existing shared sources, registry,
fixture builder, native command adapter, config/staging and protected observation
providers are coordinator-owned. No existing recorder/consumer may be repurposed
under an old fingerprint. The new recorder has no subprocess/filesystem effects;
all observations and actions come from required root-owned callbacks:

```python
record_policy_tamper(*, context_raw: bytes, bindings: dict,
                     read_snapshot, attempt_mutation, invoke_policy) -> bytes
# read_snapshot() -> canonical snapshot bytes
# attempt_mutation(resource: str, operation: str) -> canonical mutation bytes
# invoke_policy() -> canonical invocation bytes

verify_policy_tamper(raw: bytes, *, expected_digest: str,
                     context_raw: bytes, bindings: dict) -> dict
```

Verifier imports no producer or private producer parser. Stdlib and existing
canonical JSON support are sufficient. Tests supply independently authored
inert callback bytes; no native operation runs. Missing providers refuse before
any mutation. Failed/partial callback outcomes raise with bounded partial bytes;
never continue to another mutation or invoke the policy after an unexpected result.

## Caller-held context and evidence schemas

All records are canonical ASCII JSON (sorted keys, compact separators), with
exact keys, no duplicates/nonfinite numbers; byte strings use canonical base64.
Every integer is strict, not bool; unsigned values are below 2**63. Every pin
is lowercase `sha256:` plus 64 hex digits. Never derive expected pins from the
candidate being verified. Context and snapshots are at most 262144 bytes each;
mutation/invocation at most 65536 bytes each; complete record at most 4194304 bytes.
No oversized record may truncate into success.

`bindings` exact keys: `context, deployment, config, policy_executable, node,
runtime_tree, candidate, baseline, observer_source`. All are independently held
digest strings. Context digest binds context_raw. Actual installed byte pins
must come from protected root readback for the chosen successor; this contract
does not invent guest hashes or claim that the public archive is deployed.

Context exact keys: `schema, nonce, fixture, gateway, clock, bindings,
resources, argv, cwd, environment, subject`.
Schema: `aragorn/native-admission-policy-tamper-context/v1`; nonce: 64 lowercase hex.
Its bindings contains all external binding keys except context (no self-hash).
Fixture: exact existing `container_id, boot_id, netns_device, netns_inode` format.
Gateway: `pid, start_time_ticks, uid, gid`, PID/start positive, UID/GID exactly 992.
Clock: `boot_id, clock_id, time_namespace_device, time_namespace_inode`, same boot,
`CLOCK_BOOTTIME`, nonnegative device, positive inode. These are externally held
identity claims requiring root observation, not proof from equality alone.

Resources is a two-key map: `config` and `policy_executable`, exactly the credential
and printf paths above. Each value has `path, digest, identity, ancestry`.
Identity is `device, inode, mode, uid, gid, nlink, size, mtime_ns, ctime_ns`;
inode/size positive, regular single-link, no group/world write, fixed original
metadata supplied by root. Ancestry is a nonempty ordered list of `path, device,
inode, mode, uid, gid` from root through immediate parent; root holds descriptors,
checks nofollow named joins and supplies these observations. Stable directory
metadata excludes timestamps and size. Resource digests join binding pins.

Argv is the exact six-element vector above. Cwd/environment are the exact
root-selected native execution values bound by context, with no secrets retained;
only public credential paths and public fixed fixture settings may appear.
Root must reject unreviewed environment keys before live execution. Subject exact
keys: `plugin_id, candidate_path, target_path, candidate_digest, baseline_digest`.
Plugin/candidate match the fixed values above; root resolves and pins the actual
baseline target under its held parent from the existing native fixture contract.
The lane must not choose a target from untrusted observations.

Snapshot exact keys: `schema, context_digest, nonce, observed_ns, resources,
baseline_digest, catalog_digest, candidate_installed`.
Schema: `aragorn/native-admission-policy-tamper-snapshot/v1`; resources contains the
same exact metadata plus `raw_base64` for each resource. Decode and independently
hash exact raw bytes; require original context identity/ancestry and digests.
Baseline digest equals the pinned baseline, candidate_installed is false.
Catalog digest must be equal before/after every mutation and invocation. Endpoint
equality does not prove interval-wide custody or absence of mutation/restoration.

Mutation exact keys: `schema, context_digest, nonce, resource, operation,
started_ns, finished_ns, result, errno`. Schema:
`aragorn/native-admission-policy-tamper-operation/v1`; result must be `DENIED`.
Errno is a symbolic Linux name; only EACCES, EPERM or EROFS counts as protective
denial. EXDEV/EBUSY is structural refusal and leaves this batch incomplete.
All success/unknown outcomes stop the recorder, preserving partial evidence.

Invocation exact keys: `schema, context_digest, nonce, started_ns, finished_ns,
argv, exit_code, stdout_base64, stderr_base64, policy_observation_digest`.
Schema: `aragorn/native-admission-policy-tamper-invocation/v1`; argv is exact,
exit_code=1, stderr and stdout are the exact lines above.
The policy_observation_digest must be an independently retained protected root
observation, not a hash invented from CLI text. This slice carries its pin but
does not validate its missing native schema; policy execution remains unverified.
The existing policy code supplies no such provider. Root must implement and review
it before any native run; unresolved provider means no execution release.

## Twelve finite operations and record order

For config, then policy_executable, use this exact operation order:
`OVERWRITE, CHMOD, UNLINK, REPLACE_RENAME, ADJACENT_SYMLINK, PARENT_RETARGET`.
Root owns fixed scratch replacements and absent adjacent names. A callback may
not receive arbitrary path/argv/payload from the lane. Each is one attempted
operation by the pinned gateway identity. No restore, retry, cleanup or policy
invocation follows any unexpected success, changed snapshot or uncertain result.

Root's future native adapter fixes scratch directory
`/var/lib/aragorn-agent-gateway/adm03-policy-tamper`. Per resource, replacement
basename is `<resource>.replacement`, holding exactly `aragorn-adm03-tamper\n`;
overwrite uses these same bytes, chmod requests 0777, unlink uses the original
path, replacement rename moves this fixed replacement onto the original path.
Adjacent insertion uses basename `.aragorn-adm03-<resource>-<nonce>` in the
original parent and points to the fixed replacement. Parent retarget attempts
to rename the original parent to `<resource>.parent` in the scratch directory.
All scratch/adjacent preconditions and held source/destination parents belong
to root provisioning; missing or preexisting unexpected names refuse. Structural
refusals remain incomplete evidence rather than protective denial. No adapter
performing these operations is implemented or authorized by this contract.

Complete record exact keys: `schema, context_digest, before, attempts,
invocation, after, policy_execution_verified, admission_qualified,
phase3_qualified`. Schema `aragorn/native-admission-policy-tamper-record/v1`;
three flags literal false. Before/after are canonical raw snapshot base64.
Attempts has exactly 12 rows, each exactly `operation_base64, snapshot_base64`.
Invocation is canonical raw invocation base64. Require context/nonce joins and
nondecreasing observed/action times throughout; each action's start <= finish
and enclosing before/after snapshot brackets. All snapshots preserve exact
resource bytes/metadata, baseline and original catalog digest.

Success verifier result exact keys: `status, digest, operations,
policy_execution_verified, admission_qualified, phase3_qualified, limitations`.
Status `CONSISTENT_POLICY_TAMPER_RECORD`, operations=12, flags false. Limitations
must retain missing protected invocation authenticity, interval custody, fresh
target absence and native admission qualification. CLI text must never upgrade
these flags. This additive leaf can be implemented with inert callbacks now;
root provider/installed context integration stays explicitly pending.

Owner agreement after the signed checkpoint releases these four files only.
Submit stable code, exact fixture/import closure and focused stage proposal;
root reviews before registration/scheduling. Policy-failure, reload families
and ClawHub replacement remain later separate slices. All operational holds remain.
