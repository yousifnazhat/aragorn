# Aragorn

**Agent Runtime Admission, Governance, Observation, Response, and Neutralization**

Aragorn is a planned open-source admission-control foundation for agent capabilities. It binds evidence to exact artifact digests and fails closed when acquisition or required analysis is incomplete.

Current status: **private qualified Phase 0 validation milestone complete; Phase 1 admission-runtime conformance engineering started**. Retained evidence includes one fresh hidden efficacy pass, final-candidate maintenance replay, paired acquisition/reference evaluation, and the standards gate. OpenClaw `2026.7.1` passed the explicit install-block probe but failed the mandatory direct-write path, which eliminates it as a standalone admission reference monitor. A separate OS-mediated contained profile passed install, direct-write, rename, symlink, auto-discovery, runtime restart, policy-failure, unprivileged policy-tampering, exact conformance-fixture activation, three of nine inventoried update routes, six of twelve reload routes, and the retained activation and recovery slices. One additional update route failed, so the formal profile is `FAIL` and installer-ineligible; the remaining routes, including `reload/workshop-invalidation`, remain `NOT_TESTED`. Formal `ADM-01` passes for the contained conformance fixture. A separate DET-only receipt passes four fixed decision exits across three clean processes each, but is not composed with the runtime receipt. Host/root tampering and Pi also remain dynamically untested. No runtime is admission-conformant yet. This is not an unqualified fresh-final-candidate exit claim, EDR, supported release, installation boundary, general OpenClaw security finding, or claim that a skill is safe. Aragorn remains private until every roadmap phase is completed and evaluated and every applicable exit gate has passed.

The fixed OpenClaw restart evidence pair is now rechecked by an exact
`ADM-02/restart` verifier. Carried scenario claims remain retention-only. The
verifier rejects promotion and aggregate `PASS`; it grants no installer
authority and does not replace the future general verifier.

The update-slice verifier proves that one user-writable managed target was not
replaced after an exact `skill-install/update` policy denial. That slice did not
establish aggregate update conformance; cumulative formal `ADM-02/update` is now
`FAIL` because of the independently retained workshop route.

The live-reload verifiers bind one admitted forced replacement to a new watcher
snapshot consumed by the same chat session and to two forced isolated cron runs
that built fresh prompt snapshots on opposite sides of that replacement,
without a gateway restart. The cron runs used distinct isolated sessions and
lifecycle revisions but stopped at model resolution before provider execution;
this proves prompt-snapshot construction, not successful provider completion.
Formal `ADM-02/update` is now `FAIL`; formal `ADM-02/reload` remains
`NOT_TESTED`. These route-level observations grant no installer authority.

The config-activation-slice verifier proves `skills.update` disabled and
re-enabled a previously verified skill digest mounted read-only, while the same
chat session dropped and restored that skill without a gateway restart. It also
proves one missing prompt blob was rebuilt to the same prompt digest while the
bound read-only bytes stayed unchanged, without changing the session or
snapshot version. These are reactivation and cache-recovery routes, not
acquisition or authentication; they do not promote formal `ADM-02/update` or
`ADM-02/reload`.

The model-activation verifier binds the same 104-byte conformance fixture to
OpenClaw's real gateway, model transport, and `read` tool path. An
evaluator-controlled loopback provider requested that exact `SKILL.md`; the
second provider request carried the complete bytes, and the turn completed
without target mutation or gateway restart. This promotes only formal
`ADM-01`. It is not production `ALLOW` lineage, external-model efficacy,
deterministic replay, or installer authority.

The deterministic-authority verifier binds canonical manifest, analyzer
evidence, policy, and target-runtime inputs to exact canonical decisions for
`ALLOW`, `REVIEW`, `DENY`, and `ERROR`. Each vector produced byte-identical
output across three fresh CPython processes with distinct hash seeds. This
promotes only `DET-01` in a separate receipt; it does not attest the fixed
analyzer evidence, compose `ADM-01`, or grant installer authority.

The cumulative update/reload coverage verifier derives one canonical 21-route
ledger from exact source receipts and their transitive evidence. It records
3/9 update routes as `PASS`, 1/9 as `FAIL`, and 6/12 reload routes as `PASS`.
`ADM-02/update/workshop-proposal-apply` failed because the configured install
policy blocked the positive-control installer but was not invoked when workshop
apply created the workspace skill. This result is limited to the pinned runtime,
configuration, route, and retained evidence; `reload/workshop-invalidation`
remains `NOT_TESTED`. The next production decision is to mediate and protect
workspace skill writes externally or evaluate another harness.

## What works now

- Bounded, symlink-safe inventory of a local Agent Skill directory.
- Evaluation-only acquisition of one public `github.com` skill directory at an
  exact 40-hex SHA-1 commit, with API-bound commit/tree identities,
  independently verified Git blob SHA-1 values, and SHA-256 CAS retention.
- Evaluation-only discovery of bounded literal local and exact-commit GitHub
  references across retained text carriers, with opaque, mutable, dynamic, and
  unsupported cases recorded fail closed in a digest-bound source-reference
  graph.
- A distinct evidence-only admission `artifact_graph` for the first supported
  profile: self-contained local Markdown. Its verifier replays the retained
  manifest and bounded literal references independently and binds its expected
  implementation identity; scripts, executables, binaries, external or dynamic
  acquisition, unsupported Markdown references, and opaque carriers remain
  incomplete. Decision and publisher wiring are not yet enabled.
- Evaluation-only recursive acquisition of supported exact same-repository
  GitHub blob references, including references to another immutable commit,
  under shared request, byte, object, depth, reference, and deadline budgets.
  Complete expansion produces one
  deterministic comparator subject; incomplete expansion retains accounting
  but no comparator subject.
- Same-file-descriptor ingestion into a private SHA-256 content-addressed store.
- Re-verification before reads and materialization.
- Descriptor-bound comparison of a staged source-tree snapshot against a fully
  re-verified retained manifest, plus private POSIX fresh-only publication
  beneath a broker-owned, sole-writer root. No current receipt authorizes that
  publisher, and it remains absent from the CLI.
- A source-screen-only lock for exact OpenClaw and Pi Git identities. A
  separately bound OpenClaw probe retains one install-path `PASS` and one
  direct-write `FAIL`; the static lock remains a source-screen record and does
  not transfer installer authority.
- Sanitized execution from an empty control directory, with bounded output, process-group wall-clock supervision, and executable-byte identity.
- Open-once analyzer ingestion and launch from a private CAS materialization, so later replacement of the original configured file cannot change the staged entrypoint bytes.
- Byte-exact retention of analyzer stdout and stderr.
- Evidence-only analyzer-run receipts that bind the exact request, retained
  executable and configuration bytes, verifier implementation identity, raw
  streams, execution state, and canonical observations; replay rejects
  mismatched or missing CAS evidence. These receipts are not installer
  authority.
- Semantic replay of `decision/v2`: the verifier reloads the retained policy
  and manifest, replays every analyzer receipt, rebuilds each summary, and
  re-derives the verdict. Current source-tree-only inspection still fails
  closed and the replay grants no installer authority.
- Graph-bound `decision/v3` retention and replay: the verifier requires
  caller-held expected manifest, graph, policy, exact analyzer-run receipts,
  graph-verifier, and analyzer-verifier identities before evaluating the
  verified artifact closure. It remains evidence-only and is not wired to the
  CLI or publisher.
- A broker-context-only install contract requires a caller-held context digest
  and independently expected target, runtime-conformance identity, measured
  runtime identity, live destination descriptor, expiry, and current revocation
  state before replaying `decision/v3`. It returns only normalized verified
  values; it cannot grant installer authority and does not call the publisher
  while positive runtime evidence semantics remain unverified.
- Strict JSON Lines observations bound to the exact tree digest.
- Deterministic `ALLOW | REVIEW | DENY | ERROR` policy evaluation.
- Fail-closed handling of missing analyzers, malformed evidence, timeouts, output limits, and incomplete artifact closure.
- Fail-closed, version-specific normalizers for Cisco Skill Scanner `2.0.12` and NVIDIA SkillSpector `2.4.3`.
- Two locally built, digest-locked Linux/arm64 OCI closure candidates for those comparators.
- A digest-bound OCI evidence-smoke runner that launches with pulling and networking disabled, a read-only root filesystem and workspace, dropped capabilities, no-new-privileges, a non-root user, and fixed process, memory, CPU, file-descriptor, and temporary-filesystem limits.
- OCI evidence v3 retention and independent verification of the selected baseline, raw content-addressed OCI index/platform/provenance/config graph, effective runtime configuration, pre/post Docker context/engine/worker claims, pre/post container inspection records, verified subject digest, raw vendor streams, normalized observations, and derived verdict. Historical evidence v2 remains verifiable.
- A digest-frozen 18-case inert OCI pilot, balanced within development and
  provisional held-out splits, plus a control-plane audit for lineage-bound
  source provenance and cross-split near-duplicate warnings.
- A complete same-principal label-free prepare/run/collect plumbing path: the protected control
  plane retains private labels, each worker receives only a canonical sanitized
  subject and pinned execution identity, output is atomically published as an
  exact CAS closure, and collection commits the full nonce set atomically in
  the protected control state.
- OCI evidence v4 joins the private dispatch to the unsigned worker result only
  after independently re-verifying its request, subject, exact output closure,
  nested evidence v3, raw OCI evidence, and derived verdict. It deliberately
  carries `unsigned_label_free_protocol_not_isolated_or_attested`, not a signature or
  attestation claim.
- A protocol-v2 foundation that separates host-independent requested policy
  from worker/runtime measurement and binds a fresh verifier challenge.
- A protocol-v2 batch preparer that binds each declared system configuration
  to its portable-policy digest, issues one verifier-owned challenge per
  case/system/run cell, exports the exact semantic input closure, and publishes
  only a label-free worklist beside the worker bundles. Private case and run
  bindings remain in the control-plane dispatch.
- A bounded protocol-v2 CAS handoff format and importer. Export produces a
  private `0700` bundle containing only a declared closure. After an
  operator-controlled byte-preserving copy creates a receiver-readable
  snapshot, import fully re-hashes it into private staging, rechecks the source,
  and only then publishes the validated bytes into the receiving owner's CAS.
  The expected manifest digest, kind, and root digest are mandatory external
  inputs; `worker_input` additionally requires the verifier's externally held
  expected challenge. The semantic `worker_output` path requires both the
  externally retained request digest and challenge. Never make a hidden corpus
  world-readable to cross the boundary.
  Untrusted-input rejection occurs before CAS blob publication. CAS batch
  publication is not atomic yet; on a receiver-side storage failure, only
  already validated non-root blobs may remain, and the declared root is
  deliberately published last.
- `worker_input` handoffs now derive and require the exact semantic closure of
  the canonical v2 request root: the bound portable policy, sanitized subject
  manifest, and every declared subject file blob. Missing, extra, noncanonical,
  stale-challenge, or cross-root content fails before CAS blob publication.
  Baseline and image digests remain execution-identity bindings to assets the
  worker must verify;
  they are not silently treated as transported blobs.
- A separate unsigned worker-result v2 contract now binds the verifier-issued
  request digest and challenge, portable policy, subject, baseline, pinned
  image identities, normalization, execution state, and verdict invariants.
  The semantic `worker_output` builder derives the exact typed retained set:
  the result root, full input closure, baseline bytes, effective configuration,
  measured Docker executable, OCI evidence, runner receipts, container
  inspection records, raw streams, and observations. It independently checks
  the effective configuration's portable projection and Docker-byte binding.
  `export_handoff` and `import_handoff` fail closed without both verifier
  values for output. Separately named declared-byte transport helpers exist for
  transport testing and cannot be treated as semantic acceptance.
  `verify_worker_output_evidence_cas_v2` additionally replays the existing
  OCI v3 verifier against the label-free v2 result: baseline lock and entry,
  effective configuration, OCI graph, runner receipts, image/container
  inspection, raw vendor report, observations, and verdict must all agree.
  Handoff reachability remains distinct from explicit evidence acceptance.
- A signed protocol-v2 worker-output acceptance library now uses canonical
  DSSE statements and Ed25519. The statement binds one trust domain, worker,
  key, job, verifier challenge, request, result root, and exact handoff
  manifest. The verifier loads an active or revoked key only from a protected
  trust store outside the worker bundle. A protected issuance ledger holds the
  expected request identities; collection verifies the signature, imports the
  exact semantic output, replays the deep OCI verifier, and only then publishes
  an atomic acceptance receipt. Exact retry is idempotent and conflicting reuse
  of a challenge fails closed. The receipt explicitly says
  `software_key_signature_not_hardware_attested`.
- A one-shot protocol-v2 worker supervisor imports one exact input handoff,
  verifies portable policy before launch, executes the real OCI comparator,
  deeply verifies and exports the exact output closure, and only then signs
  its manifest. Its private key is outside every analyzer mount.
- One retained mount-free Lima smoke completed the real signed cross-boundary
  path and control-plane acceptance. This remains infrastructure evidence for
  one public benign fixture; Docker self-reports and a software signing key
  are not hardware attestation or efficacy evidence.
- The accepted private `local-v6.0.0` corpus contains 448 inert cases: 336
  benign and 112 adversarial. It passed internal integrity, archive-safety,
  signature, and hidden-label binding checks.
  [`benchmark/phase0-corpus-v6.lock.json`](./benchmark/phase0-corpus-v6.lock.json)
  pins its exact worker archive, signed Git freeze, and signing identity without
  checking labels into this repository. V6 is the sole fresh hidden corpus;
  the V7 final-candidate run reused it only for calibration. Its assurance is
  technical Codex authorship, not proof of an independent human identity,
  external custody, or redistribution permission.
- A machine-validated Phase 0 standards gate freezes three scoped evidence
  packs: OWASP Agentic Skills with the stable related Agentic Applications
  taxonomy, MITRE ATLAS, and NIST AI RMF/GenAI Profile. The checked-in
  [`benchmark/phase0-standards-gate.json`](./benchmark/phase0-standards-gate.json)
  accounts for 26 selected items with no unresolved disposition. Passing this
  gate means the selected risks have repository evidence or an explicit later
  phase; it is not certification, full mitigation, usability, or adoption
  evidence.

Local and evaluation-only GitHub acquisition establish only `source_tree`
closure. `resolve-artifacts` can additionally produce a
`source_reference_graph`, but that evaluation contract is not the admission
`artifact_graph`: it fetches no external bytes, marks opaque carriers
incomplete, and cannot prove that dynamic references are absent.
`expand-github` goes one step further for Phase 0 measurement by recursively
retaining only supported exact blobs from the same repository and commit. Its
comparator subject is evaluation input, not an admission manifest, and it
cannot produce `ALLOW`. Aragorn therefore returns
`ERROR / ARTIFACT_CLOSURE_INCOMPLETE` from `inspect` until the supported
production acquisition boundary exists. There is deliberately no installation
command yet.

## Requirements

- Python 3.12+
- macOS or Linux with POSIX `O_NOFOLLOW` and directory file descriptors
- Docker with a canonical local Unix-socket context and the two locked local Linux/arm64 images for the optional OCI evidence-smoke path
- A private worker scratch directory visible to the selected Docker daemon when
  using the label-free worker on macOS or another remote-daemon filesystem

Aragorn's base CLI has no third-party runtime dependencies. The signed-worker
evaluation path requires the hash-locked dependencies in
`requirements-worker.lock`; no cryptographic fallback is permitted. The
checked-in OCI baseline profile is arm64-only.

CLI exit code `0` means successful `inventory` or `acquire-github`, a
profile-complete `expand-github` or `resolve-artifacts` result, or an `ALLOW`
decision from `inspect`. `expand-github` and `resolve-artifacts` return `2` for
profile-incomplete evaluation evidence; this is not a `REVIEW` admission
verdict. Inspect decisions use `0`, `2`, `3`, and `4` for `ALLOW`, `REVIEW`,
`DENY`, and operational or policy `ERROR`; invalid syntax uses `64`.
Machine-readable result objects go to standard output; error envelopes go to
standard error.

The benchmark module returns `0` for a valid ordinary report. With
`--phase0-accounting`, it returns `0` when the comparative gate passes, `2`
for any valid Phase 0 report whose `comparison.passed` value is `false`
(including an unevaluable comparison), and `4` for invalid input or verification
failure.

## Run

Inventory and retain the exact bytes:

```console
./aragorn inventory ./path/to/skill --state ~/.local/state/aragorn
```

Acquire and retain a public GitHub skill without running repository code:

```console
./aragorn acquire-github https://github.com/owner/repository \
  0123456789abcdef0123456789abcdef01234567 path/to/skill \
  --state ~/.local/state/aragorn
```

This private evaluation command is deliberately unauthenticated and direct: it
supports no private repositories, tokens, cookies, proxies, redirects, Git
configuration, submodules, symlinks, special modes, or Git LFS objects. It pins
GitHub REST API `2026-03-10` for blobs and uses Smart HTTP protocol v2 for
commit and tree objects. It requires `object-format=sha1`, filtered shallow
fetch support, a one-object PACK v2 response of the expected type, a valid pack
checksum, and an independently reproduced Git object SHA-1. It then walks the
verified raw trees, re-verifies each REST-returned blob SHA-1, and retains the
same bytes by SHA-256 only after the complete bounded tree has validated. The
client rejects ambient `SSL_CERT_FILE` and `SSL_CERT_DIR` overrides and loads
only the Python/OpenSSL runtime's compiled CA paths. One monotonic deadline
covers the acquisition. It separately freezes canonical public addresses for
`github.com` and `api.github.com`, connects only to the matching host's set,
and retains TLS hostname verification.

Phase 1 now includes an internal one-shot gateway worker and broker supervisor.
Its canonical request has no credential, proxy, CA, state-path, header, or
caller-controlled limit fields. The privileged broker launches it under a
configured non-root UID and group, clears supplementary groups, supplies an
allowlisted environment, closes inherited descriptors, and enforces bounded
output plus process-group wall-clock deadlines. A bounded isolated resolver
under that UID resolves both fixed GitHub hosts once; the broker rejects
missing, non-global, duplicate, or noncanonical host-specific results
and passes only those exact numeric sets to the acquisition worker, which
performs no DNS resolution. The kernel boundary allows their canonical union
while the application preserves each host-to-address binding. A fixed, root-protected
per-UID lock serializes cooperating brokers that share the host control root
and namespaces; bounded pre- and post-run process censuses reject a pre-existing
or surviving real-UID peer.
Before importing any Aragorn module, each isolated process fixes its soft and
hard `RLIMIT_NPROC` at one and fails closed unless a fork probe is denied. On
Linux, the broker also requires host systemd and cgroup v2 and runs each
resolver and worker in a unique transient service. The fixed service policy
uses the dedicated UID/GID, `TasksMax=1`, control-group cleanup, no
capabilities, no-new-privileges, a read-only host filesystem, address-family
and socket-bind restrictions, and default-deny cgroup IP filtering. The
broker holds a reachable loopback listener and the isolated bootstrap must
prove that the service cannot connect to it before any Aragorn import, so a
host that silently skips the cgroup IP filter fails closed. The bootstrap also
verifies its identity, environment, capabilities,
no-new-privileges state, exact one-task cgroup, and denied fork before importing
Aragorn. Broker cleanup requires the unit to be inactive and jobless, its
cgroup to be absent or empty, and the worker UID to have no remaining process.
The transfer root must be a dedicated 512 MiB, 20,000-inode
`nosuid,nodev,noexec` tmpfs; quarantine is not published until the worker job
is removed and that root is empty. The checked-in sysusers, tmpfiles, and mount
definitions provision the stable non-login principal and private state roots.
Darwin retains the narrower UID-drop, process-group, census, and
`RLIMIT_NPROC` defense-in-depth path.
The broker then imports the declared bytes through Aragorn's cross-owner handoff
and
independently re-verifies the exact manifest, Git blob identities, source
binding, and closure in a fresh broker-owned quarantine. The returned receipt is
explicitly
`QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY`, with
`git_smart_http_v2_commit_tree_and_api_blob_identity_reverified` source
assurance. The raw commit and tree proof is enforced online but is not yet
retained in the cross-owner handoff, so this receipt cannot authorize admission,
promotion, or installation.

This is an internal primitive, not a command developers repeatedly run. The
Linux service boundary covers process and IP-address containment but does not
seal a dedicated root filesystem or attest the host platform. It is not yet the
supported production acquisition boundary: protected installation and
provisioning automation, durable raw-Git proof retention, recursive artifact
closure, control-plane promotion, and install/update wiring remain required. The direct
`acquire-github` command still runs with the operator's UID and remains
evaluation-only.

Recursively retain supported exact same-repository blob references for Phase 0
comparator evaluation:

```console
./aragorn expand-github https://github.com/owner/repository \
  0123456789abcdef0123456789abcdef01234567 path/to/skill \
  --state ~/.local/state/aragorn
```

This caches one pinned session per referenced commit while sharing one
credential, monotonic deadline, and resource budget across the expansion.
Mutable commits, cross-repository references, archives,
submodules, LFS objects, opaque carriers, dynamic fetches, and exhausted
budgets produce an incomplete receipt and no comparator subject. The command
never executes fetched bytes and never creates an admission decision.

`expand-github` is a private evaluator/operator surface, not the intended
developer workflow. The production product remains a CLI/library admission
engine that runtime and package-manager integrations call automatically during
skill install and update. It is not an agent or an `@Aragorn` chat plugin, and
developers should not have to invoke it repeatedly.

Build the evaluation-only literal source-reference graph for a retained
manifest:

```console
./aragorn resolve-artifacts <manifest-digest> \
  --state ~/.local/state/aragorn
```

The resolver reads only re-verified CAS bytes and never launches a subprocess,
uses a shell, or performs a network request. Under
`phase0-literal-source-refs/v1`, `closure.status = "complete"` means only that
every supported literal found in supported text carriers resolved to bytes
already retained in the root manifest or was explicitly classified as
non-artifact, and that no carrier was opaque. It does not establish recursive
external-artifact closure, prove that generated references are absent, satisfy
the policy-required `artifact_graph` scope, or change `inspect` from `ERROR`.
For GitHub roots, `source_assurance` explicitly records that path membership is
an authenticated GitHub API assertion while each retained blob identity is
independently rederived; Aragorn does not yet verify a raw commit/tree proof.

Run protocol-compatible analyzer adapters:

```console
./aragorn inspect ./path/to/skill \
  --state ~/.local/state/aragorn \
  --analyzers ./analyzers.json
```

Analyzer configuration contains administrator-installed adapter commands, not commands from the inspected repository. Aragorn reads configuration through one verified file descriptor, rejects configuration or executable paths inside the inspected source/state, rejects absolute, home-relative, and parent-traversing path arguments after `argv[0]`, ingests the resolved executable once, and launches a private materialization of those retained bytes. Remaining relative arguments run from a fresh empty control directory and cannot select files from the inspected workspace; use a dedicated installed wrapper for each analyzer. Operator command strings are trusted, and interpreters, imported packages, dynamic libraries, and other transitive dependencies are not yet attested. Phase 0 does not sandbox adapter code or confine detached descendants, host filesystem access, or network access: use only administrator-approved adapters on a disposable analysis host. Adapter output is always treated as untrusted.

The operator also controls the selected local source path and its ancestor namespace. Aragorn rejects a symlink as the final source root and every symlink inside that root. The Phase 0 GitHub command is an evaluation harness, not a general fetcher or credential boundary. Phase 1 promotes acquisition to a supported quarantine, dedicated fetch gateway, and recursive artifact-closure boundary.

```json
{
  "schema": "aragorn/analyzers/v1",
  "analyzers": [
    {
      "name": "skillspector",
      "version": "pinned-version",
      "argv": ["/absolute/path/to/aragorn-skillspector-adapter"]
    },
    {
      "name": "cisco-skill-scanner",
      "version": "pinned-version",
      "argv": ["/absolute/path/to/aragorn-cisco-adapter"]
    }
  ]
}
```

An adapter reads one `aragorn/analyzer-request/v1` object from standard input and writes zero or more `aragorn/observation/v1` JSON objects, one per line, to standard output. Its current directory and `HOME` are a separate empty control directory; it must use the request's absolute `workspace` field. Diagnostic logs go to standard error. The core never consumes a vendor's aggregate “safe” score as authorization.

All Phase 0 machine contracts are defined as JSON Schema Draft 2020-12 documents under [`schema/`](./schema/). The schemas define each document shape; the evaluator additionally enforces cross-record invariants such as exact matrix completeness, digest identity, lineage separation, and non-overlapping paths.

## Benchmark

Verify the digest-locked inert smoke corpus and aggregate normalized outcomes:

```console
PYTHONPATH=src python3.12 -m aragorn.benchmark \
  benchmark/suite.json benchmark/outcomes.jsonl
```

Invoke the existing private Phase 0 comparative gate with its digest-bound
accounting sidecar and retained expansion evidence:

```console
PYTHONPATH=src python3.12 -m aragorn.benchmark \
  ./private-suite.json ./private-outcomes.jsonl \
  --phase0-accounting ./private-accounting.json \
  --state ./private-evidence-state
```

This opt-in path emits `aragorn/benchmark-phase0-gate-report/v1`. It makes the
file evaluator callable; it does not create the private oracle, expansion
receipts, comparator outcomes, isolated worker, or signed measurement.

Freeze a separate paired acquisition/reference stratum before producing either
arm's outcomes:

```console
PYTHONPATH=src python3.12 scripts/phase0_acquisition_gate.py freeze \
  ./private-acquisition-oracle.json \
  ./private-root-suite.json ./private-expanded-suite.json \
  --candidate-policy ./signed-candidate-policy.json \
  > ./private-acquisition-oracle.lock.json
```

The root suite must contain only the two policy-bound comparators over each
original root tree. The expanded suite pairs the same held-out cases and
provenance with the policy-bound Aragorn candidate and comparators over each
expanded comparator-subject tree. The canonical private oracle binds both
suites, the exact GitHub commit and tree identities, expected reference
occurrences and targets, and all expansion limits. The exit-measurement
contract requires exactly 448 unique paired sources and lineages: 336 benign,
112 adversarial, and one run per case. Each suite source reference is the
`phase0-github-source:` prefix followed by the SHA-256 digest of its canonical
oracle GitHub-source object. Signature-commit the emitted lock before collecting
outcomes; its assurance records an operator assertion, not independent
authorship, trusted timestamping, or proof of wall-clock order.

Evaluate the two completed arms and their retained expansion evidence:

```console
PYTHONPATH=src python3.12 scripts/phase0_acquisition_gate.py evaluate \
  ./private-acquisition-oracle.json \
  ./private-acquisition-oracle.lock.json \
  ./private-root-suite.json ./private-root-outcomes.jsonl \
  ./private-expanded-suite.json ./private-expanded-outcomes.jsonl \
  ./private-accounting.json --state ./private-evidence-state \
  --candidate-policy ./signed-candidate-policy.json \
  --root-acceptance-ledger ./private-root-acceptance-ledger \
  --expanded-acceptance-ledger ./private-expanded-acceptance-ledger
```

This emits `aragorn/benchmark-phase0-acquisition-gate-report/v1` and compares
the expanded-arm Aragorn candidate with the best burden-compliant comparator
measured on the paired root arm. Both arms require protected acceptance ledgers:
comparator outcomes must use authenticated worker evidence and expanded Aragorn
outcomes must use authenticated candidate-composition evidence. The shared
expansion verifier independently hashes every declared literal byte span from
retained CAS source bytes. Arm swaps, suite or oracle mutation, missing case
pairs or expected references, changed source/budget bindings, missing CAS
records, unauthenticated evidence, and corrupt or incomplete closure fail
closed. Every case must produce a different expanded tree and retain at least
one oracle-expected expanded object; incomplete or no-delta expansion is an
evaluation error, not a scoreable result. The repository retains the signed
digest-only
[`benchmark/phase0-acquisition-oracle-v7.lock.json`](./benchmark/phase0-acquisition-oracle-v7.lock.json)
and
[`aggregate V7 result`](./benchmark/receipts/phase0-acquisition-v7-regression-result-2026-07-27.json).
The private oracle, paired outcomes, acceptance ledgers, and evidence CAS
remain outside the repository.

For a future fresh hidden matrix, score only its newly frozen hidden split
without mixing in GitHub acquisition accounting:

```console
PYTHONPATH=src python3.12 -m aragorn.benchmark \
  ./private-suite.json ./private-outcomes.jsonl \
  --phase0-hidden-gate --state ./private-evidence-state \
  --acceptance-ledger ./private-acceptance-ledger \
  --phase0-corpus-lock ./signed-corpus-lock.json \
  --phase0-public-manifest ./private-worker/manifest.json \
  --phase0-hidden-suite-lock ./private-hidden-suite-lock.json \
  --phase0-candidate-policy ./signed-candidate-policy-v3.json \
  --phase0-label-ledger-digest sha256:...
```

This evidence-only path emits `aragorn/benchmark-phase0-gate-report/v2`;
acquisition/reference accounting remains in the separate v1 gate. The
operator-asserted hidden-suite lock must be canonical JSON and signed-committed
before dispatch or results. The gate checks its byte, corpus, policy, label
ledger, exact 448-case public-manifest projection, suite, and three system
bindings, but cannot prove wall-clock ordering, independent authorship, or
timestamping. Any reuse of an evaluated corpus must remain explicitly
calibration-only and cannot create fresh-holdout eligibility.

Benchmark v1 accepts only synthetic UTF-8 text fixtures explicitly declared inert. It rejects changed digests, executable files, links, special files, non-UTF-8 or NUL-bearing content, duplicate or overlapping cases, lineage changes in split, class, family, or provenance, undeclared systems, and incomplete system-by-case-by-run matrices. Evaluator-only `contract_smoke` validation uses a bounded temporary CAS. The `evidence_smoke` runner instead retains exact fixture bytes in its protected evidence CAS so later evaluation can reconstruct the workspace; neither path imports or executes fixture code.

The adversarial fixtures are scanner inputs, not agent instructions. Their
[`benchmark/README.md`](./benchmark/README.md) boundary forbids using this tree as a
skill, extension, retrieval, memory, or recursive discovery root; harness
qualification must verify that exclusion before corpus access.

Every outcome carries the canonical suite digest, exact fixture tree, declared implementation and configuration digests, run number, and an evidence identity digest. Reports separate `REVIEW`, `DENY`, and `ERROR` by class and report attack flag rate, benign review rate, benign deny rate, benign intervention rate (`REVIEW + DENY + ERROR`), precision, and split-scoped family results. Error-bearing cases do not contribute a repeatability score.

`contract_smoke` validates externally supplied outcome contracts and is never executed by the runner. `evidence_smoke` exercises the runner/verifier boundary using a protected evidence CAS that the evaluator later opens read-only. The runner retains the fixture bytes plus, for every matrix cell, the executable entrypoint, effective configuration, manifest, raw streams, canonical observations, and evidence envelope. The evaluator re-hashes those blobs and independently re-derives the normalized verdict. Neither mode is an efficacy claim.

Derive the system identities that must be copied into an evidence-smoke suite, run the complete matrix, and evaluate it:

```console
PYTHONPATH=src python3.12 -m aragorn.benchmark_runner identity \
  ./analyzers.json --state ./benchmark-state

PYTHONPATH=src python3.12 -m aragorn.benchmark_runner run \
  ./evidence-smoke-suite.json ./analyzers.json --state ./benchmark-state \
  > ./outcomes.jsonl

PYTHONPATH=src python3.12 -m aragorn.benchmark \
  ./evidence-smoke-suite.json ./outcomes.jsonl --state ./benchmark-state
```

The process runner's implementation identity covers one executable entrypoint. It does not cover an interpreter, imported packages, native libraries, or a container/root filesystem; its launch pathname is also not protected from another same-UID process. The process adapter is unsandboxed and can inspect host files, the suite, or the evidence state, so held-out labels are not blind in that mode.

Run the current two-system, two-fixture OCI evidence-smoke matrix:

```console
PYTHONPATH=src python3.12 -m aragorn.oci_benchmark_runner identity

PYTHONPATH=src python3.12 -m aragorn.oci_benchmark_runner run \
  benchmark/oci-suite.json --state ./benchmark-state \
  > ./oci-outcomes.jsonl

PYTHONPATH=src python3.12 -m aragorn.benchmark \
  benchmark/oci-suite.json ./oci-outcomes.jsonl --state ./benchmark-state
```

The OCI runner verifies the locked local image identities before launch, creates containers from digest-only references with pulling disabled, inventories the CAS-materialized fixture immediately before creation and again after execution, inspects the effective container policy before execution, and mounts only that fixture read-only. It discovers one canonical local Unix endpoint, then pins every daemon command through `DOCKER_HOST` while using a fresh empty Docker configuration directory. Evidence v3 retains targeted context, engine-build, component, daemon, kernel, and security-option receipts before and after each run; the evaluator independently normalizes them and rejects drift. It also retains the raw OCI metadata graph and bounded scanner reports, applies the pinned vendor normalizer, and re-derives the verdict. A local live smoke of the checked-in development matrix produced Cisco `ALLOW` for `benign-basic` and `REVIEW` for `inert-credential-exfiltration`, and NVIDIA `REVIEW` and `DENY` respectively. Those four outcomes validate execution, retention, normalization, and verification plumbing over two synthetic fixtures; they are not accuracy or efficacy results.

Audit and run the larger frozen pilot separately so the two-case smoke remains
fast:

```console
PYTHONPATH=src python3.12 -m aragorn.corpus_audit \
  benchmark/phase0-oci-pilot-v1.json

PYTHONPATH=src python3.12 -m aragorn.oci_benchmark_runner run \
  benchmark/phase0-oci-pilot-v1.json --state ../aragorn-pilot-state \
  > ./pilot-outcomes.jsonl

PYTHONPATH=src python3.12 -m aragorn.benchmark \
  benchmark/phase0-oci-pilot-v1.json ./pilot-outcomes.jsonl \
  --state ../aragorn-pilot-state
```

The evidence-state parent must be visible to the selected Docker daemon for its
read-only bind mount. The pilot is frozen at suite digest
`sha256:3462265beb529a9688017ab35725d0107b37f2fdca5b40f61dd29b5eb3d6ce3a`.
On the local one-run 36-cell evidence smoke, Cisco flagged 2 of 9 adversarial
cases and intervened on 2 of 9 benign cases. NVIDIA flagged all 9 adversarial
cases but intervened on all 9 benign cases because every no-LLM result retained
`NVIDIA_ANALYSIS_INCOMPLETE`. This small, repository-visible, unattested pilot
demonstrates a measurable recall-versus-burden gap and validates the expanded
plumbing; it cannot establish efficacy, statistical performance, or a Phase 0
exit-gate result.

The worker protocol now defines an execution-only subject manifest and exact
request/result shapes that omit suite, case, class, family, lineage, split,
run, purpose, source, and expected-verdict fields. The nonce echo detects
accidental mismatch, and the collector now commits one exact nonce batch in a
local protected ledger after all evidence verification succeeds. An exact retry
is idempotent; conflicting reuse is rejected. The worker command and its input
surface are label-free, but running worker and control plane as the same OS
principal does not create a security boundary: that principal could still read
the protected dispatch or delete ledger state. The original monolithic OCI
runner also still loads the private suite and is not label-blind.

Run the separated plumbing path with the control state, jobs, worker-identity
manifest, and Docker-shared scratch kept outside the repository:

```console
install -d -m 700 ../aragorn-worker-scratch

PYTHONPATH=src python3.12 -m aragorn.oci_worker identity \
  --lock benchmark/baselines.lock.json \
  --timeout 120 \
  --output-limit 1048576 \
  > ../aragorn-worker-identities.json
chmod 400 ../aragorn-worker-identities.json

PYTHONPATH=src python3.12 -m aragorn.label_blind_prepare \
  benchmark/oci-suite.json \
  --worker-identities ../aragorn-worker-identities.json \
  --control-state ../aragorn-control \
  --jobs-root ../aragorn-jobs

PYTHONPATH=src python3.12 -m aragorn.oci_worker run \
  ../aragorn-jobs/<job-id>/request.json \
  --request-digest <request-digest-from-worklist> \
  --input-state ../aragorn-jobs/<job-id>/input \
  --output-state ../aragorn-jobs/<job-id>/output \
  --workspace-root ../aragorn-worker-scratch

PYTHONPATH=src python3.12 -m aragorn.label_blind_collect \
  benchmark/oci-suite.json \
  --dispatch-digest <dispatch-digest> \
  --control-state ../aragorn-control \
  --jobs-root ../aragorn-jobs
```

Preparation reports `worklist_digest` and writes its canonical, read-only,
label-free scheduler surface at `../aragorn-jobs/worklist.json`. Each entry
contains only `job_id` and `request_digest`; job paths derive from that ID. The
identity manifest must be produced by the provisioned worker with the same lock
and the request's 120-second/1-MiB limits. It is an unsigned compatibility
statement, not an attestation. The control plane must invoke the worker once for
every worklist job but transfer only `job_id`, `request_digest`,
`request.json`, and the subject input CAS. The nonce ledger is derived at
`<control-state>/nonce-ledger`; it is not a caller-selectable freshness root. A
local four-job smoke completed collection under evidence v4. Exact retries now
return the same committed collection, while conflicting nonce reuse fails.

The current local-workflow receipt records dispatch
`sha256:ba387a4cb4e227b521b2138e28a662c1140f44e396c761659d444ca5a6e79b11`
and collection
`sha256:2f2c5d8ee211b92573f22c503911d89437f5a0374783723d9a93ea88db60a921`;
it explicitly identifies the private uncommitted worktree as not source-attested.
See [the retained local smoke receipt](./benchmark/receipts/phase0-local-label-free-smoke-2026-07-22.json).

The current v1 `config_digest` includes Docker bytes and self-reported runner
identity. Consequently, the checked-in frozen pilot is compatible only with a
worker reporting that exact identity. A cross-principal or VM gate requires a
new protocol/suite version that separates portable requested policy from the
measured worker/runtime identity; v1 must not be reinterpreted in place.

Both image entries deliberately remain
`oci_closure_candidate_runner_attestation_pending`. Aragorn measures the Docker
CLI bytes and now binds the selected context, Unix endpoint, engine build, and
daemon/worker claims with pre/post continuity checks. Those fields are still
reported by Docker and can be forged by a compromised daemon; they are
attribution evidence, not hardware-backed worker attestation. The one isolated
signed smoke validates composition only; `efficacy` remains unsupported until
the frozen hidden corpus, with its exact authorship assurance disclosed, and the
comparative gates pass through that boundary.

Protocol v2 now has one internal worker invocation:
`python -m aragorn.worker_supervisor_v2 run ...`. It imports the verifier's
exact input closure, executes one label-free job, derives and exports the exact
deep-verified output closure, and publishes one scoped signed measurement. It
is an evaluation-harness command, not a command an end user should repeatedly
type. The supported product path remains automatic invocation from acquisition
and update chokepoints after Phase 0 passes.

The first unmocked composition smoke ran that command inside a fresh
mount-free Lima VM with a guest-local rootless Docker daemon and a guest-only
`0600` Ed25519 key. The control plane copied in only the exact input bundle,
copied out only the output bundle and envelope, accepted them through
`collect_signed_worker_output`, and confirmed exact retry idempotence. See the
[retained isolated protocol-v2 receipt](./benchmark/receipts/phase0-isolated-protocol-v2-smoke-2026-07-23.json).
It covers one public benign fixture and validates infrastructure only.

The corrected public candidate-composition smoke evaluated signed commit
`2667dda227479385135a171958ff3011777b8e24` in a new mount-free VM. Both
comparators crossed the authenticated boundary for one public benign and one
public adversarial case; all four results were accepted and composed with two
locally derived Aragorn outcomes. The six-cell matrix had no execution errors.
Aragorn and Cisco allowed the adversarial fixture, while SkillSpector returned
`REVIEW` with `NVIDIA_ANALYSIS_INCOMPLETE` for both fixtures. This is the honest
observed smoke result, not an efficacy claim. The
[candidate-composition smoke receipt](./benchmark/receipts/phase0-public-candidate-composition-smoke-2026-07-24.json)
binds the evaluated source claim, operator-observed runtime, exact public suite,
four verifier-accepted software-key-signed worker-result roots, and the exact
dispatch, component, candidate, and source-graph lineage used to re-derive the
composition and outcomes. Exact retry and the negative hidden-material
observations are explicitly operator-observed rather than separately attested.

## Test

```console
PYTHONPATH=src uv run --python 3.12 --with-requirements requirements-worker.lock \
  python -W error::ResourceWarning -m unittest discover -s tests -v

PYTHONPATH=src uv run --python 3.12 \
  --with-requirements requirements-worker.lock --with jsonschema \
  python scripts/validate_schemas.py
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the complete roadmap and [SECURITY.md](./SECURITY.md) for the trusted boundary and vulnerability policy.

## Phase 0 result and next production gate

The qualified Phase 0 validation milestone is complete under the checked-in
[aggregate decision rule](./benchmark/receipts/phase0-validation-milestone-2026-07-27.json).
The fresh
[V6 hidden result](./benchmark/receipts/phase0-hidden-v6-result-2026-07-26.json)
exceeded the best burden-compliant comparator by 29.4643 percentage points
while candidate benign intervention was 4.1667%, below the 5% ceiling.

The final V7 candidate reproduced those measurements across 896 authenticated
worker results and 1,344 composed outcomes. Its
[V7 maintenance receipt](./benchmark/receipts/phase0-hidden-v7-calibration-result-2026-07-27.json)
remains explicitly calibration-only, `phase0_exit_eligible: false`, and is not
additional fresh-holdout evidence.

The separately frozen
[V7 acquisition/reference evaluation](./benchmark/receipts/phase0-acquisition-v7-regression-result-2026-07-27.json)
passed with 12.5 percentage points of attack-flag lift, 0% benign intervention,
448/448 complete expansions, and zero unresolved expected references. Because
this corpus was previously attempted under V6, the V7 run is regression
evidence rather than a new fresh holdout. Its component receipt remains
`phase0_exit_eligible: false`; the aggregate rule uses it only to satisfy the
bounded terminal-depth-1 acquisition-integration criterion.

The OWASP, MITRE, and NIST standards gate remains passing with 26 selected
items, 22 evidence-mapped items, four roadmap-mapped items, and zero unresolved
dispositions. Together these records authorize Phase 1 engineering under the
qualified aggregate rule; they do not establish an unqualified fresh V7 exit,
supported acquisition, complete artifact closure, installation binding,
runtime containment, or EDR status.

Authorship remains technical Codex authorship rather than independent human
identity. Software signatures trust the operator UID and prove neither
same-UID, VM, hardware, nor platform attestation. The acquisition lock's
pre-outcome ordering remains operator-asserted without trusted timestamping.
Independent review remains a Phase 5 release requirement.

The next production gate is Phase 1: supported quarantine, recursive artifact
closure, a dedicated credential-free fetch gateway, decision receipts, and
exact-digest installation.
