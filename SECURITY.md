# Aragorn security policy and threat model

## Overview

Aragorn is a local admission controller for agent capabilities. Its first
supported surface is a file-based Agent Skill supplied as a local directory.
Aragorn inventories the tree, stores exact bytes by SHA-256, runs
administrator-configured analyzers through a bounded subprocess interface,
treats their emitted evidence as untrusted, makes a deterministic decision, and
materializes only verified content. Its private Phase 0 evaluation paths can
also acquire one unauthenticated public GitHub skill at an exact commit, build a
bounded literal source-reference graph, recursively retain supported exact
same-commit GitHub blobs for comparator input, and run two pinned local
Linux/arm64 comparator images under a fixed, network-denied OCI profile.

Aragorn does not certify that an artifact is safe. Until a runtime enforcement integration exists, it is admission control rather than endpoint detection and response.

## Threat Model, Trust Boundaries, and Assumptions

Attacker-controlled inputs include every entry, filename, and file byte below
the selected local source root; every literal URL, path, Markdown reference, and
fetch-command line parsed from those bytes; analyzer output; normalized
benchmark outcomes; repository and retained release-asset responses; and any
future extracted archive members.
Operator-controlled inputs include the selected source path and its ancestor
namespace, benchmark labels and split assignments, analyzer commands, policy,
state location, and installation destination. Developer-controlled inputs
include Aragorn's source and release process.

The long-term trusted computing base is limited to digest verification, deterministic policy evaluation, verified materialization, and the operating-system controls protecting Aragorn's state. In Phase 0, administrator-installed analyzer executables are also trusted dependencies because subprocess execution is not sandboxed. Their output remains untrusted evidence. Aragorn reads analyzer configuration once through a location-verified file descriptor, rejects configuration/executable paths inside the inspected repository or state, rejects absolute, home-relative, and parent-traversing path arguments after `argv[0]`, CAS-ingests the entrypoint once, and launches those retained bytes from a separate empty control directory. Remaining relative arguments cannot select files from the inspected workspace. Operator-supplied command strings remain trusted configuration.

Aragorn must preserve these invariants:

- Reject a symlink as the selected source root; keep one opened directory capability through validation and ingestion; and never follow symlinks, accept hardlinks, or accept non-regular files inside the tree.
- Bound file count, depth, individual size, total size, subprocess duration, and subprocess output.
- Bind every observation and decision to the exact subject digest.
- Never use a shell to launch an analyzer.
- Require one absolute operator-configured wrapper executable, hash its bytes, reject later absolute, home-relative, and parent-traversing path arguments, and never use the inspected workspace as adapter `cwd` or `HOME`.
- Never produce `ALLOW` after incomplete acquisition, missing required analysis, analyzer failure, malformed evidence, or digest disagreement.
- Treat GitHub responses as untrusted and bounded. Accept only the fixed public
  GitHub Smart HTTP and REST hosts, require protocol v2 with SHA-1 object format
  plus filtering and shallow support, and accept only a checksum-valid
  one-object PACK v2 of the requested commit or tree type whose Git SHA-1 is
  independently reproduced. Source commit/tree acquisition rejects redirects,
  deltas, extra objects, unsupported Git modes, unsafe path normalization, and
  deadline exhaustion. The separate release path accepts at most one HTTPS
  redirect from `api.github.com` to the separately pinned
  `release-assets.githubusercontent.com` host, retains no redirect query, and
  binds its evidence and bytes to caller-held digests.
  Reproduce every REST-returned blob's Git SHA-1 and publish its exact bytes to
  the SHA-256 CAS only after the complete source tree validates. The gateway
  retains the exact raw commit/tree proof in the handoff and the broker replays
  it offline. The source manifest still earns only `source_tree` closure until
  recursive artifact resolution completes.
- Treat the literal-reference resolver as an evaluation parser, not an
  acquisition or authorization boundary. It reads only re-verified, bounded CAS
  carriers; executes no content; performs no network request; marks opaque,
  mutable, dynamic, encoded, normalized, and unsupported cases incomplete; and
  redacts credential-bearing URL literals from graph evidence. A successful
  command or profile-scoped `source_reference_graph.status = "complete"` never
  satisfies the admission-required `artifact_graph` scope, changes `inspect`
  from `ERROR`, or proves that undiscoverable generated references are absent.
  Historical GitHub graph assurances remain API-asserted evidence identities.
  Those evaluation-only graphs do not consume the gateway proof and therefore
  cannot elevate their authority.
- Treat exact GitHub expansion as bounded evaluation evidence, not supported
  acquisition or admission closure. Share one immutable repository session,
  tree cache, monotonic deadline, and API request/byte budget; independently
  verify every retained blob; and follow only exact same-owner,
  same-repository, same-commit blob references. Also bound root and expanded
  bytes, object count, recursion depth, and reference occurrences. Mutable,
  cross-source, dynamic, opaque, missing, LFS, submodule, and exhausted-budget
  cases must produce an incomplete receipt with no comparator subject. A
  complete comparator subject remains inert benchmark input and can never
  satisfy `artifact_graph` or authorize `ALLOW`.
- Treat the direct Phase 0 monotonic acquisition deadline as best-effort. Its
  HTTP read timeout is activity-based and does not provide a hard wall against
  continuous trickle responses; the production fetch gateway must enforce the
  end-to-end wall-clock limit.
- Re-hash CAS content before every materialization and create it fd-relatively below an explicit trusted root without following destination symlinks.
- Never give an analyzer a core API that writes the CAS, issues an effective approval, or installs content. Phase 0 relies on the trusted-adapter assumption—not OS confinement—to keep an analyzer from accessing the host directly.
- Never import or execute an inert benchmark fixture. Bind every outcome to the canonical suite, exact tree, declared implementation and configuration, run, and evidence identity digests; reject unsafe content before evaluation; and report analyzer errors separately rather than counting them as clean, detected, or repeatable. Process evidence v1 re-verifies the retained entrypoint, effective configuration, manifest, observations, raw streams, error-code consistency, and derived verdict. OCI evidence v3 additionally binds and independently traverses the retained OCI index/platform/provenance/config graph, requires the runtime's pre/post-verified subject digest, and verifies the baseline lock and entry, effective OCI configuration, pre/post Docker runner receipts, image/container inspection records, raw vendor report, pinned normalizer, and Docker CLI identity. Evidence v4 additionally binds the exact private dispatch matrix, canonical label-free requests and results, exact worker output closures, a common nonce-binding digest, local nonce receipts, and independently re-verified nested evidence v3. The collector commits all nonce receipts atomically below the protected control state only after complete verification; the evidence alone does not prove that filesystem state exists. Historical evidence v2 remains readable but has no runner receipts. None makes an accuracy, isolation, freshness-attestation, or worker-attestation claim. `efficacy` remains unsupported until the complete implementation closure is launched in an isolated, label-blind worker. State-free external outcomes remain `contract_smoke` only, and the runners reject that purpose.
- Treat `benchmark/oci-fixtures/` as hostile test data even though it is inert UTF-8 text. Never configure it as a skill, extension, retrieval, memory, or recursive auto-discovery root. Candidate harnesses must prove their discovery roots exclude it; only the digest-bound benchmark preparation path may materialize one case into an isolated scanner workspace.
- Treat label withholding as a control-plane protocol, not a worker assertion.
  The sanitized subject manifest must independently reproduce the private tree
  digest, and worker requests/results must omit suite, case, class, family,
  lineage, split, run, purpose, source, and expectation metadata. Bind fresh
  random job identity, nonce, canonical request digest, subject, system,
  configuration, and baseline identities. Reject worker-supplied signature or
  attestation claims in the unsigned v1 protocol. The separate prepare, worker,
  and collect commands now publish an exact worker output closure, import and
  independently verify nested evidence, and atomically commit one distinct
  binding per nonce in a local protected ledger. An exact retry is idempotent;
  conflicting reuse is rejected. These controls create a label-free execution
  interface, not a label-blind security boundary. A worker running as the same
  OS principal can still inspect protected dispatch state or delete ledger
  receipts. Use a disposable VM, or another principal with a dedicated
  rootless/scoped daemon whose socket and host filesystem cannot reach the
  control state; a separate UID sharing the control plane's rootful Docker
  daemon is not an isolation boundary. Protect the control state and ledger and
  add a verifier challenge plus an explicitly scoped signed worker measurement
  before making worker-isolation claims. The monolithic OCI runner still loads
  the private suite directly.
- Treat the protocol-v2 portable policy and verifier challenge as request
  bindings, not worker attestation. The implemented v2 request rejects labels,
  host paths, runtime identity, signatures, and attestation claims and cannot
  be substituted for v1. The v2 handoff primitive can export a private,
  declared, bounded blob set. An operator-controlled byte-preserving transport
  must create a receiver-readable copy; never make a hidden bundle
  world-readable. Import accepts that copy only after matching caller-supplied
  manifest, kind, and root digests plus, for `worker_input`, the externally held
  expected verifier challenge. Semantic `worker_output` validation additionally
  requires the externally retained request digest and challenge. It re-hashes
  the complete bundle into receiver-owned staging, rechecks the untrusted
  source, and publishes only the validated snapshot into the receiver-owned
  CAS. This proves transport byte integrity only. Untrusted-input failure
  occurs before CAS blob publication.
  The CAS has no atomic batch commit yet, so a receiver-side storage failure
  may retain validated non-root blobs; the declared root is published last and
  is never newly published before them. A matching root that was already in
  the CAS remains preexisting state. For `worker_input`, the importer now
  requires the root to be a canonical v2 request and requires exactly its bound
  portable policy, sanitized subject manifest, and subject file blobs.
  Baseline and image digests are identity expectations for separately verified
  worker assets, not implicit input dependencies. The separate unsigned v2
  result and semantic output builder now derive an exact typed retained set and
  bind the effective configuration's portable projection plus measured Docker
  bytes. Semantic export/import fails closed without both external verifier
  values. Separately named declared-byte transport helpers provide no semantic
  acceptance. The v2 closure first retains exact reachability.
  `verify_worker_output_evidence_cas_v2` then replays the OCI v3 verifier over
  the label-free result; reachability alone remains insufficient.
  Protocol-v2 `limits.output_bytes` is the combined captured stdout/stderr
  limit, not the total evidence-closure limit; the handoff applies its separate
  512 MiB total closure ceiling.
  The signed-worker acceptance library adds a strict single-signature DSSE
  envelope over the trust domain, worker and key IDs, job, request, verifier
  challenge, result root, and exact worker-output handoff-manifest digest.
  Ed25519 keys are selected only from a protected verifier-owned trust store;
  unknown and revoked keys fail closed and overlapping active keys support
  rotation. The protected issuance ledger selects the expected worker, job,
  request, and challenge. `collect_signed_worker_output` holds the ledger lock
  through signature verification, semantic import, and deep OCI evidence
  verification, then publishes one immutable receipt. Exact retry returns that
  receipt; conflicting challenge reuse is rejected; a failed signature,
  import, deep verification, or receipt publication consumes nothing.
  This proves possession of a provisioned software worker key, not hardware
  identity, VM integrity, or Docker-daemon honesty. The private key must remain
  outside every analyzer/container mount. The retained protocol-v2 smoke now
  wires the real executor and signing supervisor through a mount-free isolated
  worker and authenticated control-plane collection. It validates that
  composition for one public benign fixture only; it is not efficacy evidence,
  hardware attestation, or proof that the hidden evaluation remains isolated
  at corpus scale.
- Docker versions may report optional components such as `rootlesskit` without
  a `GitCommit`. Required Engine, containerd, and runc components still require
  a commit. For an optional component only, Aragorn binds a canonical SHA-256
  identity of every bounded detail field instead of silently dropping the
  component; the independent evidence verifier derives the same identity.
- Never call a source commit, package name, wrapper script, or mutable environment a complete implementation attestation. A baseline may enter efficacy evaluation only when every executable dependency is inside the retained self-contained artifact or pinned image/rootfs closure actually launched by the isolated worker.
- Treat a locally built OCI image and one local evidence-smoke launch as a closure candidate, not a complete runner attestation. The exact image/platform/config identity and runtime controls must be retained and verified at launch. Context, endpoint, engine, and worker claims must be continuity-bound, but daemon self-report alone never clears `oci_closure_candidate_runner_attestation_pending`. A tag, Dockerfile label, manual smoke, vendor aggregate verdict, hashed CLI, or daemon ID alone is insufficient.

Aragorn assumes the host kernel, Python interpreter, administrator policy, and state-directory ownership are not compromised. It cannot protect an unrestricted administrator from bypassing the tool.

The OCI evidence-smoke path also trusts the Docker daemon initially selected by the operator's Docker configuration. Aragorn accepts only a canonical local Unix-socket endpoint, switches all execution to that exact `DOCKER_HOST` with an empty private Docker configuration, retains targeted context/version/info receipts, and rejects any normalized pre/post drift. It also retains and rechecks the Docker CLI bytes, verifies the locked local image graph, uses digest-only launch with pulling disabled, inspects the effective container policy, and grants the container only a read-only fixture mount with no network. The engine, daemon ID, kernel, components, and security options remain daemon self-report; a compromised daemon can falsify them or the container inspection response. This path must therefore use an administrator-approved disposable local daemon and remains in pending-attestation status. Unix endpoint paths may contain local usernames and are retained as security evidence.

The evaluation-only GitHub acquisition client is intentionally public and
unauthenticated.
Its direct standard-library HTTPS client sends no authorization, cookies, or
proxy configuration and rejects redirects. It rejects ambient `SSL_CERT_FILE`
and `SSL_CERT_DIR` overrides and explicitly loads the Python/OpenSSL runtime's
compiled CA file and directory, so repository-controlled or shell-inherited CA
paths cannot replace the trust set. It still trusts the host DNS resolver,
those compiled CA paths and their contents, the Python/OpenSSL runtime, and the
GitHub API, and public API rate limits make it unsuitable for mass acquisition.
Phase 1's internal Linux gateway now runs its credential-free resolver and
worker under a stable non-login UID in transient systemd services with cgroup
v2 process limits, default-deny IP filtering, no capabilities, and verified
post-run cleanup. The resolver is confined to the local DNS-stub address; the
worker is confined to the canonical union of separately resolved
`github.com` and `api.github.com` public IP sets; recursive release jobs alone
also receive the separately resolved `release-assets.githubusercontent.com`
set. The HTTPS client pins each request to its matching host set and continues
to enforce port 443 and GitHub TLS hostname verification.
Before importing Aragorn, each service must fail to reach a broker-held
loopback listener, which makes missing cgroup IP enforcement fail closed.
`AF_UNIX` and socket binding are denied, temporary paths are inaccessible, and
the only host-writable path is a runtime-verified bounded 512 MiB, 25,000-inode
`nosuid,nodev,noexec` transfer tmpfs. Unexpected transfer-root entries or
worker-job cleanup failure prevent quarantine publication.
Protected skill roots are `root:aragorn-runtime` mode `0750`: the broker remains
the only writer, while a runtime receives only the supplementary group needed
to traverse an explicitly read-only bind mount. Group membership alone is not
an admission decision and must never be paired with a writable mount.
This earns a Linux process/IP containment primitive with durable broker-replayed
raw Git commit/tree proof, not supported acquisition: the root filesystem is
not sealed, and the host kernel/systemd/Python trust boundary is not attested.
Private repositories, scoped credential injection, retry policy, general
archive closure, live public out-of-root recursive evidence,
admission-authorized protected installation, and install/update enforcement
remain unsupported. Automatic independent release-pin preflight is implemented
and unit-verified, but its transient-service path is not yet live-qualified.
Bounded ZIP/WHL/PYZ
inventory archives with an exact GitHub digest are retained as raw CAS bytes at
a deterministic reserved runtime-candidate path; verified extracted members are
bound into a separate analysis input. The edge remains fail-closed with
`GITHUB_RELEASE_ASSET_RUNTIME_CONSUMER_UNPROVEN` because no pinned runtime
resolver or rewriter consumes the candidate path. The broker does not invoke
analyzers or publish bytes while recursive closure is incomplete; neither the
retained members nor an analyzer receipt grants installer/runtime authority.
The internal request-v3 broker path remains evidence-only.
One operator-retained qualification archive replays exact request credentials,
systemd controls, recursive install, byte-identical update sequencing, and a
release-bearing `ERROR` path. The protected-state comparison remains an
operator record, the asset is only one of nine unresolved reasons, and this is
neither independent attestation nor supported acquisition.

## Attack Surface, Mitigations, and Attacker Stories

The primary initial attack surfaces are filesystem traversal, symlinks, special
files, oversized inputs, literal-reference parser ambiguity and obfuscation,
hash confusion, CAS corruption, malicious analyzer output, subprocess denial of
service, and policy fail-open behavior. The implementation uses `lstat`,
canonical relative paths, explicit resource limits, SHA-256, atomic writes,
direct `argv` execution, typed JSON evidence, deterministic policy, and
fail-closed verdicts.

A realistic attacker can control an inspected skill and attempt to escape its root, exhaust resources, exploit a parser, confuse an analyzer, or cause analyzed bytes to differ from installed bytes. A compromised host kernel, administrator, Python runtime, or Aragorn release key is outside the containment guarantee and must be addressed by host and release security.

The bounded canonical same-repository release slice is implemented as
quarantine evidence; its bytes remain unresolved until analyzed. Supported
production GitHub acquisition, general external-artifact and archive
resolution, general analyzer sandboxing, detonation, network mediation, MCP,
and runtime response remain future phases. The Phase 0 literal graph performs
no acquisition, and the exact GitHub expansion candidate covers only supported
same-commit blobs for comparison. Unsupported acquisition must return an
explicit incomplete result rather than a security claim. A
compromised Phase 0 process adapter can access the host as the current user,
read suite labels or evidence state, use the network, race a non-fd-bound launch
pathname, and detach descendants from Aragorn's supervised process group; run
only administrator-approved adapters on a disposable analysis host. The
receipt and process benchmark runner bind the retained entrypoint bytes and
effective command, so later replacement of the original configured file does
not alter the staged copy. Interpreters, imported packages, dynamic libraries,
the materialized launch pathname, and detached descendants remain outside the
stronger identity/isolation guarantee until the isolated dependency-closure
worker is implemented. The pinned OCI comparator path reduces that adapter
exposure but inherits the unattested Docker-daemon boundary described above.

The checked-in pilot's provisional held-out labels, paths, and bytes are visible
to repository readers and to the current runner process. Content digests can
also identify a previously published case even after explicit labels are
removed. The label-free protocol prevents direct ground-truth disclosure; it
cannot prevent content recognition and does not create a hidden set.

## Severity Calibration

- **Critical:** untrusted artifact code executes on the control plane; an artifact escapes the selected root; CAS corruption is installed without detection; or an unprivileged artifact can approve itself or bypass enforcement.
- **High:** required analyzer failure produces `ALLOW`; a digest mismatch is ignored; a symlink or special file crosses the trust boundary; or secrets enter an analyzer/detonation worker contrary to policy.
- **Medium:** bounded denial of service, misleading evidence attribution without an enforcement bypass, or sensitive metadata retained beyond the documented default.
- **Low:** diagnostic ambiguity, non-sensitive information disclosure, or usability defects that do not weaken a security invariant.

## Reporting

Do not publish suspected vulnerabilities before maintainers can assess them. Use GitHub private vulnerability reporting once the public repository is enabled. There are no supported releases yet.
