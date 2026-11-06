# Pi-core dependency decision and pin inventory v1

Date: 2026-11-02. Status: **dependencies selected and recorded; not installed,
built or qualified**. This is step 2 of the approved managed-profile plan.
The [machine-readable inventory](pi-core-dependency-pins-v1.json) is a design
artifact, not a production `package.json`, npm lockfile or deployment manifest.

Subsequent implementation checkpoint: [batch 1](../phase3/coordinator/pi-core-connected-batch-1.md)
translates the runtime graph into `packaging/pi-core/package-lock.json` and
prepares it for offline checks with scripts disabled. The statements below
record step 2's original evidence ceiling; they are not claims that the later
offline preparation is a Linux build or qualified deployment. Target compiler,
OS/image and compiled adapter identities remain outstanding.

## Decision

Consume the **published Pi 1.4.0 distribution artifacts**, with a thin Aragorn
adapter compiled later. Do not build the full upstream monorepo, run its model
catalog generation, install the coding-agent CLI, or use a moving `latest`/`main`
reference. This avoids silently acquiring fresh model data during an upstream
source build; it does not establish reproducible-build or supply-chain trust.

| Component | Exact selection | Reason / scope |
| --- | --- | --- |
| Pi core | `@earendil-works/pi-agent-core@1.4.0` | Stable published agent-loop package, ESM `dist/index.js` |
| Pi AI | `@earendil-works/pi-ai@1.4.0` | Exact core dependency; provider SDK presence grants no egress authority |
| Pi telemetry | `@earendil-works/pi-telemetry@1.4.0` | Transitive dependency; no exporter/backend is supplied by this package |
| TypeBox | `typebox@1.3.27` | Exact schema dependency of the published core/AI artifacts |
| Node runtime | `24.22.2`, Linux arm64/glibc | Supported Node24 line, consistent with the existing platform family; satisfies Pi's `>=22.19.0` minimum |
| Package manager | npm `11.19.1` bundled in that Node archive | Future isolated package preparation only; not an agent tool |
| Adapter compiler | `typescript@7.0.2`, with `@typescript/typescript-linux-arm64@7.0.2` | Build-only; use the pinned Linux arm64 compiler, not all platform binaries |
| Adapter types | `@types/node@22.19.19` and pinned `undici-types@6.21.0` | Same type baseline as the Pi release; no assumption that Node24-only APIs are needed |

Node24 is a compatibility/risk-management selection, not a claim of greater
security than current Node26. Its published support schedule ends 2028-04-30;
review security updates before a deployment freeze and re-pin/requalify changes
explicitly. Do not modify the frozen predecessor's Node24.16.0 identity.

## Source and artifact identity

Pi repository: `https://github.com/earendil-works/pi`.
Release `v1.4.0`, published 2026-10-21, resolves to:

```text
4a080252f06caf63a525d7873c5d94d3c23887e0
```

The release lock is 202,174 bytes with SHA-256:

```text
34fc1e9c534291db36d63ffb9dad6c962fdc5bc49afd6d802d381ae5844003a3
```

Important observed difference: moving `main` still advertised version 1.4.0
while its core manifest used `pi-schema`; the published release uses TypeBox.
The inventory is anchored to the immutable release and published registry
artifacts, not the version string on a moving branch.

Node archive:
`https://nodejs.org/dist/v24.22.2/node-v24.22.2-linux-arm64.tar.xz`.
Expected SHA-256 from the official checksum document:

```text
eb187837a2230d4047161ac0be008584e16b46f726e9c9490ee35dc6b17d9ba8
```

Node source commit: `f7f273a9bb6445f6f7fb6349105e7532972045fb`.
The Node archive was not downloaded or executed. Its kernel/libc/libstdc++
requirements must be met by the later exact managed OS image: Linux >=4.18,
glibc >=2.28, libstdc++ >=6.0.25 / `GLIBCXX_3.4.25`.

## Transitive dependency closure

The JSON inventory records **89 runtime-closure package occurrences**, including
resolved peer/support packages, and **91 total occurrences / 90 unique
name-version pairs** after the selected adapter build additions. Occurrences
preserve upstream path-specific resolution; two locations are not necessarily
two different versions. This is not a count of loaded modules or services.

For each occurrence it records the exact version, tarball URL, SHA-512 integrity,
license metadata, engine/platform restrictions and dependency edges. Resolution
starts at the release's `packages/agent`, follows exact workspace links and the
nearest ancestor `node_modules` entries, includes declared dependencies and
already-resolved peers, then adds the selected build roots. External package
integrities and runtime dependency declarations were compared against exact
registry version metadata. No npm resolver or installer was run.

Five absent optional peers remain excluded: MCP SDK, `@smithy/hash-node`,
`bufferutil`, `utf-8-validate` and `kerberos`, with exact requesting package/range
recorded in JSON. Do not silently fetch them. All other TypeScript platform
binaries are excluded from the Linux arm64 build. If the future installation
lock needs a different graph, stop and review the relevant pin change rather
than treating this source-lock-derived inventory as an already-tested npm lock.
Do not blanket-omit optional packages and accidentally remove the explicitly
selected TypeScript Linux-arm64 compiler binary. Source-lock paths record
upstream resolution provenance, not mandatory physical installation paths in
the future managed image; preserve exact versions and effective edges when
translating workspace locations to the installation lock.

Lifecycle scripts exist in `@google/genai` (preinstall) and `protobufjs`
(postinstall). **None ran.** Future artifact preparation must disable scripts;
any necessary compatibility correction needs explicit review, never an automatic
retry with scripts enabled. Upstream test/dev tools such as Vitest, canvas, shx,
Husky and the full monorepo toolchain are not selected for the managed worker.

License metadata spans MIT, Apache-2.0, BSD-3-Clause, Unlicense and 0BSD. Retain
actual license/NOTICE files when artifacts are acquired; metadata inspection is
not a complete redistribution/license audit. Node's bundled notices also apply.

## Verification performed and limits

- Read immutable upstream/registry metadata and hashed the release lock.
- Streamed and hashed core and AI tarballs without extracting/installing or
  executing them; both matched their registry SHA-512 and provenance subjects.
- Inspected their npm provenance statements: tag/commit and workflow agree with
  the selected source. **Sigstore/PGP trust chains were not independently
  validated.** Metadata consistency is not authenticated build attestation.
- Compared all selected external lock integrities and runtime dependency
  declarations against registry metadata. Other package tarballs were not
  downloaded or executed. Node's checksum is a pin, not a verified local binary.
- No implementation, package install, build, product test, pipeline stage,
  service activation, live capture or performance measurement.

The exact Aragorn adapter does not exist yet, so it has no honest build digest
to pin. Likewise the managed OS image/library closure, provider/model policy,
launch configuration and installed/loaded-source evidence remain D2 delivery
inputs. This dependency decision must not be labelled a frozen deployment.

## Next release boundary

The [acceptance mapping](pi-core-phase3-acceptance-mapping-v1.md) is now prepared
for user approval. Only after that approval and a separate implementation
instruction should Root release the connected D2 slice. Its planned entrypoint
is a thin worker under `packaging/pi-core/`; no such package or entrypoint is
created by this documentation. Publish exact writable paths, broker/launcher
contracts and focused checks before lane work.

## Primary references

- [Pi stable release](https://github.com/earendil-works/pi/releases/tag/v1.4.0) and [immutable release lock](https://github.com/earendil-works/pi/blob/4a080252f06caf63a525d7873c5d94d3c23887e0/package-lock.json).
- [Published core metadata](https://registry.npmjs.org/@earendil-works%2fpi-agent-core/1.4.0), [AI metadata](https://registry.npmjs.org/@earendil-works%2fpi-ai/1.4.0), and per-package URLs in JSON.
- [Core provenance](https://registry.npmjs.org/-/npm/v1/attestations/@earendil-works%2fpi-agent-core@1.4.0) and [AI provenance](https://registry.npmjs.org/-/npm/v1/attestations/@earendil-works%2fpi-ai@1.4.0).
- [Node24.22.2 release](https://nodejs.org/en/blog/release/v24.22.2), [checksums](https://nodejs.org/dist/v24.22.2/SHASUMS256.txt), [release index](https://nodejs.org/dist/index.json), [support schedule](https://github.com/nodejs/Release/blob/main/schedule.json), and [immutable platform requirements](https://github.com/nodejs/node/blob/f7f273a9bb6445f6f7fb6349105e7532972045fb/BUILDING.md).
- [Pi telemetry contract](https://github.com/earendil-works/pi/blob/4a080252f06caf63a525d7873c5d94d3c23887e0/packages/telemetry/README.md).
