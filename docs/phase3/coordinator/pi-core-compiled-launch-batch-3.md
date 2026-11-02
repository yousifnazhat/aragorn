# Pi-core D2 batch 3: compiled artifact and confined bootstrap contract

Date: 2026-11-02. Base: `6087a84ef97c9b6a5cf1fd821fee81e3821f0b09`.
User release: compiled Linux deployment and confined launcher/entrypoint
integration, only new/affected checks, verified signed commit and ordinary push.
No live Aragorn operations, provider calls, services or qualification campaign.

## Scope and reuse

The compiler assembler consumes the approved Node 24.22.2 and TypeScript 7.0.2
archives and existing 89-occurrence Pi runtime dependency tree. It emits the
existing worker plus new bootstrap entrypoint and preserves the frozen legacy
codec's sibling import layout. It does not install packages, execute lifecycle
scripts, substitute versions or create another agent/broker framework.

Only the pinned static Linux arm64 compiler executes, inside one exact-owned
scratch container on the already-running `colima` daemon. No image pull,
network, capabilities, root user, worker execution or VM lifecycle change is
allowed. The original 120-second budget reserves 30 seconds for ownership-checked
container/image cleanup. Outputs and failed diagnostics remain local; no broad
prune or deletion of historical evidence is permitted. Target Node is copied,
not executed. Strict source checking uses the compiler's ES2024 declarations;
`skipLibCheck` applies to upstream declarations, not Aragorn adapter source.

The credential-free `entrypoint.ts` uses a new post-exec connection to a fixed
protected Unix socket, bounded canonical frames and one deadline. Its native
path performs HELLO, START, `PROVIDER_UNAVAILABLE`, RELEASE only. It does not
activate Pi, discover provider credentials, call the legacy action endpoint or
retry. The explicit in-process composition API connects the existing actual Pi
loop for scripted offline fixtures; callbacks cannot arrive over the wire.

`pi_core_confined_launch` reuses protected admission/tree preparation and the
existing one-shot activation binder. It joins measured immutable runtime bytes,
compiled receipt, Node executable, OS tree, configuration and deployment pins;
holds their descriptors with the admitted bundle; prepares fixed systemd
confinement arguments; and exchanges the authenticated bootstrap using the
supervisor's expected child PID. It is a **guarded plan and connected bootstrap
API, not an implemented native supervisor**. It neither executes systemd nor
creates listeners, mounts filesystems, withdraws activations or proves cleanup.
Missing protected installation/OS inputs refuse before a plan is yielded.

## Concrete remaining integration gaps

The non-root action relay currently has `ProtectProc=invisible`, no capabilities
and a different UID from Pi. Installing the root-side identity measurements in
that relay cannot work as-is. This batch does not disable those protections,
grant ptrace, run the relay as root or pretend the existing sensor identifies Pi.
The native bootstrap has no provider or effect path; the confinement plan masks
the configured action endpoint until a protected identity handoff is connected.

Remaining D2 dependencies are a real protected OS/library closure; exact
installation and mount custody; the native supervisor's MainPID/InvocationID,
socket ownership, original deadline, activation withdrawal and observed cleanup;
protected identity handoff to the unprivileged action relay; credential-isolated
provider/data mediation; and useful effect/health/independent-output integration.
No placeholder digest, generated argv or bootstrap result closes these gaps.

## Coordination and checks

This chat coordinates separate build, entrypoint and confinement owners with
nonoverlapping files. Existing Admission/RUN/Workload worktrees contain preserved
drafts and older bases; none was reset, repurposed or silently fast-forwarded.
Independent future lanes should receive one published base and exact interfaces
before worktree release. More worktrees do not replace the shared integration
owner or authorize simultaneous live captures.

The registry adds four narrow stages: `pi-core-linux-build-offline`,
`pi-core-linux-compile`, `pi-core-entrypoint-offline`, and
`pi-core-confined-launch-offline`. Its finite capacity rises from 130 to 134;
only the four affected capacity checks are selected alongside those new stages.
The compiler-only stage is separate from inert command/cleanup tests. No prior
Pi-loop, launch-identity or historical suite is scheduled merely because the
runner fingerprint changes. Exact successes and all failures remain retained.

## Completed focused checkpoint

All selected checks passed on their first execution: 111 new inert checks,
one actual Linux compiler-only build check and four affected capacity checks.
No failed attempt, unchanged retry, broad regression or historical recapture.

| Stage | Result | Exact fingerprint |
| --- | --- | --- |
| `pi-core-linux-build-offline` | 41 PASS, 0.049 s | `sha256:3d64b59eb09e9a6483df0df0c71e67bfafd56ff902d49fbf511888ae04e89055` |
| `pi-core-linux-compile` | 1 PASS, 13.246 s | `sha256:300ddc9d141f467454640fd184fe4fba68a31b338cc8e8fada03cf586a94afde` |
| `pi-core-entrypoint-offline` | 29 PASS, 7.928 s | `sha256:a3b4a03071434210003efe99fdd184ff1b6fe28579d57ba951d247b4c3b12e18` |
| `pi-core-confined-launch-offline` | 41 PASS, 0.031 s | `sha256:49e6eab7c2acd79f22cf84c0693d46b2007c26449899f1d62c527b1449b3b975` |
| `pipeline-capacity` | 4 PASS, 0.006 s | `sha256:0f51747036a278a5b257f57007ed4a0c90cd3b5e34be5399adfd4d4438ab4cc8` |

Times are unittest/build durations, not Phase 3 workload measurements. Results
and logs are retained under `.aragorn/phase3-pipeline/<stage>/<fingerprint>/`.
Before first execution, review corrected source-only `.js` to `.ts` fixture
resolution, test-only metadata preservation, disjoint root checks and bounded
bootstrap expiry. Existing implementation bytes and frozen predecessors did
not change; neither the old 28-check loop nor 50-check identity suite reran.

The compiled artifact is local at
`.aragorn/pi-core-build/d2-1c37879592044638ba9d039a76891fba/deployment/`.
Its full 12,694-file inventory and build receipt remain alongside it. The tracked
[`compiled-artifact-v1.json`](../../../packaging/pi-core/compiled-artifact-v1.json)
records inputs, selected compiled-file hashes, exact receipt identities and
cleanup observations. The deployment-tree SHA256 is
`0fa00453f41ca94c7942076ce0d4130cfc7cdcd91755439460aa50f5fd9d5875`.
It is an adapter/Node/dependency artifact, **not a complete OS image, installed
deployment or qualified runtime**. Binaries/full inventory are not published by
the source push. Local receipt file SHA256:
`a91434f1c9216c628d5feb7fa7f072534109f4bb8807a556c5c31bb825323f87`.

The compiler log records successful ownership checks, removal and absence of
the exact compiler container/image; cleanup errors are empty. No VM was started
or stopped, Docker context switched, historical fixture touched or unrelated
resource removed. The compilation ran no target Node/Aragorn worker. All
entrypoint and confinement execution checks were in-memory/mocked fixtures.

The containing signed commit is this batch checkpoint. Its verified hash and
confirmed remote tip are reported in the handoff. Only batch-owned paths are
committed; unrelated drafts and all other worktrees remain intact.

## Remaining plan

1. **D0–D1 complete as design/contract:** approved Pi-core capability profile,
   immutable dependency pins and 29-requirement acceptance mapping.
2. **D2 in progress:** this compiled artifact/bootstrap slice, then protected
   OS installation, actual supervisor and action-identity handoff, provider/data
   mediation, and one useful task. Live pilot requires separate authorization.
3. **D3:** finish managed lifecycle/update/revocation, required RUN/health,
   workload/timing paths and independent consumers on the same deployment.
4. **D4:** implement the approved acceptance contract, finish independent
   inventory and freeze one exact complete deployment.
5. **D5:** separately authorized fresh acceptance, actual metrics, offline
   replay and verified cleanup. Phase 3 remains unqualified; Phase 4 is blocked.
