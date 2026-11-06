# Pi-core D2 batch 2: protected bundle preparation and peer identity

Date: 2026-11-02. Base: `8e6a3763b7780069e1379dc8240238cece94c6e8`.
The user released protected bundle launch/worker identity implementation, only
new or affected checks, a verified signed commit and push. **No live operations.**

## Bounded implementation

This batch implements the supervisor-side launch **preparation** and activation
publication boundary, and the accepted-connection Pi identity guard. It does not
start a process, install a listener/service, or silently replace the frozen
UID-only worker handler. The compiled Linux entrypoint/supervisor still needs
to consume these APIs. Do not call this a completed protected Pi launcher.

- `pi_core_bundle_launch.hold_prepared_pi_bundle` reuses the current retained
  admission/context verifier, immutable CAS/tree verification and the existing
  v2 shared installed-lineage/quarantine hold. It joins the context ID, manifest,
  exact immutable version path, installed record, policy and runtime pins;
  copies exact verified prompt/supporting bytes while protected descriptors and
  the installer lock remain held; and supplies a fresh activation/session ID.
- `bind_pi_worker_activation` accepts only a still-open preparation and one bind
  attempt. The future protected supervisor supplies its actual child PID, never
  a PID reported by Pi. Actual socket credentials, socket-issued PIDFD and kernel
  profile are checked and rechecked before exclusive root-owned publication.
  Records expire within the original preparation deadline, at most 30 seconds,
  and no later than the admission context. Failed publication is not retried or
  removed automatically; partial records remain for diagnosis.
- `pi_core_worker_identity.handle_pi_worker_connection` reads protected canonical
  activation state, binds the real peer PID/start/UID/GID/cgroup/mount namespace,
  executable/profile/skill and boot/expiry, then holds the PIDFD and v2 lineage
  lock through one request and one existing relay call. The request's session/run
  must equal the protected activation. Policy and runtime must match relay config.
  Identity/activation are checked before and after dispatch. Post-dispatch loss or
  cleanup failure is indeterminate, never an invented cancellation or retry.

The seven deployment digests supplied to preparation remain **expectations**.
This batch does not acquire the compiled Node/JS/dependency/OS closure or prove
which JavaScript a process actually loaded. The existing sensor observes the
relay process; this new frontend check is not a claim that sensor attribution
now identifies Pi. Health, grants and effect authorization remain external.

Limits are intentionally inherited: one bundle, one process in the cgroup,
at most 64 files/1 MiB, depth one and at most one supporting directory. Prompt
bytes also respect the existing 32 KiB Pi worker bound. Executable members and
script descendants are refused in this slice, not declared generally supported.
No frozen predecessors, old worktree drafts, evidence or cleanup holds change.

## Ownership and verification release

Root owns `pi_core_bundle_launch.py`, registry/capacity changes and checkpoint
documents. The identity agent owns `pi_core_worker_identity.py`; the test agent
owns `test_pi_core_launch_identity.py`; a separate reviewer checks source and
fixtures. Other worktrees and historical assignments are not released.

Only `pi-core-launch-identity-offline` and `pipeline-capacity` are selected.
The registry grows from 129 to 130 entries, so the four finite capacity checks
are affected. Its runner digest changes other fingerprints; that is not a reason
to execute old stages. The previous 28-check Pi-loop stage is not rerun.
The new stage declares its 54-file transitive Python source/test input closure;
the pipeline also binds its runner, Python toolchain/environment and worker lock.

Fixtures use actual temporary CAS, immutable files and admission-context joins.
Decision-receipt output, root ownership namespace, Linux process/PIDFD state and
transport are explicitly simulated. Socket/process execution is trapped. These
are offline implementation checks, not fresh admission, native launch, RUN,
effect, cleanup-of-a-live-fixture or Phase 3 qualification evidence.

Source review corrected the legacy-helper import, joined the context ID to the
exact installed version, bound policy to relay configuration, used the bounded
boot reader and fixed descriptor ownership before the first focused run.

## Completed focused checkpoint

Both selected stages passed once, with no failed product attempt and no rerun:

| Stage | Result | Exact fingerprint |
| --- | --- | --- |
| `pi-core-launch-identity-offline` | 50 new checks PASS (0.115 seconds) | `sha256:680a522380af03be17977b0d9c0ac32bde1c5b8ef1f8697c406f6da23f86ad5b` |
| `pipeline-capacity` | 4 affected checks PASS (0.006 seconds) | `sha256:fc648810d2c80f20c91838873e8a500e90aeb2856bba75cbfac30ccd29bbd70a` |

The pipeline used pinned-in-result host Python 3.14.6 with `-S -B`; times above
are offline unittest durations, not worker or Phase 3 performance measurements.
The connected check uses the same prepared bundle, actual newly published
activation bytes and real installed-tree verifier through the new guard, with
only the documented decision/owner/kernel/transport boundaries simulated.
Results and logs remain under `.aragorn/phase3-pipeline/<stage>/<fingerprint>/`.
The original Pi-loop checks, broader tests, historical captures and acceptance
were not executed. No services, listeners, worker processes, provider calls,
protected effects or VM changes occurred.

The containing signed commit is this batch's checkpoint; its verified hash and
confirmed remote SHA are reported in the milestone handoff. Only batch-owned
files are included. Unrelated drafts and other worktrees remain untouched.

## Remaining plan

1. **Implemented offline:** approved design/pins/mapping, Pi request-only loop,
   protected bundle preparation, one-shot activation binding and peer relay gate.
2. **D2 next:** compile/pin the Linux adapter and OS closure; connect a confined
   launcher/entrypoint that consumes these prepared bytes and calls this guard;
   add credential-isolated provider/data mediation and complete consumed-source
   custody. Then separately authorize one useful output, health and cleanup run.
3. **D3:** complete managed updates/revocation, supported scripts/descendants,
   RUN events/responses, workload/timing paths and independent consumers on the
   same deployment. Retain enforceable denials for unsupported surfaces.
4. **D4–D5:** executable approved acceptance contract, full independent inventory,
   freeze, separately authorized fresh acceptance and verified cleanup. Phase 3
   is not qualified and Phase 4 remains blocked.
