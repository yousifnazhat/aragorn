# D2 batch 47 — pin the VM owner; arm supervision before start

Signed base: `f5fe1da3aefa2a5aa9a30bdf78f18a5d0f6471e0`.
This batch closes the offline start-interlock wiring. It does not close D2 or
authorize a boot. No VM instance, variable store, cloud resource or provider call
was used. The only production execution was the signed binary's pre-target refusal.

## What gates the start call

1. The [release entry](../../../packaging/pi-core/immutable-host-b47/owner-runner.m)
   selects an exact UUID from the release inventory embedded in the executable.
   This candidate's inventory is empty, and its build refuses a nonempty one.
   There is no operator environment flag, mutable approval file or test switch in
   the binary. In the target branch, the B45 private disk/EFI identity checks and
   isolated device graph pass the same graph and output-only pipe to the VM owner.
2. The [owner](../../../packaging/pi-core/immutable-host-b47/vm-owner.m)
   holds one machine on its own serial queue. Before requesting a watchdog grant,
   it observes B46 stop-bridge readiness, obtains the real B45 recorder's arm
   signal on the graph's pipe, and syncs the private journal and attempt directory.
3. The [external watchdog](../../../scripts/pi_core_host_owner_supervision.py)
   can grant only after taking ownership of the direct child. It matches a bounded
   READY frame to the child PID and attempt UUID, durably records its decision,
   then sends a single ARM over the private inherited socket before the absolute
   RAW-clock deadline. The stop pipe remains separate. A decision record alone is
   **not** delivery; delivery alone is **not** invocation.
4. On the machine queue, the sole start site rechecks the observer, recorder,
   channels, grant identity/deadline and machine state. A stop request has no
   implied stop outcome. Loss of supervision prevents successful completion.
   A native `complete` value is only the owner's report, not independent boot,
   restoration or qualification evidence.

The design assumes a trusted host and an exclusively owned, cooperating parent
and child. The interlock is not remote attestation or protection against host
root. It cannot promise that a host won't fail between a check and a framework
call; an ambiguous outcome must not be retried.

## Artifact and checks

The [artifact pin](../../../packaging/pi-core/immutable-host-b47/runner-output.json)
binds the 125,888-byte arm64 executable, SHA-256
`a396b63bc16b52699b2ae82884199652a6506dab3896f99bec27285698bb33ea`,
to build closure `2ef1ca18f4c73f181030376b135f65b89262e9eacec5a7db41bf7d2d0940aff1`.
It has a local ad-hoc hardened signature, CDHash
`e8d543da657b914f7bb28c69aeee14c759a16352`, and only the virtualization
entitlement. That is not Developer ID, notarization or target distribution
approval. The Git-signed pin authenticates the exact digest. Verify locally
without executing the artifact:

```sh
python3.12 -B -m scripts.prepare_pi_core_vm_owner verify "$APPROVED_COMMIT" "$TRUSTED_SIGNER"
```

The private build remains under the operator's local Application Support
directory, not in Git. The artifact stage checks source snapshots, Mach-O/code
signature, the linked production constructor vs the test-only machine symbol,
and refusal under the real watchdog without supplying any target media.

| Focused stage | Passing checks | Fingerprint |
|---|---:|---|
| Watchdog ownership, durable decision, malformed/late frames and cancellation | 7 | `4dc8e9575a2e699cb71f86b4f99743985df9707e994dfde34742d6229e230a13` |
| Native owner with inert machine, actual recorder and stop bridge | 8 | `4769ed125d5b2c73e6880c93d378bed882da81f6fb533c9046cc2de3413e5a57` |
| Pinned production artifact and no-grant refusal | 3 | `dc7a8ab1c77d67ba0d2d15e001a3c9a78b796834a0e1a4ebb7339cce64512938` |
| Registry boundary, 271 → 274 | 4 | `81d1c046ab8308ef94da3064dce57083838a48c8e8972c8b576e25635a8d1ee6` |

22 passing checks. The positive native fixture observed exactly one inert start
after both local arms and the external decision. Before that decision, the fixture's
start marker was absent. Wrong PID/UUID, stale/duplicate grant, missing recorder,
wrong pipe and early stop were refused. With later supervision loss, even an
observed stopped transition could not produce a successful completion.
The original native-stage fingerprint
`79c6d86710e71d41dd8083f64a1f2740be684f39a2a229b888be1763642f702a`
failed before any test ran: the fixture called an unavailable SDK initializer.
The retained successor used the supported initializer; only that stage reran.
No media rebuild, repeated successful stage, historical replay or live trial.

1. **D2 open.** Independently verify/export the owner's new evidence and define
   host-loss reconciliation. Bind target, cost, signing/distribution, firmware,
   cleanup owner and one-shot authorization. Enrollment, compatibility boot and
   a later useful pilot remain separate decisions. Actual worker source reads,
   health, recovery/timing and useful output still need independent evidence.
2. **D3 open.** Finish remaining connected admission, RUN/health and workload paths.
3. **D4 not frozen.** Close the executable mapping and independent verifier
   inventory for the 29 requirements, then freeze one deployment.
4. **D5 not authorized.** After freeze/approval, run fresh managed admission,
   100 attempts and 100 baseline/instrumented pairs; verify thresholds, cleanup
   and independent replay.
