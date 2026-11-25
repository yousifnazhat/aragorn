# D3 — one fixed task service reached through Pi in both modes

This implements the [B90 carrier decision](pi-core-managed-task-output-batch-90.md)
in source. Both baseline and instrumented use the same Python service through the same
Pi tool. Neither a mode label nor matching recorded answers proves that instrumentation
was on or off. No guest artifact, approved inventory or verifier pin was replaced.

- The manager binds the scheduled task, original input, mode, environment, clock and
  three distinct process roles in a pinned ticket. The opted-in Pi tool forwards only
  the request and ticket digests. It cannot choose another task, path, program, model or retry.
  The service adds a fresh 256-bit nonce after task execution. Both replies must carry
  the same nonce and observation; Pi cannot precompute the successful reply from the
  scheduled fixed output. The manager checks against the separate service channel.
  Exceptions and uncertain completion yield no receipt.
- The collector owns both marks: before the first request byte goes to Pi, and after
  both the complete Pi reply and the complete service witness return. They include
  both Pi hops, the service's work and receipt of the witness, not
  post-return verification, private retention, cleanup or pre-task provisioning.
  There is no fallback host clock. The three computations reuse the frozen reference;
  the copy successor retains its fixed data, exclusive create and readback using a
  nominated directory descriptor instead of reusing Docker's container identity.
- The separate guest-side observer requires a fresh private directory before dispatch.
  It binds the systemd invocation, pidfd, process generation, namespaces, mounts and
  directory from the observer and service views, then independently reads the fixed
  file. It holds the file through the final check. This does not establish exclusive
  authorship. Retain the raw ticket, both peer replies, outer marks, receipt, original
  copy observations and reviewed reference source. The portable reader consumes pinned
  originals from a read-only content store, checks the task output independently and
  returns recorded semantics only. It never starts Pi.

## Focused evidence

Only the following new pipeline stages were selected. The checks used inert requests
and disposable files. The cross-language check ran the pinned developer Node/Pi SDK
over anonymous pipes with network and child-process permission disabled; Python
performed a real temporary copy. Linux identities, channels and clock ticks were
supplied by the fixture. Two observed ordering checks are not two measured samples.

| Stage | Checks | Retained successful fingerprint |
| --- | ---: | --- |
| pi-core-task-copy-observation-offline | 8 | afd4c844333ef4745dfdf706ff3201e365865e57ae01eab06f84c83e36012991 |
| pi-core-paired-tool-offline | 1 | aaa00c87c8600f750838687ea09fa6d647adb5b4de8014db1336a5ba917fb54e |
| pi-core-task-service-offline | 7 | 0a6bbda09a3ed247d3e5bdb0290396763b6f2d43f6fa4b664cca32f858067c71 |
| pi-core-paired-task-replay-offline | 6 | 6d4c0bff2b0edb6966016a21d2f086e44d0ca4848fb51ef2b0e90bfd420a86d7 |
| pi-core-fixed-task-path-offline | 1 | 2affa45012baa57c461f7fe50b8f52ae0276d3a5fbf21d719a5abca444a190f6 |

During review, an early, predictable Pi reply stopped the original timer before the
service response. A focused failing check retained that observation. The final checks
show that even when the test deliberately predicts the reply, the delayed service
response remains inside the interval; stale or malformed completion nonces cannot
produce a successful receipt. The unchanged eight observer checks did not rerun.

## Remaining D2–D5

1. D2: recorded action and output replay do not supply a live pilot. The approved
   local deployment, original consumed-source/health, useful result, timing, recovery
   and cleanup evidence are still required. B49 remains unchanged.
2. D3: next, provision a successor with the fixed task unit, confined Pi entrypoint,
   manager/service channels and separate witness. The native owner must pin the actual
   code, independently observe the mode and clock, prohibit endpoint delegation, keep
   peers alive through retirement, claim a request durably before dispatch, retain
   independent pins, and prove fixture cleanup/equivalence. Do not schedule pairs
   from this source batch. Admission, RUN/health and remaining workload gates stay open.
3. D4: connect originals and independent verifiers across the 29 logical requirements,
   then freeze **one** candidate for acceptance. No frozen inputs changed.
4. D5: only after freeze and separate authorization, perform fresh acceptance, the 100
   attempts and 100 baseline/instrumented pairs, cleanup readback and offline replay.
