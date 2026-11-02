# RUN release v12: fixed broker/provider descriptor bootstrap

Review base: verified signed published
`cfef272262e79a917f11e35889c1c46651c62460`. This release takes effect only at
its containing verified signed published checkpoint. Root supplies that exact
hash after normal push and remote-tip verification. The existing RUN owner
verifies and fast-forwards its own branch, preserving drafts, then acknowledges
this release. Root never modifies an active lane worktree.

## Existing requirement and exact source ownership

This is the missing real bootstrap prerequisite for the existing serialized
broker/reader/HTTP causal path: authenticate the actual broker and Root supervisor,
transfer cancellation and supervisor PIDFD ownership, join the actual receiver
FD inventory and wait for concrete provider readiness before releasing the fixed
HTTP_REFUSAL_ONLY configuration. This is not health, positive authorization or
final deployment readiness.

Read `broker-reader-bootstrap-contract-v1.md` and the RUN prompt in
`worktree-handoffs-2026-10-15.md`. RUN receives only:

1. `src/aragorn/native_phase3_broker_reader_bootstrap.py`
2. `tests/test_native_phase3_broker_reader_bootstrap.py`
3. `docs/phase3/run-health/BROKER_READER_BOOTSTRAP_HANDOFF.md`

Implement the exact owning APIs, four messages, concrete readiness frame and
bounded successful/failed raw acquisition retention. Use stdlib only; no private
helpers, arbitrary endpoint, identity/readiness callback, helper process or new
health framework. Keep original account/credential/root-only protections.
Do not edit shared protocol/journal/context/session, service/client/renderers,
units/activators, inventories, registry or another lane's paths.

Root's finite ABI decisions are the original 4-second startup cap, unchanged
session deadline, ordinary local socket buffers with checked actual getters,
exact two-FD order and one-use configuration transfer, and the explicit nested
schemas in this self-contained contract. Complete actual successful observations
must be retained, not only their digests. Missing native support refuses; no
force-buffer/sysctl/privilege change or numeric-PID fallback.

## Root-owned real caller and evidence obligations

Root supplies the independently acquired fixed-unit/MainPID/InvocationID/source/
credential expectation, original protected launch inputs, actual before/after
observations and final dynamic provision. Root constructs the provider/session
and guard listener, owns the sole readiness writer/cancellation writer lineage,
and retains separate PIDFDs for lifetime supervision. The bootstrap module
acquires and retains its own declared socket/process/descriptor observations;
its authenticated Root bindings are not independent non-root Root-proc reads.

Root keeps bootstrap READY separate from session readiness and keeps provider/
supervisor alive through the broker outer response and original session lifetime.
Root also owns launcher/service/configure integration, generated HTTP94 successor,
actual loaded/deployed inventory, bridge post-exec CLOEXEC/subscription and complete
stream/loss/program/map acquisition. Current missing loss remains UNKNOWN and
REFUSED/LOSS_UNAVAILABLE; this bootstrap cannot enable an effect or positive profile.
These concrete native-use dependencies do not block bounded offline implementation.

## Scheduling and handoff

This source release schedules no import, compilation, test or live operation.
Submit stable source hashes, complete actual import/generated/fixture closure
and focused case inventory. Root alone registers and publishes the owning
focused schedule. Use `/opt/homebrew/bin/python3.12`; preserve every actual
result/log/fingerprint and diagnose before a reviewed changed-input retry.
After reviewed PASS, stage only these three paths, make one `git commit -S`,
verify it and hand Root original hash, paths, actual result, limits and blockers.
No feature-branch push is necessary.

DNS acquisition is already integrated from original signed `a32477b`; its first
50-method PASS is unchanged and must not be rerun. Admission continues its
existing two context corrections, with no first stage yet scheduled. Workloads
continues v11's four-path actual peer-lineage acquisition concurrently. Existing
capacity is sufficient; no additional worktree is requested. Owner receipt of
this newer checkpoint remains unconfirmed until acknowledgment.

No historical suites, cache copying, unchanged retries, live operations, private
retention or cleanup. Original evidence and lane ancestry remain retained.

1. Implement/integrate ready providers with only newly scheduled focused checks.
2. Wire HTTP/DNS/destructive, all admission/RUN paths, genuine a100, cancellation,
   full timing and four actual paired tasks.
3. Close the existing 48-entry inventory and publish a freeze candidate.
4. Separately release same-deployment qualification, independent replay, the
   existing gate and approved cleanup. Final qualification remains pending.
