# Workloads peer lineage: pre-execution source review v1

Review base: signed published f65e8f3b8a79f3ac7251a69f6facc7df89042364;
current Root schedule/release checkpoint d7ebe099cc692eff476338668e5edd27a0af76cd.
Root and two independent reviewers inspected the actual four-file closure and
27 proposed methods without importing, compiling or executing project code.
No Workloads stage is registered or scheduled by this review.

## Exact reviewed bytes and claim ceiling

| Path under repository | Bytes | SHA-256 |
| --- | ---: | --- |
| src/aragorn/__init__.py | 78 | 4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01 |
| src/aragorn/native_phase3_workload_destructive_lineage.py | 29717 | 674488d0cb524ecaf327db1dab0ed20de4f679d254c5d5dda290eafcae45eb4d |
| src/aragorn/native_phase3_workload_destructive_lineage_verify.py | 17699 | 37660fdb25aa524ae6149783735e9ecdd7ccbed3ebaf39d8c81fc65f5cb254b0 |
| tests/test_native_phase3_workload_destructive_lineage.py | 37046 | dd1b2d55c119056b6e0c20f9ec3e49d27a5266ea144c8cbb8ad1ad34612f191d |

Handoff:14275 bytes,
sha256:7aef7b717ea6366b4701eee7f838ffa6c3a95a45463a357cba2fa28f4a74d1a6.
Actual project imports are exactly initializer, producer, public independent
verifier and test. Otherwise stdlib, inline independently authored raw/model
fixtures; no generated/file fixtures or historical TestCases. Producer calls
only the public verifier. No concrete independent-verifier semantic blocker was
found in this review. Results preserve UNKNOWN submission, seven false flags,
and explicit external Root loaded-config/positive-holder/source obligations.
This is not real a100 enforcement or native/deployment evidence.

## Required bounded corrections before first scheduling

1. Normal resolved numeric FD reuse: own() currently rejects every matching prior
   resource row, including CLOSED. A freshly opened descriptor reusing a closed
   number can therefore be rejected before tracking and leaked. Permit reuse
   only after the earlier generation is fully CLOSED; still reject borrowed,
   active and unresolved aliases. Track newly acquired ownership before fallible
   metadata. Model normal low-number reuse and per-generation close accounting;
   the current monotonic allocator hides this real path failure. Include final
   borrowed-PIDFD transient reads after the initial cleanup in the regression.
2. Immediate pre-read flags: guard() samples access/nonblocking/CLOEXEC before
   clock and cancellation/link/poll work, then checks only identity/owner/alias.
   Move the final flags check after those observations and finish with final
   local custody immediately before the read. Retain original errors/prefixes.
   The current last-flag regression fires during own()->flags(), not the late
   guard; arm only after acquisition/earlier guard succeeds and assert zero
   unauthorized reads/closes after the actual late mutation. Check final borrowed
   cancellation flag ordering after its link/poll observations as well; do not
   return cached true flags for a known changed descriptor.
3. Terminal transient cleanup: PIDFD close opens a new fdinfo proc FD while
   cleanup iterates a frozen resource tuple. A read failure in read_path bypasses
   its close and can leave that new known-safe owned resource outside the tuple.
   Ensure every such new transient gets its own custody-safe close attempt, with
   original errors/cleanup failures preserved. Never retry ambiguous close or
   force-close unknown/foreign handles; retain and poison unresolved ownership.
   Add a failure specifically inside PIDFD association readback during terminal
   cleanup, asserting the safe transient close and unresolved PIDFD state.
4. Selected Darwin Python fixture setup: getresuid/getresgid and SO_PEERCRED are
   Linux-only attributes absent from the selected Homebrew Python3.12 environment.
   Supply only these fabricated Linux boundaries with patch.object(create=True),
   including SO_PEERCRED=17; preserve the production Linux-only refusal. Ensure
   already-entered ExitStack patches unwind if setup fails. Do not widen general
   mocks or run a native operation to confirm availability. CLOCK_BOOTTIME already
   uses an explicit created mock. Add a focused setup-failure unwind assertion.

Only the existing v11 four assigned paths may change. Preserve public API/schema,
actual frontend peer, independent replay, sequential resolved-call semantics,
Root obligations and false claim flags. No private helper imports/new framework,
shared dependency edits, source copying or repeat design review. Root will supply
required registry description metadata; it is not a new owner source task.

Submit refreshed stable hashes, actual complete closure and focused cases. Root
reviews before registering/scheduling the first necessary stage. No unchanged
retry or historical rerun: these27 methods have never been executed. Preserve
all drafts and unaffected evidence. Operational/private-retention/cleanup holds
remain; no new test or live permission is granted by this source review.

1. Correct/review/integrate ready providers with newly necessary focused checks.
2. Wire full HTTP/DNS/destructive, admission/RUN, real a100, cancellation, full
   timing and four actual paired tasks.
3. Close the existing48-entry path/consumer/source-custody inventory and freeze.
4. Separately release same-deployment campaign, independent replay, existing gate
   and approved cleanup. Final qualification remains pending.
