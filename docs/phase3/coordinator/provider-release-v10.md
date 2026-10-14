# Shared fixture descriptor cleanup: Root implementation release

Review base: signed published `b955947bea054a8e761241d9ae9a40b089a59fa3`.
This exact assignment takes effect in its containing signed published checkpoint.
No new stage or execution is scheduled. The existing v7/v9 external ownership
remains unchanged; Root never mutates active lane worktrees.

The DNS source review found that the shared fixed fixture helper detects custody
changes but unconditionally closes remembered FD numbers in its final loop.
Root must repair that real dependency before releasing DNS validation. It is a
small independent task that fits an available internal owner; no new worktree
or shared lane edit is needed.

## Exact assignment

Root delegates to internal `provider_path_review`, in the coordinator checkout:

- `src/aragorn/native_phase3_http_fixture.py`
- `tests/test_native_phase3_http_fixture_cleanup.py` (new focused tests)

Only these two paths may be edited. No index/commit/branch/worktree operations,
project imports, compilation, test execution, live sockets/proc or staging.
Internal `coverage_ledger` independently reviews the repair and full closure.
Root owns registry/scheduling, handoff, integration and all other shared paths.

## Frozen compatibility and required behavior

Preserve `owned_http_fixture(expected_fixture)`, yielded session identity/guard,
the three-element `_fds` order (network, init-network, init-PIDFD), current fixed
namespace/root/container checks and the two established exception channels:
HTTP_FIXTURE_FINAL_GUARD_FAILED and HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED.
No alternate paths, users, capabilities, permissions or weaker fixture checks.

Track each acquired descriptor immediately, before any fallible metadata read.
Pin actual held device/inode/mode/uid/gid, noninheritability and access flags;
namespace handles require the actual expected namespace type/identity. PIDFD
ownership additionally requires the actual bounded fdinfo association to PID 1.
Do not pretend a numeric FD or generic anonymous-inode metadata alone identifies
a PIDFD. Pin original owning PID/native thread before resource acquisition.

Before each terminal close, verify original owner and current actual custody.
For PIDFD, reread association and recheck held identity after that proc read.
For namespaces, recheck actual identity after any link/flag reads. Unknown,
substituted, foreign-owner or unconfirmed association means skip that close,
retain a cleanup failure and continue attempting independent owned resources.
An exited/unavailable PIDFD association must not justify a foreign close.
Never duplicate/transfer descriptors, close a skipped number, retry an ambiguous
close or silently claim cleanup success. Consume a close attempt once.

An opening/metadata failure still attempts only known-safe already-acquired
resources. Unknown metadata ownership remains unresolved until process exit;
raw integer descriptors have no destructor that should be used as recovery.
Keep original caller/guard failures intact and attach the established cleanup
note. Without a primary failure, ordinary custody/close failure uses the existing
fixed descriptor-close diagnostic. If cleanup itself first raises KeyboardInterrupt,
SystemExit or MemoryError, preserve that original interruption after attempting
the remaining independent known-safe closes; attach the cleanup diagnostic.
No error strings containing raw evidence, private retention or deletion.

Focused tests call the real public context manager with fabricated OS/proc/
PIDFD boundaries. Cover normal reverse-order exactly-once close, partial opens,
unknown initial metadata, namespace and PIDFD substitution, late substitution
during fdinfo/flag/link readback, original owner changes, dead/unknown PIDFD
association, ambiguous close and remaining cleanup, primary error/notes, cleanup
interruptions and unchanged `_fds`/identity compatibility. No historical test
methods or live operations. Submit stable hashes and complete actual project/
stdlib/generated/fixture closure before Root registers a selected new stage.

Root integrates only after reviewed PASS, then supplies the actual new helper
pin/base for RUN's corrected closure. Preserve old HTTP evidence against its
original bytes; do not promote it to a new-closure result or rerun unrelated
checks. This repair proves no actual installed custody or Phase 3 qualification.

Completed: concrete DNS review and isolated shared-dependency defect. Released:
two Root implementation paths; RUN's same five-path corrections. Pending:
stable source, independent review, first selected validation and signed integration.

1. Implement/integrate ready providers with only newly scheduled focused checks.
2. Wire full HTTP/DNS/destructive, admission/RUN, a100, cancellation, full timing
   and four actual paired tasks.
3. Close the 48-entry inventory and publish a freeze candidate.
4. Separately release 31 cases/100 actions/100 pairs, independent replay, existing
   gate evaluation and approved cleanup. All operational holds remain.
