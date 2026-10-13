# Guarded reader transport release and coordinator checkpoint

Base: verified signed and published
`f080cf830d41d85421dd897a0783fe2899301645`.

## RUN: released bounded implementation

Root reviewed `reader-transport-contract-v1.md` against the actual existing
response, acquisition, store and process helpers. Root accepts its fixed
`/run/aragorn-phase3-reader/challenge.sock` endpoint, root:reader 0710 parent,
0660 socket, launcher-owned root notification pipe and reader FD 3 ABI.
The notice is an actual single bounded atomic write; one accepted connection
transfers exclusively to the unchanged owning acquisition function.

Root accepts terminal listener closure after notice-issued failure, TIMEOUT or
cancellation. The frozen challenge channel has no pre-challenge request tag;
unreviewed recovery could associate a late old connection with a later request.
Multiple distinct successful requests may share the held listener. Recovery
between fault scenarios remains a separately reviewed integration obligation;
no socket pathname or evidence is deleted. Existing retention/cleanup calls do
not provide hard return-time or post-transfer cancellation guarantees.

Upon signed publication of this checkpoint, RUN verifies its containing commit,
fast-forwards its own existing branch preserving drafts, reads the contract and
acknowledges agreement. Begin only these three new paths immediately:

```text
src/aragorn/native_phase3_run_reader_transport.py
tests/test_native_phase3_run_reader_transport.py
docs/phase3/run-health/READER_TRANSPORT_HANDOFF.md
```

This explicitly supersedes the older Root-only transport proposal. Do not start
the real pipe/checkpoint implementation from its design sketch. Its parser seam,
three-role stream custody, upstream connection/error accounting and checkpoint
schema still require a separate release. `normalize_process_capture` requires
closed/quiescent capture and must not be fed fabricated EOF or zero loss to
validate an ongoing loop. Root owns that contract and launcher/broker integration.

Submit actual complete source/import/fixture/generated closure, hashes and new
focused cases before execution. The contract's anticipated 13-file closure is
not permission to omit a newly used dependency. No transport stage is registered
or scheduled here. After reviewed PASS: exact three-path signed commit, verify,
original hash/results/limits handoff; Root integrates and pushes normally.

## Current lane state and evidence

Admission original `d3c5ffed8dbbf0520c9b8d2e9d798e204d09f96d` is verified and
integrated preserving ancestry. Its actual 26-check result and logs were reviewed
in the owner worktree, fingerprint
`sha256:c08b47026e885e68bab6482ca5d858863ef442774f40db55eedea486b3e9ce46`.
Policy/lifecycle acquisition and required absent-target behavior remain open.
Admission's next implementation requires its own exact protected-provider/route
contract; no new Admission paths are silently released here.

RUN's original 14-check delivery, Root's 16-check store and six-check scheduler,
and HTTP 14+7 results remain preserved. The actual HTTP report is still 68263
bytes, SHA-256 `88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9`.
No historical suite or staging operation was repeated.

Workloads' corrected six-file DNS closure passed delta review; the single
13-method `native-workload-dns-canary` stage is published in
`dns-delta-review-and-scheduling-v1.md`. Its actual result is pending. Its owner
must inspect existing results and run only that selected stage in their worktree.

All owners acknowledged `4ec18f8`. Delivery/agreement for newer `f080cf8` and
this release are unconfirmed until acknowledged. Outbound task read/send still
fails at localhost:54152; these published files are copyable handoffs. Root did
not mutate lane worktrees. The first push of f080cf8 used the unrelated active
guild account and failed 403; the changed per-command owner credential succeeded,
and Root verified the remote tip. No global account switch or force push occurred.

## Coordinator work and remaining sequence

Completed: Admission integration, DNS correction review/stage release, exact
guarded transport contract and RUN ownership transfer.
Released: RUN transport implementation; Workloads' selected DNS stage.
Pending: Root's broker evidence/submission and DNS acquisition contract reviews;
real reader/checkpoint/loss and protected admission acquisition contracts;
independent transport replay, owning launch/dispatch and deployed inventories.
Additional capacity will be requested only with a ready signed non-overlapping
assignment, branch/path/base and concrete benefit. No new worktree is needed
for the released RUN slice; the existing owner is available.

1. Implement/integrate the released transport and shared providers; publish each
   remaining ready contract without waiting for unrelated coordinator work.
2. Finish DNS and remaining Admission/RUN/Workloads paths, actual lineage,
   cancellation, full decision/task timing and real paired contexts.
3. Close all 48 ledger entries and source/loaded-identity custody; then freeze.
4. After separate operational release, collect the 31 cases, 100 attempts and
   100 pairs on one deployment, independently replay and verify approved cleanup.

Live operations, private retention, cleanup, cache copying, unchanged retries and
historical suites remain held. This is implementation release, not qualification.
