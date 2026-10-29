# RUN transport source review: two corrections before scheduling

Reviewed lane base: `95b676eca174ae5cb117fe778d3359f0e924b425`.
The containing signed checkpoint is the correction-contract base; Root supplies
its exact remote-verified hash. RUN preserves all drafts and fast-forwards its
own existing branch. Root does not modify its worktree.

Root read the entire transport implementation, its contract and handoff. Separate
reviewers inspected runtime safety, all 27 mocked methods and actual transitive
imports. The submitted source is
`e62bd5405b8aa75c48376ed0655b140f56f91371346299306e9b241b2a98432c`; test is
`1edd1cc7bf6a8e92ccec6b14aefbbeb05ba4cd64339a3306535cc666f4d98471`.
Every entry in the handoff's 13-file closure matched actual bytes. No generated,
external or historical fixture, dynamic import or real OS escape was found.
The real owning-wrapper wiring case is useful; its historical suite is excluded.
No behavioral test has been scheduled or executed for this source.

## Required corrections within the existing three paths

1. **Safe terminal cleanup.** At reviewed lines 95–98 and 133–136 resources retain
   only numbers/roles/objects; lines 449–455 close them without identity checks.
   When a custody guard detects substitution, that cleanup can close a foreign
   object now using the number. Record ownership before metadata, then record the
   actual held identity. Consume ownership once; unknown/unreadable/mismatched
   identity means preserve a cleanup failure and skip the close. For socket
   objects detach once before the conditional raw-FD close, verify the returned
   number and held identity, and ensure object destruction cannot close a skipped
   foreign FD. Pathname pins advance only after verified authorized chown/chmod;
   sockfs identity stays separate. Attempt remaining independent cleanup, preserve
   the original/retention failure, and do not retry an ambiguous close. The frozen
   descriptor_cleanup array records only actual close calls; skipped-close or
   detach errors remain in cleanup_failures with the bounded existing summaries.
2. **Close the full custody bracket.** The last notice-pipe proc read is at
   reviewed line 381; `_guard` ends with only `_context` at 401. A change during
   that read can occur after directory/path/listener/namespace checks and escape
   before READY/NOTIFIED/ACK. After all blocking raw observations, recheck held and
   named directories, socket pathname/listener, both active namespaces, writer and
   reader-FD3 identities/links/flags, reader PIDFD association/liveness and actual
   BOOTTIME before success. A final pipe-only check does not close the other
   identities' bracket. Reuse the existing snapshot shapes and stay within 32
   snapshots, 64KiB raw and 128KiB total evidence with cleanup reserve. A changed
   post-transfer guard quarantines the candidate reader, as the contract requires.

The contract's Closure section now freezes these semantics. Add focused cases for
changed and unknown FD identities (including socket destructor safety), metadata
changes authorized during pathname creation, and mutations during the final proc
read affecting pipe, namespace, directory/path/listener and clock. Assert no
usable reader escapes and actual partial evidence/cleanup errors survive. These
are proposed new cases, not permission to execute them before renewed review.

Root **accepts the notice_pipe schema ceiling** already published in v6: full
parsed flag integers and exact pipe links are retained; raw reader-FD3 fdinfo is
not. Retain the strict bounded live parse without adding undeclared fields. Its
original parse cannot be independently reconstructed from this supplement.
This clarification grants no transport authenticity or health authority.

RUN may revise only:

```text
src/aragorn/native_phase3_run_reader_transport.py
tests/test_native_phase3_run_reader_transport.py
docs/phase3/run-health/READER_TRANSPORT_HANDOFF.md
```

Submit revised stable hashes, exact complete closure and new method inventory.
Root will review the delta and then register/schedule only the necessary selected
stage. The submitted 27-method source has no result to rerun. No shared provider,
schema, registry or other lane file is released. After reviewed PASS retain the
actual result/fingerprint, stage those three paths, sign once, verify and hand off
the original commit; Root merges preserving ancestry and pushes.

Completed: full source/closure review; fdinfo limitation accepted.
Assignment: RUN corrections above; Root retains all loop/refresh/IPC/launch wiring.
Blockers: revised source review and its first selected result; actual shared paths.

1. Finish shared providers and independent consumers with selected validation.
2. Wire HTTP/DNS/destructive, all admission/RUN paths, real a100, cancellation,
   full timing and four actual paired tasks.
3. Close the same 48-entry inventory and publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs,
   independently replay, evaluate the existing gate and verify approved cleanup.
