# RUN transport renewed review: one closing-read ordering correction

Source/release base: verified published
`b4c0c2b411dab3d3575f05175eb04a3b58e4eee1`.
RUN acknowledged the published correction contract and fast-forwarded its own
existing branch, preserving its three drafts and original HTML. Root confirmed
the branch tip read-only. No active lane worktree was changed by Root.

Reviewed candidates:

| Path | Bytes | SHA-256 |
| --- | ---: | --- |
| `src/aragorn/native_phase3_run_reader_transport.py` | 43089 | `95ee8ea1c1dd2c6eead3f3738ed691655c4e14483dc5c00d9b5d6b19b59845c4` |
| `tests/test_native_phase3_run_reader_transport.py` | 51683 | `f0bb644a16603c561bc2a839b49ec5cb26668e512a243a8e0362cef017690218` |

Root reviewed the revised code and focused cases. Independent safety and test/
dependency reviewers inspected the same stable bytes. Static traversal confirms
30 methods and the same 13-file actual closure listed in the lane handoff. Every
pin matches; all 11 reused inputs also match the coordinator checkout. There are
no new generated sources, external/historical fixtures or dynamic imports. Test
OS boundaries remain mocked, and the actual owning-wrapper wiring case remains
valid. No behavioral test, import or compilation ran; no result exists yet.

## Accepted corrections and explicit limit

Ownership now records actual held identities, consumes each entry once, detaches
socket objects before conditional raw-FD close, and skips unknown or changed
identities without fabricated close rows. Authorized pathname metadata pins
advance only after held/named verification. A successfully detached object cannot
later destruct-close the skipped foreign descriptor. Original and cleanup errors
remain separate; transferred connections stay with the frozen owning wrapper.

If detach itself fails, the socket object remains held by the owner and the raised
error. This is an unresolved custody handoff, not completed neutralization. Later
Root supervision must retain those owner/error references for that lifetime and
must not discard/garbage-collect or retry the uncertain object. The bounded wire
supplement and all false authority flags remain unchanged. The previously accepted
reader-FD3 fdinfo replay limit still applies.

## One remaining correction, same three assigned paths

In the reviewed `_closing_guard` at lines 437–443, the final `_pipe_snapshot`
precedes a further blocking read of `/proc/self/fdinfo/<reader_pidfd>`. Reader FD3
flags can change during that later read; the remaining checks revisit pipe
identities and links, but never the reader flags. The existing new mutation case
hooks `/proc/<reader_pid>/fdinfo/3`, so it does not exercise this later read.

Move the final PIDFD raw association sample/validation **before** the final pipe
snapshot. Follow the final pipe snapshot with held/named metadata, owned-handle
identity, PIDFD liveness, active namespace/context and BOOTTIME closing checks.
Do not introduce another blocking proc sample after that final pipe snapshot.
Reuse the already acquired PIDFD bytes where appropriate; preserve their actual
observation and the existing bounded evidence inventory.

Add a focused subcase that changes reader FD3 flags during the closing PIDFD
fdinfo read after the owning wrapper returns. Assert that the later final pipe
sample detects it, the candidate reader is quarantined, the lifetime ends and
no second owning call/notice or foreign descriptor close occurs. Existing fixture
and source hashes must be resubmitted after this change.

This is a finite ordering correction under the published point-sample ceiling.
It does not require recursive proc resampling or assert an atomic snapshot or
continuous custody. There is no new schema, path or shared-file release. RUN may
revise only its transport module, test and `READER_TRANSPORT_HANDOFF.md`.

After revised stable hashes/full closure and Root delta review, Root will publish
the first `native-run-reader-transport` schedule. **It is not registered or
scheduled by this checkpoint.** No unchanged retry is at issue: none of these
transport candidates has been executed. Preserve all previous evidence.

Completed: renewed source/closure review, cleanup correction accepted.
Released assignment: RUN's final ordering fix and matching focused case only.
Blocker: revised source review before first transport execution. Admission's
scheduled result/delivery, connected reader/refresh/broker providers, Workloads'
destructive design and operator-created DNS capacity remain pending separately.

1. Complete providers/consumers with selected validation and signed integration.
2. Wire HTTP/DNS/destructive, all admission/RUN paths, real a100, cancellation,
   full timing and four actual paired tasks.
3. Close the same 48-entry inventory and publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs;
   independently replay, evaluate the existing gate and verify approved cleanup.
