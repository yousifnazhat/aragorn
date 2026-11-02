# DNS acquisition: pre-execution review and required corrections

Review base: signed published `b955947bea054a8e761241d9ae9a40b089a59fa3`.
RUN submitted its five assigned paths from c0. Root and three internal reviewers
read the implementation, independent consumer, contract, focused cases and
actual dependency closure. No source/test/import/compile or live execution was
performed for this review. No DNS stage is registered or scheduled.

RUN independently corrected two issues before execution: the initial snapshot
guard is now inside its closing clock bracket, and cancellation cleanup compares
the initially observed flags/link to distinguish a same-inode other pipe end.
The refreshed stable source reviewed here is:

```text
b6d7bde0a76230fca0648e4994b751ce089a2539a2c416f4eef72e1a132e9206  src/aragorn/native_phase3_dns_acquisition.py
fdc29ee997cf6c0bcb2a1c00fbf2a73a7909daeeb5aaef3f60729e24d37241c7  src/aragorn/native_phase3_dns_context.py
0f511bf234f9ef49ed6dcbfafdabeaf239dd5c069d9bc4fe6166c64ca32b9f1b  src/aragorn/native_phase3_dns_acquisition_verify.py
9d5c962929456bb8ec375b04aac26568845a556770f3ab925ed91bbf3f361d01  tests/test_native_phase3_dns_acquisition.py
```

The handoff's complete 14-file closure and all 34 methods match actual static
imports/hashes. It includes package initialization, public DNS builder, fixed
fixture helper and process/clock/broker transitives. No generated inputs, external
fixtures or historical TestCases are selected. The declared independent-consumer
source read is inventoried. Effectful OS/fixture boundaries are mocked. This
confirms the proposed stage scope, not source correctness or a test result.

## RUN corrections within the same five assigned paths

1. **Replay terminal ordering.** Verifier lines 449–457 count ERROR receives but
   do not require refusal/error evidence. A normal fabricated record with an
   ERROR/errno4 row, receive_errors=1 and errors=[] can pass. Require each fatal
   receive outcome to terminate subsequent receive/send activity, with a
   consistent failure/interruption code and non-normal state. Apply the same
   terminal rule to fatal flags/controls/peer refusal, readiness replay and failed
   readiness sends. Preserve the legitimate first successful response before a
   later receive failure. A partial/unknown counter never excuses later I/O.
2. **Known partial chronology.** Verifier line 416 checks after-snapshot ordering
   only for normal records; lines 444/499 bound calls only against BYTE/EOF
   cancellation. Join every available call/snapshot/cancellation timestamp,
   including READ_ERROR/IDENTITY_CHANGE, and reject impossible ordering unless
   the retained clock-failure evidence explicitly makes that comparison unknown.
   Do not invent absent timestamps. Do not impose normal after.started >=
   sample.finished on failures: the producer may stamp failure completion after
   its after snapshot. Check after.started against actual completed I/O instead.
3. **Cleanup consistency.** A claimed successful cancellation close requires
   available, matching actual before/after identities. Both may legitimately
   disagree with the requested identity during early refusal; an error-code
   escape cannot excuse closing a substituted object. When retained evidence
   establishes socket acquisition but socket_closed is false, require the
   corresponding SOCKET_CLOSE_FAILED observation. Preserve partial evidence.
4. **Actual socket flags and operation boundary.** Context line 178 uses
   gettimeout()==0 as its nonblocking assertion. Check actual F_GETFL/O_NONBLOCK
   and F_GETFD/CLOEXEC alongside the existing object/fileno/identity checks.
   Python timeout state alone describes the object's last configuration; the OS
   blocking mode is shared across endpoint descriptors. See the primary
   [Python socket documentation](https://docs.python.org/3.12/library/socket.html#notes-on-socket-timeouts).
   Derive the existing Boolean from actual observations without widening the
   schema. Require the exact held descriptor number as well as identity.
5. **Close the final cancellation/read/poll gaps.** Context lines 159–167 check
   cancellation before later namespace/socket observations, then lines 228–230
   read the pipe. Repeat the local pipe identity/flags/link guard immediately
   before read. An empty poll in check_cancel at 251–255 currently returns without
   a closing guard, allowing a late substitution before bind/recv/send. Recheck
   custody after polling and the relevant actual descriptor/flags immediately
   before each operation. In cleanup at 361–370, add a final identity readback
   after flags/link reads and before close. Preserve cancellation priority and
   refuse changed/unknown handles without closing or retrying them. These are
   bounded point checks, not an atomic no-race or hard syscall-return guarantee.
6. **Failed-detach lifetime.** Context lines 389–390 stores uncertain sockets only
   in a local owner reachable through the exception traceback. Keep a bounded
   process-local strong quarantine for the unresolved socket/owner until exit;
   discarding an exception must not enable destructor-close of a substituted FD.
   Poison subsequent socket acquisition after the first such uncertainty so the
   quarantine cannot grow. Preserve the existing cancellation-FD transfer/close
   rules on later refused calls and the exact public exception/record schema.
   No retry, detach loop, permission widening or recovery path is released.

Add focused fabricated-boundary regressions for each correction: normal ERROR
promotion; later I/O after each fatal kind; legitimate and contradictory partial
timestamps; contradictory successful close; kernel flags disagreeing with the
socket object; late mutation during namespace/readlink/empty-poll; and disposal
of the raised failure without destruction of a quarantined socket. Reuse the
existing helpers where sound. Submit refreshed exact hashes, complete closure
and actual method inventory before the first selected schedule. Do not execute
the proposed stage yet. Root never edits this active RUN worktree.

## Root-owned dependency repair

The shared `native_phase3_http_fixture.py` guard detects namespace/PIDFD change,
but its final loop at 162–164 closes remembered descriptor numbers unconditionally.
The DNS tests deliberately mock this helper and cannot establish its close
custody. RUN must not modify it. Root releases a separate narrow correction in
`provider-release-v10.md`; its source pin must be integrated and included in the
refreshed DNS dependency closure before DNS scheduling. No historical HTTP suite
or unchanged stage is authorized by that dependency change.

The incoming RUN owner acknowledged the initial verifier finding and agreed to
hold its stable source until this consolidated review. Outbound bridge has no
listener; no unchanged message retry occurred. Use this published correction
handoff; receipt of the complete review is separate from the earlier agreement.

Completed: complete source/closure review and concrete correction assignment.
Released: RUN fixes only its existing five paths; Root shared fixture repair.
Pending: corrected stable source, Root dependency integration and first focused
schedule. Admission v9 context assignment continues; Workloads destructive/a100
source contract remains pending. No extra worktree is needed.

1. Correct/review/integrate ready providers with only newly scheduled checks.
2. Wire full HTTP/DNS/destructive, admission/RUN, genuine a100, cancellation,
   full timing and four actual paired tasks.
3. Close all 48 path/consumer/source-custody conditions and publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. Operational holds remain unchanged.
