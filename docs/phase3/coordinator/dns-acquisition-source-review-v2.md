# DNS acquisition: corrected-source review v2

Review base: published signed `722c4794c349acc022dd6a751344408af82f454e`.
RUN acknowledged the complete first review and actual helper pin, fast-forwarded
its own existing branch preserving drafts, and submitted the corrected five-path
slice. Root and three independent internal reviewers inspected source and cases
without importing, compiling, executing or changing the lane. The actual 14-file
closure and 42 focused methods match the handoff. No DNS stage is registered or
scheduled; no failed or successful DNS run is being reported.

Exact submitted behavioral snapshot:

```text
feac70e9b5616c8f269bbc531212183688ca37a077c65ddf961f2cf718ce1c6d  src/aragorn/native_phase3_dns_acquisition.py
f2a5a128b79b0ec8d60b06a66d195bc104fa1efb700487bb2e356056cc99e83c  src/aragorn/native_phase3_dns_context.py
fd9259e83932b63838b0741f0e12e85bab8153615f1ee8c7a3dd77d9f891f199  src/aragorn/native_phase3_dns_acquisition_verify.py
77fb920ed78a5253aa7d2662470b6c11d43fdcbb1bc369d432f15f7cf8e0b775  tests/test_native_phase3_dns_acquisition.py
```

The full closure remains the handoff's 14 actual inputs, including integrated
fixture helper sha256:caa7ec1bf5ff1f768fe626009fdf208472f169abca539c5374ccf69b0f144f93.
No historical TestCases, generated inputs or external fixtures are selected.
The sole source read is the inventoried verifier.__file__ independence check.
GC touches fabricated objects; all native OS/socket/proc/clock/fixture calls are
mocked. The shared fixture is deliberately mocked and retains its separate Root
evidence; no cache copy or rerun is needed.

## Corrections already established by source review

The original ERROR promotion, fatal received flags/controls/peer/replay ordering,
failed-send later-I/O rule, matching actual cancellation-close identities and
acquired-but-unclosed socket failure-code checks are implemented. The source
contains a single strong quarantined owner, poisoned later socket acquisition
and an exclusive active-owner latch. A later fresh transferred cancellation FD
is consumed without creating another socket. These are source findings only.

## Remaining corrections within the same five paths

1. **An unresponded first readiness query is terminal.** Verifier lines 545–546
   accept a valid query with readiness_response=null and later receives whenever
   any error is present. Producer lines 343–346 immediately attempts that query's
   response; a guard, cancellation or deadline failure before creating the send
   row terminates the operation. Require this first unresponded query to be the
   final receive. Preserve a legitimate terminal failure without a send attempt.
   Regression: remove the response from a valid query fixture, append an ordinary
   receive, adjust its counter and use REFUSED/FINAL_GUARD_FAILED; reject it while
   accepting the corresponding final-query partial.

2. **Join every available partial boundary.** Verifier lines 414–465 do not order
   sample.started_ns against after.read_started_ns when there are no receives.
   A refused empty sample cannot start at 20 after its after snapshot [11,12].
   Also compare each available call end, or its start when the end is unavailable,
   against available sample completion for both receive and send rows. A missing
   endpoint or CLOCK_CHANGED code cannot erase contradictory known marks.
   Preserve legitimate failure sample completion after the after snapshot; do not
   impose the normal finish-before-after rule on all failure paths.

3. **Replay actual recoverable resource-exhaustion partials.** A MemoryError from
   actual sendto leaves an attempted response row and EVIDENCE_LIMIT, but verifier
   line 541 permits only READINESS_SEND_FAILED/INTERRUPTED/CLOCK_CHANGED. Likewise
   cancellation os.read MemoryError can retain READ_ERROR with EVIDENCE_LIMIT,
   while verifier's READ_ERROR rule permits only CANCEL_READ_FAILED/INTERRUPTED.
   Support these actual producer paths without making unrelated malformed rows
   acceptable. Add fabricated sendto and cancellation-read exhaustion cases that
   preserve the same original exception, independently replay available partial
   bytes, retain cleanup findings and confirm no retry or later I/O. Unrecoverable
   exhaustion still promises no recoverable record.

4. **Original owner custody applies to cleanup.** Context cleanup lines 390–421
   closes descriptor numbers without original PID/native-thread/account checks,
   even after an owner-change refusal. Pin the actual entry owner before further
   fallible resource metadata; check it before detach/close and after external
   metadata/flag/link work. With unchanged entry custody, invalid-request/early
   refusal still closes the known-safe transferred cancellation FD. Changed or
   unknown owner context must skip numeric closes, retain fixed per-resource
   cleanup failures and keep any still-owning unresolved socket strongly retained
   through the existing bounded quarantine. Continue only independently safe
   cleanup; do not recover, retry detach or close a foreign owner’s handle.
   Add fabricated owner changes during sampling and terminal cleanup, including
   a change during a close-time external read, and verify skipped closes/retention.
   This clarifies the existing original-owner contract without adding an API or
   permission widening. Passing a handle already owned by an active/quarantined
   caller violates exclusive transfer; no new alias-recovery contract is released.

5. **Final cancellation flags must follow link reads.** Context lines 96–113 and
   410–419 read status/descriptor flags before readlink, then recheck only fstat.
   A same-inode pipe-end or blocking/CLOEXEC change during link readback escapes
   that metadata comparison. Recheck the actual flags after link acquisition,
   then final held identity before read/close. Add a late fabricated same-inode
   flag/end mutation; verify no read or close of the changed handle. Keep these
   finite point observations at their existing non-atomic ceiling.

6. **The call timestamp/deadline check follows the operation guard.** Producer
   lines 284–296 and 352–362 stamp/check the deadline before operation_guard,
   which performs fallible proc/metadata reads. If it consumes the remaining
   budget, the syscall still executes using stale time. Complete that guard,
   then sample the actual call-start/deadline boundary before recvmsg/sendto.
   Use the same original deadline; never renew its budget. Add a fabricated guard
   that consumes the remaining time and verify no receive/send occurs. Preserve
   the established receive-deadline and readiness-send-failure terminal schemas.

7. **Make the new regression premises independent.** In the GC test at line 1068,
   Mock.detach.side_effect retains the raised OSError and its traceback, which
   independently retains the owner. A function raising a fresh unretained error,
   or explicit clearing of that exception root before GC, is necessary to prove
   strong quarantine survival after caller-error disposal. In the failed-send
   terminal regression around lines 925–935, the later row repeats the readiness
   query and can fail via the older replay rule; use an ordinary datagram with
   consistent length, or a valid WOULD_BLOCK row, to isolate the terminal rule.

Do not execute the proposed stage yet. RUN corrects only its five existing v7
paths and resubmits stable hashes, the full actual closure and focused cases.
No shared helper, existing DNS builder/verifier, transport, broker, launcher or
registry edits. Root retains registry/scheduling and the actual connected caller.
Do not rerun any existing successful slice. No new schema or framework is needed.

## Current coordination and next work

All three owners have directly acknowledged signature verification, own-branch
fast-forward to 722c479 and their exact assignments, preserving drafts. Admission
is implementing its v9 context leaf. RUN owns these corrections. Workloads is
available with its completed destructive/a100 review; Root must resolve its four
published concrete decisions and release exact source paths promptly. Root's
bootstrap/launch/HTTP caller wiring remains the shared critical path. No extra
worktree is needed for these ready scopes; outbound bridge is not retried unchanged.

Completed: corrected-source/14-input/42-case review; useful original fixes retained.
Released: only bounded corrections within RUN's existing five paths. Blockers:
remaining source/case defects, first DNS schedule, actual provider/IPC/launch and
Workloads source release. All qualification positions and operational holds remain.

1. Correct/review/integrate ready providers with only newly scheduled checks.
2. Wire HTTP/DNS/destructive, all admission/RUN, real a100, cancellation, full timing
   and four actual paired tasks.
3. Close the same 48 path/consumer/source-custody conditions and freeze implementation.
4. Separately release same-deployment 31 cases/100 actions/100 pairs, independent
   replay, existing gate evaluation and approved cleanup.
