# Root service: stable source review and first focused schedule

## First selected schedule, 29 October 2026

The user authorizes only the first 44-check service stage, signed delivery and
push to PR #1. Verified signed base:
`bdf3ec818fed339831c3d807ee2ad20dcfa2ef3e`. Original signed Admission context
`018959a4fd47205d3b467cfc99794fd649671fb7` is an integrated ancestor, with the
actual Root source pin
`53aedfa46cd67c5febcd4f5aef3ff54d41f1227cd4a5d780b42cea2fb37e9493`.
The dependency-absent statements in the historical review below are superseded.

Root and an independent read-only reviewer refreshed all 23 input hashes against
the approved handoff: unchanged service/test pins below, plus 21 tracked inputs
whose actual bytes match this verified base and the handoff inventory. Source
still contains exactly 44 new methods. No new closure, platform or native-boundary
blocker was found. No source or test edit is needed before first execution.

Registry row `native-broker-reader-service` selects only
`test_native_phase3_broker_reader_service`, with the complete 23 explicit inputs,
`needs: []` and a 120-second timeout. All preceding 126 rows are unchanged; no
historical dependency stage is selected. Runner pin remains
`46163b06a07679d157d1d37b23a8b627ea52fce1e37808753937ebbfd6edee58` and worker
lock pin `945fd7620689d38962297a61f5e888f3156b90780e7ea8d3bf62a1459d75d0f4`.

After this schedule is signed and published, Root inspects the owning checkout:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py status native-broker-reader-service
```

Reuse an exact existing PASS. Only if NEW, execute once:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-broker-reader-service
```

Retain the actual outcome, logs and matching pre/post closure. Never retry an
unchanged failure. After reviewed PASS, sign only the three assigned service
paths; retain the original signed integration ancestry. No other stages, live
operations, native service activation or qualification are authorized by this
schedule. Explicit context/session unit mocks do not establish actual native
composition. All false flags and operational/cleanup holds remain unchanged.

## Reviewed fixture correction after the first run, 29 October

Published first schedule: signed `2c6487d5f5e137e372b60f37f40344de004afc92`.
The first owning run retained FAIL, exit 1, with 43 passing methods and one
failure at matching pre/post fingerprint
`sha256:1a49e077a561c7c630b742bf3a06f616aaa8cefc31ed4b8f63a0b79984da9b44`.
The unchanged failed fingerprint must never rerun. Original result/logs remain
in its owning `.aragorn/phase3-pipeline/native-broker-reader-service/` directory;
result.json is 810 bytes, SHA-256
`c3e8de3bf16f1f9b7155c0c4aaeb125d256a015c09546789e31099045f5d75e5`.

The actual failed method is
`test_confirmed_close_is_retired_before_snapshot_clock_failure`. Static diagnosis
and independent review found that the shared `Native.read` model identifies
cancellation by numeric fd15 alone. After that pipe is closed and fd15 is reused
for supervisor fdinfo, the model incorrectly raises BlockingIOError instead of
reading the new proc-file generation. Production correctly retires the old
generation before the snapshot failure; no production change is justified.

The minimal correction resolves the current row after `read_hook` and applies
cancellation only when fd15 still has kind `pipe`. Every original test assertion
and all 44 methods are unchanged. The corrected shared test fixture is 45761
bytes, SHA-256
`474fd55ec3914de29ea11d0da3eb041a63549eed52544abe614f49f8dbec589f`.
All other 22 registered inputs, the runner and worker lock are unchanged.

Root and independent review approve only this changed-input execution of the
same 44-method stage: its common native-read model is used throughout the module.
No other stage, dependency test, runner extension or fixture bypass is needed.
After signing/publishing this correction, inspect status, require NEW and run
the same selected command once. Preserve both results separately; do not relabel
the original FAIL as PASS or erase its records. This is a diagnosed shared-fixture
repair, not an unchanged retry or final qualification.

## Historical pre-execution source review

Source release v13: verified published d7ebe099cc692eff476338668e5edd27a0af76cd.
Root and independent reviewers read the full production service and all44 new
methods, including eight late-armed custody corrections. Frozen before/after:

| Assigned path | Bytes | SHA-256 |
| --- | --- | --- |
| src/aragorn/native_phase3_broker_reader_service.py |63952|99b61fa1a258464a64017d4dad6231d9bd5f7cd87ff03c2e85f490a58ee048ed|
| tests/test_native_phase3_broker_reader_service.py |45656|98d2159b9a6212b635164a90763ff1da076295ec9b9bf0b705abffc1c93e49a6|
| docs/phase3/coordinator/broker-reader-service-handoff.md |9955|2fd07d49ff5fa854da4c8dff4bd4e9e9b6184af13e0bf0e17f233d961c7dbc1b|

No remaining concrete source blocker was found on these bytes. The accepted
socket is registered before a fallible acceptance clock; malformed arguments
cannot prevent ownership of later valid transfers; merged PIDFD roles preserve
unknown association; confirmed closed generations retire before fallible
bookkeeping; actual EOF controls/flags remain retained; all kernel-installed
ancillary integers, including0..2, are registered before metadata; and an observed
PIDFD link makes association UNKNOWN before a later guard can fail. Tests reach
those exact seams and assert no foreign read/close, correct numeric reuse and
strong unresolved ownership. No retry, reset, unlink or account widening exists.

## Complete actual closure and execution condition

The static closure is23 unique project paths:22 production paths including the
initializer, plus the new test. Source/test pins and all actual existing Root
dependencies match the handoff inventory. All other imports are standard library;
fixtures are authored inline with module-local Linux primitives, including symbols
absent on Darwin. No historical test, generated source or external fixture is
implicitly imported. The real public codec is exercised; public context/session
boundaries are explicitly mocked. This candidate's eventual unit result cannot
prove native leaf composition, installed source custody, health or qualification.

The actual Admission context source is still absent Root. Read-only lane bytes
match the reviewed53aedfa46cd67c5febcd4f5aef3ff54d41f1227cd4a5d780b42cea2fb37e9493
candidate; this is not an integrated original signed dependency. Root must review
the actual scheduled67-method result and handoff, verify its original signature,
merge its ancestry and pin the actual resulting Root bytes before service
scheduling. If those bytes differ, review the actual changed closure first.
No context source or cache is copied between worktrees.

There is no service registry row, selected execution or actual result/PASS yet.
Keep these three untested source/test/handoff drafts uncommitted until the required
closure is complete, a first selected stage is published, its actual result is
reviewed and passes. Do not substitute an import shim or fabricated aggregate.
Root can continue independent client/renderer/launch implementation meanwhile.

## Completed, assignments and remaining steps

Completed: actual service implementation and stable source/test/closure review.
Pending: original signed context delivery, complete owning execution closure and
first necessary focused stage. Admission owns context67 delivery; RUN owns its
four published bootstrap corrections; Workloads owns its four published lineage
corrections. Newer exact checkpoint acknowledgments remain separately pending.
Root retains actual protected launch/configuration/FD origins, HTTP caller and
HTTP94 successor inventories, full loss/program/map and lifecycle acquisition,
destructive observation and actual paired contexts. Missing loss stays UNKNOWN
and REFUSED/LOSS_UNAVAILABLE; existing accounts and root-only protections remain.

1. Implement/integrate released providers with only necessary new focused checks.
2. Wire full HTTP, DNS/destructive, all admission/RUN paths, genuine a100,
   cancellation, full timing and four actual paired tasks.
3. Close the existing48-entry path/consumer/source-custody inventory and freeze.
4. After separate operational release, collect31 cases,100 actions and100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. All operational/private-retention/cleanup holds remain.
