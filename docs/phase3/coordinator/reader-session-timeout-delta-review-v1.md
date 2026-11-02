# Writer timeout fixture diagnosis and changed-input schedule

Base: signed and remote-matched `1e4bf41a3dc00b889390835f472a8b82c421a66e`.
This containing published signed checkpoint schedules only the changed writer
fixture closure. It does not change production source or repeat the session.

## Actual first result retained

The one scheduled `native-reader-checkpoint-loop-session` execution ran 59
methods in 0.985 seconds: 57 ok and two writer assertion failures. Its aggregate
status is **FAIL**, child exit 1, pipeline exit 2, pre/post fingerprint equal:
`sha256:0e4c30d84cc8e12c9a7c5e708ecc611e7b2f598216a4989bf0d4e1a0e99b9ed5`.
Never relabel this result PASS.

Actual files remain in this worktree's original `.aragorn/phase3-pipeline/`
`native-reader-checkpoint-loop-session/0e4c30d84cc8e12c9a7c5e708ecc611e7b2f598216a4989bf0d4e1a0e99b9ed5/`:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| result.json | 820 | `4bc0510954e87277e977100b7353c175a285b4c5fa4a47175cd595ed85a9dc08` |
| stderr.log | 13200 | `dd3bac8455733ff873d0d1bf62cc22dab69c72b11e5d0a06e1f8a3b829a118a8` |
| stdout.log | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Every one of the 28 session methods actually reported ok, including the real
listener/response/store/checkpoint/independent-replay composition. Their complete
18-file behavioral closure and relevant environment are unchanged. Root reuses
these actual method results, not a nonexistent successful aggregate fingerprint.
There is no reason to rerun the session or any historical suite.

## Diagnosed changed input

`test_incomplete_tail_never_becomes_checkpoint` observed empty batch bytes;
`test_post_ack_close_wait_uses_outer_deadline_and_never_resets` observed no ACK.
Static review of the actual source explains both: the fake `Poll.poll` advanced
its entire timeout with `never_close` enabled even when a registered notice,
telemetry or socket descriptor was already ready. The first `_wait` therefore
expired before the intended test operation. The tail test additionally advanced
one millisecond per clock read before startup instead of its normal 100 ns.

Only the writer test changes from `de369a15a50897ab47003a24fb4b58b12056460473b55c5499d5ddd3b4074677`
to the pin below. Fake poll now filters registered readiness first and advances
elapsed timeout only for an empty ready set. The tail keeps the normal clock
step. Strengthened assertions require startup/actual challenge/tail read before
its original deadline, and no publication/ACK. The close-wait case requires
completion -> exactly one ACK -> empty poll timeout at the original minimum of
request, ACK-age and session deadlines, with only one millisecond rounding plus
1000 ns guard allowance. No production limit or assertion was relaxed.

Root and the independent reviewer approved the author's stable fixture delta.
All 19 other inputs of the original run match their published hashes. Because
the changed fake kernel is shared by 31 writer methods, all 31 belong to this
changed closure. There are no new imports, external/generated fixtures, dynamic
loads, private parsers or live OS routes. Its full project closure is:

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
a41035be551d418fb5cbfb1dbaf711cab8d1d5f612044e484187ffdac59765c7  src/aragorn/native_phase3_run_reader_checkpoint.py
28b6262f0bd18a8cb87899654d1092f3fabbfe57354609bc379f83c0f4d7d6f5  tests/test_native_phase3_run_reader_checkpoint.py
```

## Only newly necessary selected execution

The existing 119 registry entries remain unchanged. Add
`native-reader-checkpoint-writer-timeout-delta`, the one writer test module,
the three inputs above, needs=[], timeout 120 seconds. Only after publication:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py status native-reader-checkpoint-writer-timeout-delta
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-reader-checkpoint-writer-timeout-delta
```

Run in `/Users/yousi/Documents/Commits/aragorn`. Inspect status/actual result,
reuse a matching successful fingerprint or execute once. Preserve every result.
No unchanged retry; another failure needs diagnosis and a reviewed changed input
before renewed scheduling. Do not rerun the original combined stage. The
unchanged 28 session results remain method evidence under its retained FAIL;
no successful 59-method aggregate or qualification claim may be invented.

After reviewed writer PASS plus review of unchanged session results, integrate
the four v8 source/test paths and exact handoff/coordinator records in one signed
checkpoint, verify, push normally and verify remote tip. Production remains
unqualified: actual launch/bridge/IPC/source custody, complete loss, policy and
workload paths are still required. No operational hold changes.

Completed: actual first result preserved; fixture cause and exact delta reviewed.
Assignments: Root writer-only changed-closure validation/IPC provisioning;
Admission replay delivery; existing RUN DNS provider; Workloads destructive/a100
design. External newer handoff acknowledgment remains unconfirmed. No extra tree.

1. Complete ready providers/consumers with selected validation and signed integration.
2. Wire HTTP/DNS/destructive, all admission/RUN, real a100, cancellation, full
   timing and four actual paired tasks.
3. Close all 48 existing path/consumer/source-custody conditions and freeze.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment, independently replay, evaluate the existing gate and verify
   approved cleanup.
