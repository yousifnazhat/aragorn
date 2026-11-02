# Broker protocol/journal source review and selected stage

Implementation contract: `broker-reader-provider-contract-v1.md`, released in
verified signed/published `8ce7c8aa858f7b7b24e24bd8543e7ef7ce4406b5`.
Root owns the two modules, two tests and coordinator handoff. Admission's
independent transcript consumer remains a separate released assignment.

Root read both complete modules and both complete test modules, checked actual
AST imports and dependency reads, and obtained an independent journal source
review. Five pre-execution findings were closed: root-owned ancestry, one-shot
owned-descriptor cleanup without closing a substituted foreign handle, custody
checks after retained/boot reads, BOOTTIME/MONOTONIC/BOOTTIME deadline sampling,
and receipt freshness tied to the exact persisted CHECKED timestamp. Attempted
intent publication explicitly retains effect ambiguity even when a later check
prevents recording a completed event in memory.

Stable SHA-256 inputs for the exact eight-file closure:

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
8d17e7930d2c560ade4b5c0fb5b539e00ecbfb3fb9f40d910d271dd42eb48007  src/aragorn/native_phase3_broker_reader_protocol.py
b80fc8b0d0d51d430d35eaf665f2535d1418a1c085a9f975b99f67c351edc51b  src/aragorn/runtime_http_run_submission.py
94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21  src/aragorn/runtime_action_broker.py
3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d  src/aragorn/runtime_action_decision.py
0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b  src/aragorn/oci_worker_protocol.py
8d9036337eef30bfc71a79f9d9d71f392483cd0e9ce34f881bfe2a4762463878  tests/test_native_phase3_broker_reader_protocol.py
a8abbb484500c147b58ed69b6cd9dac2f7e3765db6fa882b0e898b06ae5c07a8  tests/test_runtime_http_run_submission.py
```

All remaining imports are standard library. No generated materialization,
external fixtures, historical TestCases, source loading or application operations
are part of these tests. The pipeline additionally pins its runner, worker lock,
interpreter/toolchain and selected environment. Mutable handoffs and reports are
not behavioral inputs. All prior 114 registry entries remain exactly unchanged.

The 10 protocol methods cover canonical bytes, exact fields/scalars/phase/echoes,
bounds, false flags, artifact/base64/digest/retention joins and partial/unknown/
reset/increased loss observations. The 18 journal methods exercise the real
public lifecycle and guard logic with intercepted OS/proc/clock calls: durable
ordering, existing and partial residue, timing/custody races, lock ABI, phase-two
baseline/reader joins, ambiguity and cleanup. One method exercises the actual
bounded proc-reader helper over fabricated descriptors, including partial reads,
oversize, read errors and ambiguous close. Existing write_all is reused with its
unaffected source pin; its syscall effect is modeled by the in-memory filesystem.

Root schedules only this new stage in the coordinator worktree, after verifying
the containing signed published registry checkpoint and checking prior state:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-phase3-broker-reader-submission
```

Registry: exactly these two new test modules, `needs: []`, timeout 120 seconds.
Inspect an existing matching result before execution. Preserve every actual
result/fingerprint and logs; diagnose any failure before a documented changed
retry. Do not rerun any historical suite or unchanged staging/composition.

No actual kernel ABI, protected acquisition, IPC, deployment, timing feasibility,
independent transcript agreement or successful effect gate is established by
these mocked cases. Real providers and the future single-owner caller remain
gated. The reader-loop next-release source review records its concrete unresolved
stream/storage/loss/second-phase decisions separately.

Completed: stable source and closure review, exact focused stage registration.
Released: Root's single selected stage; prior RUN, Admission and Workloads
assignments continue. Pending: actual stage result, original DNS delivery,
independent transcript delivery and all real provider/wiring obligations.

1. Run only the selected stage, retain its actual evidence and sign/integrate
   passing source without repeating unaffected checks.
2. Complete the shared HTTP causal path and remaining admission/RUN/DNS/
   destructive and four paired-task paths, full timing and cancellation.
3. Close all 48 ledger entries and deployed identity custody before freezing.
4. Separately release the final same-deployment campaign, independent replay,
   gate evaluation and approved cleanup. Operational holds remain unchanged.
