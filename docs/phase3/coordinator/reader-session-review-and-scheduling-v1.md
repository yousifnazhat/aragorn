# Connected reader writer/session: stable review and selected schedule

Released source base: signed and remote-matched
`2557e5e5601646385c1428e4d0d03aa35a8ae2d3`, provider release v8 and
reader-session-contract-v1.md. This document schedules execution only when its
containing signed checkpoint is published. The four implementation/test drafts
remain in the coordinator worktree until reviewed PASS and signed integration.

Root and the independent reviewer reviewed the stable implementations, both
in-memory syscall harnesses and complete actual imports. The two authors froze
these bytes before scheduling. There are no remaining concrete review blockers
for this offline stage. The actual 20-file repository behavioral closure is:

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
8d17e7930d2c560ade4b5c0fb5b539e00ecbfb3fb9f40d910d271dd42eb48007  src/aragorn/native_phase3_broker_reader_protocol.py
600d5da48f4a5b4702245936972c796162ca01b37c74f0ac46ea6c619ed82a7b  src/aragorn/native_phase3_clock_domain.py
80afdbcab0a4a076712b65db22b091b0a1276ae952ee276a76c1b83ffe06652e  src/aragorn/native_phase3_run_acquisition.py
66cce03e029441d01bd7de72f67da0bd927259a292be28e3e5555a0b0a353fe1  src/aragorn/native_phase3_run_reader_acquisition.py
a41035be551d418fb5cbfb1dbaf711cab8d1d5f612044e484187ffdac59765c7  src/aragorn/native_phase3_run_reader_checkpoint.py
0fe4a8a8a1bf86839fa4a7fa1bd6ecb8b5fd56e5e3ff9a1f1ad50f8ed5889d22  src/aragorn/native_phase3_run_reader_checkpoint_acquisition.py
dcf897c9f2b501e1c29287051812fa8969e2b7522da518270d62bb2bafdc442a  src/aragorn/native_phase3_run_reader_checkpoint_session.py
460d25fbc8eb8cd53d2fedf7802313d7f157c22b122c0151e92e42cbd3a92cb4  src/aragorn/native_phase3_run_reader_checkpoint_verify.py
ee6eba09de97df0c1b2f9eeeb74e22849e56d7c876a11daf211e1d626d7abbf0  src/aragorn/native_phase3_run_reader_evidence_verify.py
769cdf49fc380f97048ebe01ca2227b71584b19e8715c76ca2629dee3037d51b  src/aragorn/native_phase3_run_reader_response.py
24dbd8cdba584a55e7a787952dfa5a12d96c8b040973537c569dd52f582aba98  src/aragorn/native_phase3_run_reader_store.py
609a5a32c33a4bb5ae0dec45eb6637b9d5b853e00797308244a92b1e86aa5fe0  src/aragorn/native_phase3_run_reader_transport.py
0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b  src/aragorn/oci_worker_protocol.py
94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21  src/aragorn/runtime_action_broker.py
3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d  src/aragorn/runtime_action_decision.py
288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90  src/aragorn/runtime_action_observation_publisher.py
a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68  src/aragorn/runtime_process_profile.py
de369a15a50897ab47003a24fb4b58b12056460473b55c5499d5ddd3b4074677  tests/test_native_phase3_run_reader_checkpoint.py
b3ed6fe27831dbe49b0b8ba11c8d4bde08c5ea2e529ee232691809d52a6c1b37  tests/test_native_phase3_run_reader_checkpoint_session.py
```

The 18 production files include the inert package initializer and unchanged
listener, response/store, protected checkpoint acquisition, wire codec and both
independent consumers. The only test modules selected are the two new files
above: 31 writer methods and 28 session methods, 59 total. All other imports are
standard library. There are no historical test imports, external fixture files,
generated inputs or dynamic project imports. The pipeline separately binds its
runner/lock, selected registry metadata, actual interpreter/toolchain/environment
and absolute coordinator path. Documentation is not a behavioral input.

## Concrete review and focused coverage

The writer runs its real public one-shot loop against fabricated pipe/proc/
PIDFD/socket/file/poll/clock primitives. Cases cover idle post-trigger EAGAIN,
all valid JSON-object variants, bounded data/tails/read counts, immutable batch ->
manifest -> receipt fsync/readback/close -> completion -> original ACK ordering,
ACK socket lifetime/queued refresh, original-ACK refresh chaining, cancellation,
malformed controls, partial publication, ambiguous send/close and actual error
observations. No real telemetry, socket, protected directory or process runs.

The session composition cases run the real ReaderListener, owning response and
ReaderStore, checkpoint acquisition, reader evidence verifier and checkpoint
verifier. Their OS boundaries are replaced by strict local syscall objects;
no positive public acquisition/verifier is replaced by a truth callback.
Independently authored peer bytes exercise CHALLENGE and original-ACK REFRESH,
completion receipt chronology, retained artifacts/chain, later admissions,
startup/framing, stale/replayed inputs, cancellation, mutation, failed archive,
short/interrupted writes and terminal cleanup. Deliberate corruptions call the
real independent verifier, preserving its rejection. The fabricated opaque loss
record exercises only frozen wire/session joins; it is not semantic loss proof.

Accepted pre-execution repairs include input bounds before hashing, actual PIDFD
association before conditional close, immediate pipe custody/nonblocking checks
after the final poll/proc reads, sealed named/held file identities at publication
close, per-attempt observation reset and foreign-thread/fork refusal without
closing the original owner's handles. The regressions target these ordering and
custody seams. Uncertain socket detach keeps the local owner/exception alive;
remote process observations remain point samples, never atomic continuity proof.

The strict bridge stdout/stderr CLOEXEC requirement is preserved. A reviewed
post-exec bridge change must establish it before startup readiness; compatibility
of the current unmodified tetra bridge is not claimed. Source/identity provisioning,
actual launch/IPC, complete loss/sensor/program/map acquisition and installed
custody remain separate obligations. Every authority/qualification flag stays
false; this stage cannot establish native health, full timing, effect permission,
RUN readiness or Phase 3 qualification. Missing real loss still requires the
future service to return REFUSED/LOSS_UNAVAILABLE.

## Exact first execution

Root registers only `native-reader-checkpoint-loop-session`, needs=[], timeout
120 seconds, with exactly the 20 inputs above and two new test modules. The
existing 118 registry entries remain unchanged. Run only in
`/Users/yousi/Documents/Commits/aragorn`:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py status native-reader-checkpoint-loop-session
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-reader-checkpoint-loop-session
```

Inspect the selected status and any actual existing result first. Reuse a matching
successful fingerprint; otherwise execute once. Preserve actual fingerprints,
result and logs even on failure. Diagnose before any retry, review the changed
input/environment and publish a renewed schedule. No unchanged retry, historical
suite, cache copy, live operation, private retention or cleanup is authorized.
Reuse the unchanged transport 30, checkpoint 53, broker 28, DNS 13 and HTTP checks.

After reviewed PASS, Root stages exactly the four released source/test paths,
reader-session-handoff.md and reviewed coordinator ledger/checkpoint records.
Sign/verify the checkpoint, push normally and verify the remote tip. Preserve
original signed lane ancestry and every draft. Lane owners fast-forward only
their own worktrees to the supplied exact published hash.

Completed: stable source and full closure review; one new selected schedule.
Assignments: Root selected writer/session validation and concrete IPC/launch work;
Admission's separately scheduled replay delivery; RUN's five DNS provider paths;
Workloads' destructive/a100 design. Newer external receipt/agreement remains
unconfirmed; use copyable handoffs. No additional worktree is requested.
Blockers: actual stage result, launcher/bridge/IPC/source custody and complete
loss acquisition, remaining protected policy and workload paths.

1. Implement/integrate ready providers and consumers with only selected checks.
2. Wire full HTTP, DNS/destructive, all admission/RUN paths, real a100,
   cancellation, full timing and four actual paired tasks.
3. Close the existing 48-entry path/consumer/source-custody ledger; publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment, independently replay, evaluate the existing gate and verify
   approved cleanup.
