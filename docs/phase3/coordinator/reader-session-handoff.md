# Connected reader writer and Root checkpoint session handoff

Source release: verified published `2557e5e5601646385c1428e4d0d03aa35a8ae2d3`
(provider v8 and reader-session-contract-v1.md). Original schedule:
`1e4bf41a3dc00b889390835f472a8b82c421a66e`. Diagnosed fixture-only delta schedule:
`54a7071fcda4849870193e5f64efdba2fa10fa89`.
This handoff is integrated with the exact four released source/test paths in its
containing signed checkpoint; Root supplies the hash after normal push and
remote-tip verification. Both internal authors acknowledged the source contract.

## Implementation and connected calls

- `src/aragorn/native_phase3_run_reader_checkpoint.py`: restricted one-shot reader
  owns fixed telemetry/control/stderr/cancellation/completion pipes; bounded
  syntax-only raw NDJSON preservation; immutable batch/manifest/receipt ordering;
  original CHALLENGE/ACK socket lifetime and original-ACK REFRESH; fail-closed
  identity, framing, deadline, cancellation and ambiguous I/O handling.
- `src/aragorn/native_phase3_run_reader_checkpoint_session.py`: Root owns startup,
  real public ReaderListener and retained reader response/store, protected
  checkpoint acquisition, independent reader/checkpoint replay, received-completion
  chronology, original-ACK refresh and terminal local ownership.
- `tests/test_native_phase3_run_reader_checkpoint.py`: 31 new mocked writer methods.
- `tests/test_native_phase3_run_reader_checkpoint_session.py`: 28 new mocked session
  methods, including actual dependent public calls and both independent consumers.

Root and an independent reviewer examined the complete stable source, fixture and
20-file behavioral closure. The only change after first execution corrected the
writer's fake poll/clock model and strengthened two intended deadline assertions.
No production byte changed. Exact final closure:

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
28b6262f0bd18a8cb87899654d1092f3fabbfe57354609bc379f83c0f4d7d6f5  tests/test_native_phase3_run_reader_checkpoint.py
b3ed6fe27831dbe49b0b8ba11c8d4bde08c5ea2e529ee232691809d52a6c1b37  tests/test_native_phase3_run_reader_checkpoint_session.py
```

No external/generated fixtures, historical test imports or dynamic project loads.
All actual OS boundaries are replaced by in-memory primitives during tests;
public production calls and independent consumers stay real. Runner, selected
registry metadata, toolchain/environment and checkout path are separately bound
by the pipeline fingerprint. The original input pins and failure diagnosis are
in reader-session-review-and-scheduling-v1.md and
reader-session-timeout-delta-review-v1.md.

## Actual retained evidence, without a fabricated aggregate PASS

First selected `native-reader-checkpoint-loop-session`: **FAIL**, 59 methods,
57 ok and two writer test-fixture assertion failures. All 28 session methods
reported ok. Pre/post fingerprint is
`sha256:0e4c30d84cc8e12c9a7c5e708ecc611e7b2f598216a4989bf0d4e1a0e99b9ed5`.
The failure remains intact, including child exit 1 and pipeline exit 2.

After diagnosis, stable changed-fixture review and signed renewed scheduling,
only `native-reader-checkpoint-writer-timeout-delta` ran. It returned **PASS**, all
31 writer methods, child/pipeline exit 0. Pre/post fingerprint is
`sha256:d12e062c205649df1c382c07296637e9167944092d02bec2f961172eac0dba6c`.
The unchanged 28 session method results are reused from the first actual log;
there is no successful combined 59-method aggregate and none is claimed.
All 18 session behavioral inputs and the relevant environment match the first run.
Root verified actual result/log lengths, hashes, counts and final source pins.

Evidence stays in `/Users/yousi/Documents/Commits/aragorn/.aragorn/phase3-pipeline/`,
under the exact stage/fingerprint directories above; no cache copying occurred.

| Run | Artifact | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Initial FAIL | result.json | 820 | `4bc0510954e87277e977100b7353c175a285b4c5fa4a47175cd595ed85a9dc08` |
| Initial FAIL | stderr.log | 13200 | `dd3bac8455733ff873d0d1bf62cc22dab69c72b11e5d0a06e1f8a3b829a118a8` |
| Writer PASS | result.json | 827 | `39102fa9cb636e4c065a3d7c1c81adf7a2346f7c16001d023e5a4a6999f31b79` |
| Writer PASS | stderr.log | 5877 | `f12aa12d2b94e278abd15cf23630a7815f26c3761fd1c16bf966b7b05a168d05` |
| Both | stdout.log (each) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The earlier transport 30, checkpoint 53, broker 28, DNS 13 and HTTP credential/
composition results remain untouched. No historical suite, unchanged retry,
private retention, live operation or cleanup was performed. Existing signed lane
commits remain ancestors; these two internal Root owners did not modify any lane.

## Requirement contribution and exact remaining conditions

This closes the bounded v8 implementation assignment: actual reader-loop source
and Root checkpoint/refresh wiring through the existing owning listener/retention/
independent-consumer interfaces. It adds a partial RUN-02/shared reader path and
retention contribution. No whole 48-ledger requirement becomes qualified.
The writer's syntax claim is not independently re-established by the framing-only
checkpoint verifier. Remote custody remains point-sampled, and supplied installed
source/stream/access pins do not authenticate their own acquisition. The fabricated
opaque loss fixture exercises wire joins only. Five session authority flags remain
false; frozen transport/evidence flag inventories are preserved unchanged.

Actual deployment/caller closure is absent. The fixed launcher must establish
protected raw inputs, independent pins, accounts, pipes, actual source/namespace
identities, cancellation and child lifetime. The bridge must set required stdout/
stderr CLOEXEC after exec; unmodified tetra compatibility is unestablished.
Source-to-loaded inventories, authenticated sensor stream and complete loss/
program/map evidence remain open. Missing observations stay UNKNOWN and the
future service must REFUSE/LOSS_UNAVAILABLE, never emit synthetic positive health.
A failed socket detach retains local owner/error references until process exit;
no cross-process object custody or prompt cancellation of blocked syscalls is claimed.
Root still owns IPC, broker lock/measurement/submission wiring and deployment.

Assignments: Admission returns its separately scheduled replay result/signed
commit; RUN implements only v7's five DNS paths; Workloads develops its released
destructive/a100 design; Root resolves concrete bootstrap/cancellation FD transfer,
generated HTTP94 successor inputs and deployment compatibility before source
releasing the future IPC service/client/materializer. No new worktree is needed
for the ready DNS split. New external handoff receipt remains unconfirmed.

1. Integrate ready providers/consumers with only newly necessary focused checks.
2. Wire full HTTP, DNS/destructive, admission/RUN, real a100, cancellation, full
   timing and four actual paired tasks.
3. Close all 48 existing path/consumer/source-custody entries and publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment, independently replay, evaluate the existing gate and verify
   approved cleanup. Phase 3 remains unfinished.
