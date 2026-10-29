# Protected checkpoint acquisition: review and selected stage

Released source base: verified published `25ac9a8503d7ed6f66377ad6561149cea77588d7`,
provider release v6 and reader-checkpoint-contract-v1.md. This containing signed
checkpoint publishes the final contract clarifications and registers/schedules
exactly one new offline stage in the coordinator worktree.

Root reviewed both complete implementations, the actual import closure and the
focused case inventories. Separate agents reviewed the producer's safety and
ownership, independently authored consumer/fixtures, and both test files' fake
kernel seams. No concrete blocking defect remains at these stable hashes:

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
0fe4a8a8a1bf86839fa4a7fa1bd6ecb8b5fd56e5e3ff9a1f1ad50f8ed5889d22  src/aragorn/native_phase3_run_reader_checkpoint_acquisition.py
460d25fbc8eb8cd53d2fedf7802313d7f157c22b122c0151e92e42cbd3a92cb4  src/aragorn/native_phase3_run_reader_checkpoint_verify.py
d1934fb8edb540518a776228c693b1fea431eff0a8577d0ec3b328e2069297e7  tests/test_native_phase3_run_reader_checkpoint_acquisition.py
6db8d5bb03c37eca919cf3dc80d54662b83b8a575f12a69f368cc9fd177f66f9  tests/test_native_phase3_run_reader_checkpoint_verify.py
```

These five files are the complete repository behavioral closure. All other
imports are standard library; the initializer is inert. The consumer never
imports the producer or its private parsers. Both test files author their own
fixtures in memory; there are no generated sources, external fixture files or
historical test imports. Acquisition OS, process, clock, PIDFD and filesystem
operations are replaced by the test's fabricated kernel before invocation.
The pipeline additionally binds its runner, worker lock, selected registry
metadata, interpreter/toolchain and environment. Review/handoff documents are
not runtime inputs.

The 22 acquisition methods cover exact archive/readback ordering, initial/idle/
refresh, external pins and schemas, raw limits and chronology, strict original
ACK age, nonblocking FIFO/symlink refusal, actual held/named identities, process/
boot/namespace/PIDFD custody, prior claims, partial I/O and fsync failures, final
mutation, late completion, ambiguous close and foreign descriptor reuse. The
31 independent consumer methods cover exact pinned schemas, bounds, read/offset/
count joins, post-trigger EAGAIN, publication/ACK/archive chronology, six distinct
file identities, conservative flags and unchanged caller inputs. Subtests are
not counted as additional methods. These checks cannot establish actual Linux
custody, pipe progress, authenticated stream continuity or loss completeness.

Before publication Root accepted: REFRESH requires a prior checkpoint and positive
sequence; all six source/copy identities differ; keep the claim held through final
guards; preserve up to 32 cleanup failures for a fixed maximum of 17 simultaneous
owned descriptors. No unreviewed API or source path is released by these changes.

Only this new stage is scheduled in `/Users/yousi/Documents/Commits/aragorn`:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py status native-reader-checkpoint-acquisition
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-reader-checkpoint-acquisition
```

First inspect selected status and any actual prior result. Reuse a matching
successful result; otherwise execute once. Registry inputs are exactly the five
files above, the two named test modules, needs=[], timeout 120 seconds. Preserve
all actual result/log bytes and fingerprints, including failures. Any retry
requires a diagnosed changed input/environment, reviewed closure and scheduling.
All historical and unchanged stages remain untouched. Use Python 3.12 as shown.

After reviewed PASS, stage only the four released implementation/test paths and
their handoff plus Root-owned ledger/checkpoint documentation; sign and verify
the commit, push normally and verify the remote tip. No actual private path,
listener, sensor, broker, workload or cleanup operation is authorized here.

Completed: stable source/closure review and exact selected stage release.
Assignments: Root checkpoint validation; Admission's separately scheduled replay;
RUN transport; Workloads destructive design; operator-created DNS capacity pending.
Blockers: actual lane results/deliveries and all remaining shared path wiring.

1. Finish released providers/consumers with selected validation and signed integration.
2. Wire HTTP, then DNS/destructive, admission/RUN, real a100, cancellation, full
   timing and four actual paired tasks.
3. Close the existing 48-entry inventory before publishing a freeze candidate.
4. After separate operational release, run the 31-case/100-action/100-pair campaign,
   independently replay, evaluate the existing gate and verify approved cleanup.
