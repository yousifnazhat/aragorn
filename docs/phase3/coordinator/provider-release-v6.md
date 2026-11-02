# Reader checkpoint acquisition: bounded source release

Base: verified signed and published
`0b819f3e953aff0c879298d96d76c9d35e2f7590`. The containing signed checkpoint is
the implementation base after Root supplies its exact remote-verified hash.
Read `reader-checkpoint-contract-v1.md` and
`tetragon-stream-loss-decisions-v1.md` together with the existing reader/broker
contracts. This release changes none of their frozen wire schemas.

Root releases the smallest complete checkpoint readback/archive and independent
byte-consumer slice first. The exact write allowlist is:

```text
src/aragorn/native_phase3_run_reader_checkpoint_acquisition.py
src/aragorn/native_phase3_run_reader_checkpoint_verify.py
tests/test_native_phase3_run_reader_checkpoint_acquisition.py
tests/test_native_phase3_run_reader_checkpoint_verify.py
docs/phase3/coordinator/reader-checkpoint-acquisition-handoff.md
```

The independent consumer and its fixtures must not import the acquisition
producer or private vendor parser. Root assigns the acquisition module and
handoff to internal owner reader_store_implementation, its test to coverage_ledger,
and the independent consumer/test to provider_path_review. These owners work only
in the coordinator tree under Root review, not in any active lane tree. Shared
files, registry, all installed source and
launch/service/IPC/broker integration remain Root-owned. The matching proposed
pipe-reader writer is reserved and unreleased in this slice. A readback cannot
be relabeled actual loop progress or a fresh payload-phase observation while
that writer and its actual dispatch remain absent.

All schemas, expected identity inputs, deterministic paths, file/descriptor
ownership, clock and failure rules come from the exact contract. The acquisition
must read and retain actual bounded bytes using guarded OS operations; an injected
truth/readback callback or supplied manifest alone cannot substitute. Missing
records, incomplete publication, stale timing, changed custody or unaccounted raw
bytes refuse. Original partial observations and cleanup errors remain available.
The existing root-only permanent reader-claim store is untouched.

Root's selected stream design separates reader, bridge and sensor, actual pipe
identity from upstream continuity, and reader-owned raw bytes from protected
Root readback. Complete loss scope includes upstream queues, caches, selected
suppression, map/program observations and unmeasured early kernel omissions.
Unknown sources remain unknown. A responsive pipe reader never authorizes an
effect by itself. Second-phase refresh must preserve the original ACK/age and
before-loss baseline; no new pre-effect challenge is allowed after connect.

No new execution is scheduled here. Submit stable source hashes, actual complete
project/generated/fixture closure and focused cases first. Root reviews source,
then signs registry additions and schedules only necessary new checks. Preserve
all unaffected fingerprints, especially the completed 28-check broker and
13-check DNS results. After reviewed PASS, retain actual outputs, stage exact
paths, sign and verify one checkpoint, push normally and verify the remote tip.

Admission replay and RUN transport remain active under their accepted contracts.
Admission's stable independent source/33-case closure is reviewed; only
native-run-submission-replay is scheduled in its owning worktree by signed
checkpoint ce038d861620253859e4f7cec828a2f91402dc29 and
submission-replay-review-and-scheduling-v1.md. Actual result remains pending.

RUN's evidence-format clarification is accepted: the frozen notice_pipe snapshot
retains the exact parsed reader/writer flag integers and both raw pipe-link strings;
it has no raw reader-FD3 fdinfo field. Preserve the specified bounded strict live
fdinfo check without adding an undeclared field. Document that independent replay
cannot reconstruct that fdinfo parse from this supplement; no acquisition or
transport-authenticity claim follows. Other specified raw PIDFD/proc/status/boot
evidence remains retained. This is a claim-limit clarification, not a schema change.
Workloads has its released destructive/a100 design-review path. The additional
DNS owner is requested against the exact published v5 base and five-path contract;
do not presume worktree creation or owner agreement. No active lane tree is
changed by Root.

1. Complete reviewed provider slices and independent consumers with newly
   scheduled focused validation; integrate original signed deliveries promptly.
2. Wire the complete HTTP path, DNS/destructive actions, all admission/RUN
   behaviors, actual a100, cancellation, full timing and four paired tasks.
3. Close the same 48-entry path/consumer/source-custody inventory and publish a
   freeze candidate only after implementation gaps close.
4. After separate operational release collect 31 cases, 100 actions and 100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. All existing operational holds remain.
