# Guarded RUN transport integrated with original signed ancestry

Root reviewed and published schedule
`afb06c4eaf2074b4355fc467e052033a75a62a83` after the exact final source/closure
review. RUN verified and fast-forwarded its own existing branch, ran only the
selected new stage once, and delivered original signed commit
`5193a2fcdd0cb4173ddeeaa7188aa74fd2c7b09f` with that schedule as its direct parent.

Root verified the original ED25519 signature, exact three changed paths and all
13 committed behavioral hashes against the reviewed source. Root then merged
with `git merge --ff-only 5193a2fcdd0cb4173ddeeaa7188aa74fd2c7b09f`, preserving the
original commit and ancestry. No cherry-pick, rewrite, reset or active lane mutation
occurred. This containing signed coordinator checkpoint records the integration;
Root supplies its exact hash after normal push and remote-tip verification.

## Completed implementation and actual evidence

The integrated paths are exactly:

```text
src/aragorn/native_phase3_run_reader_transport.py
tests/test_native_phase3_run_reader_transport.py
docs/phase3/run-health/READER_TRANSPORT_HANDOFF.md
```

The transport owns one fixed seqpacket listener, bounded request history and atomic
notice pipe; validates protected supplied identities and actual OS custody; accepts
one peer and transfers it to the existing owning acquisition wrapper. It preserves
terminal failure/timeout/cancellation, partial evidence and submission uncertainty.
Safe cleanup pins resource identity, detaches socket objects before conditional
raw close, skips unknown/reused handles and advances pathname pins only after
verified authorized changes. The last PIDFD read precedes the final pipe-flags
sample, followed by held/named metadata, namespace, liveness and clock checks.

The actual first `native-run-reader-transport` execution in RUN returned PASS,
exit code 0; stderr reports **30 tests, OK**. Root inspected actual result/logs,
verified their lengths/digests and confirmed unchanged reviewed source. Pre- and
post-fingerprints both equal:

`sha256:b31f41624a6b096e7d009f690f26706c7531f7fd4c1a48a9eccac728ba26b97f`.

Original evidence stays in the RUN worktree under
`.aragorn/phase3-pipeline/native-run-reader-transport/b31f41624a6b096e7d009f690f26706c7531f7fd4c1a48a9eccac728ba26b97f/`:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| result.json | 809 | `e76b231daf6913e1917a6da1f96320f85d7b457c65fb2b5c7a7a530f9e8219e4` |
| stderr.log | 6015 | `7adc69d524be79d8a37c4b1649b95676f05181edf609f53db1fc561840d3a926` |
| stdout.log | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Preflight is PASS; all original preflight/start bytes remain retained. The complete
13-file closure is pinned in the scheduling document and committed handoff. The
new source is `609a5a32c33a4bb5ae0dec45eb6637b9d5b853e00797308244a92b1e86aa5fe0`,
test is `e3528aed2fe94ceaf8b7f8bc4718aa9fce20e696fee47587031c754041b613a3`.
Root's integrated behavioral bytes match the tested lane bytes. The selected
wiring case exercised the actual owning wrapper/challenge issuer with mocked
store/leaf/OS boundaries. No new behavior was introduced during integration, so
source/closure composition review required no repeated stage in Root.

No historical suite, unchanged retry, cache copy, live operation, private retention
or cleanup ran. Earlier Root 53-check checkpoint and 28-check broker results,
DNS 13-check result and HTTP evidence are unchanged. The same 48 ledger IDs/order
remain; RUN-02 receives only the bounded V-reader-transport reference.

## Limits, assignments and blockers

This is mocked transport/custody/wiring evidence. It establishes no native
acquisition authenticity, real consuming loop, complete upstream loss, deployed
identity, full request timing, prompt post-transfer cancellation, effect authority
or qualification. Raw reader-FD3 fdinfo is absent from the frozen supplement;
parsed flags and links are not independent replay of that raw parse. Observations
remain point samples. Failed detach leaves an unresolved owner/error-held object
that later Root supervision must retain, not discard or retry. Holds remain.

- **RUN:** bounded transport assignment complete and original commit integrated.
  Preserve its actual result; fast-forward your own branch to the new published
  checkpoint when supplied. v7 now releases the ready five-path DNS acquisition
  contract to this existing owner; acknowledge it and begin only those paths.
- **Admission:** execute/return only the already scheduled independent replay stage
  and original signed delivery. Latest read-only branch inventory still showed
  `95b676e`; the newer schedule needs owner verification/fast-forward and receipt.
- **Workloads:** original DNS delivery remains integrated. The destructive/a100
  design-review path is released; source implementation awaits its exact contract.
- **DNS capacity:** no requested additional DNS tree exists. v7 supersedes that
  pending request by reusing the available RUN owner; no extra tree is needed.
  The exact five paths and unchanged DNS contract are published in v7.
- **Root:** finish the connected writer/session/refresh contract, delegate a bounded
  writer implementation to available internal capacity, and own the actual caller,
  IPC/broker, bridge/sensor/loss, launch/source inventories and paired contexts.
  Draft design work is not a source release. Keep failed-detach ownership and
  post-connect ambiguity explicit in the future supervisor.

The critical path remains the actual consuming loop and verified Root refresh
session joined to the serialized HTTP broker, followed by the other required
providers. Lane agreement is confirmed through RUN's signed delivery; receipt of
this new integration checkpoint is not presumed. Publish copyable exact hashes
while the outbound bridge remains unavailable. Root never changes active lanes.

1. Finish and integrate shared providers/consumers with only reviewed new focused
   validation; retain original signed lane ancestry and actual results.
2. Wire full HTTP, DNS/destructive, admission/RUN, real a100, cancellation, full
   timing and four actual paired tasks.
3. Close the 48-entry path/consumer/source-custody inventory and publish a freeze
   candidate only after implementation gaps close.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. Phase 3 remains unfinished.
