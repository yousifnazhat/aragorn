# D3 batch 56 — replay a retained copy without its scratch directory

Based on signed merge `a46f842`. The existing allowed-file copy/readback task
and collector callback keep their interfaces. The independent reader can now
retain the exact bytes it read, the original receipt, and an observation tying
both to the request, deployment, pair, mode, timing marks, fixture and file
identities. It issues the observation digest last, after final custody and
close checks. Give that digest to a custodian independent of the task; a digest
obtained from the evidence being evaluated is not provenance.

The portable reader compares all three objects in a **read-only** evidence
store to the separately supplied digest and expected context. It needs neither
the old file nor an active worker. It does not rerun the task or measure time.
Unreferenced blobs after a storage failure are not a published observation.

| Affected stage | Result | Fingerprint |
|---|---|---|
| `native-workload-copy-portable-offline` | 4 new + 9 affected consumer checks passed once | `332581633d9d3050f84404e716fa380758cffd5da465a19635fee772210443f2` |
| `pipeline-capacity` | 4 checks passed once at the new 285-stage boundary | `6d754d616d2871173389acba4f073118aec3e2bc840f134fda6afa61c3248479` |

The checks used temporary files and mocked fixture custody. The capture-side
guard still identifies the existing native container fixture, **not** a Pi
guest. Do not count these checks or older receipts as a managed task pair.

1. D2 open: collect actual guest volume, worker and sensor evidence; independently
   reconcile recovery and timing. B49 is unchanged; no boot or pilot authorized.
2. D3 open: connect actual managed baseline and instrumented contexts to the
   four tasks and readback consumers; use equivalent starting state, distinct
   owned directories and independently retained pins. Admission and RUN remain open.
3. D4 not frozen: close the producer/evidence/verifier inventory for all 29
   requirements on the same deployment before freezing.
4. D5 not authorized: after freeze and separate approval, acquire fresh
   admission evidence, 100 attempts and 100 pairs; verify thresholds, cleanup
   and independent replay.
