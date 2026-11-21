# B98 — match the spent lease to the recorded terminal action

Use the [existing B93 action replay](pi-core-retained-action-replay-batch-93.md)
and its original nomination. No new private field, export, or live check is
needed. The worker request and terminal broker envelope were already checked
against each other. The consumed lease and its recorded measurement were also
checked internally. Those are distinct checks: agreement within each group
does not establish that the lease describes the same action as the envelope.

The independent reader checks the consumed claim's request and envelope digests,
the full original measured action against the terminal request, and the fields
shared by the lease and its configured grant. The recorded claim must fall in
the original lease: it cannot start before the request, end after the grant,
or have a different expiry from the request. No replay-time clock is consulted.
The parent grant binds an operation and policy; it does not itself specify the
target or payload. Those bindings belong to the issued lease and original
measured action. The protected-path digest in a record is not a new observation
of the directory or the file in it. Do not use the control directory's inode
as a substitute for the output directory.

A consistent recorded creation remains a recorded creation. A consistent
recorded block remains a block. Neither proves what happened at the output
file. For the pilot, independent observation must still establish absence
before the action and the exact expected bytes afterward in the nominated,
held output directory. An ambiguous action is not permission to retry.

**Focused result:** four new rejection checks and the affected recorded
creation/block check passed on the first run of
`pi-core-terminal-action-lease-offline`
(`sha256:1346c8c02b1341bce5eb04953812db5d53a380361acc8d51aae89e77ded52170`).
No historical capture, production broker operation, real timing or sink
observation ran. There is no independent policy-allow or installed-source
finding here.

1. **D2:** Connect the fixed worker-view proof, pilot admission and actual
   output observation. Demonstrate health, recovery, full timing and cleanup
   in the separately authorized pilot. B49 remains null.
2. **D3:** Finish connected admission, RUN/health and workload coverage.
3. **D4:** Complete the independent 29-requirement inventory, then freeze.
4. **D5:** Separately authorize fresh acceptance, 100 attempts, 100 task pairs,
   cleanup and independent replay.
