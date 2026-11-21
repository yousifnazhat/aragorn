# B90 — match the four scheduled benign tasks to the outputs in their receipts

A valid request ID and a generic `completed: true` can describe a task that
returned the wrong answer. Line count and SHA-256 even use the same input.
The managed qualifier now checks the task selected by the **frozen pair
schedule** and the exact original receipt, during the same replay introduced
in B89. It checks 25 baseline and 25 instrumented receipt outputs for each
of the four tasks. The additional guard can reject a sample. It cannot
return a replacement verdict, run a task, or skip the original receipt verifier.

The operator supplies `ManagedMeasurementReceipts.task_verifier_bundle_digest`
from a reviewed source manifest. The [reviewed source list](../../../benchmark/pi-core-managed-task-output-sources-v1.json)
names the fixed readers and helpers. Retain its canonical JSON (no final LF)
and the exact files in the evidence store before using it. There is no
default receipt-selected verifier or file path. This pin identifies the
fixed-output readers; it does not pin the whole guest or attest loaded code.

The canonical six-source manifest digest is
`sha256:b87913ccd9ec164013fb2618348393f039b1172a2c87346d111d067c5c5401e8`.
Only `pi-core-managed-fixed-tasks-offline` ran: six developer checks passed
on their first run (fingerprint
`5b04018f15605dc127fe90c963b510d7ec682855f0193cf725c87ca51d8c68bc`).
The receipts in those checks are test fixtures; zero acceptance samples were taken.

The three computation checks use the existing independent JSON-sum, line-count
and SHA-256 readers. For copy/readback the new check verifies what the receipt
*says* was returned for the frozen task, including its retained-file metadata
structure. It does **not** independently see a file. Keep the separate original
file observation, fixture custody, cleanup, clock and mode-evidence requirements.
In particular, a matching SHA-256 and a later restored file are not evidence
of a residue-free denied operation.

## Two choices before executing pairs

1. **Where does the task run?** The [four reference tasks](../../../src/aragorn/phase3_reference_tasks.py)
   are Python; the [worker filesystem](pi-core-candidate-worker-filesystem-batch-86.md)
   contains the confined Node runtime, not CPython. Python in the trusted
   coordinator is not Python inside the worker. Either measure a fixed task
   service reached through Pi in both modes (label results end-to-end and
   include the round trip), or provision and re-pin a narrowly confined
   worker-side runner in a successor. Merely changing the request's mode
   field proves neither case. No change to the candidate is implicit here.
2. **Who owns the copy directory?** The [existing guard](../../../src/aragorn/native_phase3_http_fixture.py)
   authenticates Docker's `/docker/<container_id>` cgroup, including PID 1.
   It cannot authenticate a standalone systemd VM. A managed successor must
   independently hold the nominated guest/unit, namespace, directory and file
   identities, pin the original observation per pair and mode, and verify
   custody/cleanup. Alternatively nominate a real nested container and count
   its costs in both modes. Never invent a container ID, weaken the Docker
   guard or reinterpret its old evidence.

These are engineering decisions, not requests for a host, key or live
authorization. Neither the existence of receipts nor this batch supplies a
real baseline/instrumented execution context.

1. D2: the actual confined worker observation, its private evidence policy,
   connected health, recovery, timing and separately authorized pilot remain
   open. B49 stays null.
2. D3: fixed task outputs can now be checked against the schedule. Connect
   the approved carrier and copy fixture, admission, protected sensor and
   response paths; demonstrate actual mode selection and equivalent inputs.
3. D4: keep the 29-requirement verifier inventory open until original sink
   and context evidence and all other prerequisites are independently covered.
4. D5: separate authorization and freeze precede fresh acceptance, 100
   attempts, 100 measured pairs, cleanup verification and offline replay.
