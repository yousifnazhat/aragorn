# D2 batch 48 — independent replay, export and host-loss reconciliation

Base and pinned owner release: `83e72f9c0fdf409856959bf406686462006725f2`.
The [offline entry point](../../../scripts/replay_pi_core_owner_evidence.py)
does not call the VM owner, watchdog, cloud provider or firmware APIs. It reuses
the B46 private-file read/write checks and B47 signed-release lookup. B45–B47
artifacts and the original retained source files were not changed.

## What was exported

For B47 attempt `76d727b5-d3f8-4c89-8d7c-cec20e820f0c`, the reservation,
watchdog terminal and refusal stderr were copied exactly once into a new local
0700 archive under the operator's Application Support/Aragorn-B48-Offline.
The original bytes were rehashed and reread. The report is
`consistent-held-refusal`: the watchdog reaped the child with exit 78, did
not record a grant, and the stderr bytes match the expected pre-target denial.
There is **no** owner journal, ARM decision, owner terminal or serial file from
this run. No missing file was synthesized, including an empty serial file.

Archive-manifest-sha256: `7385f1fdac18365e2092a89e18c4e962ea39289491e99334cf776b0079a797d0`

This signed checkpoint anchors the manifest digest separately from the local
archive. It is not independent runtime attestation, an off-host copy of the
payloads or proof that a provider resource was released.

## Evidence contract and use

For a target-form transcript the [owner reader](../../../scripts/verify_pi_core_owner_records.py)
checks the emitted event types, sequences, attempt, monotonic ordering, graph,
code/media binding, exact original serial length/digest and bounded sealed EOF.
It compares the independent journal to the owner terminal's embedded events.
The [watchdog reader](../../../scripts/verify_pi_core_owner_watchdog.py) then
joins reservation, READY observation, ARM decision and watchdog terminal to
those times. A decision is not delivery; the post-send timestamp may follow the
start observation. The watchdog decision and child terminal bind PID; the owner
journal itself does not record a PID or a digest of the watchdog decision.
These joins check internal consistency in a cooperating trusted host model,
not authenticity against a hostile host. Serial bytes are not interpreted as
guest boot, sector geometry, sensor health or pilot output.

The [archive](../../../scripts/pi_core_owner_archive.py) copies a bounded
allowlist to a fresh UUID directory; it refuses links, unexpected names,
overlapping roots, mutation during read or an existing export. Sources are
never removed. Partial or escalated records can be preserved without receiving
a normal disposition. The only supported normal owner sequence is the
non-escalated guest-stop sequence. Others remain indeterminate.

From the checkout, use the full approved release commit and out-of-band SSH
signer, not an untrusted value from the owner's terminal:

```sh
# First preservation only. For the known pre-target refusal omit --fixture.
python3.12 -B -m scripts.replay_pi_core_owner_evidence export "$LEDGER_ROOT" "$NEW_ARCHIVE_ROOT" "$UUID" "$RELEASE" "$SIGNER" --fixture "$FIXTURE_ROOT" --bindings "$BINDINGS" "$BINDINGS_SHA256"
# Reread an already sealed archive; do not rerun export to perform a read.
python3.12 -B -m scripts.replay_pi_core_owner_evidence replay "$MANIFEST_SHA256" "$ARCHIVE_ROOT" "$UUID" "$RELEASE" "$SIGNER"
```

For target-form replay, supply the same separately retained `--bindings FILE SHA256`
to both operations. The private 0400 file is a JSON object with schema
`aragorn/b48-independent-target-bindings/v1`, `release_commit`, `attempt_uuid`,
`fixture_identity`, `disk_identity`, `store_identity` (each `{dev,ino}`),
`store_sha256_before` and `policy_sha256_before`. Obtain these from independent
custody/enrollment records, not by copying the owner terminal. The actual
attempt inode comes from the source archive snapshot. The runner and disk
digests come from the signed release pin. Digest possession does not grant
permission. Current release authority is empty: even a perfectly joined start
transcript returns `transcript-conflicts-with-held-release`, never PASS.

Use `--portable` only to verify an already acquired, unchanged byte copy: new
local inodes are expected; private, sealed, single-link files, inventory and
hashes must still match the independently retained manifest digest. Never
substitute a digest recomputed from an untrusted copy. None of the modes deletes,
uploads, signals, re-enrolls or retries. Exit 0 means only consistent held refusal;
a preserved but indeterminate, release-conflicting or host-loss report exits 2.

## Host-loss reconciliation — operator hold, not automated recovery

| Last trustworthy evidence | What it establishes | Required action |
|---|---|---|
| No reachable host/archive, or reservation only | An attempt might have been reserved; effects and billing are unknown. | Mark the UUID unresolved. Do not infer no-start or create a replacement attempt. |
| READY/ARM decision or queued grant, no complete terminal | A decision or send was recorded, not receipt, invocation, stop or cleanup. | Preserve every available original/partial byte; fence further operations via the authorized operator. |
| Owner/stop callback, EOF, host-child kill or exit | A component reported a local condition; VM and external-resource state may differ. | Do not infer restoration, successful force-stop, or cloud release. |
| Full records, including a held refusal, after reported host loss | Offline consistency can still be evaluated, but host custody was lost. | Replay independently with `--host-loss` (and `--portable` if relocated); disposition remains `unresolved-host-loss`. |

**Before any case can be closed:** the assigned operator records the exact
account, region, dedicated-host reservation, instance, fixture, attempt and
approved window. Preserve the last off-host digest and identify any gap or
change in clock domain; never compare monotonic times across host restarts.
Under separate authority, obtain independent control-plane inventory/audit and
billing/lease readback, check for surviving or ambiguous VM/effects, and compare
the disk, variable store, firmware policy and owned resources to the pre-attempt
inventory. Reconcile evidence transfer with the designated custodian. Have a
second reviewer record the evidence IDs, uncertainties and final external
disposition. Provider termination alone does not prove restoration or release
of a dedicated-host reservation. If any required proof is unavailable, keep the
hold. Remediation, resource release or a new attempt requires separate scoped
authority; never replay the old UUID or the possibly consumed effect. No such
external reconciliation was performed in this batch.

## Affected checks

| Stage | Checks | Passing fingerprint |
|---|---:|---|
| Owner journal/terminal/serial verifier | 5 | `65cc6d537dab382101ee79df8519455628fea2394be7098f85b68d1bb11a37b4` |
| Independent watchdog records | 6 | `7a832cd1106d3b80946b5afc97ed2e4a06a26180a0f1074644b659e7238cfd47` |
| Archive and portable readback | 6 | `9acc6ba2281da83eaee4cfffc178c6c975cadd45341482c3c93e139925b840a2` |
| Joined CLI replay and host-loss disposition | 3 | `de8f7a5084349c4e5b94502352f1abdb4ece55924fa7612fedb76cf4a480db49` |
| Registry capacity and guards | 4 | `9bef45ef72e4a9759728bb423246052ac383818719b34e5a56d5cdc714ff9dab` |

24 checks passed once. The full-record cases are parser fixtures, never
substitute deployment samples. No native rebuild, recapture or live operation.

1. **D2 open.** Bind the exact host, cost/window, signing/distribution policy,
   enrollment baseline, evidence destination and cleanup owner. Review a scoped
   single-use release before seeking separate allocation, enrollment and
   compatibility-boot approvals. Worker source reads, health, recovery/timing
   and a separately authorized useful pilot still require independent evidence.
2. **D3 open.** Connect remaining admission, RUN/health and workload coverage.
3. **D4 not frozen.** Complete the independent 29-requirement inventory and freeze one deployment.
4. **D5 not authorized.** After freeze and separate approval, run fresh admission, 100 attempts
   and 100 baseline/instrumented pairs, verify thresholds and cleanup, then replay independently.
