# B110 — private retention and offline replay of the B109 output observation

The protected caller can now hand its original observation to a private evidence
store. Previously the inner caller returned the record, but the only ordinary
external output was a digest of the managed result. A digest cannot recover
the bytes after cleanup. The [new entry](../../../src/aragorn/pi_core_pilot_retention_entry.py)
wraps the original B109 call; it never reconstructs the observation from a
digest, a worker claim, the expected answer, or a second read of the file.

### Before and after the one managed call

- The optional host wrapper mode is `--retain-pilot-output`. It requires distinct,
  out-of-band pins for the actual successor host profile, prepared managed plan and
  private retention release. The default invocation gains no write destination.
  The original four module digests and B109 service manifest, runtime binding
  and layout receipt are checked. B109 is the base, not the new wrapper's host
  digest. The existing provider, credential and effect checks are unchanged.
- A future operator-owned release at `/etc/aragorn/approvals/pilot-output-retention.json`
  binds the attempt, actual host/plan/deployment, output path descriptor, boot,
  window and evidence directory/mount identities. The two fixed roles are
  `cas` and `receipts` under `/run/aragorn-pilot-output-evidence`, not paths
  chosen by Pi. They must already exist on a separate, private, approved mount.
  These are guest interface names, not provisioned or nominated destinations.
  A retention release cannot authorize boot, provider access or file creation.
- The [custody writer](../../../src/aragorn/pi_core_pilot_output_custody.py)
  spends an exclusive attempt claim **before** the managed call. Once the inner
  caller returns, only its nested `worker.pilot_output_observation` is eligible
  for storage. The writer checks the original canonical record, including the
  observed bytes, marks publication started, writes and reads back the object,
  then publishes a separate no-replace receipt. Plan and release digests are
  bound throughout. Neither raw observations nor private destinations go to stdout.
- If the inner caller captured output but later failed, retention can preserve
  those bytes within the original deadline; it cannot turn the failed call
  into success. Bad custody, missing bytes or a partial publication do not
  authorize another call. Preserve occupied slots and reconcile offline.

### Independent replay

Use the read-only [replay entry](../../../scripts/verify_pi_core_b109_retained_output.py)
with independently nominated private store and receipt directories, attempt and
actual activation IDs, path/plan/release/deployment pins, raw observation and
receipt pins, and the original action/provider archives and nominations. Obtain
these separately from the submitted records; do not select a receipt by scanning.
The verifier checks the claim, publication marker and receipt, recovers the exact
observation, then uses the B107 verifier to compare it with the recorded
`ALLOW/CREATED`, policy, path, activation and provider proposal. It does not
open the old action directory. The action/provider archives cannot double as
the observer store or receipt directory.

`MATCHED_LOCAL_CUSTODY_AND_RECORDED_PILOT_OUTPUT` means those independently
nominated **bytes and records agree**. It does not establish who collected
them, that a release was authorized, that the guard ran on a particular mount,
that Pi could not reach a physical medium, or that cleanup succeeded. Local
receipts are not an off-host witness. No original pilot observation exists
from this batch. The complete private managed result was not exported.

### Focused verification and handoff

| New pipeline stage | Checks passed on first run | SHA-256 fingerprint |
|---|---:|---|
| `pi-core-b110-private-caller-offline` | 11 | `e13a82d1d7acfebe7c1b820f5f25d739dc14b46323a25c88d0d786e500f9c6cd` |
| `pi-core-b110-private-custody-offline` | 5 | `797759cae1c098d7d981e5db5b9fb4183e414e130d4d333c0a69d3e41bf12472` |
| `pi-core-b110-private-replay-offline` | 3 | `8132b593b0d2d5531ca4c90a9579ed5ae2db0976526a4edf6c797bc0799991cb` |

The positive replay read real bytes from a temporary fixture after its original
`result.json` was removed. No historical stage, guest, service, observation
campaign, media build, provider request, spending or pilot ran. No private
release or B49 value was supplied, generated or changed.

1. **D2:** Pin the new wrapper and two host modules in a successor of B109;
   keep the B109 service and worker pins. Before boot or pilot, bind the actual
   host, private evidence destination, budget/window and cleanup authority.
   Independently evidence installed source/health, the useful task and denials,
   full timing, recovery and cleanup under a separate bounded pilot approval.
2. **D3:** Finish connected admission, RUN/health and workload coverage.
3. **D4:** Close the independent verifier inventory for all 29 requirements on
   one deployment; only then freeze.
4. **D5:** Obtain separate authorization for fresh acceptance, 100 actual
   attempts and 100 baseline/instrumented pairs, cleanup and independent replay.
