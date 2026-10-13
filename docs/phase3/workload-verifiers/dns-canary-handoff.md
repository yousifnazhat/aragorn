# DNS canary — reviewed source and focused checks passed

Original source base: `d87572182584f9c106393a2ca952c69703b6da6d`.
Verified signed current checkpoint and parent:
`95b676eca174ae5cb117fe778d3359f0e924b425` on
`codex/phase3-workload-verifiers`. Owner fast-forwarded this existing worktree
without conflicts, accepted `ownership-and-release-v2.md` and the final decisions
in `docs/phase3/coordinator/dns-canary-contract-v1.md`. Both pre-existing untracked
local drafts (`copy-readback-plan.html`, `dns-canary-contract-proposal.md`) remain
untouched and excluded. Owner read and accepted `provider-release-v4.md`,
`dns-delta-review-and-scheduling-v1.md` and the exact DNS contract at this parent.
Root reviewed the corrected source and released only the one focused stage.
Earlier owner-only fast-forward to `4ec18f80164c0cc11e387c2f292e0716f54df208`
and its review documents remain the source-delta history.

## Short delta resubmission — 2026-10-13

Root's source review identified a real 20-byte marker length error: the consumer
and independently authored fixture had `0x13`, truncating the final attempt digit
in the consumer's scan. Both wire literals are corrected to `0x14`. The consumer
now constructs the complete ASCII marker directly from the validated attempt ID,
independent of the QNAME length byte, and uses it to reconstruct the exact query
and scan arbitrary retained packets. The full identifier survives in the result.

One new focused method, `test_partial_attempt_prefix_is_not_presence`, exercises
all 25 DNS attempt IDs and all three dispositions: 19-byte partial marker and
wrong final byte return non-presence, while the complete 20-byte marker returns
presence. This regression passed in the single run below. The builder is unchanged.
The actual six-file closure/import edges remain unchanged from root's review;
only consumer/test hashes below changed. The preceding reviewed hashes are
consumer `0552643b9a6633fb604dfe8716adb1cdf79c1f0a2d48a02f6ea53360a26634bb`
and test `4c91dae3c456ff03a8ae01426a35546ef128913050ab680d415cc39a2e7e2636`;
neither had an execution or pipeline fingerprint. Root accepted the delta and
complete closure in `dns-delta-review-and-scheduling-v1.md`; the registered stage
was explicitly scheduled by the signed parent and operator handoff.

## Assigned change and behavior

Only these four new files belong to this batch:

- `src/aragorn/native_phase3_workload_dns_canary.py`
- `src/aragorn/native_phase3_workload_dns_verify.py`
- `tests/test_native_phase3_workload_dns.py`
- `docs/phase3/workload-verifiers/dns-canary-handoff.md`

Builder exports `canary_request(attempt_id)` and `readiness_request(nonce)`.
It returns finite A/IN question bytes for a026–a050 and the separate nonce query,
with fixed endpoint constants `127.0.0.1:47632/UDP`. It never opens a socket.

`verify_dns_observation` implements the exact published keyword-only signature.
It reconstructs both questions and the readiness response independently and
imports no builder. Its full independently constructed marker is the query's
20-byte first label and the literal scan target.
Canonical ASCII documents must roundtrip exactly, rejecting duplicate keys,
nonfinite numbers and alternate encodings; both independently expected pins and
the observation cross-pin are required. Exact object keys and strict integer
bounds apply to caller contexts and retained rows/counters. Canonical equality
prevents boolean/integer substitution inside identity bindings.

The consumer validates the caller-held fixture, observer/client process epochs,
init, socket, endpoint, clock domain, interval and loss source; all before/after
bindings must agree. Readiness must be a distinct exact exchange completed by
the expected client before the attempt. Attempt rows include accepted, malformed
and refused packets, including valid zero-byte UDP packets. All are checked for
the case-insensitive current literal marker; any other reserved a001–a100 marker
refuses a clean result. Counts exclude readiness. Coverage must account for it.

Missing, truncated, overflowed, lossy, reset or incomplete evidence raises a fixed
ValueError with no raw-byte diagnostics. This implementation does not attach the
contract's optional partial-presence diagnostic: failure returns neither an
absence result nor a verified interval. Evidence remains with its custodian.
A returned result asserts only `CONSISTENT_BOUNDED_DATAGRAM_EVIDENCE` and keeps
all six flags false. An empty interval/packet is never blocked-exfiltration proof.
The literal scan makes no compressed/segmented/encoded exfiltration claim.

No callers, exports, collector/replay, broker, fixture data, source pins or
configuration changed in this batch. Coordinator registry registration is in
the signed parent ancestry, outside this exact four-file lane commit.
There are no generated sources or external test
fixtures. No new library dependency. Test inputs are fabricated inline bytes and
records, with independently literal wire expectations. No native clock sampling,
listener, send, capture, file residue, fixture provisioning or cleanup occurs.

## Reviewed stable behavioral closure

Six files comprise the actual transitive project import/test closure. SHA-256
hex values below describe current source bytes, not pipeline fingerprints:

| Path | SHA-256 |
| --- | --- |
| `src/aragorn/__init__.py` | `4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01` |
| `src/aragorn/native_phase3_workload_dns_canary.py` | `dd0cba7a146a1ad3167facc28219576e12fa5d971fd2d0743d41196235c90566` |
| `src/aragorn/native_phase3_workload_dns_verify.py` | `3726fef42f6a403a918812ae5e35add487f006583957119cb63b5e033c3eb641` |
| `src/aragorn/native_phase3_http_canary_contract.py` | `bcdd7b92d3ddaddb4ab38ce5cabcdbd68c7f87c79a6251f81c1bb225313946c2` |
| `src/aragorn/oci_worker_protocol.py` | `0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b` |
| `tests/test_native_phase3_workload_dns.py` | `eed73507c989cc1614f5e2d17160f07123b4d2b7e84d23f167d06d9259cbbff6` |

Import edges: test → builder, consumer, canonical_json; consumer → existing
validate_fixture and canonical_json; HTTP fixture validator module →
canonical_json. Package initialization is included. The two existing imported
modules have no further project imports. Remaining imports are Python standard
library. The test does not read project files, launch subprocesses or load other
test helpers. Contract and fixed lab manifests informed the constants but are not
runtime-read/generated fixture inputs: `benchmark/phase3-reference-inputs/lab-data-v1.json`
and `benchmark/phase3-reference-workload-plan-v1.json` remain unchanged. Root may
include these normative references in its review; they are not hidden imports.
Mutable handoff and pipeline outputs are not behavioral stage inputs.

Coordinator registered and scheduled the following exact stage/closure:

```json
{
  "id": "native-workload-dns-canary",
  "tests": ["test_native_phase3_workload_dns"],
  "needs": [],
  "timeout_seconds": 120,
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_workload_dns_canary.py",
    "src/aragorn/native_phase3_workload_dns_verify.py",
    "src/aragorn/native_phase3_http_canary_contract.py",
    "src/aragorn/oci_worker_protocol.py",
    "tests/test_native_phase3_workload_dns.py"
  ]
}
```

The reviewed stage ran through `/opt/homebrew/bin/python3.12` in this original
workload worktree. No direct unittest/import/compile bypass occurred. Stage timeout
is a check harness limit, not a product execution deadline.

## Focused cases and actual check status

Thirteen focused test methods, all **PASS**:

1. `test_exact_builder_wire_all_reserved_attempts_and_readiness`
2. `test_consumer_independent_and_exact_claim_ceiling`
3. `test_empty_interval_and_zero_length_packet_are_not_blocking`
4. `test_scan_malformed_refused_case_and_other_attempt_contamination`
5. `test_datagram_refusals`
6. `test_maximum_retained_rows_bytes_and_interval_edges`
7. `test_missing_extra_and_strict_flags`
8. `test_binding_substitution`
9. `test_expected_context_is_validated_not_just_equal`
10. `test_readiness_requires_distinct_exact_exchange_and_client`
11. `test_coverage_loss_resets_overflow_and_incomplete_evidence`
12. `test_raw_pins_canonical_json_bounds_and_cross_pin`
13. `test_partial_attempt_prefix_is_not_presence`

Before execution the owner verified all six source hashes against Root's review
and inspected the existing pipeline state: no DNS result existed. The one newly
scheduled execution, exit 0, was:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-workload-dns-canary
```

Result: **PASS**, 13 tests, unittest time 0.085 seconds. Pipeline recorded interval
0.247859 seconds (`started_at_ns=1791922132512037000`,
`finished_at_ns=1791922132759896000`). Pre/post fingerprint matches exactly:
`sha256:89b7cb5add286a2fc0de48c41797455250b5e26f34367fc577aed04f566fe262`.

Original evidence remains in this worktree at
`.aragorn/phase3-pipeline/native-workload-dns-canary/89b7cb5add286a2fc0de48c41797455250b5e26f34367fc577aed04f566fe262/`:

| Retained file | Bytes | SHA-256 |
| --- | --- | --- |
| `result.json` | 808 | `24a14ced446c9fcc42695f66794459966039209a25663fd5ff1443b5383c4829` |
| `stderr.log` | 2095 | `6b70eb24be57450cf0f7afc833a1eecbfb907cf83562ee6642bbf0a6f5ef403e` |
| `stdout.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The owner checked actual result/log bytes and hashes read-only after the run.
No failed DNS execution or retry occurred; all existing evidence is preserved.
No historical test ran and no cache was copied. The original signed batch hash
is provided in the delivery message; only the four assigned paths are committed.

Existing benign evidence is retained, not newly revalidated or promoted by DNS:

- JSON sum: `sha256:9d5945fdbad517531b6cc61d32645596ded265683cbf82504651274557f16a82`.
- Line count: `sha256:79464c1432034d5d5a0298be6c1645e328dba1859bd75c5611fb73fb55480d0b`.
- SHA-256: `sha256:5c26a3df4d6f464ba8458d7ef60139bcc7e74c3f473044654edc3b22739c779f`.
- Copy/readback: `sha256:bc7e9c5b46f7c44569ae94dd00fcf80aafa3b51d6ff883f985b1327e5790d8db`.

The four leaves and their behavioral inputs are unchanged by this assignment;
future environment-specific applicability remains a coordinator evidence decision.

## Remaining interfaces and blockers

Root owns real exclusive endpoint acquisition; independently held observer,
client, fixture, clock, lifecycle/readiness and loss evidence; truthful complete
capture and pin custody; source identity; native dispatch/broker integration;
protected collector and replay context. Booleans/counters passing offline checks
do not establish actual acquisition, causal blocking or qualification.
The reviewed `dns-provider-contract-v1.md` five-path provider source assignment
is pending a later published base containing this original signed builder;
its existence does not release provider source work in this batch.

Truncate a051–a075, unlink a076–a100 and the actual unattributed a100 control need
published concrete coordinator contracts and exact path assignments first.
Protected interval-wide residue must cover intermediate destructive effects;
before/after equality alone is insufficient. A100 must be the real distinct
execution, never relabeled attributed evidence. No such code is added here.

Collector execute/verify/identity joins, all four actual scenarios and offline
replay, actual equivalent fresh baseline/instrumented state, host/task/input
bindings, deadlines and cancellation remain outstanding root/later release work.
Reuse the four existing benign leaves, retain TASK_ACCEPTED→TASK_COMPLETED timing
and baseline-first ordering limitations, and never duplicate samples to fill pairs.
Private evidence retention, live activity and cleanup approval remain on hold.

## Four remaining Phase 3 steps

1. Implement/integrate ready shared providers with only newly scheduled focused
   validation; unresolved retention/cleanup hold remains.
2. Wire the full HTTP causal path, then DNS/destructive actions, all admission/RUN
   paths, cancellation, full timing and four actual paired tasks. This DNS leaf's
   reviewed focused validation is complete; Root integration remains pending.
3. Close the 48-entry path/consumer/source-custody inventory and publish a freeze
   candidate only after the full coverage map is complete.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. Qualification stays false.
