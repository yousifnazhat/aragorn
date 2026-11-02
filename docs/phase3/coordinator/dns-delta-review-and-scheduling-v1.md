# DNS delta review and one selected stage

Base: verified published `4ec18f80164c0cc11e387c2f292e0716f54df208`.
This checkpoint also preserves original signed Admission delivery
`d3c5ffed8dbbf0520c9b8d2e9d798e204d09f96d` through signed merge
`f13af109a21a1fc0f4cc4f24753b1f032716317a`.

## Confirmed lane delivery and Admission integration

All three owners acknowledged the corrected checkpoint and independently
fast-forwarded their own existing worktrees. Root confirmed branch tips read-only.
Admission's actual 26-test PASS has equal pre/post fingerprint
`sha256:c08b47026e885e68bab6482ca5d858863ef442774f40db55eedea486b3e9ce46`.
Root checked original result/log bytes in the owning worktree: result.json 812
bytes, SHA-256 `529658a38ebf01bd742956df694fab531b66c17a1cc1b019a433042717804cdb`;
stderr.log 4335 bytes, `834dab28a9cd919e43c0242a7a2db0d2f348cc91c9a606472d7d6e69c89ef050`;
stdout.log empty. Its original signature and exact four assigned paths were
verified. Integrated bytes equal the original delivery; no test was rerun.
This closes only the finite policy-tamper recorder/consumer slice, not protected
native policy acquisition, absent-target behavior or full ADM-03 qualification.

## DNS selected stage released upon signed publication

Owner: `/Users/yousi/Documents/Commits/aragorn-phase3-workload-verifiers`.
The owner corrected consumer and independent fixture from 0x13 to 0x14 and now
constructs the complete 20-byte marker directly from the validated attempt ID.
The new regression covers all a026-a050 IDs and ACCEPTED/MALFORMED/REFUSED rows,
rejecting partial/wrong-final-byte presence while accepting the complete marker.

Root reviewed this delta, all 13 focused methods and the unchanged six-file
actual import/fixture closure without importing implementation or running tests:

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
dd0cba7a146a1ad3167facc28219576e12fa5d971fd2d0743d41196235c90566  src/aragorn/native_phase3_workload_dns_canary.py
3726fef42f6a403a918812ae5e35add487f006583957119cb63b5e033c3eb641  src/aragorn/native_phase3_workload_dns_verify.py
bcdd7b92d3ddaddb4ab38ce5cabcdbd68c7f87c79a6251f81c1bb225313946c2  src/aragorn/native_phase3_http_canary_contract.py
0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b  src/aragorn/oci_worker_protocol.py
eed73507c989cc1614f5e2d17160f07123b4d2b7e84d23f167d06d9259cbbff6  tests/test_native_phase3_workload_dns.py
```

Remaining imports are stdlib. Fixtures are fabricated inline; no generated
source, file-read fixture, private parser or historical test is imported. The
consumer imports no builder. Mutable handoffs/outputs are not behavioral inputs.
Pipeline runner, lock/toolchain/environment binding remains unchanged.

The registry adds only `native-workload-dns-canary`, needs `[]`, timeout 120s;
all 113 previous entries remain unchanged. Owner verifies the containing signed
published checkpoint, fast-forwards their own branch, preserves drafts, rechecks
these hashes and inspects actual existing stage results before the one command:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-workload-dns-canary
```

Run only in the owning worktree. Retain the actual result/fingerprint and logs;
diagnose failures before any changed-input retry. After reviewed PASS, sign exactly
the four ownership-v2 DNS paths, verify the signature and hand off original hash,
paths, actual result and evidence limits. No feature push. Root integrates and
publishes normally. Do not rerun Admission, RUN, HTTP or existing benign checks.

## Remaining work

Completed: Admission delivery integrated; corrected DNS source/closure reviewed.
Released: only the DNS stage above; existing ownership-v2 implementation paths.
Pending: concrete guarded-reader transport, broker evidence/submission and DNS
acquisition contracts. Root owns their review, publication and explicit ownership
transfer. No new provider implementation or operational permission is implied.

1. Publish bounded provider contracts and finish the common protected runtime path.
2. Complete DNS handoff and remaining Admission/RUN/Workloads paths; integrate
   actual lineage, cancellation, full timing and paired contexts.
3. Close the 48-entry ledger and deployed source/identity custody; publish freeze.
4. After separate operational release, complete the same-deployment 31 cases,
   100 attempts and 100 pairs, independent replay and approved verified cleanup.

No historical rerun, cache copying, unchanged retry, live operation, private
retention or cleanup is authorized. Implementation and final qualification differ.
