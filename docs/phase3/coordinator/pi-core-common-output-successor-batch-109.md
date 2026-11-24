# B109 — the protected caller and output reader share one candidate

The [source selection](../../../packaging/pi-core/managed-sources-b109.json)
pins the coordinator entry, managed bootstrap, native supervisor and pilot output
observer to signed commit `9db4643f6c40ae18bffc15163d42d80ea57b8458`.
The existing successor publisher staged them once from the retained B105 layout.
Across both source trees, the four files have identical bytes; the service
wrappers retain their original roles and templates. No worker, native binary,
policy, credential, or private B49 field changed.

Of 1,789 guest entries, **15 differ from B105**: eight module copies, three
rendered service wrappers and four inventory documents (host profile, service
manifest, runtime binding and service layout receipt). Only the two copies of
the output reader are new. The host profile has 817 files and the service
manifest has 807. All 37 worker-layout rows and both observer modules are
unchanged. Do not promote the retained B106 plan or its B105-bound receipt to
evidence of execution on B109.

The [reviewed inventory pins](../../../packaging/pi-core/managed-payload-b109.json)
were reconstructed separately from the publisher. The actual staged layout is
under `~/Library/Application Support/Aragorn-B109-Offline/`:

| Retained object | SHA-256 |
|---|---|
| `payload.json` | `f84e61381e72d7630964e07d5b4a6ee97006e7642a1666eaba4fbce7e1563232` |
| `outcome.json` | `14327842684fcf9f3f4f716eabace5f2b9bb2f1e08a3be3e2b8174ea540e1ba7` |

Only `pi-core-b109-common-repin-offline` ran: **4/4 passed on the first run**,
fingerprint `b647f5ac15a6e44eee74fb69751ea4dfe341249f06f0087f6d84227932b420c3`.
It read the changed files from that layout, checked the exact path set,
metadata and four cross-inventory source pins, and exercised substituted
predecessor, changed staged bytes and existing-output refusals. It did not
stage a second copy or rerun earlier caller, worker or package checks.

1. **D2:** Next bind the raw output observation to independent private
   retention and replay for this candidate; the public digest is not the
   observation. Actual installed identity, healthy observation, full timing,
   recovery, denials and cleanup still need an authorized pilot. No media
   was built. B49 remains unbound: no allocation, boot or live capture.
   Provider access and the one authorized create need separate explicit limits.
2. **D3:** Finish remaining connected admission, RUN/health and workload coverage.
3. **D4:** Bind all 29 managed requirements to independent verifiers on one
   deployment; freeze only after prerequisites close.
4. **D5:** Obtain separate authorization, then run fresh acceptance, 100 actual
   attempts and 100 task pairs, verify cleanup and independently replay the evidence.
