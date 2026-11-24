# B111 — one host successor for private pilot-output retention

The [preparer](../../../scripts/prepare_pi_core_b111_payload.py) stages the
ordinary host wrapper, its retention entry and the custody module from signed
merge `2aba715e7bd90f0309891686c791b2b438785f58`. The
[source catalog](../../../packaging/pi-core/managed-sources-b111.json) binds the
three Git blobs and the full host import inventory. The original B109 service
binding supplies its 119 source pins, and its three rendered role wrappers are
reused byte-for-byte. Neither retention module is added to a service or to Pi.

The publisher created `~/Library/Application Support/Aragorn-B111-Offline/`
once. Relative to B109, only four paths differ: two new host-only module files,
the updated wrapper, and the host profile that pins them. All 37 worker rows,
the native binaries and the 807-file service manifest are unchanged. This is a
non-bootable staged layout, not an installation, pilot observation or release.

| Artifact | SHA-256 |
|---|---|
| B111 host profile (819 files) | `5105455ffdb8bc0c0c8e28863230ac7539be0a8d499d31208434b3fa732080c9` |
| B111 payload (1,791 entries) | `ea17bce82e6044ac29fef1d1e893d347272cff2054298f26ed1c10c487360fa0` |
| B111 preparation outcome | `e8c292f30ed8442db237749711f6ed1e64523697eb568bcfe8e44dbfc7e5b2d3` |

The [independent payload review](../../../packaging/pi-core/managed-payload-b111.json)
also lists the unchanged service manifest, binding and layout receipt digests.
A future B110-style retention release would bind **B111** as its actual host
profile and **B109** as its base payload. Neither digest is the separate
seven-field deployment identity. Do not substitute this checkpoint for an
installed identity, the B106 worker receipt, a private release or an off-host witness.

Only `pi-core-b111-host-successor-offline` ran: **4/4 passed on the first run**,
fingerprint `8639e961d7cd8d03b3203dba47f8444954991344b52d1bc6542a868365a5e445`.
The checks read the actual staged delta, compared its signed host bytes and the
B109 service/worker pins, and verified refusal of a substituted predecessor,
a corrupted staged profile and an occupied destination. No historical checks,
duplicate preparations, media build, boot, provider call or live operation ran.

### Remaining plan

1. **D2:** Use B111 as the input to successor media preparation; do not rebuild
   the unchanged worker or services. B49 still has no approved host, budget/window,
   private evidence destination or cleanup owner. Installed source and health
   observation, full timing/recovery, the calculate-and-save pilot, denials and
   cleanup remain to be evidenced. The bounded provider request and file create
   require separate approval.
2. **D3:** Finish the remaining connected admission, RUN/health and workload paths.
3. **D4:** Close all 29 managed requirements against independently verified
   evidence from one deployment, then freeze it.
4. **D5:** Obtain separate authorization for fresh acceptance, 100 actual attempts,
   100 task pairs, cleanup and independent replay.
