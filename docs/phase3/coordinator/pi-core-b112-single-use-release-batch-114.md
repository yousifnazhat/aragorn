# B114 — one-time release preparation and replay for B112

This is the **offline engineering** step after [the B113 host binding](pi-core-b112-host-binding-batch-113.md).
It targets the B112 ARM64 disk (`aae016bd1b7ef412e619bd82adc6cb9b436349fe9bfe48a0a0ba091e8b646cec`),
not the frozen B44/B50 disk. The checked-in [build seal](../../../packaging/pi-core/immutable-host-b114/build-seal.json)
has no approval. It is not a grant, an enrolled firmware store, or a runner with
a slot. The existing B113 executable still has **zero** authorized attempts.

## How authority and evidence fit together

| Boundary | What needs to agree |
|---|---|
| Before an issued build | An operator nominates the exact prebuild commit and trusted signer. A custodian must verify the underlying private nomination, enrollment and boot decision. Their separate digests and the one release digest belong in the signed seal. Git signature verification does not verify the underlying decisions. |
| Build | The [builder](../../../scripts/prepare_pi_core_b114_owner.py) derives the candidate from the pinned B113 native inputs. One private slot binds the attempt UUID, host and fixture, disk and store identities, firmware policy, and half-open UTC window. The held artifact is not converted in place. |
| Replay | The [reader](../../../scripts/verify_pi_core_b114_boot_evidence.py) needs the separately signed artifact, matching earlier prebuild approval, the private grant, an independently nominated pre-attempt record, and an original archive. A host transcript and a guest serial finding answer different questions. Neither grants a retry or proves restoration. |

The single-use guarantee assumes an exclusively owned, non-rewound host and
retained private reservations. A lost or rolled-back host, missing record or
ambiguous outcome is a reconciliation problem, not authority to rebuild or boot
again. The guest serial format cannot attest its own containing EFI image. Local
code signing is not Developer ID, proof of distribution or an off-host witness.

The prebuild review covers 36 input files, including the seal, the new source
and the frozen B112/B113 inputs from `ff6f08a`. The issued artifact catalog
is a later output, never its own input. A future custodian must authenticate
the original decision records and retain the signed prebuild commit externally.
A separately signed descendant would publish only the verified receipt, not the
private grant or executable. A signed software merge without an approved seal
cannot issue a slot.

A future authorized build reserves both the attempt UUID and the release
digest before compilation. A partial build leaves both existing claims intact;
no alternate tool path, commit or reformatted grant authorizes a retry. The
private executable, source material and receipt must be retained where the
verifier can check them without running the executable. The replay reader's
`--portable` option applies to the evidence archive only, not to that requirement.

## Affected checks and evidence ceiling

| New pipeline stage | Passed | Fingerprint (SHA-256) |
|---|---:|---|
| `pi-core-b114-b112-release-seal-offline` | 6 | `d2d5c238f8505c2ad0f1b3c5c65e99ef2c2d23c6a53db0f75aef0b8f3af8fa9f` |
| `pi-core-b114-b112-one-time-builder-offline` | 5 | `7a9d0fd24380e8383c2e959b0a0f36a9f3e2a4a5079f7cae77c27445bd876056` |
| `pi-core-b114-b112-issued-replay-offline` | 5 | `27d4a59fa7d962b90a61f61c01d2e01b5c46da05c7fdd5396992c44b628b2df0` |

All passed on their first runs. The new tests used inert in-memory grants,
spent-claim fixtures, and synthetic wire records, not a signed private
decision or a captured boot. The builder's real receipt format was used in
the replay tests. No compiler or target runner ran, no B112 media verification
was repeated, and no B114 singleton, real host transcript or guest evidence
exists from this batch. No B49 values were changed.

## Remaining plan

1. **D2:** Before any real release, privately bind the host, budget/window,
   evidence destination and cleanup owner. Allocation, enrollment and one bounded
   compatibility boot require their own scoped authorizations. A boot is not the
   useful pilot: that still needs installed identity and sensor health, measured
   timing and recovery, a separately bounded provider call and file effect, and
   independent output, denial and cleanup evidence.
2. **D3:** Complete remaining admission, RUN/health and workload coverage on the
   common deployment.
3. **D4:** Close independent evidence coverage for all 29 managed requirements,
   then freeze the deployment once.
4. **D5:** After separate authorization, run fresh acceptance, 100 actual attempts
   and 100 baseline/instrumented pairs; verify cleanup and replay independently.
