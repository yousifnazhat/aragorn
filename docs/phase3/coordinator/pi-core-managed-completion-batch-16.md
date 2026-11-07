# Pi-core batch 16: one-shot completion, terminal custody and managed qualification

Base: signed integration `3a56d30767821062239d8a05b018714e2fb904e6`.
Scope: reviewed offline source implementation, not activation or qualification.
Three nonoverlapping coding lanes were reviewed together before delivery.

## Delivered changes

1. **One-shot Pi completion:** the existing protected entry opts into the pinned
   Pi engine's supported `finishTurn` hook after one completed ALLOW tool reply.
   It settles normally without an abort, second provider call or result rewrite.
   The option requires exactly one turn and one tool call; existing default,
   refusal, cancellation, deadline and indeterminate-effect behavior remains.
   The report is correlation-only, never independent effect or useful-task proof.
2. **Authenticated provider retirement:** channel custody now passes its exact
   retirement transition through service lifecycle checks. Only the captured
   provider may exit or have its transient unit collected after the authenticated
   terminal result. Original unit/process/cgroup/immutable configuration joins
   remain; broker and sensor still require live protected custody. Retirement
   does not release handles, claim cleanup, enable another request or renew time.
3. **Managed qualification entrypoint:** the additive
   `qualify_pi_core_phase3_exit` implements `pi-core-managed-phase3/v1`. Its fixed
   manifest requires exactly 29 MP1 requirements, all 12 designed surface groups,
   supported and denied surfaces, seven deployment bindings and independently
   selected source-pinned semantic consumers. The original 48-ID/OpenClaw
   contract is preserved through shared composition, not relabelled.

The managed campaign pins exactly 25 HTTP, DNS, truncate and unlink attempts;
25 pairs per existing reference task; the genuine destructive unattributed
control; and baseline-first real intervals. Existing arithmetic and thresholds
are reused unchanged. Raw evidence, source-bound inventory and an independently
reviewed reference-task source pin are required. Missing/extra/duplicate IDs,
N/A, mixed deployment joins, unpinned consumers and forged PASS records cannot
replace the semantic consumers. There is no default production verifier registry.

Code review caught the descriptor self-pin weakness before tests: descriptors
now have to match a separate operator-held reference-task source pin. Core
deployment/schedule/metrics pins are checked before semantic callbacks, and
managed context cannot overwrite core evidence bindings. Independent cross-review
found no remaining blocker in these changed paths.

Detailed lane contracts and trust limits:

- [One-shot completion](pi-core-one-shot-handoff.md)
- [Provider terminal custody](pi-core-service-retirement-handoff.md)
- [Managed qualification](pi-core-managed-qualification-handoff.md)

## Focused verification

**97 distinct focused checks passed, each once**, through the reviewed
`scripts/phase3_pipeline.py` registry. No failed fingerprint or test was rerun.

| Stage | Checks | SHA-256 fingerprint |
| --- | ---: | --- |
| `pi-core-one-shot-completion-offline` | 17 | `92760ef201e3b4650cb7ef7c97264aa2f7b52da867e3947e4c0c011c8f787457` |
| `pi-core-service-retirement-offline` | 33 | `c899eaa799c514dd576e20fe3b18ed9896b914b35b04a9b9d919dc98cd738fec` |
| `pi-core-managed-qualification-offline` | 43 | `40225470612616633e7a1801d9520e23667a9a64497b4d2055e390040364174a` |
| `pipeline-capacity` | 4 | `80e0777ff6736b08bffa66c0ddb92e5239ce54ee4c036607aec783b9c40e2f95` |

The managed stage includes 40 new cases and exactly three affected legacy
composition cases. The one-shot stage runs 19 bounded in-memory scenarios across
17 methods with the actual pinned Pi lifecycle. Retirement uses inert kernel
and service observations. Capacity checks cover the exact increase from 176 to
179 registered stages. No broad suite, whole-schema sweep or unchanged arithmetic
suite ran. Logs/results remain under `.aragorn/phase3-pipeline/` by stage and pin.
Synthetic contract fixtures are developer checks, not replacement final samples.

Signed source/merge hashes, signature results and exact remote readback are
retained in `.aragorn/pi-core-managed-completion-batch-16-release.json` and the
chat milestone. Only explicit batch-owned files are staged. Unrelated drafts,
duplicate-named untracked files, old images and retained evidence are preserved.

## Open boundaries and remaining plan

Native startup is still provider-unavailable. The prior static service image is
retained as its exact predecessor; this source batch neither rebuilds nor labels
that image as containing these new bytes. Changed deployment artifacts should be
assembled once the connected successor source batch is ready, not recaptured now.
No service, VM, provider key, network request or protected effect was activated.

1. **D2:** independent completed worker source-read evidence and meaningful
   progress/loss accounting; owned provider listener/native dispatch and additive
   enabled START; provider-only credential/egress profile; recovery and full
   timing. Then the separately authorized calculate-and-save pilot in the fresh
   dedicated Linux arm64/systemd VM with approved model, trust/address, spending,
   ownership and cleanup inputs. D2 is not closed.
2. **D3:** complete connected managed admission, all seven RUN event classes and
   six responses, HTTP/DNS/truncate/unlink coverage and real paired-task contexts.
3. **D4:** executable managed contract is implemented; the full real
   producer/evidence/independent-consumer inventory and concrete surface freeze
   remain. Close D2/D3 prerequisites and freeze one common deployment once.
4. **D5:** separately authorized fresh managed surface acceptance, 100 actual
   attempts and 100 actual pairs with unchanged thresholds; retain failures and
   ambiguity, verify cleanup/prior state, and independently replay offline.

The critical source-observation gap remains engineering work. Fanotify-only
access notifications cannot honestly replace completed source-delivery evidence
and complete loss accounting. Worker self-reports or `/proc` file hashes alone
remain insufficient. Even completed source delivery is not proof of arbitrary
in-memory JavaScript behavior. No Phase 4, production release or universal EDR
readiness is claimed.
