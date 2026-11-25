# Recorded admission in the managed Phase 3 qualifier

For `MP1/ADM-01/exact-admitted-bytes`, the [coordinator entrypoint](../../../scripts/verify_pi_core_recorded_admission.py)
connects the existing B104 install/action reader to the existing 29-requirement composer.
The install producer addresses the flat seven deployment bindings. The composer
addresses their versioned envelope. The reader validates the exact seven fields,
wraps them and compares their canonical digest to the operator's D4 deployment
identity. A different worker in an otherwise matching deployment refuses.

Call `qualify_with_recorded_admission` with the usual managed qualifier arguments,
the other 28 verifiers and the operator-reviewed `verifier_source_digest`
(`sha256:84856572b3403b56a7b4929e663710368fae5591defb156dc797385cf9329d06` for this revision).
Nominate the digest of **canonical JSON without a trailing LF** in
`evidence_by_requirement["MP1/ADM-01/exact-admitted-bytes"]`. Its exact keys
are `schema` (`aragorn/pi-core-recorded-admission-inputs/v1`), `owner_pin`,
`plan_pin` (install plan), `context_pin`, `manifest_pin`, `action_nomination_pin`
and `deployment_pin` (flat binding document). Obtain all nominations independently
of the submission. A verdict or verifier name in the evidence is not an input.
Other callers and the legacy contract are unchanged.

Agreement replays the admission decision, installed transaction and recorded
action, not physical acquisition or consumption of the complete closure. The
result stays **NOT_TESTED**, so quantitative results cannot promote it. The
source pin identifies a file, not an attestation of its transitive dependencies.

Only `pi-core-recorded-admission-offline` ran: four tests passed, fingerprint
`d2a395777904a18354ec589a30bfb9fdd282696b23105a73d4e7283414497d7d`.
They used original-format inert records and the actual composer. The first run
failed on the missing entrypoint. The next correctly refused the newer B111
wrapper: the independent predecessor reader does not recognize its bytes. The
test now uses the original locally retained Git blob of the accepted B85
report producer, checked by SHA-256 before import; no production pin was relaxed.
The stage also refuses a mismatched original transaction, a forged verdict,
a duplicate verifier selection and an unreviewed verifier source.

1. **D2:** no installed or useful pilot evidence. B49 and pilot authorization remain held.
2. **D3:** admission, RUN/health and actual measured workload coverage remain open.
3. **D4:** bounded ADM-01 replay connected, not qualified. Still need independent
   consumed-source/custody evidence on the selected deployment and the rest of the inventory before freeze.
4. **D5:** no fresh samples or cleanup/replay evidence; separate authorization after freeze.
