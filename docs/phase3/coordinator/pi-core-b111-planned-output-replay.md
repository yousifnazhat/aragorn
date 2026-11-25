# Replay the original B111 plan with a privately retained pilot result

The [existing private-output command](../../../scripts/verify_pi_core_b109_retained_output.py)
previously verified that the original receipt referenced the nominated attempt-plan
digest without interpreting that plan. Add `--b111-plan-path /absolute/guest/plan.json`
to the same invocation to require the original canonical plan bytes in the private
read-only **action archive**, addressed by the same independent `--plan-pin`.
The guest pathname is used only for lexical alias checks. No guest path, credential,
service or sink is opened. Keep the plan private: its configuration is not public evidence.

This mode checks the B111 host-profile pin (not the B109 base), the retained B109
service manifest/binding/layout receipt, and the pinned independent output reader.
The protected plan must name exactly the deployment and output directory/file in the
existing action/provider/output replay. Its install context must match the original
activation read from the action archive. A mismatch refuses; there is no fallback
to digest-only replay or second attempt. Without the option the B110 result is unchanged.

Only the listed fields of the original **recorded plan** are matched. The launch,
provider inputs and approval references are not replayed here. This does not authenticate the
installation, prove that the guest ran that plan, authorize a release, verify physical
custody or cleanup, or qualify a file effect. In particular, it does not make B111
a supported install producer for the historical B104 admission reader.

## Focused checks

The new stage failed on the missing option. Review found that the host digest
also needed to be distinct from the release; a failing check reproduced that
case before the fix. The final stage passed five inert checks
(`pi-core-b111-planned-output-offline`,
`5e4d23dac7fe353c132b2bb061bc46202c6725409cf805364cb3c69d3e2e2d5e`).
The successful case used the original-format private receipt and read the result
after the fixture sink was removed. Three independently sealed sets of fixture
records with the wrong install context, predecessor host, or different directory
were refused. The three affected legacy API/custody checks also passed on the final source
(`pi-core-b110-private-replay-offline`,
`5a244a40cb4485a51c14dd035a8bf20a1f582745a7b0fdd1fe975bd79dfe5bd5`).

1. **D2:** plan-to-result replay connected. A compatible local host and the pilot
   configuration are not approved; the B112 compatibility graph alone cannot run
   the useful task. Still need actual installed identity, healthy observation,
   output/denial, recovery, full timing and cleanup evidence.
2. **D3:** the measured task carrier and copy-directory custodian are unselected;
   see [the two execution choices](pi-core-managed-task-output-batch-90.md).
   Admission, RUN/health and workload paths remain open.
3. **D4:** [bounded admission replay](pi-core-recorded-admission-replay.md) is not a
   replacement for full source consumption. No verifier inventory closure or freeze.
4. **D5:** no samples taken; fresh acceptance still needs a freeze and separate authorization.
