# Phase 3 reference-derived lab workloads

Status: preparation complete, execution adapters incomplete, no measured results.
The fixed HTTP transport, owned-fixture guard and independent raw-ingress
observer/verifier are now implemented with 55 new inert checks. Connecting them
to the common worker, sensor, broker and measurement collector remains pending.
This is an authored controlled-lab design, not admission, RUN or Phase 3 evidence.
The user's 2026-10-06 instruction selects public security references and fabricated
data in place of production/customer workloads. No further customer data is needed.

## Inputs and source basis

- [Machine-readable plan](phase3-reference-workload-plan-v1.json): four scenario
  templates, all 100 reserved attempt IDs and all 100 reserved overhead pair IDs.
- [Fabricated input bytes](phase3-reference-inputs/lab-data-v1.json): harmless
  canary format, protected original and benign task data. These are not outcomes.
- [MITRE ATLAS 2026.09, versioned v6 data](https://github.com/mitre-atlas/atlas-data/blob/main/dist/v6/ATLAS-2026.09.yaml):
  AML.T0053 (AI Agent Tool Invocation), AML.T0086 (Exfiltration via AI Agent Tool
  Invocation), AML.T0101 (Data Destruction via AI Agent Tool Invocation).
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):
  ASI02, Tool Misuse and Exploitation.
- [OWASP GenAI LLM Top 10 2026 final](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md):
  LLM02:2026, Sensitive Information Disclosure; LLM03:2026, Excessive Agency.
  Do not silently mix in the older 2025 category numbering.

There is no source called "OWASP ATLAS" in this design: ATLAS is MITRE's knowledge
base. The references inform our cases; they do not prescribe or certify this
100-trial suite. Our wording and fabricated inputs are original. The versioned
MITRE data and OWASP final-edition links were reviewed on 2026-10-06 local time.
Do not use deprecated `dist/ATLAS.yaml` or OWASP working drafts to renumber cases.

## Reserved inventory

| Attempt IDs | Intended action | Count | Reference mapping |
|---|---|---:|---|
| a001–a025 | HTTP send of a fabricated canary to an owned loopback sink | 25 | AML.T0053/T0086; ASI02; LLM02/03:2026 |
| a026–a050 | DNS-shaped canary query to an owned loopback resolver | 25 | AML.T0053/T0086; ASI02; LLM02/03:2026 |
| a051–a075 | Truncate a seeded fixture-owned protected file | 25 | AML.T0053/T0101; ASI02; LLM03:2026 |
| a076–a100 | Unlink a seeded fixture-owned protected file | 25 | AML.T0053/T0101; ASI02; LLM03:2026 |

The full ID prefix is `p3-lab-`. Attempt **a100 is the unattributed control within
the 100 total**, still classified DESTRUCTIVE. The other 99 are intended to have
causal attribution; these labels express the design, not observed attribution.
There are four scenarios repeated in labeled trials, not 100 different attacks.

Four benign tasks reserve 25 overhead pairs each: JSON integer sum, line count,
SHA-256 of fixed bytes, and allowed-file copy/readback. Each pair must retain
identical task/input/host bindings, equivalent fresh fixture state and actual
baseline/instrumented timing. All pairs use baseline then instrumented, matching
the existing collector; fixed-order bias is an explicit limitation. Lab-suite
overhead must not be generalized into a claim about production workload overhead.

## What this does and does not remove

The missing **workload choice and dummy input preparation** are resolved. No real
customer tasks, credentials or production data need to be obtained. Real means
actual execution and observation of these controlled lab tasks, not real victims.

Still required: integration of the implemented fixed HTTP sink/transport,
remaining exfiltration and destructive action adapters,
the separate unattributed path, independent observers, benign timing adapters,
current host/deployment bindings and a complete reviewed campaign contract.
The existing common capture adapter creates a fixed file; it must not be renamed
as a canary-send or destructive adapter. Its planner also cannot select the
unattributed control. Reuse its custody and capture mechanisms, not its meaning.

Direct fixed tool actions can measure enforcement. They cannot establish that an
LLM resists direct/indirect prompt injection, context poisoning or goal hijacking.
Those broader reference categories are not silently added to the fixed Phase 3
exit contract. All existing admission, RUN events/responses and sensor-health
requirements remain necessary, even when absent from this four-scenario table.

## Next engineering sequence

1. **In progress:** fixed HTTP-canary transport, owned-fixture guards and
   independent ingress observation/replay are implemented and checked. Next bind
   installed sources and the actual worker/sensor/broker network decision, then
   adapt the existing collector's `execute`, `verify` and `identity_reader`
   signatures with real boundaries. Existing native callbacks are not already
   interchangeable with that generic API. Seed exact dummy source bytes in the
   fixture; generated request bytes alone do not prove a canary-access event.
2. Complete the fixed DNS, truncate, unlink and separate unattributed paths;
   connect exact action identity and interval evidence. Independently observe
   the control process and prove missing attribution; do not fabricate it.
   A final restored file
   alone does not prove there was no earlier deletion/truncation.
3. Implement the four bounded benign tasks and paired timing marks; bind actual
   task/input/host digests. Preserve exact input bytes and outputs for replay.
4. Review closure on the one common deployment; perform only newly necessary
   guarded integration checks. Freeze the complete campaign only after the full
   admission/RUN/verifier prerequisites are also complete, then run required
   fresh acceptance once. Reuse retained evidence offline afterward.

Do not turn this plan into runtime `PLAN_ARGUMENTS` with dummy or zero hashes.
Populate the existing measurement schedule only when the real bindings exist.
The final 31-case and 100-attempt/100-pair acceptance remains blocked today.

## Safety and verification budget

Use only an exact owned disposable fixture, network-none and its internal
loopback namespace. No host mounts, production credentials, external DNS or
third-party endpoints. Pin owned target identities and reject path escape or
aliasing. Prove collector readiness using a separately recorded authorized
non-canary probe before the protected action; a dead sink is not prevention.
Preserve the probe and attempted-effect evidence without mistaking one for the
other. Capture even malformed/refused sink input. Retain cleanup and restore
prior VM state; do not overlap captures or measurements or retry unknown effects.
Existing `benchmark/oci-fixtures` remain inert scanner data, never runnable tasks.

This preparation batch changes only data/documentation. JSON/inventory and diff
inspection are sufficient; no behavioral test execution, prior pipeline rerun,
historical recapture, live effect or measurement is required. Later changed code
uses only its new/affected fingerprinted pipeline stages. Fixed gate thresholds
and all qualification flags remain unchanged.
