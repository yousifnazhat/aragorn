# D4 B89 — a managed exit must reconstruct the original measurements

The [managed qualifier](../../../src/aragorn/pi_core_phase3_qualification.py)
previously ran the semantic consumers and applied the quantitative thresholds
to a metrics document. A passing document did not require the composer's
caller to supply the original collection. Now a would-be pass must also run
the [existing independent receipt replay](../../../src/aragorn/phase3_measurement_replay.py)
on read-only evidence. A missing collection is a refusal, not a fallback to
aggregates. A failed prerequisite does not trigger a receipt replay.

Supply `measurement_receipts=ManagedMeasurementReceipts(...)` with independently
held inputs, not with a previous replay report. These pins become available
at different times:

| When | What the operator must retain |
| --- | --- |
| Before capture | The reviewed deployment, schedule and metrics implementation; collector and replay code digests; executor, receipt verifier and identity-reader source pins plus the actual independent verifier callable. |
| Before the first operation | The one-use collection **commitment** digest and separately retained readback. |
| After the last operation | The digest of the completed **collection**, including its original ordered receipt references. The completed collection must not be a field of the pre-capture schedule. |

The qualifier snapshots its inputs before semantic callbacks. It compares the
collection with the exact metrics bytes judged for `MP1/MEASUREMENT_SEMANTICS`.
Replay reconstructs 100 attempts and 100 baseline/instrumented pairs from
their original receipts in the committed order. A caller's claimed PASS, a
different qualifying aggregate, or a labeled test collection cannot replace
those bytes. A collection label is a format check, not an attestation.

This does not grant authority to collect anything. Source identities alone
do not establish that a verifier is correct, that an observation came from
the nominated deployment, or that a measured interval covers a real effect.
The seven deployment bindings, 29 managed requirements, independent clock,
protected sink and cleanup evidence, and all quantitative thresholds remain.
The legacy 48-ID entrypoint and standalone replay retain their own contracts.

**Focused offline result:** ten managed composition cases passed, fingerprint
`ba27ef1f5535c3faaa3ae352c09f23c88c1a26728793699aa94d162751b76772`, on the
first run. The archive builder was shared between unit fixtures; the real
replay implementation read only temporary test records. Neither the
collector, the broad managed suites nor the legacy qualification suite ran.

1. D2: the approved bundle is now checked in strict worker replay. The fixed
   worker observation and its private recording, installed health, recovery,
   timing and useful pilot are outstanding; B49 stays null.
2. D3: connect remaining admission, RUN/health and workload paths to the
   common deployment and its independent observations.
3. D4: the managed exit now requires receipt reconstruction. Complete the
   real per-surface verifier inventory and resolve prerequisites before freeze.
4. D5: separate authorization, fresh acceptance, measured attempts/pairs,
   verified cleanup and final independent replay. No acceptance run occurred.
