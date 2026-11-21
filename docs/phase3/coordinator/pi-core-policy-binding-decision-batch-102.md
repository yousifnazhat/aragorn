# B102 — one deployment digest is being used for two different policies

**Decision needed.** A genuine protected install and a provider-enabled
calculate-and-save action cannot use the same managed deployment as currently
wired. The problem is not a missing key or an unselected model. Do not try to
fix it by assigning a test digest to both policies.

| Boundary | What the connected source checks |
|---|---|
| Install | The [installer](../../../src/aragorn/pi_core_bundle_install_entry.py) compares the install context's policy digest with `deployment["policy"]`. [Context verification](../../../src/aragorn/protected_install_context.py) passes it to [decision replay](../../../src/aragorn/decision_receipt.py), which reads the original CAS bytes. The [admission parser](../../../src/aragorn/admission_decision.py) requires `aragorn/policy/v1` or `/v2`. |
| Launch | The [bundle launcher](../../../src/aragorn/pi_core_bundle_launch.py) checks the same equality before preparing the worker. Its activation carries that same deployment policy digest. |
| Provider | The [protected approval](../../../src/aragorn/pi_core_provider_approval.py) reads the actual runtime policy, checks its digest against the requested action and binds the request to the activation via [mediation](../../../src/aragorn/pi_core_provider_mediation.py). The [runtime parser](../../../src/aragorn/runtime_action_decision.py) requires `aragorn/runtime-action-policy/v1`. |
| File action | The [managed bootstrap](../../../src/aragorn/pi_core_managed_bootstrap.py) and [request handoff](../../../src/aragorn/pi_core_request_handoff.py) also join the grant/worker binding's policy digest to the activation. A separate provider control directory does not split these identities. |

The schema discriminators and required fields differ. One canonical JSON
document cannot satisfy both validators. The [approved SDD](../../design/pi-core-managed-capability-sdd-v1.md)
specifies seven deployment dimensions but no two-policy format. B99 and B100
remain valid for their narrower findings: agreement between recorded requests,
and historical admission replay, respectively. Neither replay took real policy
bytes through both production validators for one installed worker.

## Proposed decision (not adopted)

Keep the seven dimensions. Let the managed deployment's `policy` digest name
a versioned, canonical two-member manifest: one digest for the original admission
policy and one for the original runtime-action policy. No document may select
its own expected digest. Verify the manifest against the independently nominated
deployment. The installer must consume its admission member; the broker,
provider and runtime grant must consume its runtime member. The worker
activation must bind the whole deployment and the runtime member. A change to
either policy must change the deployment identity. No fallback to accepting
either digest, and no change to the historical OpenClaw contract.

An alternative is to retain the admission digest as the deployment's `policy`
and bind the runtime digest through a versioned protected configuration. That
requires proving the runtime selection is covered by the existing deployment
configuration identity, not just present in a service file. Neither option is
implemented or implied by prior pilot approvals.

After approval, connect the selected binding through install, launch, grant,
provider and independent replay before preparing successor inventories. The
first affected check should pass two *distinct, valid* policy documents
through their real validators for one deployment and reject missing, swapped
or changed members. Do not use a fixture-only positive to advance the pilot.

1. **D2:** Resolve this policy decision first; the bounded worker receipt,
   independent output observation, storage custody, sensor health, timing,
   recovery and a separately authorized pilot remain open. B49 stays null.
2. **D3:** Finish admission, RUN/health and workload coverage on the common deployment.
3. **D4:** Verify the full 29-requirement inventory and freeze once.
4. **D5:** Obtain separate authorization for fresh acceptance, 100 attempts,
   100 task pairs, cleanup verification and replay.

This is a source-trace and decision checkpoint. No implementation, tests,
rebuild, guest, capture, provider request or spend.
