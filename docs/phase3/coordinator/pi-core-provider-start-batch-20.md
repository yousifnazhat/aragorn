# Pi-core batch 20: owned provider listener and protected START

Base: verified signed integration `ab7e8bfa610935d10dfe0485a736e76b4aa4801a`.
Scope: additive offline native provider/START wiring, only new/affected checks,
signed source/integration delivery. No VM, service, live socket, provider call,
credential access, target build/execution or qualification is authorized.

## Connected scope and ownership

The provider lane owns `pi_core_native_provider.py`, its new focused tests and
[handoff](pi-core-native-provider-handoff.md). The START lane owns the additive
Python configuration/exchange and TypeScript entrypoint, its new inert fixture,
focused tests and [handoff](pi-core-provider-start-handoff.md). The coordinator
owns supervisor/request/observer joins, exact payload mediation, the existing
managed-bootstrap refusal, shared registry, integration tests and delivery.
Independent review is read-only; lanes do not schedule checks or mutate Git.

One absent-only `provider/provider.sock` lives under the held bootstrap namespace.
Its owner borrows the exact authenticated service lifetime and delegates to the
existing protected mediator and OpenAI Responses service. It does not replace
the security core, provide an arbitrary callback or close borrowed channels.

Protected START v3 binds the prepared prompt, task, model, route and one-call
budget. Existing v1/v2 bootstrap stays unavailable. The exact native dispatch and
held source observer must be ready before START; complete source-health progress
is checked before protected work, after dynamic provider sources can load.
One deadline is anchored externally at START and shared by provider/action I/O;
later calls cannot renew it. The actual outgoing normalized Pi transcript must
equal the held prepared request before root approval, durable budget consumption
or provider handoff.

Provider dispatch precedes action handling. Authenticated terminal receipt,
permanent provider retirement, successful delivery and current source health are
required before protected action. Broker/sensor custody remains held. Missing,
changed or retired listener ownership refuses source-channel recognition.
Failed accept consumes the provider attempt; ambiguous service/delivery/cleanup
retains a hold. Both owned endpoint cleanups precede RELEASE and unit cleanup.
Worker summaries cannot substitute for authenticated provider/action evidence.

The existing high-level managed service bootstrap explicitly refuses enabled
provider configuration **before activation**. Its fixed units are still
credential-free and network-isolated. A successor must provision the exact
credential, approved narrow egress and root-owned provider approval/control
state, then pass the same held service lease to this native caller. An action
service's nonroot broker configuration cannot stand in for that root data gate.

## Review and verification

Static cross-lane review corrected two defects before checks: Pi's user task is
a text-block array, not a scalar string, and `maxRunMs` must constrain the native
provider/action deadline as well as the worker's local timer. The real pinned Pi
fixture and native request projection are compared within one existing new case.
Review also replaced a supervisor call to the observer's thread-private budget
guard with bounded, exact Node-owner custody inspection. Full source health
continues through the existing owner-thread command path before protected work.

The three new stages are `pi-core-native-provider-offline`,
`pi-core-provider-start-offline` and `pi-core-native-provider-wiring-offline`.
The only existing selection is the four affected `pipeline-capacity` cases for
the bounded increase from 187 to 190. Explicit reviewed input lists include
transitive local Python imports, helper scripts, new fixtures and pinned Node
toolchain/dependency declarations. No old behavioral stage is scheduled.

**94 distinct new/affected checks passed.** Initial execution retained 21 native
provider passes before a missing Linux-only socket constant in the Mac fixture
interrupted that module. START retained 25 passes, including every real pinned
Pi case; only the invalid-route assertion expected the wrong exception class.
The 25 wiring checks and four capacity checks passed on their first execution.

Only those two fixture defects were corrected; production source stayed
unchanged. Narrow selector modules then ran the corrected provider case plus
17 previously unreached cases, and the single corrected START assertion. No
successful behavioral check or Node fixture was rerun. The original failures
and successful per-case logs remain retained, not overwritten or promoted into
full-stage passes. The changed helper-test file means the original wiring-stage
fingerprint is not a current whole-closure cache hit; its unchanged executable
checks and production inputs were reviewed against the retained passing run.
This is not a claim that the entire new fingerprint was executed.

| Selection | Retained result | SHA-256 fingerprint |
| --- | --- | --- |
| Initial native provider | FAIL; 21 methods passed, then fixture interruption | `f3b6a752b22e7c406015bba340152ae64b64671bc6bf98b9f23f5f3bc85170d1` |
| Native provider corrected/unreached only | 18 PASS | `3b94576208bc51570c4d56b475254dae53b759b354da993e636270ad2e0f72b0` |
| Initial START | FAIL; 25 methods passed, one assertion error | `dcb9a1489bf3c4a7e509420351720c4f4b16c5bbd6e4dd269b31490ce14195b3` |
| START corrected assertion only | 1 PASS | `ec59f557f004c59509d84bd1c3b17112c9b8d90b2ddeacbf8b70c24aa087207f` |
| Native wiring | 25 PASS | `cb5cb80c6a78dc87cc23d225a98b2ab19c594458c218ba6d4f9254fe80bf0601` |
| Pipeline capacity | 4 PASS | `0f79237355a484b5fe0cb6d939e3a8d9251d2df4542c7a740d0a788a11453dfb` |

Only these pipeline selections executed, in order:

```sh
/opt/homebrew/bin/python3 -B scripts/phase3_pipeline.py run pi-core-native-provider-offline pi-core-provider-start-offline pi-core-native-provider-wiring-offline pipeline-capacity
/opt/homebrew/bin/python3 -B scripts/phase3_pipeline.py run pi-core-native-provider-offline pi-core-provider-start-offline
```

For the second command, the registry explicitly names only the two narrow
remaining/repaired selector modules. All logs are under the matching stage and
fingerprint in `.aragorn/phase3-pipeline/`. No cache record was removed, modified
or retried unchanged. The tests use authored objects/OS peers; they do not prove real source consumption,
sensor health, provider delivery, useful work, recovery, timing or cleanup.
Predecessor artifacts, previous successes/failures and unrelated drafts remain.

Signed source/merge hashes and exact remote readback will be retained in
`.aragorn/pi-core-provider-start-batch-20-release.json` and the chat checkpoint.

## Remaining plan

1. **D2:** finish protected credential/egress/approval lifecycle and its managed
   caller; assemble the common changed-artifact successor, install and prepare
   exact protected inventories under separate authority; establish actual Node
   route/kernel feasibility, recovery and full timings. Then the separately
   authorized useful calculate-and-save pilot, denial cases and verified cleanup.
2. **D3:** remaining managed admission, seven RUN event classes/six responses,
   HTTP/DNS/truncate/unlink and actual paired-task contexts on that deployment.
3. **D4:** complete executable 29-requirement surface mapping and independent
   producer/evidence/verifier inventory; resolve prerequisites and freeze once.
4. **D5:** separately authorized fresh managed acceptance, 100 actual attempts,
   100 actual pairs, unchanged thresholds, retained failed/indeterminate samples,
   cleanup/prior-state restoration and independent offline replay.
