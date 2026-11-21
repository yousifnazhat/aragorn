# D2 batch 60 — pin the stopped-worker observer for the immutable host

Signed parent: `241427f8cf1237015b7dba2df214bc843b17ed99`. The B55 storage
admission result remains intact; neither that stage nor B59 was rerun. Starting
from the B41 payload and the B53 plan, this offline preparation changed **two
Python sources, added nine, and replaced the host profile**. The changed files
are retained at `~/Library/Application Support/Aragorn-B60-Offline/changed-files/`.
This is input for the immutable-image assembler, not an installer or a bootable image.
Never copy over a live or retained predecessor. No B49 binding changed.

| Retained file in the same directory as `outcome.json` | SHA-256 | Scope |
|---|---|---|
| `coordinator-host.json` | `196c83779a50be791477d269a44b6095dfe02939ebb62f44a9b21aae04ca277c` | Full successor profile, 802 paths, including 113 reviewed repository source/wrapper paths. |
| `payload.json` | `4040b02c5deafc78f5416951942923c22b0f6f2ddb51244dd46129943260d6be` | Full expected physical payload, 862 entries. The changed-files subtree was read back. |
| `worker-source-plan.json` | `2f61a4a6bb4f4dc6f5554435fe3825a3390990af759e9cb9826bf18fcaea90ec` | Accepted by the existing plan parser. Only the observer pin changed; no worker, loader or bundle rebuild. |
| `helper-inputs.json` | `d2ad83195f13cb1f1f78e2c15d8c4497b517b734257bdeb311425a94248ed758` | Static readback of 28 helper-related ARM64 inputs and 27 declared native dependency pairs. Not an import or process trace. |

The source identities were derived from signed tree `be952dd4fd9eb2e8d7265ea2bf3da883194c9e7c`.
The embedded helper was extracted as a literal without executing it
(`aef5d0aebb0c1d98d91da4c627c51b991f902baf2c3005a473bf4fcaaf693725`).
The interpreter digest is `7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57`.
The original complete import-tree and ABI pins are reused; neither Linux, the helper
nor the target interpreter ran. The full successor disk, installed export,
runtime loading, current evidence head and host approval are not claimed.

| Affected stage | First-run passes | Retained fingerprint |
|---|---:|---|
| `pi-core-mask-host-inputs-offline` | 5 | `a69387987a9732444e263b3907e410ff255142df44de16915a21e688c619acf8` |
| `pi-core-mask-host-materialization-offline` | 1 | `b0f77c3b6c19ae7f45b5928239b9ce553abd57cf9c50ba628666f25dbf86384c` |
| `pipeline-capacity` | 4 | `a1c952bbdba8a7a6eb8e480bac6cac7079aa3ce7650a6ba72d6f1fe4866fffb7` |

1. **D2:** connect the capture under protected authority, join the full worker walk,
   raw observations and independent current head; prepare the pilot successor.
   Installed isolation, sensor health, recovery/timing and the useful pilot still need evidence.
2. **D3:** complete common-deployment admission, RUN/health, and workload paths.
3. **D4:** close executable coverage and independent review of the 29 requirements; then freeze.
4. **D5:** after separate authorization run fresh admission, 100 attempts and 100 task pairs,
   verify thresholds, cleanup, restoration and independent replay.
