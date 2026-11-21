# D2 batch 61 — cross-check the full archive and the stopped-worker receipt

Signed parent: `ec17512557214fb6f2ac43c9cd5d3cccad9a3710`. This reader runs on
the verification side, not in the guest. Neither B60's packaged host files
nor any historical reader, receipt or B49 field was changed.

Use `python -m scripts.verify_pi_core_joined_mask_receipts` with:

| Inputs | Source |
|---|---|
| `--archive`, `--profile-pin`, `--latest-pin`, `--witness-pin` | Existing read-only B58 archive and the separately obtained expected profile, independent current head and outer mask witness digests. |
| `--store`, `--receipt-directory`, `--capture-pin`, `--receipt-pin` | B59 observer's private local content store, its separate receipt directory, and the expected capture-binding and receipt digests. |

Supply absolute, existing directory paths. The command neither creates a store
nor looks up a missing pin. It runs the complete B58 v2 admission check and
replays B59's original retained observations. It then requires agreement on
the deployment, boot, both principals and namespaces, mapped state device,
ordered backing devices, filesystem type, exact raw worker and manager mount
streams, exact mask witness, worker root, device-directory identity and **both
complete device-name lists** in the full walk. A local success cannot cover
up a missing sensor-role mount or an extra exposed state path in the other archive.

The five pins have different meanings. In particular the B59 source-observation
profile is not the B58 pilot profile, and the B59 binding digest is not the
B58 role-capture digest. The B58 format carries no full-walk observation
interval or matching systemd invocation. Matching bytes do not prove that
everything was observed simultaneously, that the latest pin is fresh, or
that a second administrator controls the receipt. The report means only
consistent offline records. No code identity, live isolation, recovery,
authorization or qualification is awarded.

| Affected stage | First-run passes | Retained fingerprint |
|---|---:|---|
| `pi-core-joined-mask-receipts-offline` | 7 | `c7f31dc6b60129e10983b7526b472e903d6d29f47f8e8335410a5e203793820a` |
| `pipeline-capacity` (291 slots) | 4 | `2165c75d4ef7ebd4eca7acc5250a51869af4e19a284ac94f4495de0d15efc215` |

The seven checks used private temporary stores and inert records, not an installed
worker. They include individually resealed but mismatched inputs, missing
receipts, an incomplete full walk, and a positive comparison with writes
disabled. No previous acceptance or acquisition stage was run.

1. **D2:** connect the protected caller and acquire the complete role and
   worker evidence for one deployment. Actual external freshness, installed
   identity, health, recovery, timing and the useful pilot remain outstanding.
2. **D3:** complete admission, RUN/health and real workload coverage.
3. **D4:** close all 29 independent verifier mappings; then freeze.
4. **D5:** separate approval for fresh acceptance, 100 attempts, 100 paired
   tasks, verified cleanup, restoration and independent replay.
