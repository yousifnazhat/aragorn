# D2 batch 64 — complete physical inputs for the protected host and split worker

Parent: signed `82af7c8873155207d94184a52a3697094466d865` (B63 source
`52d17288a46675a163b9639a0f9a0f04ee8f0e04`). A fresh private directory
now contains a full `root/` and canonical `payload.json` in the existing B41
immutable-image assembler's input format, not another delta. It combines the
original B41 files, B63 replacements, and actual B53 archive member bytes.
The manifest and every staged file were read back. No disk was rebuilt.

| Guest pathname | What is staged |
|---|---|
| `/var/lib/aragorn/pi-os` | Nine B3 OS files. The launcher's eight required mountpoints are empty. |
| `/var/lib/aragorn/pi-runtime` | Four B36 files, including the gate, Node and admitted-runtime bundle bytes. This is a separate source for the read-only bind, **not** a bundle admission record. |
| `/etc/aragorn/approvals`, `/var/lib/aragorn-capture-claims` | Empty root-private mountpoints. No release or spent marker exists; the B62 release must name an actual guest boot. |
| `/var/lib/aragorn/admitted`, `/var/lib/aragorn-runtime-action`, `/var/lib/aragorn-runtime-provider` | Empty outer guest destinations. No bundle, service volume, grant, journal or policy was installed. |

The two outer worker directories use mode 0755, as required by the launcher's
root-owner check; descendants use directories 0555 and files 0444/0555.
Read-only *mounts* remain an independent operational requirement. The pinned
181,293-entry original guest inventory was checked for collisions or nonphysical
ancestors before publishing. No writable state, ledger, evidence store or
bootstrap socket was embedded in the worker. The `/run` anchor and
plan-selected raw evidence paths must be provisioned separately.

Retained: `~/Library/Application Support/Aragorn-B64-Offline/`.
The [independently computed manifest pin](../../../packaging/pi-core/split-guest-payload-b64.json)
is `7cde35a23833f7f68ab2589479d09c508304ac1ddabc747319553bf7df244ab4`
(909 entries, 818 regular files, 183,983,962 file bytes). The local
`outcome.json` is `18dd1e8d57a4ca40e1f6bdbe188fe2ad647fed7386ca66793b74d08436916f38`.
Recorded root ownership describes the guest manifest, **not** root ownership
on the developer's Mac or an observed guest installation.

| Affected stage | Passed | Retained fingerprint |
|---|---:|---|
| `pi-core-split-guest-inputs` | 10 | `04aae0bed7673922a9adf73c7f5bf440507ec14400328845c75644befef60fbe` |
| `pi-core-split-guest-preparation` | 1 | `9cf59a04f5149bdea5adfee11010ff3dba1765c9b5e5176b830a096138a53ea2` |
| `pipeline-capacity` | 4 | `860eb56e86a04bb84a70bfa6fdf805d586781c5dcf63c04448e491e560433fbb` |

1. **D2 open.** Connect the protected service image/configuration to this same
   candidate, plus the storage and evidence topology. Then bind media, firmware
   and owner to the actual successor, not the old compatibility boot. No
   installed observation, recovery, timing or useful pilot has taken place.
2. **D3 open.** Complete admission, RUN/health and workload paths on that deployment.
3. **D4 not frozen.** Close independent verifier coverage for all 29 requirements.
4. **D5 not authorized.** Fresh surface acceptance, 100 attempts and 100 pairs,
   cleanup, restoration and independent replay follow freeze and separate approval.

B49 unchanged; no spending, boot, mount, capture, provider or live operation.
