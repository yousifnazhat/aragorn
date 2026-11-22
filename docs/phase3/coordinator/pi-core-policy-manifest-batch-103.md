# B103 — bind distinct admission and runtime policies to one managed deployment

This implements the approved option from [B102](pi-core-policy-binding-decision-batch-102.md).
The deployment keeps its seven fields. Its managed `policy` field now pins
canonical JSON with exactly `schema` (`aragorn/pi-core-policy-manifest/v1`),
`admission_policy_digest`, and `runtime_action_policy_digest`. Retain the two
original canonical documents in the nominated CAS, not in the install plan or
worker request. Both are rehashed and checked by their original policy parsers;
there is no bare-policy fallback on the managed install or launch path.

- [Install](../../../src/aragorn/pi_core_bundle_install_entry.py) checks the
  admission context against the admission member before any publication.
- [Preparation and activation](../../../src/aragorn/pi_core_bundle_launch.py)
  require both the admission context and the runtime grant to match their
  respective members. The activation carries the full deployment digest and
  the runtime member; existing broker, request and provider paths keep their
  runtime-pin, actual-policy and grant checks.
- [Install replay](../../../scripts/verify_pi_core_installed_bundle_readback.py)
  distinguishes the reviewed producer revisions by exact source pins. For a
  successor report it checks the original manifest and both policies, and
  `--replay-admission` checks the retained decision with the admission member.
  Historical B76/B85 readback retains its original contract.
- [Action replay](../../../scripts/verify_pi_core_retained_action.py) can require
  `--expected-deployment-digest` from the independent reviewer. It verifies the
  nominated seven-field deployment bytes and joins its runtime member to the
  activation, then uses the existing grant and request replay. Historical
  B93/B99 output is unchanged without this option. A shared deployment pin by
  itself does not establish that two records name the same installed context.

## Focused verification

Only these six offline stages ran. **153 checks passed**, including independent
replay of an actual admitted policy decision in an inert fixture and refusal of
missing, swapped, changed, noncanonical and wrong-role inputs.

| Stage prefix (`pi-core-…-offline`) | Checks | Pipeline fingerprint (SHA-256) |
|---|---:|---|
| `bundle-install-entry` | 53 | `392eb2abf0d79fb2b7482ffed804a7b0022de2879acbafee95dfc16edc8cf0a3` |
| `install-postpublication-bytes` | 11 | `51374d266245bdc840b7ae947bf316c18e20a2c621b939012b82ed0ccff66d79` |
| `launch-identity` | 51 | `3350d537314264fb4dfba04d79fbb700076fa0f60977f7243e70cc52e8c81925` |
| `installed-bundle-readback` | 23 | `138caa01ffe3cb0d1988c4c067f421d9dbfbf3a7813ae7e17d69c28e0a672475` |
| `install-admission-replay` | 7 | `9ac2ddcb144a0d953beb5154c5eafbef1bc344d05b293cbb1f0e3de2fa36231c` |
| `public-pilot-recorded-correspondence` | 8 | `8e8fb27c8350f016988b9fd3be48380b655e46c5dde4f5ef3be8487c7cc03a58` |

1. **D2:** Re-pin only the changed protected sources in a successor inventory;
   preserve existing inventories and historical evidence. Join the exact
   install context and installed bytes to the recorded action on that
   deployment. Independent physical output observation, storage custody,
   sensor health, timing, recovery and useful pilot evidence remain open.
2. **D3:** Finish admission, RUN/health and workload coverage on the common
   deployment.
3. **D4:** Require the managed policy manifest in the frozen evidence inventory
   and close all 29 requirements before freezing. Do not change the legacy
   OpenClaw contract.
4. **D5:** Separately authorize fresh acceptance, 100 attempts, 100 pairs,
   cleanup and independent replay.

No guest boot, live install, provider use, spending, capture, or qualification.
B49 remains null. This checkpoint records code-level checks, not pilot readiness.
