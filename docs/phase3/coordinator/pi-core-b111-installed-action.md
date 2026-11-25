# D2: B111 install report to recorded action

Use `python3.12 -m scripts.verify_pi_core_b111_install_action` with the repository
and `src` on the import path. Supply `--archive` (an existing private CAS) and
the seven **independently nominated** inputs: `--owner-pin` (original wrapper stdout),
`--plan-pin` (install plan, not attempt plan), `--context-pin`, `--manifest-pin`,
`--deployment-pin` (the flat seven bindings), `--action-nomination-pin` and
`--expected-action-receipt-pin` (original broker terminal receipt). Do not take
expected values from the submission. There is no directory scan, fallback to a
predecessor or retry. The command reads archived documents, not guest paths.

The B110 wrapper added private output retention; its install dispatch, admitted
entry, policy helper and install-report encoder are unchanged from the B85/B104
path. The new reader requires the exact B111 host inventory **and** wrapper.
It uses the existing admission decision/revocation, bundle, runtime policy and
action readers. It reconstructs the install transaction and active record,
compares the protected version/destination, and binds the original action's
terminal receipt. This version is deliberately separate: the B100/B104 readers,
B105 source pins, and historical D4 registration remain unchanged.

`CONSISTENT_RECORDED_B111_INSTALL_AND_ACTION` does not prove current authority,
physical installation, worker consumption, healthy acquisition, effect or time.
An original refusal can match its own terminal receipt. It cannot substitute
for an original create. The B111 planned-output reader remains a separate check;
use the same independently nominated action/deployment when comparing findings.

The one new stage, `pi-core-b111-install-action-offline`, failed for the missing
reader, then passed six checks (fingerprint
`27e17f757aaef53afea1c54c599c5ebc54545e98cd6ee775082a996d6d566596`).
The inert fixtures exercised the real pinned wrapper's stdout encoder and the
original action receipt producer. Re-pinning a changed wrapper, install context,
transaction, root or valid but different action/receipt did not pass the join.
The test fixture is the signed public **guest** inventory expressed as JSON with a
terminal LF; its canonical bytes have SHA-256 `5105455ffdb8bc0c0c8e28863230ac7539be0a8d499d31208434b3fa732080c9`.
It contains guest paths, sizes and hashes; no execution, credentials or host nomination.

1. D2: this replay is available; actual installed source/health, denials, effect,
   recovery, timing and cleanup require the separately approved pilot and host.
2. D3: the approved fixed task service goes through Pi in both modes; do not
   treat the choice of carrier as an installed or measured context.
3. D4: the independent inventory and freeze remain open.
4. D5: no samples; post-freeze approval still required.
