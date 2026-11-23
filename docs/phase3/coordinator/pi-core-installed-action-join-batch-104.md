# B104 — re-pin protected sources and join the exact installed bundle to the recorded action

## Protected source successor

The [reviewed delta](../../../packaging/pi-core/managed-sources-b104.json) and
[offline preparer](../../../scripts/prepare_pi_core_b104_sources.py) use the
retained [B94 inventories](pi-core-managed-inventories-batch-94.md) and signed
`f4d78b03aa798d7265cd785a6a1de76d630de232`, tree
`a785ebdd10e9d57e618b67d39bac1f07325be37e`. The coordinator re-pins six changed
modules: install entry, bundle launch, request recovery, service lifecycle,
state admission and state exposure. All but the install entry are also in
the service inventory; the three existing service wrappers embed the renewed
inventory. No other file rows, worker contents or native binaries changed.

The four documents were retained once and read back at
`~/Library/Application Support/Aragorn-B104-Offline/`. The service receipt is
for the proposed layout, not an installed service. Preserve B94 and do not
regenerate B104 or substitute a different predecessor on a later run.

| Retained file | SHA-256 |
|---|---|
| `coordinator-host.json` | `70d6998fc0b50512cb0583261fd1ca633a3aedef24ca68fa0db73b2b0a20ae87` |
| `manifest.json` | `deef4f046aaff76a486e327f75e98e8b9ef4a4daa5d4ecbaed8620edc97f69c0` |
| `runtime-binding.json` | `76fd1f597cc65b9bc98a30d2d470bb27938f92253aff0b1df6770db9bf2dd240` |
| `service-runtime-receipt.json` | `d7bb0b594df97eb7ba53e3bac535308e33da3b4ca2feff99a97fde17ecc927b0` |

## Exact install-to-action replay

The [joined reader](../../../scripts/verify_pi_core_install_action_join.py)
requires a read-only evidence store and independently held pins for the
install owner, plan, context document, source manifest, action nomination,
and deployment. It runs managed admission replay and the existing closed
terminal action replay. It derives the expected transaction from the
approved context and independently verified retained tree, then compares
its digest to the original install stdout and the corresponding active-record
digest to the action activation. No raw private active-record export is needed.

It also checks the original manifest's root `SKILL.md` digest and the retained
action lineage's protected root device/inode, target, version and skill path.
Agreement on deployment or payload bytes alone cannot pass. This proves
consistency of records at those boundaries, not same-inode custody between
observations, acquisition authenticity, worker consumption, or physical effect.
The original B76/B85 and B93/B99 stand-alone readers are unchanged.

Only two new stages ran. The joined reader passed four focused checks at
`0db961946be4295f8266467da6aaf01b37d944a00dd061085dee77be99e8e4cc` using
existing inert producers and the real replay readers. The inventory stage
passed two at `959e426aa97626bd9a8c7e9255554b5a8831282f45f69086efd4e380d77aa992`.
The earlier inventory fingerprint
`b970576bca760ed583294c9d29eeca412de2bc4b154f1696101b7599fbb44190`
remains failed: the intended overwrite refusal raised `BuildError` while the
check incorrectly expected `ValueError`. Only that check's stage ran again
after correcting the expected exception. The joined reader and historical
stages were not rerun.

1. **D2:** The source pins and joined reader are ready offline. Prepare the
   common successor and its exact evidence nominations; production install
   and action records on the successor are not yet available. Keep B49 null.
   Independent output observation, sensor health, timing, recovery and the
   separately authorized useful pilot remain open.
2. **D3:** Finish connected admission, RUN/health and workload coverage.
3. **D4:** Close all 29 independent requirement bindings, then freeze once.
4. **D5:** Separately authorize fresh acceptance, 100 attempts and 100 pairs,
   cleanup verification and independent replay.

No live install, boot, activation, provider call, capture, spending or
qualification occurred.
