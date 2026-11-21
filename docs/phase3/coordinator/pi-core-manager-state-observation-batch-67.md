# D2 batch 67 — measure both ends of manager state binds

Signed parent: `b468fd4`. A mount path alone does not prove which directory is
visible there. The stopped-worker observer now keeps open the manager's state
anchor, both source directories under it, and the two final action/provider
destinations. It separately resolves their names before and after the existing
mask probe, from the same manager root. Missing paths, a changed component or
an uncertain observation cannot produce a positive result. It does not read
state contents, open a block device, attach storage or resume the worker.

The second version of the local capture retains these statx frames in the
existing five-member receipt. [Replay](../../../src/aragorn/pi_core_manager_state_view.py)
checks device/inode, file type, mode, owner and mount ID against the original
manager mountinfo. A service destination must show the same directory as its
source but on its own expected bind mount. A complete, stable mismatch can be
retained as negative evidence; partial acquisition isn't a successful receipt.

For a new cross-archive assessment, the
[joined reader](../../../scripts/verify_pi_core_joined_mask_receipts.py) takes
the same five independent pins as B61 **plus `--require-manager-state`**.
It compares both source and target identity maps with the separately retained
B58 archive. Historical v1 mask receipts still replay for their original purpose;
they cannot satisfy this requirement. Nothing here proves an underlying disk
is the nominated external asset, that the off-volume head is current, or that
the sensor and Pi were verified on a real deployment.

| Only affected stages | First-run passes | Fingerprint |
|---|---:|---|
| `pi-core-manager-state-observer-offline` | 25 | `0f1ea0a968568dd918a67b8559b71f866391c66c8c10fae14acf394860a20287` |
| `pi-core-joined-mask-receipts-offline` | 11 | `6e4b1f9d6d8259c16448254b15169f569f60e616c2f44e4801fdef846c8912e2` |

Checks used inert kernel views and temporary receipt stores. No broad suite,
live evidence, capacity check, predecessor rebuild, spending or B49 change.

1. **D2 open:** B65 media inputs predate this observer. Connect configuration
   visibility and volume identity to the common deployment, then pin the changed
   sources before any authorized installation. Real observation/health,
   recovery, timing and the separately authorized useful pilot remain.
2. **D3 open:** remaining admission, RUN/health and workload paths.
3. **D4 not frozen:** executable independent coverage of all 29 requirements.
4. **D5 not authorized:** fresh admission, 100 attempts, 100 pairs, independent
   replay and verified restoration after freeze and separate approval.
