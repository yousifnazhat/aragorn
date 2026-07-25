from __future__ import annotations

import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aragorn.oci_worker_protocol import canonical_json
from scripts.freeze_hidden_suite import (
    FreezeError,
    freeze,
    validate_freeze_receipt_bindings,
)


class FreezeReceiptTests(unittest.TestCase):
    def test_invalid_date_and_symlinked_private_path_fail_first(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_state = root / "run"
            run_state.mkdir(mode=0o700)
            common = {
                "release_dir": root,
                "evaluator_passphrase": b"test-only",
                "corpus_lock_path": ROOT / "benchmark" / "phase0-corpus.lock.json",
                "candidate_policy_path": (
                    ROOT / "benchmark" / "phase0-candidate-policy.json"
                ),
                "private_suite_root": root / "private-suite",
                "lock_output": root / "lock.json",
                "receipt_output": root / "receipt.json",
                "run_state_root": run_state,
            }
            with self.assertRaisesRegex(FreezeError, "real YYYY-MM-DD"):
                freeze(
                    **common,
                    recorded_on="2026-99-99",
                )

            target = root / "target"
            target.mkdir()
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(FreezeError, "symlink component"):
                freeze(
                    **{**common, "private_suite_root": alias / "private-suite"},
                    recorded_on="2026-07-24",
                )

    def test_schema_valid_label_digest_substitution_is_rejected(self) -> None:
        lock_raw = (ROOT / "benchmark" / "phase0-hidden-suite.lock.json").read_bytes()
        receipt_raw = (
            ROOT
            / "benchmark"
            / "receipts"
            / "phase0-hidden-suite-freeze-2026-07-24.json"
        ).read_bytes()
        corpus_lock_raw = (ROOT / "benchmark" / "phase0-corpus.lock.json").read_bytes()
        lock = json.loads(lock_raw)
        receipt = json.loads(receipt_raw)
        corpus_lock = json.loads(corpus_lock_raw)

        validate_freeze_receipt_bindings(
            receipt,
            receipt_raw,
            lock,
            lock_raw,
            corpus_lock,
            corpus_lock_raw,
        )

        changed = deepcopy(receipt)
        changed["evaluator"]["label_ledger_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            FreezeError,
            "label ledger digest does not match lock",
        ):
            validate_freeze_receipt_bindings(
                changed,
                canonical_json(changed),
                lock,
                lock_raw,
                corpus_lock,
                corpus_lock_raw,
            )


if __name__ == "__main__":
    unittest.main()
