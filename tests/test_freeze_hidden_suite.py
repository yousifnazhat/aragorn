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
    _match_prior_freeze,
    freeze,
    validate_freeze_receipt_bindings,
)


class FreezeReceiptTests(unittest.TestCase):
    def test_preserved_evaluator_source_is_exclusive_and_bound(self) -> None:
        arguments = {
            "release_dir": ROOT,
            "corpus_lock_path": ROOT / "benchmark" / "phase0-corpus.lock.json",
            "candidate_policy_path": (
                ROOT / "benchmark" / "phase0-candidate-policy-v2.json"
            ),
            "private_suite_root": ROOT / "unused-suite",
            "lock_output": ROOT / "unused-lock",
            "receipt_output": ROOT / "unused-receipt",
            "recorded_on": "2026-07-25",
            "run_state_root": ROOT,
        }
        for evaluator_passphrase, verified_evaluator_package in (
            (None, None),
            (b"secret", ROOT),
        ):
            with self.subTest(
                evaluator_passphrase=evaluator_passphrase is not None,
                verified_evaluator_package=verified_evaluator_package is not None,
            ), self.assertRaisesRegex(FreezeError, "select exactly one"):
                freeze(
                    **arguments,
                    evaluator_passphrase=evaluator_passphrase,
                    verified_evaluator_package=verified_evaluator_package,
                )

        prior = {
            "receipt": {
                "release": {
                    "release_manifest_digest": "release",
                    "worker_archive_digest": "worker",
                    "evaluator_ciphertext_digest": "evaluator",
                    "source_bundle_digest": "source",
                },
                "evaluator": {
                    "manifest_digest": "manifest",
                    "label_ledger_digest": "labels",
                    "public_manifest_digest": "public",
                },
            }
        }
        release = {
            "release_manifest_digest": "release",
            "worker_archive_digest": "worker",
            "evaluator_archive_digest": "evaluator",
            "source_bundle_digest": "source",
        }
        evaluator = {
            "evaluator_manifest_digest": "manifest",
            "label_ledger_digest": "labels",
            "public_manifest_digest": "public",
        }
        _match_prior_freeze(prior, release, evaluator)
        changed = deepcopy(evaluator)
        changed["label_ledger_digest"] = "changed"
        with self.assertRaisesRegex(FreezeError, "prior signed freeze"):
            _match_prior_freeze(prior, release, changed)

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
