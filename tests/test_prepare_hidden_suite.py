from __future__ import annotations

import json
import sys
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts.prepare_hidden_suite import (
    _FREEZE_COMMIT,
    _FREEZE_TREE,
    _SIGNER_FINGERPRINT,
    _SIGNER_PRINCIPAL,
    _V2_GATE,
    PreparationError,
    _committed_document,
    _receipt,
    _state_paths,
    _verified_repository,
    validate_preparation_receipt_bindings,
    validate_retained_preparation_receipt,
)


class HiddenPreparationReceiptTests(unittest.TestCase):
    def test_preparation_commit_must_strictly_follow_freeze(self) -> None:
        with (
            patch(
                "scripts.prepare_hidden_suite._git",
                side_effect=[
                    f"{ROOT}\n".encode(),
                    b"sha1\n",
                    b"",
                    f"{_V2_GATE.freeze_commit}\n".encode(),
                ],
            ),
            self.assertRaisesRegex(PreparationError, "strictly follow"),
        ):
            _verified_repository(_V2_GATE)

    def test_calibration_v2_receipt_is_bound_and_not_a_holdout(self) -> None:
        hidden_lock = json.loads(
            (
                ROOT / "benchmark" / "phase0-hidden-suite-calibration-v2.lock.json"
            ).read_bytes()
        )
        freeze_receipt = json.loads(
            (
                ROOT
                / "benchmark"
                / "receipts"
                / "phase0-hidden-suite-calibration-v2-freeze-2026-07-25.json"
            ).read_bytes()
        )
        systems = [
            system for system in hidden_lock["systems"] if system["name"] != "aragorn"
        ]
        digest = "sha256:" + "1" * 64
        commits = {
            "freeze": {
                "commit": _V2_GATE.freeze_commit,
                "tree": _V2_GATE.freeze_tree,
                "signature_status": "verified",
                "principal": _SIGNER_PRINCIPAL,
                "fingerprint": _SIGNER_FINGERPRINT,
            },
            "preparation": {
                "commit": "2" * 40,
                "tree": "3" * 40,
                "signature_status": "verified",
                "principal": _SIGNER_PRINCIPAL,
                "fingerprint": _SIGNER_FINGERPRINT,
            },
        }
        preparation = {
            "schema": "aragorn/benchmark-prepare-result/v2",
            "suite_digest": hidden_lock["suite_digest"],
            "dispatch_digest": digest,
            "candidate_policy_digest": hidden_lock["candidate_policy_digest"],
            "worker_identities_digest": canonical_digest(
                {
                    "schema": "aragorn/benchmark-system-identities/v1",
                    "systems": systems,
                }
            ),
            "worklist_digest": digest,
            "job_count": 896,
        }
        matrix = {
            "case_count": 448,
            "comparator_count": 2,
            "runs_per_case": 1,
            "job_count": 896,
            "worklist_count": 896,
            "issuance_count": 896,
            "acceptance_count": 0,
            "systems": systems,
        }
        receipt = _receipt(
            recorded_on=_V2_GATE.recorded_on,
            commits=commits,
            trust_store_digest=digest,
            key_id=digest,
            result=preparation,
            matrix=matrix,
            gate=_V2_GATE,
        )
        validate_preparation_receipt_bindings(
            receipt,
            canonical_json(receipt),
            hidden_lock,
            freeze_receipt,
            verified_preparation=commits["preparation"],
            gate=_V2_GATE,
        )
        self.assertEqual(
            receipt["limitations"]["evaluation_status"],
            "calibration_rerun_on_previously_evaluated_corpus_not_fresh_holdout",
        )
        with self.assertRaisesRegex(PreparationError, "contract changed"):
            validate_preparation_receipt_bindings(
                receipt,
                canonical_json(receipt),
                hidden_lock,
                freeze_receipt,
                verified_preparation=commits["preparation"],
            )
        with self.assertRaisesRegex(PreparationError, "registered profile"):
            _receipt(
                recorded_on=_V2_GATE.recorded_on,
                commits=commits,
                trust_store_digest=digest,
                key_id=digest,
                result=preparation,
                matrix=matrix,
                gate=replace(_V2_GATE, calibration_only=False),
            )
        _state_paths(
            Path("/private/tmp/aragorn-phase0-v2-calibration-run"),
            _V2_GATE,
        )
        with self.assertRaisesRegex(PreparationError, "path binding"):
            _state_paths(Path("/private/tmp/wrong-run-root"), _V2_GATE)

        for path, value in (
            (("assurance",), "independent"),
            (("state", "operator_uid_protected"), False),
            (("matrix", "comparator_count"), 1),
            (("worker_surface", "forbidden_evaluator_metadata_absent"), False),
            (("limitations", "evaluation_status"), "fresh_holdout"),
        ):
            changed = deepcopy(receipt)
            target = changed
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaisesRegex(
                PreparationError,
                "contract changed",
            ):
                validate_preparation_receipt_bindings(
                    changed,
                    canonical_json(changed),
                    hidden_lock,
                    freeze_receipt,
                    verified_preparation=commits["preparation"],
                    gate=_V2_GATE,
                )

    def test_signed_policy_loader_accepts_formatted_json(self) -> None:
        with patch(
            "scripts.prepare_hidden_suite._committed_bytes",
            return_value=b'{\n  "schema": "example/v1"\n}\n',
        ):
            self.assertEqual(
                _committed_document("2" * 40, Path("policy.json"), "policy"),
                {"schema": "example/v1"},
            )

    def test_receipt_rejects_matrix_substitution(self) -> None:
        hidden_lock = json.loads(
            (ROOT / "benchmark" / "phase0-hidden-suite.lock.json").read_bytes()
        )
        freeze_receipt = json.loads(
            (
                ROOT
                / "benchmark"
                / "receipts"
                / "phase0-hidden-suite-freeze-2026-07-24.json"
            ).read_bytes()
        )
        digest = "sha256:" + "1" * 64
        commits = {
            "freeze": {
                "commit": _FREEZE_COMMIT,
                "tree": _FREEZE_TREE,
                "signature_status": "verified",
                "principal": _SIGNER_PRINCIPAL,
                "fingerprint": _SIGNER_FINGERPRINT,
            },
            "preparation": {
                "commit": "2" * 40,
                "tree": "3" * 40,
                "signature_status": "verified",
                "principal": _SIGNER_PRINCIPAL,
                "fingerprint": _SIGNER_FINGERPRINT,
            },
        }
        systems = [
            system for system in hidden_lock["systems"] if system["name"] != "aragorn"
        ]
        preparation = {
            "schema": "aragorn/benchmark-prepare-result/v2",
            "suite_digest": hidden_lock["suite_digest"],
            "dispatch_digest": digest,
            "candidate_policy_digest": hidden_lock["candidate_policy_digest"],
            "worker_identities_digest": canonical_digest(
                {
                    "schema": "aragorn/benchmark-system-identities/v1",
                    "systems": systems,
                }
            ),
            "worklist_digest": digest,
            "job_count": 896,
        }
        matrix = {
            "case_count": 448,
            "comparator_count": 2,
            "runs_per_case": 1,
            "job_count": 896,
            "worklist_count": 896,
            "issuance_count": 896,
            "acceptance_count": 0,
            "systems": systems,
        }
        receipt = _receipt(
            recorded_on="2026-07-24",
            commits=commits,
            trust_store_digest=digest,
            key_id=digest,
            result=preparation,
            matrix=matrix,
        )
        validate_preparation_receipt_bindings(
            receipt,
            canonical_json(receipt),
            hidden_lock,
            freeze_receipt,
            verified_preparation=commits["preparation"],
        )

        changed = deepcopy(receipt)
        changed["preparation"]["worker_identities_digest"] = "sha256:" + "4" * 64
        changed["preparation_result_digest"] = canonical_digest(changed["preparation"])
        with self.assertRaisesRegex(
            PreparationError,
            "matrix accounting changed",
        ):
            validate_preparation_receipt_bindings(
                changed,
                canonical_json(changed),
                hidden_lock,
                freeze_receipt,
                verified_preparation=commits["preparation"],
            )

        changed = deepcopy(receipt)
        changed["source"]["preparation_tree"] = "4" * 40
        with self.assertRaisesRegex(PreparationError, "signed source changed"):
            validate_preparation_receipt_bindings(
                changed,
                canonical_json(changed),
                hidden_lock,
                freeze_receipt,
                verified_preparation=commits["preparation"],
            )

    def test_retained_receipt_requires_preparation_before_retention(self) -> None:
        claimed_commit = "2" * 40
        retained_commit = "4" * 40
        receipt = {"source": {"preparation_commit": claimed_commit}}

        with (
            patch(
                "scripts.prepare_hidden_suite._verified_repository",
                return_value={"preparation": {"commit": claimed_commit}},
            ),
            self.assertRaisesRegex(PreparationError, "strictly follow"),
        ):
            validate_retained_preparation_receipt(receipt, b"", {}, {})

        freeze_receipt = {"source": {"preparation_commit": _FREEZE_COMMIT}}
        with (
            patch(
                "scripts.prepare_hidden_suite._verified_repository",
                return_value={"preparation": {"commit": retained_commit}},
            ),
            self.assertRaisesRegex(PreparationError, "strictly follow the freeze"),
        ):
            validate_retained_preparation_receipt(freeze_receipt, b"", {}, {})

        with (
            patch(
                "scripts.prepare_hidden_suite._verified_repository",
                return_value={"preparation": {"commit": retained_commit}},
            ),
            patch(
                "scripts.prepare_hidden_suite._verified_commit",
                return_value={"commit": claimed_commit},
            ),
            patch(
                "scripts.prepare_hidden_suite._git",
                side_effect=[b"", b"", b""],
            ),
            self.assertRaisesRegex(PreparationError, "lacks the regular"),
        ):
            validate_retained_preparation_receipt(receipt, b"", {}, {})

        with (
            patch(
                "scripts.prepare_hidden_suite._verified_repository",
                return_value={"preparation": {"commit": retained_commit}},
            ),
            patch(
                "scripts.prepare_hidden_suite._verified_commit",
                return_value={"commit": claimed_commit},
            ),
            patch(
                "scripts.prepare_hidden_suite._git",
                side_effect=[
                    b"",
                    b"",
                    b"100644 blob "
                    + b"5" * 40
                    + b"\tscripts/prepare_hidden_suite.py\0",
                    b"benchmark/receipts/receipt.json\0",
                ],
            ),
            self.assertRaisesRegex(PreparationError, "already exists"),
        ):
            validate_retained_preparation_receipt(receipt, b"", {}, {})


if __name__ == "__main__":
    unittest.main()
