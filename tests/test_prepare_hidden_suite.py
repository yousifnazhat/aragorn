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
    _CORPUS_LOCK_PATH,
    _FREEZE_COMMIT,
    _FREEZE_TREE,
    _SIGNER_FINGERPRINT,
    _SIGNER_PRINCIPAL,
    _V1_GATE,
    _V2_GATE,
    _V3_GATE,
    _V4_GATE,
    PreparationError,
    _committed_document,
    _preflight_suite,
    _receipt,
    _state_paths,
    _verified_repository,
    validate_preparation_receipt_bindings,
    validate_retained_preparation_receipt,
)


class HiddenPreparationReceiptTests(unittest.TestCase):
    def test_gate_selects_its_corpus_lock_without_changing_retained_profiles(
        self,
    ) -> None:
        retained_path = Path("benchmark/phase0-corpus.lock.json")
        self.assertEqual(_V1_GATE.corpus_lock_path, retained_path)
        self.assertEqual(_V2_GATE.corpus_lock_path, retained_path)
        self.assertEqual(
            _V3_GATE.corpus_lock_path,
            Path("benchmark/phase0-corpus-v3.lock.json"),
        )
        self.assertEqual(
            _V4_GATE.corpus_lock_path,
            Path("benchmark/phase0-corpus-v4.lock.json"),
        )
        self.assertEqual(_CORPUS_LOCK_PATH, retained_path)

        digest = "sha256:" + "1" * 64
        cases = {
            f"case-{index:03d}": {"tree_digest": digest}
            for index in range(448)
        }
        loaded = {
            "digest": _V2_GATE.suite_digest,
            "runs_per_case": 1,
            "cases": cases,
            "systems": {
                "candidate": {
                    "name": "aragorn",
                    "version": "test",
                    "implementation_digest": digest,
                    "config_digest": digest,
                }
            },
            "manifests": {case_id: {"case_id": case_id} for case_id in cases},
        }
        synthetic = replace(
            _V2_GATE,
            corpus_lock_path=Path("benchmark/phase0-corpus-v3.lock.json"),
        )
        with (
            patch(
                "scripts.prepare_hidden_suite.load_suite_for_run",
                return_value=loaded,
            ),
            patch(
                "scripts.prepare_hidden_suite._validate_phase0_hidden_binding"
            ) as validate,
        ):
            _preflight_suite(
                Path("/private/phase0-v3/private-suite.json"),
                {"label_ledger_digest": digest},
                synthetic,
            )
        self.assertEqual(
            validate.call_args.kwargs["corpus_lock_path"],
            ROOT / synthetic.corpus_lock_path,
        )

    def test_v3_gate_binds_fresh_hidden_freeze(self) -> None:
        self.assertEqual(
            _V3_GATE.freeze_commit,
            "4210a5b4305a558016ec7ee6520e13e99f38d576",
        )
        self.assertEqual(
            _V3_GATE.freeze_tree,
            "ab7294a2d096306567a2939065aa68d4fa524bdc",
        )
        self.assertEqual(
            _V3_GATE.lock_digest,
            "sha256:68ed78218e3efe41b2cdef1c0873472b52093a42b4001f9b6a60d860476b9def",
        )
        self.assertEqual(
            _V3_GATE.freeze_receipt_digest,
            "sha256:b6aadf115dd6542cd6d2e0a8005151017efe402bc801db17ffe3bb360080c56b",
        )
        self.assertEqual(
            _V3_GATE.suite_digest,
            "sha256:75bb5723bbc4973f94f5bea7d54eee76025da57cce806e0aef11740ec83305af",
        )
        self.assertEqual(
            _V3_GATE.candidate_policy_digest,
            "sha256:817bc01e97437c2d5a38971c5164dae28570a4d492b78816165ff97d0358ff73",
        )
        self.assertEqual(
            _V3_GATE.state_binding_digest,
            "sha256:e29cd500844122f1c9c4213f1653ca2928bcc49fa1cb2f7ed06005d240ae75ba",
        )
        self.assertEqual(
            _state_paths(
                Path(
                    "/Users/yousi/Documents/Codex/2026-07-25/"
                    "aragorn-phase0-hidden-v3-control/run-state"
                ),
                _V3_GATE,
            )["outcomes"],
            Path(
                "/Users/yousi/Documents/Codex/2026-07-25/"
                "aragorn-phase0-hidden-v3-control/run-state/outcomes.jsonl"
            ),
        )
        self.assertFalse(_V3_GATE.calibration_only)

    def test_v4_gate_binds_local_hidden_freeze(self) -> None:
        self.assertEqual(
            _V4_GATE.freeze_commit,
            "f348b9f16c0e69ebc293b1c043803fc645f452f1",
        )
        self.assertEqual(
            _V4_GATE.freeze_tree,
            "ecf8f360a48055bd4b54af7727fd01a28cd970f5",
        )
        self.assertEqual(
            _V4_GATE.lock_digest,
            "sha256:df5d79e7eac04ceef4d181abfc37f2ed2a11c20266cc74297cea35b7486df587",
        )
        self.assertEqual(
            _V4_GATE.freeze_receipt_digest,
            "sha256:64780dbf3364cc5c3ed94047a4d0f9dff6ee6bf43d1a89b52cc25fe3632c780c",
        )
        self.assertEqual(
            _V4_GATE.suite_digest,
            "sha256:797ded20e3c9b9082e9ea53dd13cbfef463dfe6d7adf8ea88b6698bd34861072",
        )
        self.assertEqual(
            _V4_GATE.candidate_policy_digest,
            "sha256:c9e5e3b1092a427662306608bd1a15de00a306ea30e4e9bab91ce9fb8c3d929c",
        )
        self.assertEqual(
            _V4_GATE.state_binding_digest,
            "sha256:4a590e6577e73def9ff27cb6cdb69a8309afff3a50e44a189abb77a8eacbffba",
        )
        self.assertEqual(
            _state_paths(
                Path(
                    "/Users/yousi/Documents/Codex/2026-07-26/"
                    "aragorn-phase0-hidden-v4-control/run-state"
                ),
                _V4_GATE,
            )["outcomes"],
            Path(
                "/Users/yousi/Documents/Codex/2026-07-26/"
                "aragorn-phase0-hidden-v4-control/run-state/outcomes.jsonl"
            ),
        )
        self.assertEqual(
            _V4_GATE.trust_domain,
            "phase0.hidden-local-v4.0.0",
        )
        self.assertFalse(_V4_GATE.calibration_only)

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
