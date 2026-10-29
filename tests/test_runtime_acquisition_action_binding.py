from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from aragorn import runtime_acquisition_action_binding as subject

_ROOT = Path(__file__).resolve().parents[1]


def _load(path: str) -> dict:
    return json.loads((_ROOT / path).read_bytes())


class _SplitReceipt(dict):
    def __getitem__(self, key: str) -> object:
        if key == "source":
            return {"commit": "0" * 40}
        if key == "runtime":
            return {"release_identity_digest": "sha256:" + "0" * 64}
        return super().__getitem__(key)


class RuntimeAcquisitionActionBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.archive = _ROOT / subject.phase1.ARCHIVE_PATH
        cls.phase1_receipt = _load(subject._PHASE1_RECEIPT_PATH)
        cls.p37c_observation = _load(subject.p37c._RETAINED_PATH)
        cls.p37b_observation = _load(
            "benchmark/evidence/runtime-action-worker-openclaw-systemd-"
            "composition-p3-7b-2026-08-09.json"
        )
        cls.p36b_observation = _load(
            "benchmark/evidence/runtime-producer-lineage-openclaw-systemd-"
            "composition-p3-6b-2026-08-07.json"
        )
        cls.p37b_receipt = _load(
            "benchmark/receipts/phase3-runtime-action-worker-openclaw-systemd-"
            "qualification-v1-2026-08-09.json"
        )
        cls.p37c_receipt = _load(subject._P37C_RECEIPT_PATH)

    def test_exact_content_binding_qualifies_without_broad_authority(self) -> None:
        qualification = self._qualify()
        self.assertEqual(qualification["decision"], subject._DECISION)
        self.assertEqual(
            qualification["cases"]["cross_capture_content_binding"],
            {"bytes": 140, "skill_digest": subject._SKILL_DIGEST, "status": "PASS"},
        )
        self.assertEqual(
            qualification["cases"]["p3_7c_coherent_action"],
            {
                "driver_status": "COMPLETED",
                "effect_status": "CREATED",
                "grant_state": "CONSUMED",
                "status": "PASS",
                "verdict": "ALLOW",
            },
        )
        for field in (
            "aggregate_gate_eligible",
            "same_custody_epoch",
            "same_release_identity",
            "semantic_skill_causation_established",
            "run_01_eligible",
            "run_02_eligible",
            "phase3_exit_eligible",
            "edr_claim_eligible",
            "installer_authority_eligible",
            "public_release_eligible",
        ):
            self.assertIs(qualification["decision"][field], False)

    def test_retained_receipt_is_exact_canonical_derivation(self) -> None:
        qualification = self._qualify()
        raw = (
            _ROOT / "benchmark/receipts/phase3-runtime-acquisition-action-binding-"
            "v1-2026-08-11.json"
        ).read_bytes()
        self.assertEqual(raw, subject.canonical_json(qualification) + b"\n")
        self.assertEqual(json.loads(raw), qualification)

    def test_implementation_pin_is_required(self) -> None:
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._qualify(implementation_digest=None)

    def test_phase1_receipt_repin_is_rejected(self) -> None:
        receipt = copy.deepcopy(self.phase1_receipt)
        receipt["qualification"]["installer_work_eligible"] = True
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._qualify(phase1_receipt=receipt)

    def test_p37c_receipt_repin_is_rejected(self) -> None:
        receipt = copy.deepcopy(self.p37c_receipt)
        receipt["decision"]["run_01_eligible"] = True
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._qualify(p37c_receipt=receipt)

    def test_parent_content_repin_is_rejected(self) -> None:
        observation = copy.deepcopy(self.p36b_observation)
        observation["producer"]["tree_entry"]["digest"] = "sha256:" + "a" * 64
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._qualify(p36b_observation=observation)

    def test_boolean_claim_promotion_is_rejected_by_exact_receipt_identity(
        self,
    ) -> None:
        receipt = copy.deepcopy(self.p37c_receipt)
        receipt["decision"]["run_01_eligible"] = 0
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._qualify(p37c_receipt=receipt)

    def test_mapping_is_canonicalized_before_validated_values_are_reused(self) -> None:
        qualification = self._qualify(
            phase1_receipt=_SplitReceipt(copy.deepcopy(self.phase1_receipt))
        )
        phase1 = qualification["bindings"]["phase1"]
        self.assertEqual(
            phase1["source_commit"], "c87b82b9b7a4b8465b9958d33d997fd014f49257"
        )
        self.assertEqual(
            phase1["release_identity_digest"],
            "sha256:063fc5c033e7c1bb70b3223148899ae72ed591930c42f32e8468e18cff1154b7",
        )

    def _qualify(self, **overrides: object) -> dict:
        arguments = {
            "phase1_archive_path": self.archive,
            "phase1_receipt": self.phase1_receipt,
            "p37c_observation": self.p37c_observation,
            "p37b_observation": self.p37b_observation,
            "p36b_observation": self.p36b_observation,
            "p37b_receipt": self.p37b_receipt,
            "p37c_receipt": self.p37c_receipt,
            "implementation_digest": self._implementation_digest(),
        }
        arguments.update(overrides)
        return subject.runtime_acquisition_action_binding_qualification(**arguments)

    @staticmethod
    def _implementation_digest() -> str:
        raw = Path(subject.__file__).read_bytes()
        return "sha256:" + hashlib.sha256(raw).hexdigest()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
