from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn.cas import CAS
from aragorn.phase1_acquisition_lock import (
    PHASE1_ACQUISITION_LOCK_WORKLOAD_DIGEST,
    Phase1AcquisitionLockError,
    derive_phase1_acquisition_lock_milestone,
    phase1_acquisition_lock_workload,
    verify_phase1_acquisition_lock_milestone,
)

_ROOT = Path(__file__).resolve().parents[1]


def _evidence() -> dict:
    return {
        "schema": "aragorn/phase1-acquisition-lock-evidence/v1",
        "scope": "supported-acquisition-lock/v1",
        "workload": phase1_acquisition_lock_workload(),
        "workload_digest": PHASE1_ACQUISITION_LOCK_WORKLOAD_DIGEST,
    }


def _read_only_cas(root: Path, *, populated: bool) -> CAS:
    writable = CAS(root)
    if populated:
        paths = [
            *(_ROOT / "benchmark" / "evidence").glob("*"),
            *(_ROOT / "benchmark" / "receipts").glob("*"),
            _ROOT / "benchmark" / "admission-runtime-candidates-v1.lock.json",
            (
                _ROOT
                / "benchmark"
                / "admission"
                / "openclaw-v2026.7.1"
                / "update-reload-route-inventory-v1.json"
            ),
        ]
        for path in paths:
            if path.is_file():
                raw = path.read_bytes()
                writable.put(BytesIO(raw), max_bytes=len(raw))
    return CAS(root, read_only=True)


class Phase1AcquisitionLockTests(unittest.TestCase):
    def test_current_release_evidence_remains_non_pass(self) -> None:
        with TemporaryDirectory() as temporary:
            cas = _read_only_cas(Path(temporary), populated=True)
            evidence = _evidence()
            milestone = derive_phase1_acquisition_lock_milestone(
                evidence,
                evidence_cas=cas,
            )

            self.assertEqual(
                milestone["claims"]["installed_digest_integrity"],
                {"checked": 2, "mismatches": 0, "status": "EVIDENCE_ONLY"},
            )
            self.assertEqual(
                milestone["claims"]["static_artifact_capture"],
                {
                    "captured": 0,
                    "total": 2,
                    "minimum_percent": 95,
                    "status": "NOT_TESTED",
                },
            )
            self.assertEqual(
                milestone["claims"]["unresolved_required_non_allow"],
                {
                    "qualifying": 0,
                    "total": 1,
                    "required_percent": 100,
                    "allowed_outcomes": ["ERROR", "REVIEW"],
                    "observed_outcomes": ["ERROR"],
                    "status": "EVIDENCE_ONLY",
                },
            )
            self.assertEqual(
                milestone["claims"]["runtime_conformance"]["status"],
                "FAIL",
            )
            self.assertEqual(
                milestone["claims"]["supported_replay"]["install"]["status"],
                "EVIDENCE_ONLY",
            )
            self.assertEqual(
                milestone["decision"]["status"],
                "FAIL",
            )
            self.assertFalse(milestone["decision"]["phase1_exit_eligible"])
            self.assertIsNone(
                verify_phase1_acquisition_lock_milestone(
                    evidence,
                    milestone,
                    evidence_cas=cas,
                )
            )

    def test_missing_leaf_evidence_returns_not_tested(self) -> None:
        with TemporaryDirectory() as temporary:
            cas = _read_only_cas(Path(temporary), populated=False)
            milestone = derive_phase1_acquisition_lock_milestone(
                _evidence(),
                evidence_cas=cas,
            )

        self.assertEqual(milestone["decision"]["status"], "NOT_TESTED")
        self.assertFalse(milestone["decision"]["phase1_exit_eligible"])
        self.assertTrue(milestone["decision"]["reason_codes"])

    def test_caller_cannot_replace_workload_or_restore_assertion_fields(self) -> None:
        with TemporaryDirectory() as temporary:
            cas = _read_only_cas(Path(temporary), populated=False)
            replacements = []

            changed_outcome = _evidence()
            changed_outcome["workload"]["thresholds"][
                "unresolved_allowed_outcomes"
            ] = ["DENY", "ERROR", "REVIEW"]
            replacements.append(changed_outcome)

            changed_digest = _evidence()
            changed_digest["workload_digest"] = "sha256:" + "0" * 64
            replacements.append(changed_digest)

            caller_assertions = _evidence()
            caller_assertions["installed_digest_checks"] = [
                {
                    "expected_digest": "sha256:" + "1" * 64,
                    "installed_digest": "sha256:" + "1" * 64,
                    "evidence_role": "PHASE1_EXIT_ELIGIBLE",
                }
            ]
            replacements.append(caller_assertions)

            for candidate in replacements:
                with (
                    self.subTest(candidate=candidate),
                    self.assertRaises(Phase1AcquisitionLockError),
                ):
                    derive_phase1_acquisition_lock_milestone(
                        candidate,
                        evidence_cas=cas,
                    )

    def test_writable_cas_and_forged_aggregate_are_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            writable = CAS(temporary)
            with self.assertRaisesRegex(
                Phase1AcquisitionLockError,
                "must be read-only",
            ):
                derive_phase1_acquisition_lock_milestone(
                    _evidence(),
                    evidence_cas=writable,
                )

        with TemporaryDirectory() as temporary:
            cas = _read_only_cas(Path(temporary), populated=False)
            evidence = _evidence()
            milestone = derive_phase1_acquisition_lock_milestone(
                evidence,
                evidence_cas=cas,
            )
            forged = deepcopy(milestone)
            forged["decision"] = {
                "status": "PASS",
                "phase1_exit_eligible": True,
                "reason_codes": [],
            }
            with self.assertRaisesRegex(
                Phase1AcquisitionLockError,
                "does not match its derived aggregate",
            ):
                verify_phase1_acquisition_lock_milestone(
                    evidence,
                    forged,
                    evidence_cas=cas,
                )

    def test_schema_pins_the_same_release_workload(self) -> None:
        schema = json.loads(
            (
                _ROOT
                / "schema"
                / "phase1-acquisition-lock-evidence-v1.schema.json"
            ).read_bytes()
        )
        self.assertEqual(
            schema["properties"]["workload"]["const"],
            phase1_acquisition_lock_workload(),
        )
        self.assertEqual(
            schema["properties"]["workload_digest"]["const"],
            PHASE1_ACQUISITION_LOCK_WORKLOAD_DIGEST,
        )


if __name__ == "__main__":
    unittest.main()
