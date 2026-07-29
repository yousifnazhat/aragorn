from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase1_acquisition_lock_v2 import (
    PHASE1_ACQUISITION_LOCK_WORKLOAD_V2_DIGEST,
    Phase1AcquisitionLockV2Error,
    derive_phase1_acquisition_lock_milestone_v2,
    phase1_acquisition_lock_workload_v2,
    verify_phase1_acquisition_lock_milestone_v2,
)

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / "benchmark" / "evidence"
_EVIDENCE_ENVELOPE = _EVIDENCE / "phase1-acquisition-lock-evidence-v2.json"
_MILESTONE = (
    _ROOT
    / "benchmark"
    / "receipts"
    / "phase1-acquisition-lock-milestone-v2-2026-07-29.json"
)
_SOURCES = {
    "recursive_archive": _EVIDENCE
    / (
        "phase1-github-recursive-anthropics-claude-plugins-"
        "hook-development-6b708ace-2026-07-29.tar.gz"
    ),
    "recursive_inventory": _EVIDENCE
    / (
        "phase1-github-recursive-anthropics-claude-plugins-"
        "hook-development-6b708ace-2026-07-29.inventory.json"
    ),
    "transition_archive": _EVIDENCE
    / (
        "phase1-protected-transition-obra-superpowers-"
        "requesting-code-review-2026-07-29.tar.gz"
    ),
}


def _envelope() -> dict:
    workload = phase1_acquisition_lock_workload_v2()
    return {
        "schema": "aragorn/phase1-acquisition-lock-evidence/v2",
        "scope": "supported-acquisition-lock/v2",
        "leaf_digests": workload["leaf_digests"],
        "workload_digest": PHASE1_ACQUISITION_LOCK_WORKLOAD_V2_DIGEST,
    }


def _cas(root: Path, *, populated: bool) -> CAS:
    writable = CAS(root)
    if populated:
        leaves = phase1_acquisition_lock_workload_v2()["leaf_digests"]
        sources = {
            leaves["recursive"]["archive"]: _SOURCES["recursive_archive"],
            leaves["recursive"]["inventory"]: _SOURCES["recursive_inventory"],
            leaves["protected_transition"]["archive"]: _SOURCES["transition_archive"],
        }
        for expected, source in sources.items():
            raw = source.read_bytes()
            writable.put_expected(
                BytesIO(raw),
                expected_digest=expected,
                max_bytes=len(raw),
            )
    return CAS(root, read_only=True)


class Phase1AcquisitionLockV2Tests(unittest.TestCase):
    def test_real_release_evidence_passes_and_forgery_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = _cas(Path(temporary), populated=True)
            evidence = _envelope()
            milestone = derive_phase1_acquisition_lock_milestone_v2(
                evidence,
                evidence_cas=cas,
            )

            self.assertEqual(evidence, json.loads(_EVIDENCE_ENVELOPE.read_bytes()))
            self.assertEqual(milestone, json.loads(_MILESTONE.read_bytes()))
            self.assertEqual(
                _EVIDENCE_ENVELOPE.read_bytes(),
                canonical_json(evidence) + b"\n",
            )
            self.assertEqual(
                _MILESTONE.read_bytes(),
                canonical_json(milestone) + b"\n",
            )
            self.assertEqual(
                milestone["claims"]["installed_digest_integrity"],
                {
                    "trees": 2,
                    "files": 4,
                    "mismatches": 0,
                    "changed_paths": 1,
                    "status": "PASS",
                },
            )
            self.assertEqual(
                milestone["claims"]["static_artifact_capture"],
                {
                    "captured": 13,
                    "total": 13,
                    "percent": 100.0,
                    "minimum_percent": 95,
                    "status": "PASS",
                },
            )
            self.assertEqual(
                milestone["claims"]["unresolved_required_non_allow"],
                {
                    "qualifying": 18,
                    "total": 18,
                    "allowed_outcomes": ["ERROR", "REVIEW"],
                    "observed_outcome": "ERROR",
                    "status": "PASS",
                },
            )
            self.assertEqual(milestone["decision"]["status"], "PASS")
            self.assertTrue(milestone["decision"]["acquisition_lock_exit_eligible"])
            self.assertIsNone(
                verify_phase1_acquisition_lock_milestone_v2(
                    evidence,
                    milestone,
                    evidence_cas=cas,
                )
            )

            forged = deepcopy(milestone)
            forged["claims"]["installed_digest_integrity"]["files"] = 5
            with self.assertRaisesRegex(
                Phase1AcquisitionLockV2Error,
                "does not match its derived aggregate",
            ):
                verify_phase1_acquisition_lock_milestone_v2(
                    evidence,
                    forged,
                    evidence_cas=cas,
                )

    def test_empty_cas_is_not_tested(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            milestone = derive_phase1_acquisition_lock_milestone_v2(
                _envelope(),
                evidence_cas=_cas(Path(temporary), populated=False),
            )

        self.assertEqual(milestone["decision"]["status"], "NOT_TESTED")
        self.assertFalse(milestone["decision"]["acquisition_lock_exit_eligible"])
        self.assertEqual(
            {claim["status"] for claim in milestone["claims"].values()},
            {"NOT_TESTED"},
        )

    def test_writable_tampered_and_caller_modified_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            writable = CAS(temporary)
            with self.assertRaisesRegex(
                Phase1AcquisitionLockV2Error,
                "must be read-only",
            ):
                derive_phase1_acquisition_lock_milestone_v2(
                    _envelope(),
                    evidence_cas=writable,
                )

        changed = _envelope()
        changed["leaf_digests"]["recursive"]["archive"] = "sha256:" + "0" * 64
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(
                Phase1AcquisitionLockV2Error,
                "release-owned envelope",
            ),
        ):
            derive_phase1_acquisition_lock_milestone_v2(
                changed,
                evidence_cas=_cas(Path(temporary), populated=False),
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cas = _cas(root, populated=True)
            digest = phase1_acquisition_lock_workload_v2()["leaf_digests"][
                "protected_transition"
            ]["archive"]
            value = digest[7:]
            blob = root / "blobs" / "sha256" / value[:2] / value[2:]
            raw = bytearray(blob.read_bytes())
            raw[-1] ^= 1
            blob.chmod(0o600)
            blob.write_bytes(raw)
            blob.chmod(0o444)

            milestone = derive_phase1_acquisition_lock_milestone_v2(
                _envelope(),
                evidence_cas=cas,
            )

        self.assertEqual(
            milestone["claims"]["installed_digest_integrity"]["status"],
            "FAIL",
        )
        self.assertEqual(milestone["decision"]["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
