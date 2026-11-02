from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import admission_openclaw_final_v3_core_updater_qualification as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]


class CoreUpdaterQualificationTests(unittest.TestCase):
    def test_exact_qualification_matches_retained_receipt_and_keeps_aggregate_false(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = CAS(temporary)
            for item in (subject._EVIDENCE, subject._ACQUISITION):
                raw = (_ROOT / item["path"]).read_bytes()
                store.put_expected(BytesIO(raw), expected_digest=item["digest"], max_bytes=len(raw))
            result = subject.qualify_openclaw_final_v3_core_updater_subfixture(evidence_cas=store)
        receipt = _ROOT / "benchmark/receipts/phase3-openclaw-final-v3-core-updater-route-qualification-v1-2026-09-06.json"
        self.assertEqual(receipt.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})
        self.assertTrue(all(value is False for key, value in result["decision"].items() if key.endswith("_eligible")))
        self.assertFalse(result["capture"]["independent_host_destruction_attestation"])

    def test_signed_observation_and_native_capture_joins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = CAS(temporary)
            raw = (_ROOT / subject._EVIDENCE["path"]).read_bytes()
            store.put_expected(BytesIO(raw), expected_digest=subject._EVIDENCE["digest"], max_bytes=len(raw))
            evidence = subject._load_original(store)
            result = subject._verify_capture(evidence)
        self.assertTrue(result["route_semantics"]["replacement_target_unchanged"])
        self.assertFalse(result["route_semantics"]["pass_authority"])
        self.assertEqual(raw, canonical_json(evidence) + b"\n")

    def test_modified_capture_or_summary_cannot_gain_pass(self) -> None:
        evidence = json.loads((_ROOT / subject._EVIDENCE["path"]).read_bytes())
        mutations = [
            ("decision", "route_pass_count", 1),
            ("decision", "phase3_exit_eligible", True),
            ("route_observation", "bundle", []),
        ]
        for outer, key, value in mutations:
            with self.subTest(key=key):
                changed = deepcopy(evidence)
                changed[outer][key] = value
                with self.assertRaises(AdmissionEvidenceError):
                    subject._verify_capture(changed)

    def test_missing_cas_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(AdmissionEvidenceError):
            subject.qualify_openclaw_final_v3_core_updater_subfixture(evidence_cas=CAS(temporary))

    def test_original_observation_without_native_provenance_cannot_gain_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = CAS(temporary)
            raw = (_ROOT / subject._EVIDENCE["path"]).read_bytes()
            store.put_expected(BytesIO(raw), expected_digest=subject._EVIDENCE["digest"], max_bytes=len(raw))
            with self.assertRaises(AdmissionEvidenceError):
                subject.qualify_openclaw_final_v3_core_updater_subfixture(evidence_cas=store)

    def test_unsigned_source_change_fails_closed(self) -> None:
        evidence = json.loads((_ROOT / subject._EVIDENCE["path"]).read_bytes())
        with (
            patch.object(subject, "_signed_record", return_value=b"changed"),
            self.assertRaisesRegex(AdmissionEvidenceError, "source checkout drift"),
        ):
            subject._verify_materialization(evidence)

    def test_native_acquisition_repin_cannot_bypass_signed_retention(self) -> None:
        raw = (_ROOT / subject._ACQUISITION["path"]).read_bytes()
        value = json.loads(raw)
        value["acquisition"]["runtime_tree_after"]["tree_digest"] = "sha256:" + "0" * 64
        forged = canonical_json(value) + b"\n"
        identity = {**subject._ACQUISITION, "bytes": len(forged), "digest": subject._digest(forged)}
        with tempfile.TemporaryDirectory() as temporary:
            store = CAS(temporary)
            store.put(BytesIO(forged), max_bytes=len(forged))
            with patch.object(subject, "_ACQUISITION", identity), self.assertRaises(AdmissionEvidenceError):
                subject._verify_acquisition(store, {})

    def test_native_verifier_dependency_drift_is_rejected(self) -> None:
        original_git = subject._git

        def changed_git(arguments: list[str], **kwargs: object) -> bytes:
            if arguments == ["show", "c6f5266e9a6544ebdc679136f98445943bb922f4:src/aragorn/admission_openclaw_final_v3_core_updater_provenance.py"]:
                return b"changed native verifier"
            return original_git(arguments, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            store = CAS(temporary)
            raw = (_ROOT / subject._ACQUISITION["path"]).read_bytes()
            store.put(BytesIO(raw), max_bytes=len(raw))
            evidence = json.loads((_ROOT / subject._EVIDENCE["path"]).read_bytes())
            with patch.object(subject, "_git", side_effect=changed_git), self.assertRaisesRegex(AdmissionEvidenceError, "native provenance verifier dependency changed"):
                subject._verify_acquisition(store, evidence)


if __name__ == "__main__":
    unittest.main()
