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
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(AdmissionEvidenceError):
                subject.qualify_openclaw_final_v3_core_updater_subfixture(evidence_cas=CAS(temporary))

    def test_unsigned_source_change_fails_closed(self) -> None:
        evidence = json.loads((_ROOT / subject._EVIDENCE["path"]).read_bytes())
        with patch.object(subject, "_signed_record", return_value=b"changed"):
            with self.assertRaisesRegex(AdmissionEvidenceError, "source checkout drift"):
                subject._verify_materialization(evidence)


if __name__ == "__main__":
    unittest.main()
