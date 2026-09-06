from __future__ import annotations

import base64
import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import admission_openclaw_final_v3_det01_qualification as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json


class Det01QualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = (subject._ROOT / subject._EVIDENCE["path"]).read_bytes()
        cls.evidence = json.loads(cls.raw)
        cls.signed = {subject._MATERIALIZER: (subject._ROOT / subject._MATERIALIZER).read_bytes()}

    def test_exact_signed_capture_qualifies_only_one_case(self) -> None:
        with TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            cas.put_expected(BytesIO(self.raw), expected_digest=subject._EVIDENCE["digest"],
                             max_bytes=len(self.raw))
            result = subject.qualify_openclaw_final_v3_det01_subfixture(evidence_cas=cas)
            self.assertEqual(result["case"], {"id": "DET-01", "status": "PASS"})
            self.assertEqual(result["bindings"]["source"], subject._SOURCE)
            self.assertEqual(result["bindings"]["retention"], subject._RETENTION)
            self.assertEqual(result["bindings"]["observation"], subject._EVIDENCE)
            self.assertTrue(all(value is False for key, value in result["decision"].items()
                                if key.endswith("_eligible")))
            self.assertFalse(result["capture"]["independent_host_destruction_attestation"])
            self.assertIn("NOT_FINAL_CAMPAIGN_SUBFIXTURE_EVIDENCE", result["limitations"])

    def test_missing_or_changed_cas_evidence_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            with self.assertRaises(AdmissionEvidenceError):
                subject.qualify_openclaw_final_v3_det01_subfixture(evidence_cas=cas)
            with patch.object(cas, "read", return_value=self.raw.replace(b'"OBSERVED"', b'"PASS"', 1)):
                with self.assertRaises(AdmissionEvidenceError):
                    subject.qualify_openclaw_final_v3_det01_subfixture(evidence_cas=cas)

    def test_signed_source_parent_change_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            with patch.dict(subject._SOURCE, {"parent": "0" * 40}):
                with self.assertRaises(AdmissionEvidenceError):
                    subject.qualify_openclaw_final_v3_det01_subfixture(evidence_cas=cas)

    def test_lifecycle_and_execution_mutations_are_rejected(self) -> None:
        mutations = [
            (("lifecycle", "fresh_path_observed"), False),
            (("lifecycle", "destroyed_before_capture_return"), 1),
            (("lifecycle", "before_materialization", "entries"), ["stale"]),
            (("lifecycle", "after_destruction", "entries"), ["cases"]),
            (("lifecycle", "during_execution", "root", "inode"), 1),
            (("bundle", 0, "role"), "fixture"),
            (("materializer", "command", "exit_code"), False),
            (("replay", "command", "argv"), ["/tmp/replay"]),
            (("replay", "command", "environment", "PYTHONHASHSEED"), "random"),
            (("replay", "command", "completed_at"), "2026-09-03T18:27:28.000Z"),
            (("vector_set", "digest"), "sha256:" + "0" * 64),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path):
                value = deepcopy(self.evidence["subfixture"])
                node = value
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = replacement
                with self.assertRaises(AdmissionEvidenceError):
                    subject._verify_subfixture(value, self.evidence["recorded_at"], self.signed)

    def test_replay_mutation_with_recomputed_output_join_is_rejected(self) -> None:
        value = deepcopy(self.evidence["subfixture"])
        value["replay"]["document"]["cases"][0]["replays"][0]["stdout_digest"] = "sha256:" + "0" * 64
        raw = canonical_json(value["replay"]["document"]) + b"\n"
        value["replay"]["command"]["stdout"] = {
            "base64": base64.b64encode(raw).decode(), "bytes": len(raw), "digest": subject._digest(raw),
        }
        with self.assertRaises(ValueError):
            subject._verify_subfixture(value, self.evidence["recorded_at"], self.signed)

    def test_boolean_number_substitution_is_rejected(self) -> None:
        for key, value in (("det_01_eligible", 0), ("bytes", False), ("exit_code", 0.0)):
            with self.subTest(key=key), self.assertRaises(AdmissionEvidenceError):
                subject._verify_scalar_types({key: value})


if __name__ == "__main__":
    unittest.main()
