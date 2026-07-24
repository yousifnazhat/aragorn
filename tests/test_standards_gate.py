from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from aragorn.standards_gate import StandardsGateError, validate_standards_gate


ROOT = Path(__file__).parents[1]
GATE_PATH = ROOT / "benchmark" / "phase0-standards-gate.json"


class StandardsGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(GATE_PATH.read_text(encoding="utf-8"))

    def test_checked_in_gate_has_three_resolved_packs(self) -> None:
        self.assertEqual(
            validate_standards_gate(self.document, repository_root=ROOT),
            {
                "pack_count": 3,
                "item_count": 26,
                "evidence_mapped": 22,
                "roadmap_mapped": 4,
                "unresolved": 0,
            },
        )

    def test_missing_evidence_reference_is_rejected(self) -> None:
        document = deepcopy(self.document)
        document["packs"][0]["items"][0]["evidence_refs"] = ["missing-evidence.json"]
        with self.assertRaisesRegex(
            StandardsGateError,
            "standards evidence does not resolve",
        ):
            validate_standards_gate(document, repository_root=ROOT)

    def test_evidence_reference_cannot_escape_repository(self) -> None:
        document = deepcopy(self.document)
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as directory:
            outside = Path(directory) / "outside-evidence.txt"
            outside.write_text("outside", encoding="utf-8")
            reference = "../" + outside.relative_to(ROOT.parent).as_posix()
            document["packs"][0]["items"][0]["evidence_refs"] = [reference]
            with self.assertRaisesRegex(
                StandardsGateError,
                "standards evidence escapes repository root",
            ):
                validate_standards_gate(document, repository_root=ROOT)

    def test_duplicate_item_id_is_rejected(self) -> None:
        document = deepcopy(self.document)
        document["packs"][1]["items"][0]["id"] = document["packs"][0]["items"][0]["id"]
        with self.assertRaisesRegex(StandardsGateError, "item inventory does not match"):
            validate_standards_gate(document, repository_root=ROOT)

    def test_selected_item_cannot_be_omitted_with_a_forged_summary(self) -> None:
        document = deepcopy(self.document)
        removed = document["packs"][0]["items"].pop()
        document["gate"]["summary"]["item_count"] -= 1
        document["gate"]["summary"][removed["disposition"]] -= 1
        with self.assertRaisesRegex(StandardsGateError, "item inventory does not match"):
            validate_standards_gate(document, repository_root=ROOT)

    def test_source_cannot_be_moved_to_another_pack(self) -> None:
        document = deepcopy(self.document)
        document["packs"][1]["sources"][0]["source_id"] = "nist-ai-100-1"
        with self.assertRaisesRegex(
            StandardsGateError,
            "source inventory does not match",
        ):
            validate_standards_gate(document, repository_root=ROOT)

    def test_source_pin_tampering_is_rejected(self) -> None:
        document = deepcopy(self.document)
        document["packs"][0]["sources"][0]["artifact_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            StandardsGateError,
            "content does not match its frozen v1 identity",
        ):
            validate_standards_gate(document, repository_root=ROOT)

    def test_forged_summary_is_rejected(self) -> None:
        document = deepcopy(self.document)
        document["gate"]["summary"]["item_count"] += 1
        with self.assertRaisesRegex(StandardsGateError, "summary does not match"):
            validate_standards_gate(document, repository_root=ROOT)


if __name__ == "__main__":
    unittest.main()
