from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_protected_session_snapshot_fixed_chat as chat
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark/evidence/openclaw-v2026.7.1-protected-session-snapshot-fixed-2026-08-12.json"
)
_PARENT = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-session-snapshot-fixed-fresh-session-route-coverage-v1-2026-08-13.json"
)


class FixedChatRouteTests(unittest.TestCase):
    def test_exact_eight_route_result_and_hostile_subsequence(self) -> None:
        raw = _EVIDENCE.read_bytes()
        parent = json.loads(_PARENT.read_bytes())
        with TemporaryDirectory() as temporary:
            cas = CAS(temporary)
            cas.put(BytesIO(raw), max_bytes=len(raw))
            result = chat.verify_openclaw_protected_session_snapshot_fixed_chat(
                parent, evidence_cas=cas
            )
        self.assertEqual(
            result["profile"]["counts"], {"fail": 0, "not_tested": 13, "pass": 8}
        )
        statuses = {item["id"]: item["status"] for item in result["profile"]["routes"]}
        self.assertEqual(statuses[chat._ROUTE], "PASS")
        self.assertEqual(list(statuses.values()).count("PASS"), 8)
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key != "status"
            )
        )

        evidence = json.loads(raw)
        mutations = [
            lambda value: value["action"]["observations"]["final_snapshot"][
                "entry"
            ].__setitem__(
                "session_id",
                value["action"]["observations"]["initial_snapshot"]["entry"][
                    "session_id"
                ][::-1],
            ),
            lambda value: value["action"]["observations"].__setitem__(
                "attacker_blob_unreferenced_after", False
            ),
            lambda value: value["action"]["observations"]["mutation"].__setitem__(
                "changed_json_paths", []
            ),
            lambda value: value["action"]["observations"][
                "native_recovery_timing"
            ].__setitem__("final_store_mtime_ms", 1),
            lambda value: value["action"]["observations"]["final_snapshot"][
                "store"
            ].__setitem__("digest", "sha256:" + "0" * 64),
            lambda value: value["action"]["observations"]["injected_turn"]["send"][
                "command"
            ].__setitem__("pid", 1),
            lambda value: value["action"].__setitem__("id", "forged"),
            lambda value: value["action"]["observations"]["pre_injected_snapshot"][
                "store"
            ].__setitem__("digest", "sha256:" + "0" * 64),
        ]
        for mutate in mutations:
            changed = deepcopy(evidence)
            mutate(changed)
            with self.assertRaises(AdmissionEvidenceError):
                chat._verify_chat_subsequence(changed)

        changed_parent = deepcopy(parent)
        changed_parent["profile"]["counts"]["pass"] = 8
        with TemporaryDirectory() as temporary:
            cas = CAS(temporary)
            cas.put(BytesIO(raw), max_bytes=len(raw))
            with self.assertRaises(AdmissionEvidenceError):
                chat.verify_openclaw_protected_session_snapshot_fixed_chat(
                    changed_parent, evidence_cas=cas
                )


if __name__ == "__main__":
    unittest.main()
