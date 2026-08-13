from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import admission_protected_restore_authority_chat as chat
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / chat.prompt._EVIDENCE["path"]
_PARENT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-restore-authority-session-"
    "consumer-route-coverage-v1-2026-08-13.json"
)


class ProtectedRestoreAuthorityChatTests(unittest.TestCase):
    def test_eight_route_coverage_and_hostile_inputs_fail_closed(self) -> None:
        raw = _EVIDENCE.read_bytes()
        evidence = json.loads(raw)
        parent = json.loads(_PARENT.read_bytes())
        with TemporaryDirectory() as temporary:
            cas = CAS(temporary)
            cas.put(BytesIO(raw), max_bytes=len(raw))
            first = chat.verify_openclaw_protected_restore_authority_chat(
                parent, evidence_cas=cas
            )
            self.assertEqual(
                first,
                chat.verify_openclaw_protected_restore_authority_chat(
                    parent, evidence_cas=cas
                ),
            )

        self.assertEqual(
            first["profile"]["counts"],
            {"fail": 0, "not_tested": 13, "pass": 8},
        )
        parent_statuses = {
            item["id"]: item["status"] for item in parent["profile"]["routes"]
        }
        statuses = {item["id"]: item["status"] for item in first["profile"]["routes"]}
        self.assertEqual(
            {route for route in statuses if statuses[route] != parent_statuses[route]},
            {chat._ROUTE},
        )
        self.assertEqual(statuses[chat._ROUTE], "PASS")
        self.assertTrue(
            all(
                value is False
                for key, value in first["decision"].items()
                if key != "status"
            )
        )
        self.assertIn(
            "CHAT_ROUTE_REUSES_SHARED_PROMPT_REBUILD_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            first["limitations"],
        )
        self.assertIn(
            "BLACK_BOX_NATIVE_CHAT_PERSISTENCE_WITHOUT_DIRECT_SESSION_UPDATES_TRACE",
            first["limitations"],
        )

        mutations = [
            lambda value: value["action"]["observations"]["rebuilt_snapshot"][
                "entry"
            ].__setitem__("session_id", "00000000-0000-4000-8000-000000000000"),
            lambda value: value["action"]["observations"]["rebuilt_snapshot"][
                "prompt"
            ].__setitem__("digest", "sha256:" + "0" * 64),
            lambda value: value["action"]["observations"]["rebuild_turn"].__setitem__(
                "confirmed", False
            ),
            lambda value: value["action"]["observations"]["invalidation"][
                "store_after_rewrite"
            ].__setitem__("digest", "sha256:" + "0" * 64),
            lambda value: value["action"]["observations"].__setitem__(
                "runtime_tree_after", {}
            ),
            lambda value: value["action"].__setitem__("id", "forged"),
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
                chat.verify_openclaw_protected_restore_authority_chat(
                    changed_parent, evidence_cas=cas
                )
        with (
            TemporaryDirectory() as temporary,
            self.assertRaises(AdmissionEvidenceError),
        ):
            chat.verify_openclaw_protected_restore_authority_chat(
                parent, evidence_cas=CAS(temporary)
            )

        for module in (chat.prompt.prompt, chat.prompt.curator):
            with (
                patch.object(module, "__file__", __file__),
                self.assertRaises(AdmissionEvidenceError),
            ):
                chat._verify_chat_subsequence(evidence)


if __name__ == "__main__":
    unittest.main()
