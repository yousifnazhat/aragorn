from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import (
    admission_protected_final_combined_v2_chat_session_snapshot_consumer_catalog_fixed as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject.parent._EVIDENCE["path"]
_PARENT = _ROOT / subject._PARENT_RECEIPT["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-chat-session-"
    "snapshot-consumer-catalog-fixed-route-coverage-v1-2026-08-22.json"
)


class FinalCombinedV2ChatSessionSnapshotConsumerCatalogFixedTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store = CAS(temporary.name)
        store.put_expected(
            BytesIO(evidence),
            expected_digest=subject._digest(evidence),
            max_bytes=len(evidence),
        )
        return subject.verify_openclaw_final_combined_v2_chat_session_snapshot_consumer_catalog_fixed(
            evidence_cas=store
        )

    def test_exact_shared_chat_pass_and_hostile_inputs_fail_closed(self) -> None:
        raw = _EVIDENCE.read_bytes()
        result = self.verify(raw)
        self.assertEqual(result, self.verify(raw))
        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})
        statuses = {item["id"]: item["status"] for item in result["profile"]["routes"]}
        self.assertEqual(statuses[subject._ROUTE], "PASS")
        self.assertEqual(statuses[subject._SOURCE_ROUTE], "NOT_TESTED")
        self.assertEqual(list(statuses.values()).count("PASS"), 1)
        self.assertEqual(
            result["bindings"]["parent_qualification_canonical_digest"],
            subject._PARENT_RESULT_DIGEST,
        )
        self.assertEqual(
            result["bindings"]["parent_verifier"]["digest"],
            subject._PARENT_MODULE["digest"],
        )
        self.assertEqual(
            result["bindings"]["session_snapshot_observation"]["digest"],
            subject.parent._EVIDENCE["digest"],
        )
        self.assertFalse(result["route_semantics"]["shared_capture_independent"])
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.parent.current.base.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        self.assertIn(
            "CHAT_ROUTE_REUSES_SHARED_SESSION_SNAPSHOT_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            result["limitations"],
        )
        self.assertIn(
            "BLACK_BOX_NATIVE_CHAT_PERSISTENCE_WITHOUT_DIRECT_SESSION_UPDATES_TRACE",
            result["limitations"],
        )
        self.assertIn(
            "MODEL_TURNS_FAILED_NO_PROVIDER_BODY_SUCCESSFUL_REPLY_OR_DELIVERY_CLAIM",
            result["limitations"],
        )
        self.assertIn(
            "ONE_TAMPER_RECOVERY_TRIGGER_NOT_GENERAL_CHAT_ROUTE_COVERAGE",
            result["limitations"],
        )
        for limitation in (
            "FOURTEEN_SELECTED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "COMPILED_CLOSURE_REUSED_FROM_PRIOR_CAPTURE_WITH_IDENTICAL_RUNTIME_TREE",
            "ACQUISITION_IMAGE_DIFFERS_FROM_CURRENT_ROUTE_CAPTURE_IMAGE",
        ):
            self.assertIn(limitation, result["limitations"])
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

        evidence = json.loads(raw)

        def rejects(changed: dict[str, object]) -> None:
            with self.assertRaises(AdmissionEvidenceError):
                subject._verify_chat_subsequence(changed)

        changed = deepcopy(evidence)
        changed["route_id"] = subject._ROUTE
        rejects(changed)

        changed = deepcopy(evidence)
        changed["route_observation"]["document"]["action"]["observations"][
            "injected_turn"
        ]["request_params"]["sessionKey"] = "agent:main:forged"
        rejects(changed)

        changed = deepcopy(evidence)
        action = changed["route_observation"]["document"]["action"]
        action["commands"][4], action["commands"][5] = (
            action["commands"][5],
            action["commands"][4],
        )
        rejects(changed)

        changed = deepcopy(evidence)
        action = changed["route_observation"]["document"]["action"]
        injected = action["observations"]["injected_turn"]
        for command in (
            action["commands"][4],
            injected["commands"][0],
            injected["send"]["command"],
        ):
            command["pid"] = 1
        rejects(changed)

        changed = deepcopy(evidence)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["final_snapshot"]["prompt"]["digest"] = "sha256:" + "0" * 64
        rejects(changed)

        changed = deepcopy(evidence)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["final_snapshot"]["entry"]["session_id"] = (
            "00000000-0000-4000-8000-000000000000"
        )
        rejects(changed)

        changed = deepcopy(evidence)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["native_recovery_timing"]["final_store_mtime_ms"] = 1
        rejects(changed)

        changed = deepcopy(evidence)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["injected_turn"]["wait"]["response"]["value"]["status"] = "success"
        rejects(changed)

        changed = deepcopy(evidence)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["final_system_prompt_report"]["ready"] = True
        rejects(changed)

        changed = deepcopy(evidence)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["compiled_route_replay"]["native_agent_execution"] = True
        rejects(changed)

        with (
            patch.object(subject, "_PARENT_RESULT_DIGEST", "sha256:" + "0" * 64),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.verify(raw)
        with (
            patch.dict(subject._PARENT_MODULE, {"digest": "sha256:" + "0" * 64}),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.verify(raw)
        with (
            patch.dict(subject._PARENT_RECEIPT, {"digest": "sha256:" + "0" * 64}),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.verify(raw)

        signed_parent = json.loads(_PARENT.read_bytes())
        for field, value in (("counts", True), ("decision", 0)):
            changed_parent = deepcopy(signed_parent)
            if field == "counts":
                changed_parent["profile"]["counts"]["PASS"] = value
            else:
                changed_parent["decision"]["edr_eligible"] = value
            with (
                patch.object(
                    subject,
                    "_PARENT_RESULT_DIGEST",
                    subject.parent._canonical_digest(changed_parent),
                ),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject._verify_parent_result(changed_parent, signed_parent)

        changed_parent = deepcopy(signed_parent)
        changed_parent["profile"]["routes"][1]["id"] = changed_parent["profile"][
            "routes"
        ][0]["id"]
        with (
            patch.object(
                subject,
                "_PARENT_RESULT_DIGEST",
                subject.parent._canonical_digest(changed_parent),
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject._verify_parent_result(changed_parent, signed_parent)

        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v2_chat_session_snapshot_consumer_catalog_fixed(
                evidence_cas=CAS(temporary)
            )


if __name__ == "__main__":
    unittest.main()
