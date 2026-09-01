from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import (
    admission_protected_final_combined_v3_workshop_invalidation as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject.parent._EVIDENCE["path"]
_PARENT = _ROOT / subject._PARENT_RECEIPT["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-workshop-"
    "invalidation-route-coverage-v1-2026-09-01.json"
)


class FinalCombinedV3WorkshopInvalidationTests(unittest.TestCase):
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
        return subject.verify_openclaw_final_combined_v3_workshop_invalidation(
            evidence_cas=store
        )

    def test_exact_shared_reload_pass_and_parent_binding(self) -> None:
        result = self.verify()
        self.assertEqual(result, self.verify())
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
        self.assertEqual(result["bindings"]["parent_receipt"], subject._PARENT_RECEIPT)
        signed_parent = json.loads(_PARENT.read_bytes())
        self.assertEqual(
            result["bindings"]["workshop_proposal_apply_observation"],
            signed_parent["bindings"]["workshop_proposal_apply_observation"],
        )
        self.assertFalse(result["route_semantics"]["shared_capture_independent"])
        self.assertFalse(
            result["route_semantics"]["native_independent_route_execution"]
        )
        self.assertTrue(result["route_semantics"]["transitions_dynamically_exercised"])
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.parent.v3_contract.contract._ELIGIBILITY_KEYS
            )
        )
        for limitation in (
            "WORKSHOP_INVALIDATION_REUSES_SHARED_PROPOSAL_APPLY_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            "NO_NATIVE_INDEPENDENT_WORKSHOP_INVALIDATION_ROUTE_EXECUTION",
            "BLACK_BOX_NEXT_TURN_DERIVATION_NO_DIRECT_INVALIDATION_FUNCTION_TRACE",
            "NEXT_SAME_SESSION_TURN_FAILED_WITH_NETWORK_ERROR_NO_MODEL_REPLY_OR_DELIVERY_CLAIM",
            "NO_MODEL_PROVIDER_REQUEST_OR_SUCCESS_CLAIM",
            "NO_PRE_EFFECT_NO_MUTATION_CLEANUP_ROLLBACK_OR_QUARANTINE_CLAIM",
            "STORE_TRANSITION_CHRONOLOGY_USES_SESSION_ENTRY_UPDATED_AT_NO_FILE_MTIME_RETAINED",
            "SESSION_STORE_AND_PROMPT_RAW_BYTES_NOT_RETAINED",
            "PRIOR_V3_ROUTE_PASSES_NOT_COMPOSED_ACROSS_FRESH_SESSIONS",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ):
            self.assertIn(limitation, result["limitations"])
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_reload_bridge_recomputes_promoted_facts(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects(changed: dict[str, object]) -> None:
            with (
                patch.object(subject.parent, "_verify_observations", return_value=None),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject._verify_reload_bridge(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        after["final_snapshot"]["entry"]["session_id"] = (
            "00000000-0000-4000-8000-000000000000"
        )
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        after["final_snapshot"]["entry"]["prompt"]["digest"] = "sha256:" + "0" * 64
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        after["final_snapshot"]["entry"]["snapshot_version"] = after[
            "initial_snapshot"
        ]["entry"]["snapshot_version"]
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        after["final_snapshot"]["file"] = deepcopy(after["initial_snapshot"]["file"])
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        after["final_catalog"]["response"]["value"] = deepcopy(
            after["catalog_before"]["response"]["value"]
        )
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        after["target_final"] = deepcopy(
            changed["route_observation"]["document"]["actions"][0]["prerequisites"][
                "target_before"
            ]
        )
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        action["commands"][7], action["commands"][8] = (
            action["commands"][8],
            action["commands"][7],
        )
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        record = after["native_apply_result"]["response"]["value"]["record"]
        record["appliedAt"] = "2026-08-28T19:50:11.772Z"
        record["updatedAt"] = record["appliedAt"]
        rejects(changed)

        changed = deepcopy(original)
        changed["route_id"] = subject._ROUTE
        rejects(changed)

    def test_probe_summary_booleans_are_not_pass_authority(self) -> None:
        evidence = json.loads(_EVIDENCE.read_bytes())
        after = evidence["route_observation"]["document"]["actions"][0]["observations"]
        for key in (
            "final_same_session_catalog_exact",
            "immediate_post_apply_same_session",
            "immediate_post_apply_store_unchanged",
        ):
            after[key] = not after[key]
        for key in (
            "final_snapshot_check",
            "final_snapshot_transition",
            "immediate_post_apply_snapshot_check",
            "initial_snapshot_check",
        ):
            after[key] = {name: not value for name, value in after[key].items()}
        subject._verify_reload_bridge(evidence)

    def test_parent_custody_and_missing_cas_fail_closed(self) -> None:
        for target, value in (
            ("_PARENT_RESULT_DIGEST", "sha256:" + "0" * 64),
            (
                "_PARENT_MODULE",
                {**subject._PARENT_MODULE, "digest": "sha256:" + "0" * 64},
            ),
            (
                "_PARENT_RECEIPT",
                {**subject._PARENT_RECEIPT, "digest": "sha256:" + "0" * 64},
            ),
        ):
            with (
                patch.object(subject, target, value),
                self.assertRaises(AdmissionEvidenceError),
            ):
                self.verify()

        signed_parent = json.loads(_PARENT.read_bytes())
        changed_parent = deepcopy(signed_parent)
        changed_parent["decision"]["edr_eligible"] = 0
        with (
            patch.object(
                subject,
                "_PARENT_RESULT_DIGEST",
                canonical_digest(changed_parent),
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject._verify_parent_result(changed_parent, changed_parent)

        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v3_workshop_invalidation(
                evidence_cas=CAS(temporary)
            )


if __name__ == "__main__":
    unittest.main()
