from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import (
    admission_protected_final_combined_v2_workshop_invalidation as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject.parent._EVIDENCE["path"]
_PARENT = _ROOT / subject._PARENT_RECEIPT["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-workshop-"
    "invalidation-route-coverage-v1-2026-08-26.json"
)


class FinalCombinedV2WorkshopInvalidationTests(unittest.TestCase):
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
        return subject.verify_openclaw_final_combined_v2_workshop_invalidation(
            evidence_cas=store
        )

    def test_exact_shared_reload_pass_and_parent_binding(self) -> None:
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
            result["bindings"]["parent_receipt"], subject._PARENT_RECEIPT
        )
        signed_parent = json.loads(_PARENT.read_bytes())
        self.assertEqual(
            result["bindings"]["workshop_proposal_apply_observation"],
            signed_parent["bindings"]["workshop_proposal_apply_observation"],
        )
        self.assertFalse(result["route_semantics"]["shared_capture_independent"])
        self.assertEqual(
            result["route_semantics"]["source_capture_route"],
            subject._SOURCE_ROUTE,
        )
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.parent.contract.base.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        for limitation in (
            "WORKSHOP_INVALIDATION_REUSES_SHARED_PROPOSAL_APPLY_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            "ONE_APPLIED_WORKSHOP_RESIDUE_AND_ONE_OBSERVED_POST_APPLY_FAIL_CLOSED_CATALOG_STORE_TRANSITION_ONLY",
            "BLACK_BOX_NEXT_TURN_DERIVATION_NO_DIRECT_INVALIDATION_FUNCTION_TRACE",
            "NEXT_SAME_SESSION_TURN_FAILED_WITH_NETWORK_ERROR_NO_MODEL_REPLY_OR_DELIVERY_CLAIM",
            "WRITTEN_WORKSHOP_RESIDUE_NOT_CLEANED_UP",
            "NO_CATALOG_AVAILABILITY_OR_PROVIDER_SUCCESS_CLAIM",
            "APPLIED_TARGET_BYTES_NOT_RETAINED_METADATA_DIGEST_ONLY",
            "WORKSHOP_SCAN_CLEAN_IS_SELF_REPORTED_DIAGNOSTIC_ONLY",
            "STORE_TRANSITION_CHRONOLOGY_USES_SESSION_ENTRY_UPDATED_AT_NO_FILE_MTIME_RETAINED",
        ):
            self.assertIn(limitation, result["limitations"])
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_coordinated_repin_hostile_reload_semantics_fail_closed(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects(changed: dict[str, object]) -> None:
            observed = changed["route_observation"]["document"]["actions"][0][
                "observations"
            ]
            digests = {
                name: canonical_digest(observed[name])
                for name in subject._SUBTREE_DIGESTS
            }
            with (
                patch.object(subject, "_SUBTREE_DIGESTS", digests),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject._verify_reload_subsequence(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        observations["immediate_post_apply_snapshot"] = deepcopy(
            observations["final_snapshot"]
        )
        rejects(changed)

        changed = deepcopy(original)
        turn = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]["next_same_session_turn"]
        turn["wait"]["response"]["value"] = {
            "endedAt": 1_787_754_759_457,
            "runId": (
                "aragorn-protected-route-workshop-next-same-session-"
                f"{subject._NONCE}"
            ),
            "status": "success",
        }
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["actions"][0]["observations"][
            "next_same_session_turn"
        ]["reply"] = {"text": "forged"}
        rejects(changed)

        changed = deepcopy(original)
        final = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]["final_snapshot"]
        final["entry"]["prompt"]["bytes"] = 738
        final["entry"]["prompt"]["file"]["size"] = 738
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        observations["final_snapshot"]["entry"]["snapshot_version"] = (
            1_787_754_737_358
        )
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        old_store = observations["initial_snapshot"]["file"]
        final_store = observations["final_snapshot"]["file"]
        final_store["digest"] = old_store["digest"]
        final_store["inode"] = old_store["inode"]
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        observations["final_snapshot"]["entry"]["updated_at"] = (
            1_787_754_760_000
        )
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        observations["final_snapshot"]["entry"]["session_id"] = (
            "00000000-0000-4000-8000-000000000000"
        )
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        observations["final_catalog"]["response"]["value"] = {
            "ok": True,
            "skills": [],
        }
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        observations = action["observations"]
        observations["catalog_before"] = deepcopy(
            observations["catalog_after_apply"]
        )
        action["commands"][0] = deepcopy(
            observations["catalog_before"]["command"]
        )
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        observations = action["observations"]
        observations["catalog_after_apply"] = deepcopy(
            observations["catalog_before"]
        )
        action["commands"][5] = deepcopy(
            observations["catalog_after_apply"]["command"]
        )
        rejects(changed)

        changed = deepcopy(original)
        apply_record = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]["native_apply_result"]["response"]["value"]["record"]
        apply_record["appliedAt"] = "2026-08-26T14:32:36.999Z"
        apply_record["updatedAt"] = apply_record["appliedAt"]
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        observations["target_final"]["skill"]["exists"] = False
        observations["target_final"]["skill"]["digest"] = None
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        action["commands"][7], action["commands"][8] = (
            action["commands"][8],
            action["commands"][7],
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["actions"][0]["observations"][
            "forged_claim"
        ] = True
        rejects(changed)

        changed = deepcopy(original)
        changed["decision"]["route_pass_count"] = 1
        rejects(changed)

        changed = deepcopy(original)
        changed["route_id"] = subject._ROUTE
        changed["route_observation"]["route"]["id"] = subject._ROUTE
        changed["route_observation"]["document"]["routes"][0]["id"] = (
            subject._ROUTE
        )
        changed["route_observation"]["document"]["selected_route_ids"] = [
            subject._ROUTE
        ]
        rejects(changed)

    def test_parent_and_missing_cas_fail_closed(self) -> None:
        raw = _EVIDENCE.read_bytes()
        for target, value in (
            ("_PARENT_RESULT_DIGEST", "sha256:" + "0" * 64),
            ("_PARENT_MODULE", {**subject._PARENT_MODULE, "digest": "sha256:" + "0" * 64}),
            (
                "_PARENT_RECEIPT",
                {**subject._PARENT_RECEIPT, "digest": "sha256:" + "0" * 64},
            ),
        ):
            with (
                patch.object(subject, target, value),
                self.assertRaises(AdmissionEvidenceError),
            ):
                self.verify(raw)

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

        changed_parent = deepcopy(signed_parent)
        changed_parent["profile"]["routes"][0]["id"] = changed_parent["profile"][
            "routes"
        ][1]["id"]
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
            subject.verify_openclaw_final_combined_v2_workshop_invalidation(
                evidence_cas=CAS(temporary)
            )


if __name__ == "__main__":
    unittest.main()
