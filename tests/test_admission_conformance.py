from __future__ import annotations

import unittest
from copy import deepcopy

from aragorn.admission_conformance import (
    MANDATORY_ADMISSION_SCENARIOS,
    AdmissionConformanceError,
    validate_admission_conformance,
)

_DIGEST = "sha256:" + "1" * 64


def _result(status: str = "PASS") -> dict[str, object]:
    reasons = [] if status == "PASS" else ["TEST_INCOMPLETE"]
    evidence = [_DIGEST] if status in {"PASS", "FAIL"} else []
    return {
        "schema": "aragorn/admission-conformance-result/v1",
        "profile": "admission-conformant/v1",
        "recorded_at": "2026-07-27T00:00:00Z",
        "bindings": {
            "runtime": {
                "name": "example-runtime",
                "version": "1.0.0",
                "repository_url": "https://github.com/example/runtime",
                "commit": "1" * 40,
                "source_tree_digest": _DIGEST,
            },
            "adapter": {
                "name": "example-adapter",
                "implementation_digest": _DIGEST,
                "configuration_digest": _DIGEST,
            },
            "environment": {
                "worker_digest": _DIGEST,
                "os_profile_digest": _DIGEST,
            },
            "aragorn": {
                "implementation_digest": _DIGEST,
                "policy_digest": _DIGEST,
            },
        },
        "properties": [
            {
                "id": property_id,
                "status": status,
                "scenarios": [
                    {
                        "id": scenario_id,
                        "status": status,
                        "evidence_digests": evidence.copy(),
                        "reason_codes": reasons.copy(),
                    }
                    for scenario_id in scenario_ids
                ],
            }
            for property_id, scenario_ids in MANDATORY_ADMISSION_SCENARIOS.items()
        ],
        "decision": {
            "status": status,
            "installer_work_eligible": status == "PASS",
        },
    }


class AdmissionConformanceTests(unittest.TestCase):
    def test_all_mandatory_scenarios_pass(self) -> None:
        self.assertEqual(validate_admission_conformance(_result()), "PASS")

    def test_not_tested_cannot_authorize_installer_work(self) -> None:
        document = _result("NOT_TESTED")
        document["decision"]["installer_work_eligible"] = True
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "installer eligibility",
        ):
            validate_admission_conformance(document)

    def test_one_failed_scenario_fails_property_and_profile(self) -> None:
        document = _result()
        failed = document["properties"][2]["scenarios"][3]
        failed.update(
            {
                "status": "FAIL",
                "reason_codes": ["RENAME_BYPASS"],
            }
        )
        document["properties"][2]["status"] = "FAIL"
        document["decision"] = {
            "status": "FAIL",
            "installer_work_eligible": False,
        }
        self.assertEqual(validate_admission_conformance(document), "FAIL")

    def test_missing_activation_path_is_rejected(self) -> None:
        document = _result()
        document["properties"][2]["scenarios"].pop()
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "every mandatory path",
        ):
            validate_admission_conformance(document)

    def test_forged_aggregate_pass_is_rejected(self) -> None:
        document = _result("NOT_TESTED")
        document["decision"] = {
            "status": "PASS",
            "installer_work_eligible": True,
        }
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "profile status",
        ):
            validate_admission_conformance(document)

    def test_evidence_and_reasons_must_be_canonical(self) -> None:
        document = deepcopy(_result())
        scenario = document["properties"][0]["scenarios"][0]
        scenario["evidence_digests"] = [
            "sha256:" + "2" * 64,
            _DIGEST,
        ]
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "sorted and unique",
        ):
            validate_admission_conformance(document)


if __name__ == "__main__":
    unittest.main()
