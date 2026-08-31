from __future__ import annotations

import unittest

from aragorn.admission_openclaw_final_v3_campaign import (
    CampaignContractError,
    build_openclaw_final_v3_campaign_contract,
    run_openclaw_final_v3_campaign,
    validate_openclaw_final_v3_campaign_contract,
)


class OpenClawFinalV3CampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = build_openclaw_final_v3_campaign_contract(
            campaign_nonce="a" * 64
        )

    def test_contract_orders_fresh_cases_and_keeps_oracles_non_authoritative(
        self,
    ) -> None:
        cases = self.contract["ordered_cases"]
        self.assertEqual(
            self.contract["expected_counts"],
            {
                "ADM-01": 1,
                "ADM-02-FORMAL-STANDALONE": 6,
                "ADM-02-ROUTES": 21,
                "ADM-03": 2,
                "DET-01": 1,
                "TOTAL": 31,
            },
        )
        self.assertEqual(len(cases), 31)
        self.assertEqual(cases[0]["case_id"], "DET-01")
        self.assertEqual(cases[1]["case_id"], "ADM-01/exact-admitted-bytes")
        self.assertEqual(
            [case["case_id"] for case in cases[2:8]],
            [
                "ADM-02/install",
                "ADM-02/direct-write",
                "ADM-02/rename",
                "ADM-02/symlink",
                "ADM-02/auto-discovery",
                "ADM-02/restart",
            ],
        )
        self.assertEqual(cases[-2]["case_id"], "ADM-03/policy-failure")
        self.assertEqual(cases[-1]["case_id"], "ADM-03/policy-tampering")
        self.assertEqual(len({case["fixture_id"] for case in cases}), 31)
        parent_digest = self.contract["frozen_parent"]["digest"]
        self.assertTrue(
            all(
                case["isolation"]
                == {
                    "destroy_before_next": True,
                    "fresh": True,
                    "network": "none",
                    "parent_identity_digest": parent_digest,
                    "reuse": False,
                }
                for case in cases
            )
        )
        oracles = [
            case["regression_oracle"] for case in cases if case["regression_oracle"]
        ]
        self.assertEqual(len(oracles), 9)
        self.assertEqual(
            cases[12]["regression_oracle"]["path"],
            (
                "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
                "curator-restore-route-coverage-v1-2026-08-30.json"
            ),
        )
        self.assertEqual(
            cases[19]["regression_oracle"]["path"],
            (
                "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
                "cron-rescan-route-coverage-v1-2026-08-30.json"
            ),
        )
        self.assertEqual(
            cases[23]["regression_oracle"]["path"],
            (
                "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
                "prompt-rebuild-route-coverage-v1-2026-08-30.json"
            ),
        )
        self.assertEqual(
            cases[27]["regression_oracle"]["path"],
            (
                "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-"
                "session-snapshot-consumer-route-coverage-v1-2026-08-31.json"
            ),
        )
        self.assertTrue(
            all(
                oracle["authority"] == "REGRESSION_ORACLE_ONLY_NOT_CAMPAIGN_EVIDENCE"
                for oracle in oracles
            )
        )
        self.assertTrue(
            all(
                value is False
                for key, value in self.contract["decision"].items()
                if key.endswith("_eligible")
            )
        )

    def test_runner_sequences_all_cases_without_promoting_observations(self) -> None:
        calls: list[str] = []

        def execute(request: dict) -> dict:
            case = request["case"]
            calls.append(case["case_id"])
            return {
                "case_id": case["case_id"],
                "destroyed": True,
                "evidence_refs": [f"sha256:{case['ordinal'] + 1:064x}"],
                "fixture_id": case["fixture_id"],
                "fresh": True,
                "outcome": "OBSERVED",
                "parent_identity_digest": request["frozen_parent"]["digest"],
            }

        result = run_openclaw_final_v3_campaign(self.contract, execute)
        self.assertEqual(
            calls, [case["case_id"] for case in self.contract["ordered_cases"]]
        )
        self.assertEqual(result["execution"]["attested_fresh_subfixture_count"], 31)
        self.assertEqual(result["decision"]["case_observed_count"], 31)
        self.assertEqual(result["decision"]["case_total"], 31)
        self.assertEqual(len(result["declared_regression_oracles"]), 9)
        self.assertTrue(
            all(
                value is False
                for key, value in result["decision"].items()
                if key.endswith("_eligible")
            )
        )

    def test_runner_rejects_pass_or_parent_drift(self) -> None:
        case = self.contract["ordered_cases"][0]

        def result(outcome: str, parent: str) -> dict:
            return {
                "case_id": case["case_id"],
                "destroyed": True,
                "evidence_refs": ["sha256:" + "1" * 64],
                "fixture_id": case["fixture_id"],
                "fresh": True,
                "outcome": outcome,
                "parent_identity_digest": parent,
            }

        with self.assertRaisesRegex(CampaignContractError, "cannot grant PASS"):
            run_openclaw_final_v3_campaign(
                self.contract,
                lambda request: result("PASS", request["frozen_parent"]["digest"]),
            )
        with self.assertRaisesRegex(CampaignContractError, "parent binding"):
            run_openclaw_final_v3_campaign(
                self.contract,
                lambda request: result("OBSERVED", "sha256:" + "0" * 64),
            )

    def test_validator_rejects_case_reordering(self) -> None:
        self.contract["ordered_cases"][0], self.contract["ordered_cases"][1] = (
            self.contract["ordered_cases"][1],
            self.contract["ordered_cases"][0],
        )
        with self.assertRaisesRegex(CampaignContractError, "contract changed"):
            validate_openclaw_final_v3_campaign_contract(self.contract)

    def test_validator_rejects_parent_repin_and_duplicate_evidence(self) -> None:
        self.contract["frozen_parent"]["identity"]["image_id"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(CampaignContractError, "parent identity changed"):
            validate_openclaw_final_v3_campaign_contract(self.contract)

        contract = build_openclaw_final_v3_campaign_contract(campaign_nonce="b" * 64)

        def execute(request: dict) -> dict:
            case = request["case"]
            digest = "sha256:" + "1" * 64
            return {
                "case_id": case["case_id"],
                "destroyed": True,
                "evidence_refs": [digest, digest],
                "fixture_id": case["fixture_id"],
                "fresh": True,
                "outcome": "OBSERVED",
                "parent_identity_digest": request["frozen_parent"]["digest"],
            }

        with self.assertRaisesRegex(CampaignContractError, "evidence references"):
            run_openclaw_final_v3_campaign(contract, execute)

    def test_runner_rejects_string_subclasses_and_cross_case_evidence_reuse(
        self,
    ) -> None:
        class EqualToEverything(str):
            def __eq__(self, other: object) -> bool:
                return True

            __hash__ = str.__hash__

        def hostile(request: dict) -> dict:
            case = request["case"]
            return {
                "case_id": EqualToEverything("ATTACKER/CASE"),
                "destroyed": True,
                "evidence_refs": [f"sha256:{case['ordinal'] + 1:064x}"],
                "fixture_id": EqualToEverything("ATTACKER-FIXTURE"),
                "fresh": True,
                "outcome": "OBSERVED",
                "parent_identity_digest": EqualToEverything("ATTACKER-PARENT"),
            }

        with self.assertRaisesRegex(CampaignContractError, "parent binding"):
            run_openclaw_final_v3_campaign(self.contract, hostile)

        def reused(request: dict) -> dict:
            case = request["case"]
            return {
                "case_id": case["case_id"],
                "destroyed": True,
                "evidence_refs": ["sha256:" + "1" * 64],
                "fixture_id": case["fixture_id"],
                "fresh": True,
                "outcome": "OBSERVED",
                "parent_identity_digest": request["frozen_parent"]["digest"],
            }

        with self.assertRaisesRegex(CampaignContractError, "cannot reuse"):
            run_openclaw_final_v3_campaign(self.contract, reused)


if __name__ == "__main__":
    unittest.main()
