from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from aragorn.admission_openclaw_final_v3_campaign import (
    build_openclaw_final_v3_campaign_contract,
)
from aragorn.admission_openclaw_final_v3_campaign_dispatch import (
    CURRENT_V3,
    MISSING_ADAPTER,
    V3_CAPTURE_REQUIRED,
    V3_PORT_REQUIRED,
    V3_REBIND_REQUIRED,
    CampaignDispatchError,
    dispatch_openclaw_final_v3_campaign_case,
    openclaw_final_v3_campaign_case_ids,
    openclaw_final_v3_campaign_readiness,
    openclaw_final_v3_campaign_registry,
)
from scripts.materialize_openclaw_final_v3_rebound_probes import (
    _BUNDLES as V3_MATERIALIZED_BUNDLES,
)


class OpenClawFinalV3CampaignDispatchTests(unittest.TestCase):
    def test_registry_matches_contract_order_and_readiness_counts(self) -> None:
        contract = build_openclaw_final_v3_campaign_contract(campaign_nonce="a" * 64)
        expected_ids = tuple(case["case_id"] for case in contract["ordered_cases"])
        self.assertEqual(openclaw_final_v3_campaign_case_ids(), expected_ids)

        readiness = openclaw_final_v3_campaign_readiness()
        self.assertEqual(readiness["case_count"], 31)
        self.assertEqual(
            readiness["implementation_counts"],
            {
                CURRENT_V3: 8,
                V3_CAPTURE_REQUIRED: 4,
                V3_REBIND_REQUIRED: 0,
                V3_PORT_REQUIRED: 14,
                MISSING_ADAPTER: 5,
            },
        )
        self.assertEqual(readiness["remaining_implementation_count"], 23)
        self.assertFalse(readiness["native_execution_enabled"])
        self.assertTrue(readiness["case_inventory_complete"])
        self.assertFalse(readiness["execution_descriptors_complete"])
        self.assertEqual(
            readiness["capture_required_case_ids"],
            [
                "ADM-02/update/archive-source-force-replacement",
                "ADM-02/update/core-updater-plugin-replacement",
                "ADM-02/reload/chat-session-snapshot-consumer",
                "ADM-02/reload/session-snapshot-consumer",
            ],
        )

    def test_every_descriptor_has_only_fixed_paths_and_no_execution(self) -> None:
        registry = openclaw_final_v3_campaign_registry()
        self.assertFalse(registry["native_execution_enabled"])
        self.assertIn(
            "PROVISIONAL_STAGING_PATHS_NOT_EXECUTABLE_BYTE_PINS",
            registry["limitations"],
        )
        for ordinal, descriptor in enumerate(registry["cases"]):
            with self.subTest(case_id=descriptor["case_id"]):
                self.assertEqual(descriptor["ordinal"], ordinal)
                self.assertFalse(descriptor["native_execution_enabled"])
                self.assertEqual(descriptor["argv"][0], descriptor["interpreter"])
                self.assertIn(
                    descriptor["interpreter"],
                    {"/usr/local/bin/node", "/usr/local/bin/python3.12"},
                )
                self.assertRegex(
                    descriptor["argv"][1],
                    rf"^/campaign/cases/{ordinal:02d}-[^/]+/[^/]+$",
                )
                bundle_paths = [item["path"] for item in descriptor["bundle"]]
                self.assertIn(descriptor["argv"][1], bundle_paths)
                self.assertEqual(len(bundle_paths), len(set(bundle_paths)))

        missing = [
            case
            for case in registry["cases"]
            if case["implementation_state"] == MISSING_ADAPTER
        ]
        self.assertEqual(len(missing), 5)
        self.assertTrue(
            all(
                sum(item["role"] == "adapter" for item in case["bundle"]) == 1
                for case in missing
            )
        )

        rebound = [
            case
            for case in registry["cases"]
            if case["implementation_state"] == V3_CAPTURE_REQUIRED
        ]
        self.assertEqual(len(rebound), 4)
        source_path = (
            Path(__file__).resolve().parents[1]
            / "scripts/materialize_openclaw_final_v3_rebound_probes.py"
        )
        source_raw = source_path.read_bytes()
        for case in rebound:
            materializer = case["materializer"]
            self.assertEqual(
                [item["path"].rsplit("/", 1)[-1] for item in case["bundle"]],
                list(V3_MATERIALIZED_BUNDLES[case["case_id"]]),
            )
            self.assertEqual(
                materializer["argv"],
                [
                    "/usr/local/bin/python3.12",
                    ("/src/scripts/materialize_openclaw_final_v3_rebound_probes.py"),
                    case["case_id"],
                    case["argv"][1].rsplit("/", 1)[0],
                ],
            )
            self.assertRegex(materializer["source"]["digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(materializer["source"]["bytes"], len(source_raw))
            self.assertEqual(
                materializer["source"]["digest"],
                "sha256:" + hashlib.sha256(source_raw).hexdigest(),
            )

    def test_representative_invocations_are_exact_and_non_authoritative(self) -> None:
        det = dispatch_openclaw_final_v3_campaign_case("DET-01")
        self.assertEqual(
            det["descriptor"]["argv"],
            [
                "/usr/local/bin/python3.12",
                "/campaign/cases/00-det-01/run_admission_authority_replay.py",
            ],
        )
        self.assertEqual(
            [item["role"] for item in det["descriptor"]["bundle"]],
            ["probe", "vector"],
        )

        force = dispatch_openclaw_final_v3_campaign_case(
            "ADM-02/update/plugin-force-reinstall"
        )["descriptor"]
        self.assertEqual(force["implementation_state"], CURRENT_V3)
        self.assertEqual(force["interpreter"], "/usr/local/bin/python3.12")
        self.assertEqual(sum(item["role"] == "fixture" for item in force["bundle"]), 6)

        curator = dispatch_openclaw_final_v3_campaign_case(
            "ADM-02/update/curator-restore-activation"
        )["descriptor"]
        self.assertEqual(curator["implementation_state"], CURRENT_V3)
        self.assertIsNone(curator["materializer"])

        cron = dispatch_openclaw_final_v3_campaign_case(
            "ADM-02/reload/cron-rescan"
        )["descriptor"]
        self.assertEqual(cron["implementation_state"], CURRENT_V3)
        self.assertIsNone(cron["materializer"])

        prompt = dispatch_openclaw_final_v3_campaign_case(
            "ADM-02/reload/missing-prompt-blob-rebuild"
        )["descriptor"]
        self.assertEqual(prompt["implementation_state"], CURRENT_V3)
        self.assertIsNone(prompt["materializer"])

        invalidation = dispatch_openclaw_final_v3_campaign_case(
            "ADM-02/reload/workshop-invalidation"
        )["descriptor"]
        self.assertEqual(invalidation["implementation_state"], V3_PORT_REQUIRED)
        self.assertEqual(
            invalidation["argv"][1],
            (
                "/campaign/cases/28-adm-02-reload-workshop-invalidation/"
                "protected-workshop-invalidation-v3-probe.mjs"
            ),
        )

        serialized = json.dumps(
            {
                "dispatch": det,
                "readiness": openclaw_final_v3_campaign_readiness(),
            },
            sort_keys=True,
        )
        self.assertNotIn('"decision"', serialized)
        self.assertNotIn('"outcome"', serialized)
        self.assertNotIn('"PASS"', serialized)
        self.assertNotIn("_eligible", serialized)

    def test_dispatch_rejects_every_inexact_or_non_string_case_id(self) -> None:
        class StringSubclass(str):
            pass

        invalid = (
            None,
            b"DET-01",
            StringSubclass("DET-01"),
            "det-01",
            " DET-01",
            "DET-01 ",
            "DET-01\n",
            "ADM-02/update/not-a-route",
        )
        for value in invalid:
            with (
                self.subTest(value=repr(value)),
                self.assertRaisesRegex(CampaignDispatchError, "exact registry member"),
            ):
                dispatch_openclaw_final_v3_campaign_case(value)

    def test_callers_cannot_mutate_the_fixed_registry(self) -> None:
        first = openclaw_final_v3_campaign_registry()
        first["cases"][0]["argv"].append("--caller-path")
        first["cases"][0]["bundle"][0]["path"] = "/tmp/caller"

        fresh = dispatch_openclaw_final_v3_campaign_case("DET-01")["descriptor"]
        self.assertEqual(len(fresh["argv"]), 2)
        self.assertEqual(
            fresh["bundle"][0]["path"],
            "/campaign/cases/00-det-01/run_admission_authority_replay.py",
        )


if __name__ == "__main__":
    unittest.main()
