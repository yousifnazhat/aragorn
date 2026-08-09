from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_protected_profile import (
    compose_openclaw_protected_profile_coverage,
    compose_openclaw_protected_profile_coverage_v2,
    compose_openclaw_protected_profile_coverage_v3,
)
from aragorn.admission_runtime_profile import load_runtime_profile
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"


class ProtectedProfileCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = load_runtime_profile(
            (_ADMISSION / "protected-consumer-profile-v1.json").read_bytes()
        )
        cls.inventory = json.loads(
            (_ADMISSION / "update-reload-route-inventory-v1.json").read_bytes()
        )
        cls.candidates = json.loads(
            (_ROOT / "benchmark/admission-runtime-candidates-v1.lock.json").read_bytes()
        )
        receipts = _ROOT / "benchmark/receipts"
        cls.workshop = json.loads(
            (
                receipts / "phase1-openclaw-protected-workshop-route-v1-2026-08-04.json"
            ).read_bytes()
        )
        cls.archive = json.loads(
            (
                receipts
                / "phase3-openclaw-protected-archive-route-qualification-v1-2026-08-04.json"
            ).read_bytes()
        )
        cls.config = json.loads(
            (
                receipts
                / "phase3-openclaw-protected-config-route-qualification-v1-2026-08-07.json"
            ).read_bytes()
        )
        cls.prompt = json.loads(
            (
                receipts
                / "phase3-openclaw-protected-prompt-rebuild-route-qualification-v1-2026-08-09.json"
            ).read_bytes()
        )
        cls.snapshot = json.loads(
            (
                receipts
                / "phase3-openclaw-protected-session-snapshot-route-qualification-v1-2026-08-09.json"
            ).read_bytes()
        )
        cls.cron = json.loads(
            (
                receipts
                / "phase3-openclaw-protected-cron-rescan-route-qualification-v1-2026-08-09.json"
            ).read_bytes()
        )
        cls.coverage_v3 = json.loads(
            (
                receipts
                / "phase3-openclaw-protected-profile-route-coverage-v3-2026-08-09.json"
            ).read_bytes()
        )

    def compose(
        self,
        qualifications: list[dict] | None = None,
        *,
        profile: dict | None = None,
        inventory: dict | None = None,
        candidates: dict | None = None,
    ) -> dict:
        return compose_openclaw_protected_profile_coverage(
            self.profile if profile is None else profile,
            self.inventory if inventory is None else inventory,
            self.candidates if candidates is None else candidates,
            [self.workshop, self.archive, self.config]
            if qualifications is None
            else qualifications,
        )

    def compose_v3(self, qualifications: list[dict]) -> dict:
        return compose_openclaw_protected_profile_coverage_v3(
            self.profile,
            self.inventory,
            self.candidates,
            qualifications,
        )

    def test_composes_three_passes_and_eighteen_not_tested_in_inventory_order(
        self,
    ) -> None:
        result = self.compose([self.workshop, self.archive, self.config])
        reversed_result = self.compose([self.config, self.archive, self.workshop])

        self.assertEqual(result, reversed_result)
        self.assertEqual(
            canonical_digest(result),
            "sha256:85b06c0032a183bcdf4072927c75deb3ae5bf1fa343aacaaa82cee1981f755ae",
        )
        self.assertNotIn("recorded_at", result)
        self.assertEqual(result["counts"], {"PASS": 3, "NOT_TESTED": 18})
        self.assertEqual(len(result["routes"]), 21)
        self.assertEqual(
            result["route_inventory_canonical_digest"],
            "sha256:c175cd145a0c18d80921edbeb2452e34182188f97ee4e3b8d26176e7e38f5b41",
        )
        self.assertEqual(
            [route["id"] for route in result["routes"]],
            [
                f"{route['id']}/{path['id']}"
                for route in self.inventory["routes"]
                for path in route["paths"]
            ],
        )
        self.assertEqual(
            {route["id"] for route in result["routes"] if route["status"] == "PASS"},
            {
                "ADM-02/update/archive-source-force-replacement",
                "ADM-02/update/config-entry-activation",
                "ADM-02/update/workshop-proposal-apply",
            },
        )
        self.assertEqual(
            result["decision"],
            {
                "status": "PARTIAL_ROUTE_COVERAGE",
                "aggregate_admission_eligible": False,
                "admission_profile_eligible": False,
                "installer_work_eligible": False,
                "phase3_exit_eligible": False,
            },
        )

    def test_rejects_unknown_duplicate_forged_fail_and_cross_profile(self) -> None:
        cases = {}
        unknown = deepcopy(self.workshop)
        unknown["route"]["id"] = "ADM-02/reload/workshop-invalidation"
        cases["unknown"] = [unknown, self.archive, self.config]
        cases["duplicate"] = [self.archive, self.archive, self.config]
        forged = deepcopy(self.archive)
        forged["route"]["observed_outcome"] = "DENIED"
        cases["forged"] = [self.workshop, forged, self.config]
        failed = deepcopy(self.workshop)
        failed["route"]["status"] = "FAIL"
        cases["FAIL"] = [failed, self.archive, self.config]
        cross_profile = deepcopy(self.archive)
        cross_profile["profile"] = "other-profile"
        cases["cross-profile"] = [self.workshop, cross_profile, self.config]

        for name, qualifications in cases.items():
            with self.subTest(name=name), self.assertRaises(AdmissionEvidenceError):
                self.compose(qualifications)

    def test_requires_all_pins_and_reuses_profile_inventory_validation(self) -> None:
        with self.assertRaises(AdmissionEvidenceError):
            self.compose([self.archive, self.config])

        profile = deepcopy(self.profile)
        profile["decision"] = {"installer_work_eligible": True, "status": "PASS"}
        inventory = deepcopy(self.inventory)
        inventory["routes"][0]["paths"].pop()
        candidates = deepcopy(self.candidates)
        candidates["candidates"][0]["version"] = "changed"
        for name, kwargs in {
            "profile": {"profile": profile},
            "inventory": {"inventory": inventory},
            "candidates": {"candidates": candidates},
        }.items():
            with self.subTest(name=name), self.assertRaises(AdmissionEvidenceError):
                self.compose(**kwargs)

    def test_v2_composes_four_passes_and_seventeen_not_tested(self) -> None:
        qualifications = [self.workshop, self.archive, self.config, self.prompt]
        result = compose_openclaw_protected_profile_coverage_v2(
            self.profile,
            self.inventory,
            self.candidates,
            qualifications,
        )
        reversed_result = compose_openclaw_protected_profile_coverage_v2(
            self.profile,
            self.inventory,
            self.candidates,
            list(reversed(qualifications)),
        )

        self.assertEqual(result, reversed_result)
        self.assertEqual(
            canonical_digest(result),
            "sha256:859bf73e0a78eb8f12d9ff96c9220bbdd35ed7510f25063d4b68838ca694b2bd",
        )
        self.assertEqual(result["counts"], {"PASS": 4, "NOT_TESTED": 17})
        self.assertEqual(
            {route["id"] for route in result["routes"] if route["status"] == "PASS"},
            {
                "ADM-02/update/archive-source-force-replacement",
                "ADM-02/update/config-entry-activation",
                "ADM-02/update/workshop-proposal-apply",
                "ADM-02/reload/missing-prompt-blob-rebuild",
            },
        )
        self.assertEqual(
            result["limitations"],
            [
                "ONLY_FOUR_EXACT_ROUTE_QUALIFICATIONS_COMPOSED",
                "NO_AGGREGATE_ADMISSION_INSTALLER_OR_PHASE3_AUTHORITY",
            ],
        )
        with self.assertRaises(AdmissionEvidenceError):
            compose_openclaw_protected_profile_coverage_v2(
                self.profile,
                self.inventory,
                self.candidates,
                qualifications[:-1],
            )

    def test_v3_composes_five_passes_one_fail_and_fifteen_not_tested(self) -> None:
        qualifications = [
            self.workshop,
            self.archive,
            self.config,
            self.prompt,
            self.snapshot,
            self.cron,
        ]
        result = self.compose_v3(qualifications)

        self.assertEqual(result, self.compose_v3(list(reversed(qualifications))))
        self.assertEqual(result, self.coverage_v3)
        self.assertEqual(
            canonical_digest(result),
            "sha256:3eaf398f1d2d19bb3dd38fb92c5e09f2d6235fbb042f7315b7ea2caf2f26b5e1",
        )
        self.assertEqual(
            result["counts"], {"PASS": 5, "FAIL": 1, "NOT_TESTED": 15}
        )
        routes = {route["id"]: route for route in result["routes"]}
        self.assertEqual(
            routes["ADM-02/reload/session-snapshot-consumer"],
            {
                "id": "ADM-02/reload/session-snapshot-consumer",
                "status": "FAIL",
                "qualification_digest": (
                    "sha256:203bbbcfc020f0c325001aaeda4b6e9a944d56703ffee600b7561040843096ff"
                ),
            },
        )
        self.assertEqual(routes["ADM-02/reload/cron-rescan"]["status"], "PASS")
        self.assertEqual(
            result["decision"],
            {
                "status": "FAIL",
                "aggregate_admission_eligible": False,
                "admission_profile_eligible": False,
                "installer_work_eligible": False,
                "phase3_exit_eligible": False,
            },
        )
        self.assertEqual(
            result["limitations"],
            [
                "FIVE_EXACT_ROUTE_PASSES_AND_ONE_EXACT_ROUTE_FAILURE_COMPOSED",
                "KNOWN_EXACT_ROUTE_FAILURE_PREVENTS_AGGREGATE_AUTHORITY",
                "NO_AGGREGATE_ADMISSION_INSTALLER_OR_PHASE3_AUTHORITY",
            ],
        )

    def test_v3_rejects_status_decision_substitution_and_missing_pin(self) -> None:
        qualifications = [
            self.workshop,
            self.archive,
            self.config,
            self.prompt,
            self.snapshot,
            self.cron,
        ]
        cases = []
        for index, status in ((4, "PASS"), (5, "FAIL")):
            changed = deepcopy(qualifications)
            changed[index]["route"]["status"] = status
            cases.append(changed)
        for index, status in ((4, "ROUTE_PASS"), (5, "ROUTE_FAIL")):
            changed = deepcopy(qualifications)
            changed[index]["decision"]["status"] = status
            cases.append(changed)
        cases.append(qualifications[:-1])

        for qualifications in cases:
            with self.subTest(), self.assertRaises(AdmissionEvidenceError):
                self.compose_v3(qualifications)


if __name__ == "__main__":
    unittest.main()
