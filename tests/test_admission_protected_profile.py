from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_protected_profile import (
    compose_openclaw_protected_profile_coverage,
)
from aragorn.admission_runtime_profile import load_runtime_profile

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
            [self.workshop, self.archive] if qualifications is None else qualifications,
        )

    def test_composes_two_passes_and_nineteen_not_tested_in_inventory_order(
        self,
    ) -> None:
        result = self.compose([self.workshop, self.archive])
        reversed_result = self.compose([self.archive, self.workshop])

        self.assertEqual(result, reversed_result)
        self.assertNotIn("recorded_at", result)
        self.assertEqual(result["counts"], {"PASS": 2, "NOT_TESTED": 19})
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
        cases["unknown"] = [unknown, self.archive]
        cases["duplicate"] = [self.archive, self.archive]
        forged = deepcopy(self.archive)
        forged["route"]["observed_outcome"] = "DENIED"
        cases["forged"] = [self.workshop, forged]
        failed = deepcopy(self.workshop)
        failed["route"]["status"] = "FAIL"
        cases["FAIL"] = [failed, self.archive]
        cross_profile = deepcopy(self.archive)
        cross_profile["profile"] = "other-profile"
        cases["cross-profile"] = [self.workshop, cross_profile]

        for name, qualifications in cases.items():
            with self.subTest(name=name), self.assertRaises(AdmissionEvidenceError):
                self.compose(qualifications)

    def test_requires_both_pins_and_reuses_profile_inventory_validation(self) -> None:
        with self.assertRaises(AdmissionEvidenceError):
            self.compose([self.archive])

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


if __name__ == "__main__":
    unittest.main()
