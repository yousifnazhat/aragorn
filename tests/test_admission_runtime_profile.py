from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_runtime_profile import (
    load_runtime_profile,
    validate_openclaw_protected_consumer_profile,
    verify_openclaw_protected_consumer_routes,
)
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]


class ProtectedConsumerProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(self.temporary.name)
        self.profile_path = (
            _ROOT
            / "benchmark"
            / "admission"
            / "openclaw-v2026.7.1"
            / "protected-consumer-profile-v1.json"
        )
        self.profile_raw = self.profile_path.read_bytes()
        self.profile = load_runtime_profile(self.profile_raw)
        self.inventory = json.loads(
            (
                self.profile_path.parent / "update-reload-route-inventory-v1.json"
            ).read_bytes()
        )
        self.candidates = json.loads(
            (
                _ROOT
                / "benchmark"
                / "admission-runtime-candidates-v1.lock.json"
            ).read_bytes()
        )
        self.receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / "phase1-openclaw-contained-restart-probe-2026-07-27.json"
            ).read_bytes()
        )

    def retain_source_evidence(self) -> None:
        evidence = _ROOT / "benchmark" / "evidence"
        for name in (
            "openclaw-v2026.7.1-contained-restart-environment-2026-07-27.json",
            "openclaw-v2026.7.1-contained-restart-probe-2026-07-27.json",
        ):
            raw = (evidence / name).read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))
        self.cas.put(BytesIO(self.profile_raw), max_bytes=len(self.profile_raw))

    def test_exact_profile_keeps_unexecuted_routes_not_tested(self) -> None:
        self.retain_source_evidence()

        result = verify_openclaw_protected_consumer_routes(
            self.receipt,
            evidence_cas=self.cas,
            route_profile=self.profile,
            route_inventory=self.inventory,
            runtime_candidates=self.candidates,
        )

        self.assertEqual(
            result["scenario_statuses"],
            {"ADM-02/update": "NOT_TESTED", "ADM-02/reload": "NOT_TESTED"},
        )
        self.assertFalse(result["installer_work_eligible"])
        result["limitations"].clear()
        validate_openclaw_protected_consumer_profile(
            self.profile,
            route_inventory=self.inventory,
            runtime_candidates=self.candidates,
        )
        self.assertEqual(
            len(self.profile["routes"]),
            sum(len(route["paths"]) for route in self.inventory["routes"]),
        )

    def test_profile_cannot_omit_or_promote_a_route(self) -> None:
        omitted = deepcopy(self.profile)
        omitted["routes"].pop()
        with self.assertRaises(AdmissionEvidenceError):
            validate_openclaw_protected_consumer_profile(
                omitted,
                route_inventory=self.inventory,
                runtime_candidates=self.candidates,
            )

        promoted = deepcopy(self.profile)
        promoted["decision"] = {
            "installer_work_eligible": True,
            "status": "PASS",
        }
        with self.assertRaises(AdmissionEvidenceError):
            validate_openclaw_protected_consumer_profile(
                promoted,
                route_inventory=self.inventory,
                runtime_candidates=self.candidates,
            )

    def test_route_closure_requires_retained_profile_bytes(self) -> None:
        evidence = _ROOT / "benchmark" / "evidence"
        for name in (
            "openclaw-v2026.7.1-contained-restart-environment-2026-07-27.json",
            "openclaw-v2026.7.1-contained-restart-probe-2026-07-27.json",
        ):
            raw = (evidence / name).read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))

        with self.assertRaisesRegex(
            AdmissionEvidenceError,
            "profile is not retained",
        ):
            verify_openclaw_protected_consumer_routes(
                self.receipt,
                evidence_cas=self.cas,
                route_profile=self.profile,
                route_inventory=self.inventory,
                runtime_candidates=self.candidates,
            )

    def test_profile_loader_rejects_duplicate_keys(self) -> None:
        with self.assertRaisesRegex(AdmissionEvidenceError, "duplicate"):
            load_runtime_profile(b'{"schema":"one","schema":"two"}\n')


if __name__ == "__main__":
    unittest.main()
