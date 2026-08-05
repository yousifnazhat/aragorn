from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_runtime_profile as runtime_profile
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_runtime_profile import (
    load_runtime_profile,
    validate_openclaw_protected_consumer_profile,
    verify_openclaw_protected_consumer_routes,
    verify_openclaw_protected_workshop_route,
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
        self.protected_receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / "phase1-openclaw-protected-route-actions-v5-2026-07-29.json"
            ).read_bytes()
        )
        self.protected_evidence_path = (
            _ROOT
            / "benchmark"
            / "evidence"
            / "openclaw-v2026.7.1-protected-route-actions-v5-2026-07-29.json"
        )
        self.protected_evidence = json.loads(
            self.protected_evidence_path.read_bytes()
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

    def retain_protected_workshop_evidence(self) -> None:
        for path in (
            self.protected_evidence_path,
            self.profile_path,
            self.profile_path.parent / "protected-route-probe.mjs",
            self.profile_path.parent / "protected-route-config-v1.json",
            _ROOT
            / "benchmark"
            / "fixtures"
            / "phase1-protected-workshop"
            / "PROPOSAL.md",
        ):
            raw = path.read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))

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

    def test_exact_workshop_denial_qualifies_only_that_route(self) -> None:
        self.retain_protected_workshop_evidence()

        result = verify_openclaw_protected_workshop_route(
            self.protected_receipt,
            evidence_cas=self.cas,
            route_profile=self.profile,
            route_inventory=self.inventory,
            runtime_candidates=self.candidates,
        )
        expected = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / "phase1-openclaw-protected-workshop-route-v1-2026-08-04.json"
            ).read_bytes()
        )

        self.assertEqual(result, expected)
        self.assertEqual(result["route"]["status"], "PASS")
        self.assertEqual(result["decision"]["status"], "ROUTE_PASS")
        self.assertFalse(result["decision"]["admission_profile_eligible"])
        self.assertFalse(result["decision"]["installer_work_eligible"])
        self.assertFalse(result["decision"]["phase3_exit_eligible"])

    def test_workshop_qualification_rejects_receipt_or_source_drift(self) -> None:
        self.retain_protected_workshop_evidence()
        changed = deepcopy(self.protected_receipt)
        changed["containment"]["privileged"] = True

        with self.assertRaisesRegex(AdmissionEvidenceError, "receipt changed"):
            verify_openclaw_protected_workshop_route(
                changed,
                evidence_cas=self.cas,
                route_profile=self.profile,
                route_inventory=self.inventory,
                runtime_candidates=self.candidates,
            )

        with TemporaryDirectory() as temporary:
            incomplete = CAS(temporary)
            for path in (
                _ROOT
                / "benchmark"
                / "evidence"
                / "openclaw-v2026.7.1-protected-route-actions-v5-2026-07-29.json",
                self.profile_path,
                self.profile_path.parent / "protected-route-probe.mjs",
                self.profile_path.parent / "protected-route-config-v1.json",
            ):
                raw = path.read_bytes()
                incomplete.put(BytesIO(raw), max_bytes=len(raw))
            with self.assertRaisesRegex(
                AdmissionEvidenceError,
                "proposal is not retained",
            ):
                verify_openclaw_protected_workshop_route(
                    self.protected_receipt,
                    evidence_cas=incomplete,
                    route_profile=self.profile,
                    route_inventory=self.inventory,
                    runtime_candidates=self.candidates,
                )

    def test_workshop_semantics_reject_boundary_and_effect_drift(self) -> None:
        boundary_mutations = (
            (
                "writable mount",
                lambda value: value["roots"]["workspace_skills"]["records"][0][
                    "mount_options"
                ].append("rw"),
            ),
            (
                "changed source",
                lambda value: value["roots"]["workspace_skills"]["records"][
                    0
                ].__setitem__("root", "/tmp/unprotected"),
            ),
        )
        for label, mutate in boundary_mutations:
            with self.subTest(label=label):
                boundary = deepcopy(self.protected_evidence["protected_boundary"])
                mutate(boundary)
                with self.assertRaises(AdmissionEvidenceError):
                    runtime_profile._verify_protected_boundary(boundary)

        action_mutations = (
            (
                "missing EROFS",
                lambda value: value["actions"][2]["observations"][
                    "native_apply_result"
                ]["response"]["value"]["error"].__setitem__(
                    "message",
                    "write rejected",
                ),
            ),
            (
                "successful apply",
                lambda value: value["actions"][2]["observations"][
                    "native_apply_result"
                ]["command"].__setitem__("exit_code", 0),
            ),
            (
                "created target",
                lambda value: value["actions"][2]["observations"]["target_after"][
                    "directory"
                ].__setitem__("exists", True),
            ),
            (
                "discovered target",
                lambda value: value["actions"][2]["observations"][
                    "discovery_after"
                ].__setitem__("target_matches", ["aragorn-protected-workshop"]),
            ),
            (
                "changed gateway",
                lambda value: value["actions"][2]["prerequisites"][
                    "gateway_process"
                ].__setitem__("pid", 2),
            ),
        )
        for label, mutate in action_mutations:
            with self.subTest(label=label):
                evidence = deepcopy(self.protected_evidence)
                mutate(evidence)
                with self.assertRaises(AdmissionEvidenceError):
                    runtime_profile._verify_protected_workshop_action(
                        evidence,
                        self.protected_receipt,
                    )


if __name__ == "__main__":
    unittest.main()
