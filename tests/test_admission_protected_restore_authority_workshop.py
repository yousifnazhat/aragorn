from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_protected_restore_authority_workshop as workshop
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from scripts.materialize_fixed_admission_probes import (
    transformed_restore_authority_probe,
)

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_EVIDENCE = _ROOT / workshop._EVIDENCE["path"]
_RECEIPT = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-restore-authority-workshop-proposal-apply-v1-2026-08-13.json"
)
_PARENT = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-restore-authority-fresh-session-route-coverage-v1-2026-08-13.json"
)
_PROFILE = _ADMISSION / "protected-restore-authority-profile-v1.json"
_LOCK = _ADMISSION / "protected-restore-authority-runtime-v1.lock.json"
_CONFIG = _ADMISSION / "protected-restore-authority-config-v1.json"
_SOURCE_PROBE = _ADMISSION / "protected-route-probe.mjs"
_TARGET = _ROOT / "benchmark/fixtures/phase3-protected-archive-existing/SKILL.md"
_PROPOSAL = _ROOT / "benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md"


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_bytes())


class ProtectedRestoreAuthorityWorkshopTests(unittest.TestCase):
    def test_six_route_coverage_and_hostile_inputs_fail_closed(self) -> None:
        receipt = _load(_RECEIPT)
        parent = _load(_PARENT)
        profile = _load(_PROFILE)
        lock = _load(_LOCK)
        evidence = _load(_EVIDENCE)
        inventory = _load(_ADMISSION / "update-reload-route-inventory-v1.json")
        candidates = _load(
            _ROOT / "benchmark/admission-runtime-candidates-v1.lock.json"
        )

        with TemporaryDirectory() as temporary:
            cas = CAS(temporary)
            for raw in (
                _PROFILE.read_bytes(),
                _LOCK.read_bytes(),
                _CONFIG.read_bytes(),
                _SOURCE_PROBE.read_bytes(),
                transformed_restore_authority_probe("protected-route-probe.mjs"),
                _TARGET.read_bytes(),
                _PROPOSAL.read_bytes(),
                _EVIDENCE.read_bytes(),
            ):
                cas.put(BytesIO(raw), max_bytes=len(raw))

            def verify(
                *,
                source: dict[str, object] = receipt,
                selected_parent: dict[str, object] = parent,
                selected_profile: dict[str, object] = profile,
                selected_lock: dict[str, object] = lock,
                selected_inventory: dict[str, object] = inventory,
                selected_candidates: dict[str, object] = candidates,
                selected_cas: CAS = cas,
            ) -> dict[str, object]:
                return workshop.verify_openclaw_protected_restore_authority_workshop_proposal_apply(
                    source,
                    evidence_cas=selected_cas,
                    route_profile=selected_profile,
                    runtime_lock=selected_lock,
                    route_inventory=selected_inventory,
                    runtime_candidates=selected_candidates,
                    fresh_session_qualification=selected_parent,
                )

            first = verify()
            self.assertEqual(first, verify())
            self.assertEqual(
                first["profile"]["counts"],
                {"fail": 0, "not_tested": 15, "pass": 6},
            )
            statuses = {
                item["id"]: item["status"] for item in first["profile"]["routes"]
            }
            self.assertEqual(
                {route for route, status in statuses.items() if status == "PASS"},
                workshop._PASS_ROUTES,
            )
            self.assertTrue(
                all(
                    value is False
                    for key, value in first["decision"].items()
                    if key != "status"
                )
            )
            self.assertIn(
                "NO_WRITABLE_WORKSPACE_POSITIVE_CONTROL_IN_THIS_CAPTURE",
                first["limitations"],
            )
            self.assertIn(
                "LEGACY_PROPOSAL_VOLUME_HAS_PHASE_LABEL_ONLY_NO_CURRENT_SOURCE_COMMIT_OR_DIGEST_LABEL",
                first["limitations"],
            )

            def evidence_case(label: str) -> None:
                changed = deepcopy(evidence)
                action = changed["actions"][0]
                before = action["prerequisites"]
                after = action["observations"]
                commands = action["commands"]
                if label == "route":
                    changed["routes"][0]["status"] = "PASS"
                elif label == "boundary":
                    changed["protected_boundary"]["runtime"]["read_only"] = False
                elif label == "config":
                    changed["protected_boundary"]["configuration"][
                        "canonical_digest"
                    ] = "sha256:" + "0" * 64
                elif label == "runtime":
                    changed["runtime_binding"]["commit"] = "0" * 40
                elif label == "probe":
                    changed["implementation_digest"] = "sha256:" + "0" * 64
                elif label == "proposal":
                    before["draft"]["observation"]["digest"] = "sha256:" + "0" * 64
                elif label == "argv":
                    commands[2]["argv"] = commands[0]["argv"]
                    after["native_apply_result"]["command"]["argv"] = commands[0][
                        "argv"
                    ]
                elif label == "pid":
                    commands[1]["pid"] = commands[0]["pid"]
                elif label == "time":
                    commands[0]["completed_at"] = commands[0]["started_at"]
                    after["discovery_before"]["command"]["completed_at"] = commands[0][
                        "started_at"
                    ]
                elif label == "denial":
                    after["native_apply_result"]["response"]["value"]["error"][
                        "code"
                    ] = "UNAVAILABLE"
                elif label == "target":
                    after["target_after"]["directory"]["exists"] = True
                elif label == "discovery":
                    after["discovery_after"]["target_matches"] = [
                        "aragorn-protected-workshop"
                    ]
                elif label == "output":
                    commands[1]["stdout_excerpt"] = "{}\n"
                else:  # pragma: no cover
                    raise AssertionError(label)
                workshop._verify_evidence(
                    changed, receipt, profile, lock, _CONFIG.read_bytes()
                )

            def receipt_case() -> None:
                changed = deepcopy(receipt)
                changed["results"]["pass"] = [workshop._ROUTE]
                verify(source=changed)

            def parent_case() -> None:
                changed = deepcopy(parent)
                changed["profile"]["counts"]["pass"] = 6
                verify(selected_parent=changed)

            def profile_case() -> None:
                changed = deepcopy(profile)
                changed["controls"]["curator_restore_authority"] = "local"
                verify(selected_profile=changed)

            def lock_case() -> None:
                changed = deepcopy(lock)
                changed["source"]["commit"] = "0" * 40
                verify(selected_lock=changed)

            def inventory_case() -> None:
                changed = deepcopy(inventory)
                changed["schema"] += "X"
                verify(selected_inventory=changed)

            def candidates_case() -> None:
                changed = deepcopy(candidates)
                changed["schema"] += "X"
                verify(selected_candidates=changed)

            def cas_case() -> None:
                with TemporaryDirectory() as empty:
                    verify(selected_cas=CAS(empty))

            cases = [
                *(
                    (label, lambda label=label: evidence_case(label))
                    for label in (
                        "route",
                        "boundary",
                        "config",
                        "runtime",
                        "probe",
                        "proposal",
                        "argv",
                        "pid",
                        "time",
                        "denial",
                        "target",
                        "discovery",
                        "output",
                    )
                ),
                ("receipt", receipt_case),
                ("parent", parent_case),
                ("profile", profile_case),
                ("lock", lock_case),
                ("inventory", inventory_case),
                ("candidates", candidates_case),
                ("CAS", cas_case),
            ]
            for label, case in cases:
                with (
                    self.subTest(hostile=label),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    case()


if __name__ == "__main__":
    unittest.main()
