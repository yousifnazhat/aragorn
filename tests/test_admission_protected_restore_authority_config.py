from __future__ import annotations

import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import admission_protected_restore_authority_config as config
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from scripts.materialize_fixed_admission_probes import (
    transformed_restore_authority_probe,
)

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_EVIDENCE = _ROOT / config._EVIDENCE["path"]
_RECEIPT = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-restore-authority-config-activation-v1-2026-08-13.json"
)
_PARENT = (
    _ROOT
    / "benchmark/receipts/phase3-openclaw-protected-curator-restore-denial-route-qualification-v1-2026-08-13.json"
)
_PROFILE = _ADMISSION / "protected-restore-authority-profile-v1.json"
_LOCK = _ADMISSION / "protected-restore-authority-runtime-v1.lock.json"
_CONFIGURATION = _ADMISSION / "protected-restore-authority-config-v1.json"


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_bytes())


class ProtectedRestoreAuthorityConfigTests(unittest.TestCase):
    def test_two_route_coverage_and_hostile_inputs_fail_closed(self) -> None:
        receipt = _load(_RECEIPT)
        parent = _load(_PARENT)
        profile = _load(_PROFILE)
        lock = _load(_LOCK)
        evidence = _load(_EVIDENCE)
        inventory = _load(_ADMISSION / "update-reload-route-inventory-v1.json")
        candidates = _load(
            _ROOT / "benchmark/admission-runtime-candidates-v1.lock.json"
        )
        probe = transformed_restore_authority_probe(
            "protected-config-activation-probe.mjs"
        )

        with TemporaryDirectory() as temporary:
            cas = CAS(temporary)
            for raw in (
                _PROFILE.read_bytes(),
                _LOCK.read_bytes(),
                _CONFIGURATION.read_bytes(),
                probe,
                _EVIDENCE.read_bytes(),
            ):
                cas.put(BytesIO(raw), max_bytes=len(raw))

            def verify(
                *,
                source: dict[str, object] = receipt,
                selected_parent: dict[str, object] = parent,
                selected_profile: dict[str, object] = profile,
                selected_lock: dict[str, object] = lock,
                selected_cas: CAS = cas,
            ) -> dict[str, object]:
                return config.verify_openclaw_protected_restore_authority_config_activation(
                    source,
                    evidence_cas=selected_cas,
                    route_profile=selected_profile,
                    runtime_lock=selected_lock,
                    route_inventory=inventory,
                    runtime_candidates=candidates,
                    curator_qualification=selected_parent,
                )

            first = verify()
            self.assertEqual(first, verify())
            self.assertEqual(
                first["profile"]["counts"],
                {"fail": 0, "not_tested": 19, "pass": 2},
            )
            statuses = {
                item["id"]: item["status"] for item in first["profile"]["routes"]
            }
            self.assertEqual(
                {route for route, status in statuses.items() if status == "PASS"},
                config._PASS_ROUTES,
            )
            self.assertTrue(
                all(
                    value is False
                    for key, value in first["decision"].items()
                    if key != "status"
                )
            )

            def evidence_case(label: str) -> None:
                changed = deepcopy(evidence)
                before = changed["action"]["prerequisites"]
                after = changed["action"]["observations"]
                commands = changed["action"]["commands"]
                if label == "route":
                    changed["route"]["status"] = "PASS"
                elif label == "EROFS":
                    after["update"]["response"]["value"]["error"]["code"] = "OK"
                elif label == "config":
                    after["config_after"]["file"]["mode"] = "660"
                elif label == "runtime":
                    after["runtime_tree_after"]["tree_digest"] = "sha256:" + "0" * 64
                elif label == "discovery":
                    after["discovery_after"]["response"]["value"]["modelVisible"] = (
                        False
                    )
                elif label == "argv":
                    commands[2]["argv"] = commands[0]["argv"]
                    before["discovery_before"]["command"]["argv"] = commands[0]["argv"]
                elif label == "pid":
                    for index, command in enumerate(commands, 1):
                        command["pid"] = index
                elif label == "time":
                    commands[0]["completed_at"] = commands[0]["started_at"]
                    before["version"]["completed_at"] = before["version"]["started_at"]
                elif label == "output":
                    commands[0]["stdout_excerpt"] = "forged\n"
                    before["version"]["stdout_excerpt"] = "forged\n"
                else:  # pragma: no cover
                    raise AssertionError(label)
                config._verify_evidence(
                    changed, profile, lock, _CONFIGURATION.read_bytes()
                )

            def receipt_case() -> None:
                changed = deepcopy(receipt)
                changed["results"]["pass"] = [config._CONFIG_ROUTE]
                verify(source=changed)

            def parent_case() -> None:
                changed = deepcopy(parent)
                changed["route"]["status"] = "NOT_TESTED"
                verify(selected_parent=changed)

            def profile_case() -> None:
                changed = deepcopy(profile)
                changed["controls"]["curator_restore_authority"] = "local"
                verify(selected_profile=changed)

            def lock_case() -> None:
                changed = deepcopy(lock)
                changed["source"]["commit"] = "0" * 40
                verify(selected_lock=changed)

            def cas_case() -> None:
                with TemporaryDirectory() as empty:
                    verify(selected_cas=CAS(empty))

            cases = [
                *(
                    (label, lambda label=label: evidence_case(label))
                    for label in (
                        "route",
                        "EROFS",
                        "config",
                        "runtime",
                        "discovery",
                        "argv",
                        "pid",
                        "time",
                        "output",
                    )
                ),
                ("receipt", receipt_case),
                ("parent", parent_case),
                ("profile", profile_case),
                ("lock", lock_case),
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
